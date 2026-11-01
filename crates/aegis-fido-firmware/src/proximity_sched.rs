//! Scheduler de proximidade do dispatcher FreeRTOS (extraido de dispatch.rs).
//!
//! Corte auditoria: dispatch vira roteador fino e reexporta ProxSchedState daqui.
//! Contrato (R15/R16, sec. 9): preservado - fail-closed, sem relogio host (now_ms injetado),
//! sem segredo em log (opcodes/estados/contadores apenas). no_std-safe (core + alloc).

/// Trava de presença RSSI (proximidade BLE) no caminho FreeRTOS.
///
/// O `mod` inteiro é `#[cfg(feature = "proximity")]` (fora do caminho
/// FreeRTOS os hooks ficam sem chamador: `allow(dead_code)` documenta o
/// aguardo da task BLE; build default e freertos sem proximity não veem
/// nada daqui).
///
/// Estado beacon/key/fob (RAM; fail-closed sem chave):
/// - `fob_id`: `Option<6 B>` via `proximity::beacon_fob_id` — MAC BLE
///   real (`ble_nimble::own_addr`, fail-closed; `None` com stack down ou
///   no host => sem adv, nunca inventa MAC nem usa placeholder).
/// - `key`: K_prox de 16 B em RAM + flag `key_present`. O boot faz `load`
///   ou `rekey` SOMENTE se `bonded || claimed`; sem vínculo, ausente
///   (sem adv) até o pareamento.
/// - `ctr`: contador do beacon rolling-code (volta a 0 a cada rekey;
///   satura em `u32::MAX` e pede rekey antes de avançar).
///
/// Gaps documentados do caminho FreeRTOS (o dispatcher BLE completo, com
/// os 2 pontos `Paired`, `BIND_RELEASE` e `RECOVERY_UNLOCK`, vive no loop
/// legado `run_authenticator`, fora da variante FreeRTOS):
/// - `note_paired_with_storage` (rekey + `save` + ctr=0) é o ponto de
///   pareamento do scheduler; chamar quando a task BLE publicar a conclusão
///   do bonding na fila (hoje nenhum evento carrega esse sinal: sem bomba
///   BLE aqui). O `note_paired` RAM-only segue como legado ate a fiacao.
/// - `erase` (zeroize + ctr=0 + adv off) é o hook de `BIND_RELEASE` /
///   `RECOVERY_UNLOCK`; sem esses ramos no scheduler (sem dispatch
///   GATT), ele roda ao vivo só no `Shutdown` (higiene da RAM).
/// - Sem sensor RSSI no scheduler: amostra ausente = `None` (fraco,
///   fail-closed, tende a travar; nunca zero). `Locked` só via
///   `confirm_lock` explícito; `update` nunca sai de `Locked` sozinho;
///   `unlock` exige presença + PIN (sessão PIN fora do scheduler, logo o
///   tick ao vivo passa `pin_ok=false`: presença sozinha nunca destrava).
/// - Boot/pareamento com NVS (`prox_k`): `note_boot_with_storage` faz
///   `load` ou `rekey`+`save` SOMENTE se `bonded || claimed`; sem vínculo,
///   ausente (sem adv) até `note_paired_with_storage`. Os `note_boot` /
///   `note_paired` RAM-only sao legado (sem reuso entre boots).
/// - Sem WiFi nem `PairingManager` no dispatcher FreeRTOS: intervalo
///   sempre normal e estado sempre `Idle` (gaps: desacelerar com WiFi e
///   ligar à janela real de pareamento quando entrarem no scheduler).
/// - `fob_id` tenta o MAC real via `proximity::beacon_fob_id`
///   (fail-closed; `None` sem sync ou no host => sem adv).
///
/// Sem segredos em log: só estados e contadores, nunca `key`/TAG.
use crate::ble_nimble::{esp_ble_proximity_start, esp_ble_stop, should_adv_proximity};
use crate::pairing::PairingState;
use crate::persistence::{FlashStorageBackend, SecureStorage};
use crate::proximity::{
    beacon_fob_id, coex_proximity_allowed, encode_proximity_svc_data, generate_proximity_key,
    proximity_tag, rekey_proximity, ProximityConfig, ProximityMonitor, ProximityState,
    PROXIMITY_BEACON_VERSION,
};

/// Tick de presença ~1 s (o scheduler entrega `Tick10ms` a ~1 Hz).
const PROX_TICK_MS: u64 = 1000;
/// Presença física (BOOT) vale ~1,5 s (mesma ordem do latch legado).
const PROX_PRESENCE_MS: u64 = 1500;

/// Deriva o `fob_id`: MAC BLE real via FFI, fail-closed.
///
/// Usa `proximity::beacon_fob_id` (`ble_nimble::own_addr`; `None` sem
/// sync ou no host => sem adv). Nunca inventa MAC nem usa placeholder.
fn prox_fob_id() -> Option<[u8; 6]> {
    beacon_fob_id()
}

/// Estado de proximidade do scheduler FreeRTOS (tipado, sem JSON).
///
/// `monitor` aplica a política canônica (`< -75 dBm` por 10 s, hist
/// 5 dB, `Locked` só via `confirm_lock`, unlock só com presença +
/// PIN); o resto é o beacon rolling-code (chave + contador + gates).
pub struct ProxSchedState {
    monitor: ProximityMonitor,
    key: [u8; 16],
    key_present: bool,
    fob_id: Option<[u8; 6]>,
    ctr: u32,
    last_ms: Option<u64>,
    adv_on: bool,
    bonded: bool,
    claimed_trusted: bool,
    presence_until_ms: Option<u64>,
}

impl ProxSchedState {
    /// Estado inicial: `Near`, sem chave (fail-closed), ctr=0.
    pub fn new() -> Self {
        Self {
            monitor: ProximityMonitor::new(ProximityConfig::default()),
            key: [0u8; 16],
            key_present: false,
            fob_id: prox_fob_id(),
            ctr: 0,
            last_ms: None,
            adv_on: false,
            bonded: false,
            claimed_trusted: false,
            presence_until_ms: None,
        }
    }

    /// Boot com NVS: `load` ou `rekey`+`save` SOMENTE se `trusted`.
    ///
    /// Caminho canonico (aposenta o RAM-only `note_boot`): tenta o `load`
    /// da NVS cifrada primeiro (reuso entre boots); se ausente ou
    /// corrompido e `trusted`, gera via `rng` e persiste com `save`.
    /// Falha de `save` = fail-closed (chave zerada, sem adv). Sem vinculo
    /// a chave segue ausente (sem adv ate `note_paired_with_storage`).
    /// Retorna `true` com chave valida em RAM. Sem segredos em log.
    pub fn note_boot_with_storage<B, R>(
        &mut self,
        storage: &mut SecureStorage<B>,
        rng: &mut R,
        trusted: bool,
    ) -> bool
    where
        B: FlashStorageBackend,
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        self.fob_id = beacon_fob_id();
        if self.load_key_from_storage(storage) {
            self.bonded = true;
            log::info!("[PROX] K_prox carregado da NVS no boot.");
            return true;
        }
        if trusted {
            self.key = generate_proximity_key(rng);
            self.key_present = true;
            if self.save_key_to_storage(storage, rng) {
                self.bonded = true;
                log::info!("[PROX] K_prox gerado e persistido no boot (vinculo previo).");
                return true;
            }
            self.key = [0u8; 16];
            self.key_present = false;
            log::info!("[PROX] save K_prox falhou (fail-closed, sem chave).");
            return false;
        }
        log::info!("[PROX] sem K_prox (fail-closed ate parear).");
        false
    }

    /// Boot legado RAM-only (aposentado): gera K_prox em RAM sem NVS.
    ///
    /// Mantido p/ o dispatcher ate fiar `note_boot_with_storage` no boot
    /// (sem reuso entre boots); novos usos devem preferir o caminho com
    /// storage. `trusted` = `bonded || claimed` no boot FreeRTOS.
    pub fn note_boot(&mut self, trusted: bool) {
        self.fob_id = beacon_fob_id();
        if trusted {
            self.key = generate_proximity_key(&mut rand_core::OsRng);
            self.key_present = true;
            self.bonded = true;
            log::info!("[PROX] K_prox gerado no boot (vinculo previo).");
        } else {
            log::info!("[PROX] sem K_prox (fail-closed ate parear).");
        }
    }

    /// Fia o vinculo no scheduler: espelha `TrustFacade::is_claimed`.
    ///
    /// Chamar apos `BindingManager::load_from_storage` (e apos cada
    /// `claim`/`release`/`recovery_unlock` quando a fila BLE existir).
    /// Sem chamada, `trusted = bonded` (fail-closed ate fiar;
    /// `EXTERNAL_BLOCKED: BindingWire`).
    #[allow(dead_code)] // T8: fiacao futura (task BLE); sem warn ate o uso.
    pub fn sync_trust_claimed(&mut self, claimed: bool) {
        self.claimed_trusted = claimed;
    }

    /// Fia a facade inteira (vinculo latched; janela entra via `tick`).
    ///
    /// `pairing` real segue como parametro do `tick`; aqui so o
    /// vinculo e latched (o resto da facade segue no dispatcher).
    #[allow(dead_code)] // T8: fiacao futura (dispatcher); sem warn ate o uso.
    pub fn sync_from_trust(&mut self, trust: &crate::binding::TrustFacade) {
        self.claimed_trusted = trust.is_claimed();
    }

    /// Carrega o K_prox da NVS cifrada para a RAM.
    ///
    /// `true` com chave valida; `false` ausente/corrompido
    /// (fail-closed, sem adv). Sem segredos em log.
    pub fn load_key_from_storage<B>(
        &mut self,
        storage: &crate::persistence::SecureStorage<B>,
    ) -> bool
    where
        B: crate::persistence::FlashStorageBackend,
    {
        match crate::proximity::load_proximity_key(storage) {
            Ok(k) => {
                self.key = k;
                self.key_present = true;
                true
            }
            Err(_) => false,
        }
    }

    /// Persiste o K_prox da RAM na NVS cifrada.
    pub fn save_key_to_storage<B, R>(
        &mut self,
        storage: &mut crate::persistence::SecureStorage<B>,
        rng: &mut R,
    ) -> bool
    where
        B: crate::persistence::FlashStorageBackend,
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        crate::proximity::save_proximity_key(storage, &self.key, rng).is_ok()
    }

    /// Gaps ainda abertos vistos deste scheduler (canonico `binding`).
    #[allow(dead_code)] // T8: diagnostico futuro; sem warn ate o uso.
    pub fn open_gaps() -> [crate::binding::FreertosTrustGap; 7] {
        crate::binding::FreertosTrustGap::freertos_open_gaps()
    }

    /// Tick com amostra RSSI injetada (R14 HW-first).
    ///
    /// `Some(dbm)` = leitura real do radio (o chamador aplica antes o
    /// gate `authorize_proximity_sample(bonded, usb)` e passa `None` se
    /// vetado: bonding -> coex USB). `None` = sensor ausente
    /// (fail-closed, igual ao `tick`). Espelha o `tick`; manter em par.
    /// Sem bloqueio: sem impacto no TWDT; pet segue no scheduler.
    #[allow(dead_code)] // T8: radio futuro; sem warn ate o sensor.
    pub fn tick_with_sample(
        &mut self,
        now_ms: u64,
        usb_active: bool,
        wifi_active: bool,
        pairing: PairingState,
        sample: Option<i16>,
    ) {
        if self
            .last_ms
            .is_some_and(|last| now_ms.saturating_sub(last) < PROX_TICK_MS)
        {
            return;
        }
        let elapsed_s = match self.last_ms {
            Some(last) => u32::try_from(now_ms.saturating_sub(last) / 1000)
                .unwrap_or(60)
                .clamp(1, 60),
            None => 1,
        };
        self.last_ms = Some(now_ms);
        self.monitor.update(sample, elapsed_s);
        let presence = self.presence_now(now_ms);
        if presence {
            let _ = self.try_unlock(true, false);
            if self.monitor.state() == ProximityState::Locked {
                log::info!("[PROX] presenca sem PIN: permanece Locked.");
            }
            self.presence_until_ms = None;
        }
        let usb_ok = coex_proximity_allowed(usb_active);
        let trusted = self.bonded || self.claimed_trusted;
        self.fob_id = prox_fob_id();
        let want =
            should_adv_proximity(pairing, self.bonded, trusted, usb_active, self.key_present)
                && usb_ok
                && self.fob_id.is_some();
        if want {
            if self.ctr == u32::MAX {
                self.key = generate_proximity_key(&mut rand_core::OsRng);
                self.key_present = true;
                self.ctr = 0;
                log::info!("[PROX] rekey pos-rollover (ctr=0).");
            } else if let Some(fob) = self.fob_id {
                let tag = proximity_tag(&self.key, PROXIMITY_BEACON_VERSION, self.ctr, &fob);
                let svc = encode_proximity_svc_data(self.ctr, &tag);
                let rc = esp_ble_proximity_start(&svc, wifi_active);
                if rc == 0 {
                    if !self.adv_on {
                        log::info!("[PROX] adv presenca ligado (Idle+bonded+USB idle).");
                    }
                    self.adv_on = true;
                    self.ctr = self.ctr.saturating_add(1);
                } else {
                    self.adv_on = false;
                    log::info!("[PROX] adv start rc={} (retry ~1 s).", rc);
                }
            }
        } else if self.adv_on {
            let _ = esp_ble_stop();
            self.adv_on = false;
            log::info!("[PROX] adv presenca desligado.");
        }
    }

    /// Ponto de pareamento do scheduler: rekey do K_prox + `save` + ctr=0.
    ///
    /// Caminho canonico (aposenta o RAM-only `note_paired`): gera e persiste
    /// via `rekey_proximity`; chamar quando a task BLE publicar a conclusao
    /// do bonding na fila. Falha de `save` = fail-closed (chave zerada).
    /// `true` com chave valida em RAM. Sem segredos em log.
    pub fn note_paired_with_storage<B, R>(
        &mut self,
        storage: &mut SecureStorage<B>,
        rng: &mut R,
        now_ms: u64,
    ) -> bool
    where
        B: FlashStorageBackend,
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        match rekey_proximity(storage, rng) {
            Ok(key) => {
                self.key = key;
                self.key_present = true;
                self.bonded = true;
                self.ctr = 0;
                self.last_ms = Some(now_ms);
                log::info!("[PROX] rekey pos-pareamento persistido (ctr=0).");
                true
            }
            Err(_) => {
                self.key = [0u8; 16];
                self.key_present = false;
                log::info!("[PROX] rekey pos-pareamento falhou (fail-closed).");
                false
            }
        }
    }

    /// Ponto de pareamento legado RAM-only (aposentado): rekey sem `save`.
    ///
    /// Espelha os 2 pontos `Paired` do dispatcher BLE legado
    /// (ausentes no caminho FreeRTOS: sem bomba BLE/GATT aqui).
    /// Mantido p/ o dispatcher ate fiar `note_paired_with_storage`;
    /// novos usos devem preferir o caminho com storage (reuso entre boots).
    /// Chamar quando a task BLE publicar a conclusão do bonding na
    /// fila. Sem segredos em log.
    #[allow(dead_code)]
    pub fn note_paired(&mut self, now_ms: u64) {
        self.key = generate_proximity_key(&mut rand_core::OsRng);
        self.key_present = true;
        self.bonded = true;
        self.ctr = 0;
        self.last_ms = Some(now_ms);
        log::info!("[PROX] rekey pos-pareamento (ctr=0).");
    }

    /// Hook de `BIND_RELEASE` / `RECOVERY_UNLOCK`: apaga K_prox
    /// (zeroize), zera o contador e desliga o adv. Sem esses ramos no
    /// scheduler (sem dispatch GATT); ao vivo roda no `Shutdown`
    /// (higiene da RAM).
    pub fn erase(&mut self) {
        self.key = [0u8; 16];
        self.key_present = false;
        self.ctr = 0;
        self.adv_on = false;
    }

    /// Registra presença física (borda de subida do BOOT).
    /// Estado atual do monitor de proximidade (Near, Away, Locked).
    pub fn state(&self) -> ProximityState {
        self.monitor.state()
    }

    pub fn note_presence(&mut self, now_ms: u64) {
        self.presence_until_ms = Some(now_ms.saturating_add(PROX_PRESENCE_MS));
    }

    /// `fob_id` p/ o futuro start de rádio `0xFFFE` (gap documentado).
    #[allow(dead_code)]
    fn fob_id(&self) -> Option<[u8; 6]> {
        self.fob_id
    }

    /// Presença válida agora? (fora do latch = `false`, nunca zero.)
    fn presence_now(&self, now_ms: u64) -> bool {
        self.presence_until_ms.is_some_and(|until| now_ms < until)
    }

    /// Tenta destravar: só `Locked` + presença + PIN (`unlock` canônico).
    ///
    /// A sessão PIN (pinUvAuth) ainda está fora do scheduler: o tick
    /// ao vivo passa `pin_ok=false`, então presença sozinha nunca
    /// destrava.
    fn try_unlock(&mut self, presence: bool, pin_ok: bool) -> bool {
        self.monitor.unlock(presence, pin_ok)
    }

    /// Confirma a trava: `Away` vira `Locked`. Nunca chamado sozinho
    /// pelo tick (só via comando explícito do host/agente).
    #[allow(dead_code)]
    fn confirm_lock(&mut self) -> ProximityState {
        self.monitor.confirm_lock()
    }

    /// Tick de presença ~1 s: gates + amostra + beacon (sem auto-unlock).
    ///
    /// Throttle: ignora chamadas com `< 1000 ms` desde o último tick
    /// (o rádio só é tocado no tick válido: sem spam de start).
    /// Gates do adv (`should_adv_proximity` canônico: pareamento
    /// `Idle`, `bonded`, trusted, USB inativo por coex, K_prox
    /// presente como `KEY`; `trusted` é `bonded` até o
    /// `BindingManager` entrar no scheduler; `wifi_active` desacelera
    /// o intervalo no backend pela coex `USB > WiFi > BLE`).
    /// USB veta: com USB ativo o adv para e desliga.
    /// Amostra: sensor RSSI ausente no scheduler = `None` (fraco,
    /// fail-closed; nunca zero). `elapsed` real entre ticks (clamp
    /// 1..=60 s, igual ao `MAX_ELAPSED_SECS_PER_UPDATE` do monitor).
    /// Beacon real `0xFFFE` com `TAG(AES-CCM-128)` e ctr via
    /// `esp_ble_proximity_start`; falha desliga e retenta no próximo
    /// tick (~1 s). Rollover: rekey em RAM com ctr=0, sem adv neste
    /// tick (retoma no próximo com ctr=0).
    /// Nunca auto-unlock nem auto-lock: `Away` não vira `Locked`
    /// sozinho; presença sem PIN só é registrada em log.
    pub fn tick(
        &mut self,
        now_ms: u64,
        usb_active: bool,
        wifi_active: bool,
        pairing: PairingState,
    ) {
        if self
            .last_ms
            .is_some_and(|last| now_ms.saturating_sub(last) < PROX_TICK_MS)
        {
            return;
        }
        let elapsed_s = match self.last_ms {
            Some(last) => u32::try_from(now_ms.saturating_sub(last) / 1000)
                .unwrap_or(60)
                .clamp(1, 60),
            None => 1,
        };
        self.last_ms = Some(now_ms);
        // Amostra RSSI: sensor ausente no scheduler => `None` (fraco,
        // fail-closed; nunca zero). Quando o sensor existir, o gate
        // canônico `authorize_proximity_sample(bonded, usb)` (bonding
        // -> coex USB) decide entre a leitura real e `None`.
        let sample: Option<i16> = crate::proximity::freertos_tick_sample();
        self.monitor.update(sample, elapsed_s);
        // Presença sem PIN nunca destrava (fail-closed, sem auto-unlock);
        // latch de uso único: consumido neste tick.
        let presence = self.presence_now(now_ms);
        if presence {
            let _ = self.try_unlock(true, false);
            if self.monitor.state() == ProximityState::Locked {
                log::info!("[PROX] presenca sem PIN: permanece Locked.");
            }
            self.presence_until_ms = None;
        }
        // Gates do adv (`Idle` + trusted + USB idle + `KEY` presente).
        let usb_ok = coex_proximity_allowed(usb_active);
        let trusted = self.bonded || self.claimed_trusted;
        // Fob renovado a cada tick (stack pode subir depois do boot);
        // `None` => sem adv (fail-closed, mesmo contrato do loop legado).
        self.fob_id = prox_fob_id();
        let want =
            should_adv_proximity(pairing, self.bonded, trusted, usb_active, self.key_present)
                && usb_ok
                && self.fob_id.is_some();
        if want {
            // Rollover: rekey em RAM + ctr=0; sem adv neste tick.
            if self.ctr == u32::MAX {
                self.key = generate_proximity_key(&mut rand_core::OsRng);
                self.key_present = true;
                self.ctr = 0;
                log::info!("[PROX] rekey pos-rollover (ctr=0).");
            } else if let Some(fob) = self.fob_id {
                let tag = proximity_tag(&self.key, PROXIMITY_BEACON_VERSION, self.ctr, &fob);
                let svc = encode_proximity_svc_data(self.ctr, &tag);
                let rc = esp_ble_proximity_start(&svc, wifi_active);
                if rc == 0 {
                    if !self.adv_on {
                        log::info!("[PROX] adv presenca ligado (Idle+bonded+USB idle).");
                    }
                    self.adv_on = true;
                    self.ctr = self.ctr.saturating_add(1);
                } else {
                    self.adv_on = false;
                    log::info!("[PROX] adv start rc={} (retry ~1 s).", rc);
                }
            }
        } else if self.adv_on {
            let _ = esp_ble_stop();
            self.adv_on = false;
            log::info!("[PROX] adv presenca desligado.");
        }
    }
}

impl Default for ProxSchedState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fob_id_fail_closed_sem_mac_inventado() {
        // Contrato F6: sem stack BLE (host) => `None`, nunca placeholder.
        // No device com stack synced => `Some` (não testável no host).
        assert_eq!(prox_fob_id(), None);
    }

    #[test]
    fn fob_id_exposto_sem_segredo() {
        let s = ProxSchedState::new();
        assert_eq!(s.fob_id(), prox_fob_id());
        assert_eq!(s.fob_id(), None);
    }

    #[test]
    fn boot_sem_vinculo_fail_closed_e_com_vinculo_gera_chave() {
        let mut s = ProxSchedState::new();
        s.note_boot(false);
        assert!(!s.key_present);
        assert!(!s.bonded);
        assert_eq!(s.monitor.state(), ProximityState::Near);

        let mut t = ProxSchedState::new();
        t.note_boot(true);
        assert!(t.key_present);
        assert!(t.bonded);
    }

    #[test]
    fn boot_with_storage_reusa_chave_persistida() {
        let mut st = SecureStorage::new(
            crate::persistence::MockFlashBackend::new(),
            &[0x55u8; 32],
            &[0xAAu8; 32],
        );
        let mut rng = rand_core::OsRng;
        // Primeiro boot com vinculo: gera e persiste.
        let mut a = ProxSchedState::new();
        assert!(a.note_boot_with_storage(&mut st, &mut rng, true));
        assert!(a.key_present && a.bonded);
        let k1 = a.key;
        // Segundo boot: reusa a chave da NVS (mesma chave, sem rekey).
        let mut b = ProxSchedState::new();
        assert!(b.note_boot_with_storage(&mut st, &mut rng, true));
        assert!(b.key_present && b.bonded);
        assert_eq!(b.key, k1);
    }

    #[test]
    fn boot_with_storage_sem_vinculo_fail_closed() {
        let mut st = SecureStorage::new(
            crate::persistence::MockFlashBackend::new(),
            &[0x55u8; 32],
            &[0xAAu8; 32],
        );
        let mut rng = rand_core::OsRng;
        let mut s = ProxSchedState::new();
        assert!(!s.note_boot_with_storage(&mut st, &mut rng, false));
        assert!(!s.key_present);
        assert!(!s.bonded);
    }

    #[test]
    fn pareamento_persiste_rekey_e_boot_reusa() {
        let mut st = SecureStorage::new(
            crate::persistence::MockFlashBackend::new(),
            &[0x55u8; 32],
            &[0xAAu8; 32],
        );
        let mut rng = rand_core::OsRng;
        let mut s = ProxSchedState::new();
        assert!(!s.key_present);
        assert!(s.note_paired_with_storage(&mut st, &mut rng, 9000));
        assert!(s.key_present && s.bonded);
        assert_eq!(s.ctr, 0);
        let k1 = s.key;
        // Reboot: o boot com vinculo reusa a chave do pareamento.
        let mut t = ProxSchedState::new();
        assert!(t.note_boot_with_storage(&mut st, &mut rng, true));
        assert_eq!(t.key, k1);
    }

    #[test]
    fn pareamento_faz_rekey_e_zera_ctr() {
        let mut s = ProxSchedState::new();
        s.note_boot(true);
        s.ctr = 7;
        let k1 = s.key;
        s.note_paired(9000);
        assert!(s.key_present);
        assert!(s.bonded);
        assert_eq!(s.ctr, 0);
        // TRNG: rekey troca a chave (colisão 1/2^128).
        assert_ne!(s.key, k1);
    }

    #[test]
    #[ignore = "device-only: exige BLE stack (own_addr/beacon_fob_id Some) + radio; host fail-closed com fob_id None"]
    fn tick_throttle_1s_e_gate_idle_bonded_sem_usb() {
        let mut s = ProxSchedState::new();
        // Sem vínculo: tick processa, mas sem adv (fail-closed).
        s.tick(0, false, false, PairingState::Idle);
        assert!(!s.adv_on);
        assert_eq!(s.ctr, 0);

        // Com vínculo: adv liga e o contador avança ~1 Hz.
        s.note_boot(true);
        s.tick(1000, false, false, PairingState::Idle);
        assert!(s.adv_on);
        assert_eq!(s.ctr, 1);
        // Throttle: < 1000 ms ignora.
        s.tick(1500, false, false, PairingState::Idle);
        assert_eq!(s.ctr, 1);
        s.tick(2000, false, false, PairingState::Idle);
        assert_eq!(s.ctr, 2);
        // Fora de `Idle`: sem adv.
        s.tick(3000, false, false, PairingState::Locked);
        assert!(!s.adv_on);
    }

    #[test]
    #[ignore = "device-only: exige BLE stack (own_addr/beacon_fob_id Some) + radio; host fail-closed com fob_id None"]
    fn usb_veta_beacon_e_desliga_adv() {
        let mut s = ProxSchedState::new();
        s.note_boot(true);
        s.tick(0, false, false, PairingState::Idle);
        assert!(s.adv_on);
        // USB monta: veta e desliga.
        s.tick(1000, true, false, PairingState::Idle);
        assert!(!s.adv_on);
        // USB sai: volta no próximo tick.
        s.tick(2000, false, false, PairingState::Idle);
        assert!(s.adv_on);
    }

    #[test]
    fn amostra_ausente_trava_mas_nunca_sozinha() {
        let mut s = ProxSchedState::new();
        s.note_boot(true);
        // `None` (sensor ausente) conta como fraco: 10 ticks => `Away`.
        for i in 0..10u64 {
            s.tick(i * 1000, false, false, PairingState::Idle);
        }
        assert_eq!(s.monitor.state(), ProximityState::Away);
        // Nunca auto-lock: mais 60 s fracos e segue `Away`.
        for i in 10..70u64 {
            s.tick(i * 1000, false, false, PairingState::Idle);
        }
        assert_eq!(s.monitor.state(), ProximityState::Away);
        // `Locked` só via `confirm_lock`.
        assert_eq!(s.confirm_lock(), ProximityState::Locked);
        // Sem RSSI bom no scheduler (`None` sempre): segue `Locked`.
        for i in 70..80u64 {
            s.tick(i * 1000, false, false, PairingState::Idle);
        }
        assert_eq!(s.monitor.state(), ProximityState::Locked);
    }

    #[test]
    fn unlock_exige_presenca_e_pin_juntos() {
        let mut s = ProxSchedState::new();
        s.note_boot(true);
        for i in 0..10u64 {
            s.tick(i * 1000, false, false, PairingState::Idle);
        }
        s.confirm_lock();
        assert_eq!(s.monitor.state(), ProximityState::Locked);
        // Presença sozinha (PIN fora do scheduler) nunca destrava.
        assert!(!s.try_unlock(true, false));
        assert!(!s.try_unlock(false, true));
        assert_eq!(s.monitor.state(), ProximityState::Locked);
        // Tick ao vivo com presença e sem PIN: permanece `Locked`.
        s.note_presence(10_000);
        s.tick(10_000, false, false, PairingState::Idle);
        assert_eq!(s.monitor.state(), ProximityState::Locked);
        // Presença + PIN destrava (via comando explícito, fora do tick).
        assert!(s.try_unlock(true, true));
        assert_eq!(s.monitor.state(), ProximityState::Near);
    }

    #[test]
    #[ignore = "device-only: exige BLE stack (own_addr/beacon_fob_id Some) + radio; host fail-closed com fob_id None"]
    fn release_apaga_chave_ctr_e_adv() {
        let mut s = ProxSchedState::new();
        s.note_boot(true);
        s.tick(0, false, false, PairingState::Idle);
        assert!(s.adv_on);
        s.erase();
        assert!(!s.key_present);
        assert_eq!(s.key, [0u8; 16]);
        assert_eq!(s.ctr, 0);
        assert!(!s.adv_on);
        // Pós-erase o gate nega: sem adv no próximo tick.
        s.tick(1000, false, false, PairingState::Idle);
        assert!(!s.adv_on);
    }

    #[test]
    #[ignore = "device-only: exige BLE stack (own_addr/beacon_fob_id Some) + radio; host fail-closed com fob_id None"]
    fn rollover_faz_rekey_e_volta_a_zero() {
        let mut s = ProxSchedState::new();
        s.note_boot(true);
        s.tick(0, false, false, PairingState::Idle);
        assert!(s.adv_on);
        s.ctr = u32::MAX;
        s.tick(1000, false, false, PairingState::Idle);
        assert_eq!(s.ctr, 0);
        assert!(s.key_present);
    }

    #[test]
    fn presenca_expira_em_15s() {
        let mut s = ProxSchedState::new();
        s.note_presence(0);
        assert!(s.presence_now(0));
        assert!(s.presence_now(1499));
        assert!(!s.presence_now(1500));
    }
}
