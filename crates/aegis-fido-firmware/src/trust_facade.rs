//! Facade de confianca T8: binding + pairing + proximity + recovery.
//!
//! Extraida de `binding.rs` sem mudanca de comportamento (auditoria
//! riscos 2+3). Agrega `BindingManager` + `PairingManager` (+
//! `ProximityMonitor` com a feature `proximity`) + `RecoveryPolicy`;
//! a NVS entra via `SecureStorage` injetado. Ordem canonica: binding ->
//! UP -> PIN. `confirm_lock` e o unico ponto canonico de trava;
//! `NEED_BINDING (0x05)` so em BLE/WiFi, nunca em USB. R12 mutavel
//! (compila com/sem `proximity`); R13/R14: sem burn, sem segredo em log.

extern crate alloc;

use crate::binding::{require_bound_usage, BindingError, BindingManager};
use crate::pairing::PairingManager;
use crate::persistence::{FlashStorageBackend, SecureStorage};
#[cfg(feature = "proximity")]
use crate::proximity::{ProximityConfig, ProximityMonitor, ProximityState};
use crate::trust_gap::TrustTransport;

/// Facade de confianca T8 (ordem binding -> UP -> PIN).
///
/// Agrega `BindingManager` + `PairingManager` (+ `ProximityMonitor` com a
/// feature `proximity`) + `RecoveryPolicy` (`crate::recovery::*`); a NVS
/// entra via `SecureStorage` injetado em cada chamada (sem dono interno).
/// `no_std` compativel: sem alloc, sem I/O, relogio injetado (`now_ms`).
#[derive(Debug, Clone)]
pub struct TrustFacade {
    binding: BindingManager,
    pairing: PairingManager,
    #[cfg(feature = "proximity")]
    proximity: ProximityMonitor,
}

impl TrustFacade {
    /// Facade zerada: `Unclaimed` + `Idle` (+ `Near` com proximity).
    pub fn new() -> Self {
        Self {
            binding: BindingManager::new(),
            pairing: PairingManager::new(),
            #[cfg(feature = "proximity")]
            proximity: ProximityMonitor::new(ProximityConfig::default()),
        }
    }

    /// Facade com politica de proximidade explicita (R12 mutavel).
    #[cfg(feature = "proximity")]
    pub fn new_with_proximity(config: ProximityConfig) -> Self {
        Self {
            binding: BindingManager::new(),
            pairing: PairingManager::new(),
            proximity: ProximityMonitor::new(config),
        }
    }

    /// Acesso ao vinculo (leitura).
    pub fn binding(&self) -> &BindingManager {
        &self.binding
    }

    /// Acesso ao vinculo (mutavel: claim/verify/release via `BindingManager`).
    pub fn binding_mut(&mut self) -> &mut BindingManager {
        &mut self.binding
    }

    /// Acesso ao pareamento (leitura).
    pub fn pairing(&self) -> &PairingManager {
        &self.pairing
    }

    /// Acesso ao pareamento (mutavel: hold/tick/complete via `PairingManager`).
    pub fn pairing_mut(&mut self) -> &mut PairingManager {
        &mut self.pairing
    }

    /// Acesso ao monitor de proximidade (leitura).
    #[cfg(feature = "proximity")]
    pub fn proximity(&self) -> &ProximityMonitor {
        &self.proximity
    }

    /// Acesso ao monitor de proximidade (mutavel: `update` via facade).
    #[cfg(feature = "proximity")]
    pub fn proximity_mut(&mut self) -> &mut ProximityMonitor {
        &mut self.proximity
    }

    /// `true` quando ha dono vinculado.
    pub fn is_claimed(&self) -> bool {
        self.binding.is_claimed()
    }

    /// `true` quando a janela de 60 s esta aberta (`PairingManager`).
    pub fn is_pairing_window_open(&self, now_ms: u64) -> bool {
        self.pairing.is_pairing_window_open(now_ms)
    }

    /// Estado atual de proximidade (copia).
    #[cfg(feature = "proximity")]
    pub fn proximity_state(&self) -> ProximityState {
        self.proximity.state()
    }
}
impl TrustFacade {
    /// Gate CONFIG na ordem canonica: binding -> UP -> PIN.
    ///
    /// - BLE/WiFi sem dono => `NotClaimed` (`0x05` via `to_vendor_status`);
    ///   USB nunca nega por vinculo (isento, segue para UP/PIN).
    /// - Sem UP => `PresenceRequired` (`0x01`); `requires_pin` sem PIN =>
    ///   `PinRequired` (`0x02`). USB isento de `0x05` mas nao de UP/PIN.
    pub fn authorize_config(
        &self,
        transport: TrustTransport,
        presence_confirmed: bool,
        pin_authenticated: bool,
        requires_pin: bool,
    ) -> Result<(), BindingError> {
        if transport.requires_binding() && !self.binding.is_claimed() {
            return Err(BindingError::NotClaimed);
        }
        if !presence_confirmed {
            return Err(BindingError::PresenceRequired);
        }
        if requires_pin && !pin_authenticated {
            return Err(BindingError::PinRequired);
        }
        Ok(())
    }

    /// Gate USO (CODE/LIST/GetAssertion/display): nunca exige vinculo.
    ///
    /// So UP fisico; espelha `require_bound_usage` (keypass sem vinculo passa).
    pub fn authorize_usage(&self, presence_confirmed: bool) -> Result<(), BindingError> {
        require_bound_usage(self.binding.is_claimed())?;
        if !presence_confirmed {
            return Err(BindingError::PresenceRequired);
        }
        Ok(())
    }

    /// UNICO ponto canonico de trava: `Away` vira `Locked`.
    ///
    /// Nao chamar `ProximityMonitor::confirm_lock` direto no caminho
    /// FreeRTOS; passar por aqui (auditoria unica). Nos demais estados,
    /// sem efeito (mesma semantica do monitor).
    #[cfg(feature = "proximity")]
    pub fn confirm_lock(&mut self) -> ProximityState {
        self.proximity.confirm_lock()
    }

    /// Destrava somente de `Locked` com presenca fisica E PIN valido.
    #[cfg(feature = "proximity")]
    pub fn unlock_proximity(&mut self, presence: bool, pin_ok: bool) -> bool {
        self.proximity.unlock(presence, pin_ok)
    }

    /// Atualiza a politica de proximidade (relogio injetado, testavel).
    #[cfg(feature = "proximity")]
    pub fn proximity_update(&mut self, rssi_dbm: Option<i16>, elapsed_secs: u32) -> ProximityState {
        self.proximity.update(rssi_dbm, elapsed_secs)
    }

    /// Persiste o vinculo (`Claimed`) com verify-after-write (NVS injetada).
    pub fn persist_binding<B: FlashStorageBackend>(
        &self,
        storage: &mut SecureStorage<B>,
    ) -> Result<(), BindingError> {
        self.binding.persist(storage)
    }

    /// Apaga vinculo da NVS, zera RAM e volta a `Unclaimed` (reclaim livre).
    pub fn wipe_binding<B: FlashStorageBackend>(&mut self, storage: &mut SecureStorage<B>) {
        self.binding.wipe(storage);
    }

    /// Define o PIN de recovery (exige UP; 4-6 digitos; NVS injetada).
    pub fn set_recovery_pin<B: FlashStorageBackend>(
        &self,
        storage: &mut SecureStorage<B>,
        pin: &str,
        presence_confirmed: bool,
    ) -> Result<(), crate::recovery::RecoveryError> {
        crate::recovery::set_recovery_pin(storage, pin, presence_confirmed)
    }

    /// Verifica o PIN no device (consome 1 tentativa por erro; NVS injetada).
    pub fn verify_recovery_pin<B: FlashStorageBackend>(
        &self,
        storage: &mut SecureStorage<B>,
        pin: &str,
        presence_confirmed: bool,
    ) -> Result<(), crate::recovery::RecoveryError> {
        crate::recovery::verify_recovery_pin(storage, pin, presence_confirmed)
    }

    /// Resgate com app novo perdido: UP + PIN certo => wipe do vinculo.
    ///
    /// Libera re-claim; PIN preservado (novo dono define outro via `SET`).
    pub fn recovery_unlock<B: FlashStorageBackend>(
        &mut self,
        storage: &mut SecureStorage<B>,
        pin: &str,
        presence_confirmed: bool,
    ) -> Result<(), crate::recovery::RecoveryError> {
        crate::recovery::recovery_unlock(storage, &mut self.binding, pin, presence_confirmed)
    }
}

impl Default for TrustFacade {
    fn default() -> Self {
        Self::new()
    }
}
impl TrustFacade {
    /// Carrega o vinculo da NVS sem aplicar parcial (fail-closed, T8).
    ///
    /// Par presente e valido => facade `Claimed`; ausente => `Unclaimed`;
    /// parcial/corrompido => `Err(Corrupted)` (nega fechado, nunca
    /// `Unclaimed` silencioso: sem reclaim hostil apos queda). Primeiro
    /// boot (NVS vazia) => `Ok` sem dono. `PairingManager`/`ProximityMonitor`
    /// comecam zerados (RAM nao sobrevive a reset: `Idle`/`Near`).
    pub fn load_from_storage<B: FlashStorageBackend>(
        storage: &SecureStorage<B>,
    ) -> Result<Self, BindingError> {
        Ok(Self {
            binding: BindingManager::load_from_storage(storage)?,
            pairing: PairingManager::new(),
            #[cfg(feature = "proximity")]
            proximity: ProximityMonitor::new(ProximityConfig::default()),
        })
    }

    /// FAIL-SAFE / POWER-LOSS (T8): todo estado incerto nega fechado.
    ///
    /// - claim: so RAM ate `persist`; reset antes => NVS intacta, nega.
    /// - persist: queda entre os dois `store` => parcial; boot le
    ///   `Corrupted` (nunca `Unclaimed` silencioso); este metodo restaura
    ///   o snapshot em falha de escrita (sem reclaim hostil).
    /// - challenge/verify: uso unico em RAM; reset => challenge perdido,
    ///   dono pede outro; replay do antigo nega.
    /// - release/wipe: queda no meio => parcial `Corrupted`, nega fechado.
    /// - K_prox rekey: queda entre delete/save => ausente; sem adv ate
    ///   novo pareamento (fail-closed, ver `proximity`).
    /// - recovery: parcial hash/salt/retries => nao provisionado ou
    ///   `Corrupted`, nega; decremento de retry e conservador (trava).
    /// - Sem trava permanente (R13): `Locked` sai com `factory_reset`
    ///   fisico (hold 5 s + UP); sem burn, sem eFuse, sem secure-boot.
    /// - Sem bloqueio: metodos puros/sem I/O; TWDT/pet seguem no loop
    ///   legado e no scheduler (nenhum `delay`/laço aqui).
    ///
    /// Persiste com rollback para o snapshot anterior em falha.
    ///
    /// Snapshot = vinculo carregado antes de persistir (ou `Unclaimed`).
    /// Se `persist` falhar (ex.: queda entre os dois `store`), restaura o
    /// snapshot (melhor esforco) e retorna `Storage`: nunca deixa a NVS
    /// vazia quando havia dono (fail-closed). Reset no meio: o parcial
    /// resultante le `Corrupted` no boot e nega fechado.
    pub fn persist_binding_with_rollback<B: FlashStorageBackend>(
        &self,
        storage: &mut SecureStorage<B>,
    ) -> Result<(), BindingError> {
        let snapshot =
            BindingManager::load_from_storage(storage).unwrap_or_else(|_| BindingManager::new());
        if self.binding.persist(storage).is_err() {
            let snap = snapshot;
            let _ = snap.persist(storage);
            return Err(BindingError::Storage);
        }
        Ok(())
    }
}
#[cfg(test)]
mod trust_facade_tests {
    use super::*;
    use crate::binding::NEED_BINDING_STATUS;
    use crate::persistence::MockFlashBackend;

    fn facade_storage() -> SecureStorage<MockFlashBackend> {
        SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32])
    }

    #[test]
    fn config_ordem_binding_up_pin_usb_isento() {
        let f = TrustFacade::new();
        assert_eq!(
            f.authorize_config(TrustTransport::Ble, true, true, false),
            Err(BindingError::NotClaimed)
        );
        assert_eq!(
            f.authorize_config(TrustTransport::Wifi, false, false, false),
            Err(BindingError::NotClaimed)
        );
        assert_eq!(
            f.authorize_config(TrustTransport::Ble, true, true, false)
                .unwrap_err()
                .to_vendor_status(),
            NEED_BINDING_STATUS
        );
        assert_eq!(
            f.authorize_config(TrustTransport::Usb, false, true, false),
            Err(BindingError::PresenceRequired)
        );
        assert_eq!(
            f.authorize_config(TrustTransport::Usb, true, false, true),
            Err(BindingError::PinRequired)
        );
        f.authorize_config(TrustTransport::Usb, true, true, true)
            .expect("usb com UP+PIN passa sem dono");
        f.authorize_usage(true).expect("uso com UP passa sem dono");
        assert_eq!(
            f.authorize_usage(false),
            Err(BindingError::PresenceRequired)
        );
    }

    #[test]
    fn recovery_via_facade_wipe_e_reclaim() {
        let mut st = facade_storage();
        let mut f = TrustFacade::new();
        f.set_recovery_pin(&mut st, "4242", true).expect("set pin");
        f.verify_recovery_pin(&mut st, "4242", true)
            .expect("verify ok");
        f.recovery_unlock(&mut st, "4242", true)
            .expect("unlock idempotente sem dono");
        assert!(!f.is_claimed());
    }
}
#[cfg(test)]
mod trust_failsafe_tests {
    use super::*;
    use crate::binding::{BIND_ID_LEN, BIND_PUB_LEN, BIND_PUB_NVS_KEY};
    use crate::persistence::{FlashStorageBackend, MockFlashBackend, StorageError};

    /// Backend que falha exatamente na N-esima escrita (queda simulada).
    struct FailWrites<B> {
        inner: B,
        count: core::cell::Cell<u64>,
        fail_at: core::cell::Cell<Option<u64>>,
    }

    impl<B: FlashStorageBackend> FlashStorageBackend for FailWrites<B> {
        fn read_raw(&self, key: &str) -> Result<alloc::vec::Vec<u8>, StorageError> {
            self.inner.read_raw(key)
        }
        fn write_raw(&mut self, key: &str, data: &[u8]) -> Result<(), StorageError> {
            let c = self.count.get() + 1;
            self.count.set(c);
            if self.fail_at.get() == Some(c) {
                return Err(StorageError::FlashWriteError);
            }
            self.inner.write_raw(key, data)
        }
        fn delete_raw(&mut self, key: &str) -> Result<(), StorageError> {
            self.inner.delete_raw(key)
        }
        fn exists(&self, key: &str) -> bool {
            self.inner.exists(key)
        }
    }

    impl<B> FailWrites<B> {
        fn set_fail_at(&self, n: u64) {
            self.fail_at.set(Some(n));
        }
    }

    fn claimed_facade(sec1: &[u8; BIND_PUB_LEN], id: &[u8; BIND_ID_LEN]) -> TrustFacade {
        let mut f = TrustFacade::new();
        f.binding_mut()
            .claim(sec1, id, true, true)
            .expect("claim ok");
        f
    }

    fn app_key(seed: u8) -> [u8; BIND_PUB_LEN] {
        let sk = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).expect("scalar");
        let pt = sk.verifying_key().to_sec1_point(false);
        let mut sec1 = [0u8; BIND_PUB_LEN];
        sec1.copy_from_slice(pt.as_bytes());
        sec1
    }

    #[test]
    fn partial_nvs_denies_closed_never_silent_unclaimed() {
        let mut st = SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32]);
        st.store(BIND_PUB_NVS_KEY, &[0x04u8; BIND_PUB_LEN], &[0u8; 12])
            .expect("parcial: so pub gravada");
        assert_eq!(
            TrustFacade::load_from_storage(&st).unwrap_err(),
            BindingError::Corrupted
        );
        let st2 = SecureStorage::new(MockFlashBackend::new(), &[0x55u8; 32], &[0xAAu8; 32]);
        let f = TrustFacade::load_from_storage(&st2).expect("vazio = unclaimed");
        assert!(!f.is_claimed());
        assert_eq!(
            f.authorize_config(TrustTransport::Ble, true, true, false),
            Err(BindingError::NotClaimed)
        );
    }

    #[test]
    fn persist_rollback_restores_owner_on_mid_write_failure() {
        let backend = FailWrites {
            inner: MockFlashBackend::new(),
            count: core::cell::Cell::new(0),
            fail_at: core::cell::Cell::new(None),
        };
        let mut st = SecureStorage::new(backend, &[0x55u8; 32], &[0xAAu8; 32]);
        let sec1_a = app_key(0x11);
        let f_a = claimed_facade(&sec1_a, &[0xAAu8; BIND_ID_LEN]);
        f_a.persist_binding_with_rollback(&mut st)
            .expect("persist A ok");
        let sec1_b = app_key(0x22);
        let f_b = claimed_facade(&sec1_b, &[0xBBu8; BIND_ID_LEN]);
        st.backend().set_fail_at(4);
        assert_eq!(
            f_b.persist_binding_with_rollback(&mut st),
            Err(BindingError::Storage)
        );
        let back = TrustFacade::load_from_storage(&st).expect("dono restaurado");
        assert!(back.is_claimed());
        assert_eq!(back.binding().state(), f_a.binding().state());
    }
}
