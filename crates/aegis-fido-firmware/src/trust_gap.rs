//! Trust gaps do small loop FreeRTOS (T8, ExternallyBlocked).
//!
//! Extraido de `binding.rs` sem mudanca de comportamento (auditoria
//! riscos 2+3). `TrustTransport` marca quem exige vinculo (BLE/WiFi;
//! USB e isento e nunca emite `NEED_BINDING (0x05)`). `FreertosTrustGap`
//! lista as 7 pecas ainda sem fiacao no scheduler; cada `reason()` diz
//! a peca exata que falta. Nunca fabricar valores: ausente = fail-closed.

/// Transporte para o gate de vinculo (T8).
///
/// USB e isento de `NEED_BINDING (0x05)`: posse do cabo e o vinculo fisico.
/// BLE/WiFi exigem vinculo previo (claim + challenge assinado).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustTransport {
    /// USB/CTAP nativo + serial: nunca emite `0x05`.
    Usb,
    /// BLE vendor (GATT `0xFFFD`): sem dono => `0x05`.
    Ble,
    /// WiFi mgmt (AP/station HTTP): sem dono => `0x05`.
    Wifi,
}

impl TrustTransport {
    /// `true` somente para BLE/WiFi (unicos que emitem `NEED_BINDING`).
    pub fn requires_binding(self) -> bool {
        matches!(self, Self::Ble | Self::Wifi)
    }
}
/// Gap externo ainda aberto no small loop FreeRTOS (`run_authenticator_freertos`).
///
/// Cada variante carrega a peca exata que falta (sem fabricar valores).
/// `fiar` = novo metodo `sync_*`/`tick_with_*` nesta facade ou no
/// `prox_sched`; `ExternallyBlocked` = documentado aqui ate o HW/fila
/// existir. Nunca retorna sucesso silencioso nem inventa RSSI/MAC/chave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreertosTrustGap {
    /// Sem bomba BLE/GATT no scheduler: nenhum `FirmwareEvent` carrega o
    /// sinal `Paired`; `note_paired` aguarda a task BLE publicar na fila.
    BleDispatch,
    /// Sensor RSSI HW ausente no scheduler: amostra `None` fail-closed.
    RssiSensor,
    /// NVS `prox_k` nao fiada no small loop: `load` le ausente, rekey em RAM.
    NvsProxK,
    /// `BindingManager::is_claimed` nao sincronizado no small loop:
    /// `trusted = bonded` ate `sync_trust_claimed`.
    BindingWire,
    /// Sessao PIN (pinUvAuth) fora do scheduler: tick passa `pin_ok=false`.
    PinSession,
    /// Sem dispatch GATT `0xFFFD` (`BIND_RELEASE`/`RECOVERY_UNLOCK`) no
    /// scheduler: `erase` so no `Shutdown`.
    GattDispatch,
    /// WiFi sempre `false` no small loop: intervalo nunca desacelera.
    WifiCoex,
}

impl FreertosTrustGap {
    /// Peca exata que falta (para `EXTERNAL_BLOCKED`).
    pub fn reason(self) -> &'static str {
        match self {
            Self::BleDispatch => "sem bomba BLE/GATT: nenhum FirmwareEvent carrega Paired",
            Self::RssiSensor => "sensor RSSI HW ausente: amostra None fail-closed, nunca zero",
            Self::NvsProxK => "NVS prox_k nao fiada no small loop: load ausente, rekey em RAM",
            Self::BindingWire => "BindingManager.is_claimed nao sincronizado: trusted=bonded",
            Self::PinSession => "sessao PIN fora do scheduler: tick passa pin_ok=false",
            Self::GattDispatch => "sem dispatch GATT 0xFFFD: erase so no Shutdown",
            Self::WifiCoex => "WiFi sempre false no small loop: intervalo nunca desacelera",
        }
    }

    /// Gaps ainda abertos no small loop FreeRTOS (T8).
    pub fn freertos_open_gaps() -> [Self; 7] {
        [
            Self::BleDispatch,
            Self::RssiSensor,
            Self::NvsProxK,
            Self::BindingWire,
            Self::PinSession,
            Self::GattDispatch,
            Self::WifiCoex,
        ]
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_usb_isento_ble_wifi_exigem() {
        assert!(!TrustTransport::Usb.requires_binding());
        assert!(TrustTransport::Ble.requires_binding());
        assert!(TrustTransport::Wifi.requires_binding());
    }

    #[test]
    fn gaps_freertos_documentam_peca_exata() {
        let gaps = FreertosTrustGap::freertos_open_gaps();
        assert_eq!(gaps.len(), 7);
        for g in gaps {
            assert!(!g.reason().is_empty());
        }
        assert!(FreertosTrustGap::RssiSensor
            .reason()
            .contains("fail-closed"));
        assert!(FreertosTrustGap::BindingWire
            .reason()
            .contains("trusted=bonded"));
    }
}
