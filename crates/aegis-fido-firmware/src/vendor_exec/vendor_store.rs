//! Vendor NVS persistence (move-only split of `vendor_exec`).
//!
//! Single `NamespacedStore` path for the F2/F3 blobs (raw keys, no quota,
//! envelope verify-after-write, idempotent delete). `Err` = storage failure
//! (fail-closed); callers roll back via snapshot.

extern crate alloc;

use crate::persistence::{
    FlashStorageBackend, NamespacedStore, NamespacedStoreError, SecureStorage,
};
use aegis_fido_core::credential::key_manager::KeyManager;
use aegis_fido_core::ctap::client_pin::ClientPinState;
use aegis_fido_core::oath::applet::OathApplet;

/// Chaves NVS (≤15 chars) dos blobs de estado F2.
pub const NVS_KEYS_SLOTS: &str = "key_slots_v1";
pub const NVS_KEYS_OATH: &str = "oath_creds_v1";
/// Chaves NVS (F3) do PIN: hash 16B (ausente = sem PIN) + retries 1B.
pub const NVS_PIN_HASH: &str = "pin_hash";
pub const NVS_PIN_RETRIES: &str = "pin_retries";

/// Falha tipada fail-closed do executor vendor (sem segredo, sem panics).
///
/// R15/R16: sem bool que esconde a causa; o chamador traduz `Err` no wire
/// (0x04). S9: verify-after-write herdado do `NamespacedStore` (torn
/// write nega e desfaz o slot); rollback via snapshot do chamador.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VendorExecError {
    /// Falha de storage, verify-after-write ou blob invalido.
    Storage,
}

impl core::fmt::Display for VendorExecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Storage => write!(f, "vendor storage failure"),
        }
    }
}

impl From<NamespacedStoreError> for VendorExecError {
    fn from(_: NamespacedStoreError) -> Self {
        Self::Storage
    }
}

/// Chaves NVS legadas deste namespace (prefixo vazio = chave crua).
/// Preserva os bytes exatos gravados pelo caminho direto anterior.
fn vendor_key_ok(label: &str) -> bool {
    label == NVS_KEYS_SLOTS
        || label == NVS_KEYS_OATH
        || label == NVS_PIN_HASH
        || label == NVS_PIN_RETRIES
}

/// Namespace unico dos blobs F2/F3: chaves cruas, sem quota, teto do
/// envelope (`MAX_PLAINTEXT_BYTES`, fail-closed no `store`), delete
/// idempotente (paridade com o `delete` direto anterior).
fn vendor_ns() -> NamespacedStore {
    NamespacedStore {
        prefix: "",
        max_bytes: None,
        quota_index_key: None,
        max_slots: 0,
        delete_absent_ok: true,
        strict_index_reads: false,
        validate: vendor_key_ok,
    }
}

/// Persiste o estado das chaves via `NamespacedStore` (fail-closed).
/// `Err` = save falhou; o chamador faz rollback via snapshot.
pub fn save_keys_result<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    keys: &KeyManager,
) -> Result<(), VendorExecError> {
    let blob = keys.export_state();
    vendor_ns().put(storage, NVS_KEYS_SLOTS, &blob)?;
    Ok(())
}

/// Persiste o estado OATH via `NamespacedStore` (fail-closed).
/// `Err` = save falhou; o chamador faz rollback via snapshot.
pub fn save_oath_result<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    oath: &OathApplet,
) -> Result<(), VendorExecError> {
    let blob = oath.export_state();
    vendor_ns().put(storage, NVS_KEYS_OATH, &blob)?;
    Ok(())
}

/// Persiste o estado das chaves e OATH via `NamespacedStore`.
pub fn save_states<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    keys: &KeyManager,
    oath: &OathApplet,
) -> bool {
    save_keys_result(storage, keys).is_ok() && save_oath_result(storage, oath).is_ok()
}

/// Persiste o estado PIN (F3: hash + retries) via `NamespacedStore`.
///
/// Sessão pinUvAuth é RAM por desenho (morre no reboot). `Err` fail-closed;
/// hash ausente apaga a chave (idempotente, paridade com o `delete` direto
/// anterior a T5).
pub fn save_pin_state_result<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    pin: &ClientPinState,
) -> Result<(), VendorExecError> {
    match pin.pin_hash {
        Some(h) => vendor_ns().put(storage, NVS_PIN_HASH, &h)?,
        None => vendor_ns().delete(storage, NVS_PIN_HASH)?,
    }
    vendor_ns().put(storage, NVS_PIN_RETRIES, &[pin.pin_retries])?;
    Ok(())
}

/// Compat fina sobre `save_pin_state_result` (BLE/dispatch congelados).
/// Caminho unico: delega ao `NamespacedStore`, sem write-path direto.
pub fn save_pin_state<B: FlashStorageBackend>(
    storage: &mut SecureStorage<B>,
    pin: &ClientPinState,
) -> bool {
    save_pin_state_result(storage, pin).is_ok()
}

/// Carrega o PIN no boot via `NamespacedStore` (ausente = padrão + `Ok`;
/// corrompido = padrão + `Err` fail-closed).
pub fn load_pin_state_result<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
    pin: &mut ClientPinState,
) -> Result<(), VendorExecError> {
    match vendor_ns().get(storage, NVS_PIN_HASH) {
        Ok(v) if v.len() == 16 => {
            let mut h = [0u8; 16];
            h.copy_from_slice(&v);
            pin.pin_hash = Some(h);
        }
        Ok(_) => {
            pin.pin_hash = None;
            pin.pin_retries = 8;
            return Err(VendorExecError::Storage);
        }
        Err(NamespacedStoreError::NotFound) => pin.pin_hash = None,
        Err(_) => {
            pin.pin_hash = None;
            pin.pin_retries = 8;
            return Err(VendorExecError::Storage);
        }
    }
    match vendor_ns().get(storage, NVS_PIN_RETRIES) {
        Ok(v) if v.len() == 1 => pin.pin_retries = v[0].min(8),
        Ok(_) => {
            pin.pin_retries = 8;
            return Err(VendorExecError::Storage);
        }
        Err(NamespacedStoreError::NotFound) => pin.pin_retries = 8,
        Err(_) => {
            pin.pin_retries = 8;
            return Err(VendorExecError::Storage);
        }
    }
    Ok(())
}

/// Compat fina sobre `load_pin_state_result` (boot/dispatch congelados).
/// Caminho unico: delega ao `NamespacedStore`, sem read-path direto.
pub fn load_pin_state<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
    pin: &mut ClientPinState,
) -> bool {
    load_pin_state_result(storage, pin).is_ok()
}

/// Carrega estados do NVS no boot via `NamespacedStore` (ausente = vazio +
/// `Ok`; corrompido = vazio + `Err` p/ WARN do chamador, fail-closed).
pub fn load_states_result<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
    keys: &mut KeyManager,
    oath: &mut OathApplet,
) -> Result<(), VendorExecError> {
    let mut ok = true;
    match vendor_ns().get(storage, NVS_KEYS_SLOTS) {
        Ok(blob) => {
            if keys.import_state(&blob).is_err() {
                ok = false;
            }
        }
        Err(NamespacedStoreError::NotFound) => {}
        Err(_) => ok = false,
    }
    match vendor_ns().get(storage, NVS_KEYS_OATH) {
        Ok(blob) => {
            if oath.import_state(&blob).is_err() {
                ok = false;
            }
        }
        Err(NamespacedStoreError::NotFound) => {}
        Err(_) => ok = false,
    }
    if ok {
        Ok(())
    } else {
        Err(VendorExecError::Storage)
    }
}

/// Compat fina sobre `load_states_result` (boot congelado).
/// Caminho unico: delega ao `NamespacedStore`, sem read-path direto.
pub fn load_states<B: FlashStorageBackend>(
    storage: &SecureStorage<B>,
    keys: &mut KeyManager,
    oath: &mut OathApplet,
) -> bool {
    load_states_result(storage, keys, oath).is_ok()
}
