//! Executor vendor keys/OATH on-device (F2).
//!
//! Gates idênticos ao BLE/serial (`authorize_vendor_op`, ordem
//! binding -> UP -> PIN); executor real sobre `KeyManager`/`OathApplet`
//! com persistência NVS (snapshot + rollback se o save falhar).
//! IMPORT (`0x21`) segue gate-ok `0x04` (envelope AEGN + vault = F2b).
//! Sem PII/segredos no wire: só metadados e códigos (§9.7).
//!
//! Thin shim: NVS em `vendor_store`, chaves em `vendor_keys`, OATH em
//! `vendor_oath`, PIV enroll em `vendor_piv`, dispatcher em
//! `vendor_dispatch`, testes em `vendor_tests`. Todos os paths públicos
//! são re-exportados abaixo (move-only, sem mudanca de comportamento).

mod vendor_caps;
mod vendor_dispatch;
mod vendor_keys;
mod vendor_oath;
mod vendor_piv;
mod vendor_store;
#[cfg(test)]
mod vendor_tests;

pub use self::vendor_caps::{
    OP_GET_CAPS, capability_ids, diet_gated_ops, is_get_caps_op, preset_name,
    unsupported_count,
};
pub use self::vendor_dispatch::exec_vendor_op;
pub use self::vendor_store::*;
