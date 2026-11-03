//! OOB-assisted BLE pairing (MITM sem display).
//!
//! Contexto: a SM NimBLE exige MITM (`sm_mitm = 1`, LESC + bonding,
//! `no_std` mirror em `super::nimble_backend::BLE_SM_MITM_REQUIRED`), mas o
//! device nao tem display/teclado (`NO_INPUT_NO_OUTPUT`): um telefone
//! consent-only (sem metodo de confirmacao) nao consegue completar o
//! pareamento — o JustWorks e rejeitado fail-closed (`AUTH_REQUIREMENTS`).
//! Sem enfraquecer o MITM, a saida e OOB: a chave temporaria viaja pelo
//! canal USB/serial ja confiavel (posse fisica do cabo + sessao
//! desbloqueada + vinculo), e o BLE completa LESC+OOB.
//!
//! Suporte NimBLE (IDF v5.3.1 pinado, verificado nos headers locais
//! `C:\.embuild\espressif\esp-idf\v5.3.1`, esp-nimble `2cf7edd`):
//! - `ble_hs_cfg.sm_oob_data_flag` (lido live pelo SM a cada
//!   `Pairing Req/Rsp`, `ble_sm.c`).
//! - `BLE_SM_IOACT_OOB` (=1, TK legado 16 B via `pkey.oob[16]`,
//!   `ble_sm.c`, mesmo padrao do exemplo oficial `bleprph` v5.3.1).
//! - `BLE_SM_IOACT_OOB_SC` (=5, `pkey.oob_sc_data.{local,remote}`,
//!   `struct ble_sm_sc_oob_data { r[16], c[16] }`).
//! - `ble_sm_sc_oob_generate_data()` + `ble_sm_inject_io()`
//!   (guard `NIMBLE_BLE_SM`, sempre ON com bonding).
//!
//! Escopo desta lane (host-testavel, `no_std`): opcode, validacao
//! fail-closed, gates e politica de arming. O radio (armazenar o TK,
//! `sm_oob_data_flag`, `PASSKEY_ACTION`, inject) vive no componente C
//! `components/aegis_ble` (chamado via `super::nimble_backend::esp_ble_*`).
//!
//! Contrato wire (serial/USB `CMD_MSG`, status-first como o BLE):
//! - Request: `[0x42, tk0..tk15]` — opcode + EXATAMENTE 16 B (random OOB
//!   do peer / TK legado; ver nota LESC-SC abaixo). Qualquer outro
//!   comprimento nega fail-closed (`0x04`, corpo vazio, sem armar).
//! - TK todo-zero e rejeitado (fail-closed: TK=0 e a chave mais fraca;
//!   colisao aleatoria tem prob. 2^-128, nunca legitimo do host).
//! - Response: `[status]` (`0x00` ok + corpo vazio; negacoes abaixo).
//! - Transporte: SOMENTE serial/USB. O reassembler BLE rejeita `0x42`
//!   (`is_ble_fragment_opcode` nao o lista → `InvalidOpcode`); expor o
//!   TK no ar derrotaria o proposito do OOB.
//!
//! Gates (classe CONFIG sensivel, mesma severidade do DELETE `0x23`,
//! ordem canonica):
//! 1. `binding_ok` (prova de vinculo de uso unico), senao `0x05`
//!    (`NeedBinding`). Em `test-mode`, bypass com `ltrace` (mesma regra
//!    de `authorize_vendor_op`).
//! 2. `presence_confirmed` (UP fisico por operacao), senao `0x01`.
//!    O OOB NAO dispensa UP: o `on_link_secured` continua exigindo o
//!    latch no `ENC_CHANGE` (pareamento so completa com toque).
//! 3. `session_unlocked` (sessao PIN viva / SecureGuard unlocked — o
//!    chamador entrega `pin_ok` efetivo), senao `0x02` (`PinRequired`).
//! 4. Janela de pareamento: exigida pelo funil serial (fail-closed
//!    `0x05` com a janela fechada, mesma UX do CONFIG); ver o ramo
//!    `is_ble_oob_op` em `freertos_route` / loop legado.
//!
//! Arming (one-shot): sucesso arma o TK para o PROXIMO pareamento. O
//! latch de radio (lado C) consome de uso unico no inject, limpa no
//! disconnect e expira por re-arm (last-wins). Divergencia Rust<->C
//! falha fechado: sem latch no C, o SM rejeita OOB (`BLE_SM_ERR_OOB`)
//! e o MITM segue exigido — nunca cai para JustWorks.
//!
//! Nota LESC-SC (honestidade de fio, NimBLE v5.3.1 `ble_sm_sc.c`):
//! no `OOB_SC`, o SM usa `remote->r` como TK do DHKey-check e verifica
//! `f4(peer_pub, peer_pub, r_remote) == remote->c`. Com 16 B (so o `r`
//! do peer), o glue C injeta `remote = { r: TK, c: TK }`: a checagem de
//! confirm falha fechado rapido (`CONFIRM_MISMATCH`, sem bonding, sem
//! retry) em vez de travar em timeout. OOB-SC pleno (par `(r,c)` real
//! do peer, 32 B) e follow-up documentado (op `0x42` estendida ou nova
//! op); o caminho legado `IOACT_OOB` (peer sem SC) completa com os 16 B.
//! MITM intacto nos dois casos: sem o TK OOB, o atacante nao passa.

extern crate alloc;

use super::gatt_core::BleGattError;
#[cfg(feature = "debug-terminal")]
use crate::lifetime_trace::{LifetimeCategory as LtCat, LifetimeEvent as LtEvt};
use alloc::vec::Vec;

/// Vendor op de arming OOB (`0x42`, primeiro byte livre apos
/// `VENDOR_SIGN 0x41`).
///
/// Auditoria (primeiro byte do payload `CMD_MSG` / mensagem vendor BLE):
/// - `0x20-0x27` vendor keys/OATH (todas tomadas).
/// - `0x28-0x2D` bind-mgmt (todas tomadas).
/// - `0x2E` rescue (payload de `OP_MSG`, nunca opcode de fragmento).
/// - `0x2F` trigger de pareamento produto (USB/serial, nunca vendor).
/// - `0x30-0x34` OTA (`OP_OTA_BEGIN..OP_OTA_ABORT`, fonte em `ota`).
/// - `0x35-0x37` wallet (`OP_WALLET_GEN/LIST/ADDR`).
/// - `0x38` fw-log (`OP_FW_LOG`).
/// - `0x39` PIV enroll (`OP_PIV_ENROLL`).
/// - `0x3A-0x3E` Secure Guard.
/// - `0x3F` GET_CAPS. `0x40` SET_UP_POLICY. `0x41` VENDOR_SIGN.
/// - `0x42` LIVRE: nenhuma definicao de opcode na arvore (verificado;
///   teste de auditoria abaixo trava os vizinhos).
pub const OP_BLE_OOB: u8 = 0x42;

/// Comprimento do TK OOB (random do peer, 128 bits).
pub const OOB_TK_LEN: usize = 16;

/// `true` para a op de arming OOB (`0x42`, serial/USB only).
///
/// Funis de transporte incluem este predicado ao lado de
/// `is_get_caps_op` / `is_set_up_policy_op` (ramo dedicado com gates
/// binding -> UP -> sessao; NUNCA no reassembler BLE).
pub fn is_ble_oob_op(op: u8) -> bool {
    op == OP_BLE_OOB
}

/// Valida o corpo da op OOB (tudo apos o opcode).
///
/// Retorna os 16 B do TK em caso valido. Qualquer outro comprimento —
/// incluindo vazio e 32 B (par `(r,c)` SC e follow-up, nao esta op) —
/// nega fail-closed com `InvalidFragment`. TK todo-zero tambem nega
/// (chave mais fraca; nunca legitimo do host).
pub fn validate_oob_tk(payload: &[u8]) -> Result<[u8; OOB_TK_LEN], BleGattError> {
    if payload.len() != OOB_TK_LEN {
        return Err(BleGattError::InvalidFragment);
    }
    let mut tk = [0u8; OOB_TK_LEN];
    tk.copy_from_slice(payload);
    if tk.iter().all(|&b| b == 0) {
        return Err(BleGattError::InvalidFragment);
    }
    Ok(tk)
}

/// Gate normativo da op OOB (classe CONFIG sensivel).
///
/// Ordem canonica binding -> UP -> sessao (app alheio sempre ve
/// `NEED_BINDING` primeiro). `session_unlocked` = sessao PIN viva
/// (`pinUvAuth` via ClientPIN) ou SecureGuard unlocked (o funil
/// entrega o efetivo). Em `test-mode`, o vinculo faz bypass com
/// `ltrace` (mesma regra de `authorize_vendor_op`); UP e sessao
/// seguem exigidos nas duas modalidades (sem oraculo sem toque).
pub fn authorize_ble_oob_op(
    binding_ok: bool,
    session_unlocked: bool,
    presence_confirmed: bool,
) -> Result<(), BleGattError> {
    if crate::binding::binding_bypass_enabled() {
        crate::ltrace!(LtCat::Transport, LtEvt::TpOpen, "binding-bypass");
    } else if !binding_ok {
        return Err(BleGattError::NeedBinding);
    }
    if !presence_confirmed {
        return Err(BleGattError::PresenceRequired);
    }
    if !session_unlocked {
        return Err(BleGattError::PinRequired);
    }
    Ok(())
}

/// Executa a op OOB (`0x42`): valida gates + corpo e arma o TK.
///
/// Retorna `(wire_status, body)` status-first como o BLE: sucesso =
/// `(0x00, [])`; negacoes mapeiam via `to_vendor_status`
/// (`0x05`/`0x01`/`0x02`/`0x04`). O latch de radio e aplicado pelo
/// funil serial (via `nimble_backend::esp_ble_arm_oob`) SOMENTE com
/// `st == 0x00`; aqui nao ha efeito colateral (puro e host-testavel).
/// Op desconhecida (defesa em profundidade) = `0x04`.
pub fn exec_ble_oob(
    op: u8,
    payload: &[u8],
    binding_ok: bool,
    session_unlocked: bool,
    presence_confirmed: bool,
) -> (u8, Vec<u8>) {
    if !is_ble_oob_op(op) {
        return (BleGattError::InvalidOpcode.to_vendor_status(), Vec::new());
    }
    if let Err(e) = authorize_ble_oob_op(binding_ok, session_unlocked, presence_confirmed) {
        return (e.to_vendor_status(), Vec::new());
    }
    match validate_oob_tk(payload) {
        Ok(_) => (0x00, Vec::new()),
        Err(e) => (e.to_vendor_status(), Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn tk(byte: u8) -> Vec<u8> {
        vec![byte; OOB_TK_LEN]
    }

    #[test]
    fn opcode_audit_oob_is_first_free_after_vendor_sign() {
        // Vizinhos travados (auditoria completa no doc de OP_BLE_OOB).
        assert_eq!(OP_BLE_OOB, 0x42);
        assert!(is_ble_oob_op(0x42));
        assert!(!is_ble_oob_op(0x41));
        assert!(!is_ble_oob_op(0x43));
        assert!(!is_ble_oob_op(0x2F));
        assert_eq!(crate::ble_gatt::OP_PIV_ENROLL, 0x39);
        assert_eq!(crate::fw_log::OP_FW_LOG, 0x38);
        assert_eq!(crate::ble_gatt::SECURE_GUARD_OP_MAX, 0x3E);
        assert_eq!(crate::vendor_exec::OP_GET_CAPS, 0x3F);
        assert_eq!(crate::ctap_cmd::OP_SET_UP_POLICY, 0x40);
        // `0x41` VENDOR_SIGN: valor travado em
        // `vendor_exec/vendor_keys.rs::OP_VENDOR_SIGN` (modulo privado da
        // lane vendor; aqui basta `!is_ble_oob_op(0x41)` acima).
        // 0x42 fora de todas as faixas existentes (nenhum funil engole).
        assert!(!crate::ble_gatt::is_vendor_keys_oath_op(OP_BLE_OOB));
        assert!(!crate::ble_gatt::is_wallet_op(OP_BLE_OOB));
        assert!(!crate::ble_gatt::is_secure_guard_op(OP_BLE_OOB));
        assert!(!crate::ble_gatt::is_bind_mgmt_op(OP_BLE_OOB));
        assert!(!crate::fw_log::is_fw_log_op(OP_BLE_OOB));
        assert!(!crate::ble_gatt::is_piv_enroll_op(OP_BLE_OOB));
        assert!(!crate::vendor_exec::is_get_caps_op(OP_BLE_OOB));
        // Serial/USB only: o reassembler BLE rejeita 0x42 fail-closed.
        assert!(!crate::ble_gatt::is_ble_fragment_opcode(OP_BLE_OOB));
        assert_eq!(
            crate::ble::gatt_core::BleReassembler::new().start_new(OP_BLE_OOB, OOB_TK_LEN),
            Err(BleGattError::InvalidOpcode)
        );
    }

    #[test]
    fn validation_accepts_exactly_16_nonzero_bytes() {
        assert!(validate_oob_tk(&tk(0xA5)).is_ok());
        let mut varied = [0u8; OOB_TK_LEN];
        for (i, b) in varied.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
        assert_eq!(validate_oob_tk(&varied).unwrap(), varied);
        // Um unico byte nao-zero basta (rejeita-se SO o todo-zero).
        let mut edge = [0u8; OOB_TK_LEN];
        edge[OOB_TK_LEN - 1] = 1;
        assert!(validate_oob_tk(&edge).is_ok());
    }

    #[test]
    fn validation_rejects_garbage_fail_closed() {
        for payload in [
            vec![],
            vec![0x01],
            vec![0xA5; OOB_TK_LEN - 1],
            vec![0xA5; OOB_TK_LEN + 1],
            vec![0xA5; 32],
            vec![0xFF; 64],
        ] {
            assert_eq!(
                validate_oob_tk(&payload),
                Err(BleGattError::InvalidFragment),
                "len={}",
                payload.len()
            );
            // Via executor: status 0x04, corpo vazio (sem vazamento).
            let (st, body) = exec_ble_oob(OP_BLE_OOB, &payload, true, true, true);
            assert_eq!(st, 0x04, "len={}", payload.len());
            assert!(body.is_empty());
        }
        // TK todo-zero: 0x04 fail-closed (nunca arma a chave mais fraca).
        let (st, body) = exec_ble_oob(OP_BLE_OOB, &[0u8; OOB_TK_LEN], true, true, true);
        assert_eq!(st, 0x04);
        assert!(body.is_empty());
    }

    #[test]
    fn gates_binding_then_up_then_session() {
        let good = tk(0x5A);
        // Ordem canonica: binding primeiro (app alheio ve NEED_BINDING).
        let (st, _) = exec_ble_oob(OP_BLE_OOB, &good, false, false, false);
        if crate::binding::binding_bypass_enabled() {
            assert_eq!(st, 0x01, "test-mode: bypass de vinculo, UP nega");
        } else {
            assert_eq!(st, 0x05, "sem vinculo = NEED_BINDING");
        }
        // Sem UP (com vinculo + sessao): 0x01. OOB nao dispensa presenca.
        let (st, _) = exec_ble_oob(OP_BLE_OOB, &good, true, true, false);
        assert_eq!(st, 0x01, "OOB nunca pula UP");
        // Travado (vinculo + UP, sem sessao): 0x02 NEED_PIN.
        let (st, _) = exec_ble_oob(OP_BLE_OOB, &good, true, false, true);
        assert_eq!(st, 0x02, "sessao travada = NEED_PIN");
        // Tudo ok: 0x00 + corpo vazio.
        let (st, body) = exec_ble_oob(OP_BLE_OOB, &good, true, true, true);
        assert_eq!(st, 0x00);
        assert!(body.is_empty());
    }

    #[test]
    fn unknown_op_rejected_fail_closed() {
        let (st, body) = exec_ble_oob(0x41, &tk(0x5A), true, true, true);
        assert_eq!(st, 0x04);
        assert!(body.is_empty());
        let (st, body) = exec_ble_oob(0x00, &tk(0x5A), true, true, true);
        assert_eq!(st, 0x04);
        assert!(body.is_empty());
    }

    #[test]
    fn oob_does_not_open_ble_fragment_path() {
        // Fragmento unico 0x42 no reassembler BLE: rejeitado antes de
        // qualquer gate (o TK nunca viaja no ar).
        let mut r = crate::ble::gatt_core::BleReassembler::new();
        let mut frag = vec![OP_BLE_OOB, 0x00, OOB_TK_LEN as u8];
        frag.extend_from_slice(&tk(0x5A));
        assert_eq!(r.feed(&frag), Err(BleGattError::InvalidOpcode));
        assert!(!r.is_active());
    }
}
