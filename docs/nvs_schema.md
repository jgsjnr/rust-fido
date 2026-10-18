# NVS Schema — Wave0 baseline (Fase 0, G0)

Fonte: `crates/aegis-fido-firmware/src/persistence.rs` (`SecureStorage`, `MockFlashBackend`).

## Envelope AEGN v1 (atual, observado no codigo)

| Campo | Tamanho | Valor |
| --- | --- | --- |
| magic | 4 | `41 45 47 4E` ("AEGN") |
| version | 1 | `0x01` |
| nonce | 12 | AES-GCM nonce (hoje: caller-supplied; TRNG vira MUST na W1) |
| ciphertext+tag | N+16 | AES-256-GCM |

- Chave: HKDF-SHA256(master eFuse OTP, salt 32B, info `"AegisKey-NVS-Storage-v1"`).
- Erros: `KeyNotFound | CorruptedEnvelope | DecryptionFailed | FlashWriteError | BufferOverflow`.
- Backend prod: NVS cifrada; `MockFlashBackend` SOMENTE em `#[cfg(test)]` (CI grep FAIL fora de test).

## Chaves observadas hoje (testes)

- `credential_01`, `pin_hash` (apenas fixtures de roundtrip/tamper em `persistence.rs`).

## Chaves formais (W1, sequencial: schema -> RESC-gate -> nonce -> retries/sign_count)

Reservadas, ainda NAO implementadas nesta Wave0:

| Chave | Conteudo | Nota |
| --- | --- | --- |
| `pin_retries` | u8 remaining + hash | persistir retries; teste `power_loss_mid_write` |
| `sign_count` | u32 monotonico | atomico por credencial; rollback = FAIL |
| `resc_state` | estado RESC | gate UP+PIN; `resc_sem_up_nega` / `resc_pin_nega` |
| `cred_slot_*` | envelope AEGN | dual-slot + backup + verify-after-write (W3) |

## Regras

- G0: nenhum byte de envelope muda nesta wave (somente documentacao).
- W3: dual-slot + backup + rollback emulador + `factory_provision --dry-run` + readback sha256.