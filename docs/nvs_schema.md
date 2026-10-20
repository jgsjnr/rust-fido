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
## Chaves Phase8 (UX-conex)

Envelope inalterado (AEGN v1, TRNG interno, zeroize). Novas chaves formais:

| Chave | Conteudo | Gate | Nota |
| --- | --- | --- | --- |
| `wifi_ap_pass` | senha AP `8..63` ascii | UP+PIN (`wifi_ap.rs`) | troca via `POST /config/wifi`, NVS intacta sem auth |
| `wifi_sta_ssid` | SSID station `1..32` ascii | UP+PIN (`wifi_station.rs`) | par com `wifi_sta_pass`, nunca em claro no log |
| `wifi_sta_pass` | senha WPA2 `8..63` ascii | UP+PIN (`wifi_station.rs`) | idem, `has_station_credentials` exige o par |

mDNS sem NVS: `aegiskey-XXXX.local` deriva do serial a cada boot (`mdns.rs`), lowercase, fallback `0001`.

## Chaves Binding + Recovery (aditivo §11)

Envelope inalterado (AEGN v1, TRNG interno, zeroize). USB/CTAP nunca toca nestas chaves.

| Chave | Conteudo | Gate | Nota |
| --- | --- | --- | --- |
| `app_bind_pub` | SEC1 65B do app dono | claim (Unclaimed+pareamento+UP) | `binding.rs`, verify-after-write; parcial => `Corrupted` (bloqueia reclaim) |
| `app_bind_id` | id opaco 16B | claim (eco) | par com `app_bind_pub`; wipe em release/unlock/reset |
| `rec_pin_hash` | SHA-256(salt\|\|pin) 32B | `0x2C` com UP | `recovery.rs`; segredo nunca sai, nunca logado |
| `rec_pin_salt` | salt 16B TRNG | `0x2C` com UP | gerado via TRNG injetavel; zeroize apos uso |
| `rec_pin_retries` | restantes 1B (inicia 8) | `0x2D` decrementa | persistida contra queda; 0 => `Locked` (so reset fisico) |

## Chaves Carteira Cripto (codec Step 5 — implementado no core)

Envelope inalterado (AEGN v1, TRNG interno, zeroize). Storage-only BTC/EVM/SOL
sobre `KeyManager`; sem OTP, sem lock dedicado. Detalhe em `docs/carteira-cripto.md`.
Roteamento slot→rede persiste como bytes; chaves canônicas no código
(`wallet_slot_nvs_key`) — fonte única, sem drift com este doc.

| Chave | Conteudo | Gate | Nota |
| --- | --- | --- | --- |
| `wallet_slot_btc` | envelope AEGN do segredo BTC | UP+PIN | storage-only |
| `wallet_slot_evm` | envelope AEGN do segredo EVM | UP+PIN | storage-only |
| `wallet_slot_sol` | envelope AEGN do segredo SOL | UP+PIN | storage-only |
| `wallet_routing` (proposta) | pares `[slot_id, net]` (`net`: 0x01 btc, 0x02 evm, 0x03 sol; 0x00 inválido) | UP | `export_routing`/`import_routing` (`wallet/store.rs`); rejeita ímpar/desconhecido/slot≥32/dup; ordenado por slot |

Wiring no firmware (instanciar `WalletStore` + ler/escrever NVS no boot):
follow-up de design — fora deste passo.
