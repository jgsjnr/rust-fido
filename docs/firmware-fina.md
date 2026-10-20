# Firmware Fina — Auditoria Ficar vs Mover

Objetivo: decidir o que permanece no firmware (fronteira rígida) e o que pode sair para host/app para fechar o envelope de flash/RAM.
Fronteira rígida: **segredo / chave / assinatura / RNG / gates FICAM**; **computação pública sobre dados já públicos PODE IR**. Nenhuma mudança de wire (CBOR IDs, AEGN envelope, GATT revisão 0x01, NVS layout) nesta auditoria.

Baseline SIZE atual (fonte: `docs/size-wave1.md`, 2026-10-18):
- `idf.py size` — `aegis-app-esp32 1786736` / `devkitc 1785232` / `tdisplay 1824016` bytes (bins C).
- Host: `cargo build` + `cargo test` workspace, 77 testes verdes, sem aumento de bin além de poucas centenas de bytes de lógica.
- Regra: sem regressão RAM/flash sem justificativa; envelope AEGN preservado, CBOR IDs preservados, journal NVS sem mudar layout flash.

Contexto: S3 ~2.6MB/3MB (folga curta); classic no limite (opt-z). Todo byte movido conta no classic; no S3 conta para não estourar OTA + NVS.

## Tabela ficar-vs-mover

| Item | Fica / Move | Motivo (fronteira) | Economia estimada |
|---|---|---|---|
| Derivação endereço pubkey (`crates/aegis-fido-core/src/wallet/address.rs`: `bitcoin_p2wpkh_address`, `ethereum_address`, `solana_address`, `address_for_public_key`; deps `sha3/ripemd/bech32/bs58/hex`) | **MOVE** | Entrada é pubkey pública, saída é encoding público; não toca privado (BEHAVIOR no header confirma). Computação pública pura. | **M–L (est.)** — arquivo 185 linhas + 4 crates encodings; método: `cargo bloat`/`nm` nos símbolos `bech32::segwit::encode_v0`, `Keccak256`, `Ripemd160`, `bs58::encode`. Remover do firmware elimina as 4 deps do bin ESP. |
| Formatações CBOR/display (`crates/aegis-fido-core/src/crypto/cose.rs` `to_cose_cbor` pretty/display, `crates/aegis-fido-firmware/src/display/ui.rs` `draw_*`, `totp_view::TotpEntry` → string) | **MOVE (formatação); FICA (parse/encode wire)** | Wire `from_cbor_bytes`/`from_cose_cbor`/`ctap/cbor.rs` é caminho CTAP e fica. Formatação para tela/log/debug (hex, strings, `Display`) é pública e pode ir para app. | **M (est.)** — `display/ui.rs` 982 linhas + `embedded-graphics` fontes; método: `idf.py size` antes/depois com `board-ttgo-classic` vs S3; display já fatiado em bandas 135x40=10800B vs full 64800B. |
| Remontagem GATT (`crates/aegis-fido-firmware/src/ble_gatt.rs`: `BleReassembler::feed/start_new`, `CONTROL_POINT_LENGTH 512`, `MAX_FRAGMENT_BYTES 244`, `BleCompleteMessage`) | **MOVE (reassemble); FICA (gates)** | Reassemble é concat + header `[op,len_hi,len_lo]` sem segredo. Gates (`authorize_vendor_op`, `is_config_op/is_usage_op`, `dispatch_bind_*`, `GATT_REVISION 0x01`, `to_vendor_status`) ficam. | **S (est.)** — ~140 linhas + buffer RAM 512B (`CONTROL_POINT_LENGTH`); método: medir `.bss` + `feed` via `nm`. Ganho maior em RAM que flash. |
| Retry/backoff (`crates/aegis-fido-firmware/src/wifi_station.rs`: `WIFI_STA_RETRY_BACKOFF_MS 60000`, `sta_retry_due`, `WifiStationManager::update/on_failed`, `main.rs` espelhos radio) | **MOVE** | Política de temporização pura, sem chave; radio C não faz retry (`STA_FAILED`: "Rust re-arma com backoff; sem retry automático no C"). App pode agendar. | **S (est.)** — ~30 linhas + 1 constante u64; método: `idf.py size` diff + inspeção `sta_retry_due`. Poucos bytes flash, economiza wake/radio. |
| Countdown (`crates/aegis-fido-firmware/src/totp_view.rs`: `totp_remaining_secs`, `totp_challenge_for_unix_secs`, `TOTP_PERIOD_SECS 30`; `display/ui.rs` countdown bar) | **MOVE (display); FICA (cálculo TOTP)** | `remaining = 30 - t%30` e barra de progresso são aritmética pública. `OathApplet::device_code` + segredo + UP ficam. | **S (est.)** — ~10 linhas aritmética + desenho barra; método: diff `totp_remaining_secs` fora do bin. Dezenas de bytes. |
| Segredos (`credential/key_manager.rs` `secrets: Vec<KeyEntry>` + `ZeroizeOnDrop`, `vault_store.rs`, `persistence.rs` `SecureStorage` AES-GCM, `efuse.rs` BLOCK7 master + BLOCK8 salt) | **FICA** | Material privado + envelope AEGN + OTP hardware; mover vaza fronteira. | — (custo aceito; `zeroize` + `verify-after-write` inegociáveis) |
| PIN hash (`crypto/pin_protocol.rs`: `pin_hash` = `sha256(pin)[..16]`, `pad_pin`, `ctap/client_pin.rs` `ClientPinState::pin_hash`, `recovery.rs` 8 tentativas NVS) | **FICA** | Derivação de credencial + retries + `UpAndPin`; hash fora do device permite offline-brute. | — |
| Nonces (`crypto/aead.rs` `seal_blob` nonce 12B rand, `credential/non_resident.rs` `wrap` `nonce_bytes [0u8;12]`, cred_id `[ver\|nonce12\|ct]`) | **FICA** | Unicidade/anti-replay AES-GCM; reuso = quebra confidencialidade. Geração usa `CryptoRng`. | — |
| Sign (`crypto/curves.rs` `KeyPair::sign/verify`, `credential/key_manager.rs::sign`, `binding.rs` `sign_der/verify`) | **FICA** | Assinatura com chave privada só no device; mover = exfiltrar chave ou oráculo solto. | — |
| TRNG (`rand_core::CryptoRng`, `dispatch_bind_challenge` 32B via TRNG, `KeyPair::generate`, `Bip39::generate`, `EcdhKeyAgreement::generate`, `esp_fill_random` no HAL) | **FICA** | Fonte de entropia hardware; host não é confiável para challenge/keygen. | — |
| Gates (`core/policy.rs` `UpPolicy/UpOnly/UpAndPin/check_up`, `ble_gatt::authorize_vendor_op/vendor_op_requires_pin/binding_err_to_gatt`, `wifi_station::require_bound_station`, `binding::BindingManager::verify`, `persistence` UP+PIN guards) | **FICA** | Ordem canônica binding→UP→PIN + wire codes (`NEED_UP 0x01`, `NEED_PIN 0x02`, `NEED_BINDING 0x05`, `RESCUE_STATUS_CONFIRMATION_FAILED`); mover quebra segurança e compat. | — |

Método geral de estimativa: S = dezenas–poucas centenas B flash e/ou <512B RAM; M = poucos KB (1–8KB, tipicamente strings/fontes/CBOR-display); L = >8KB (crate de encoding inteira). Valores marcados `est.` — confirmar com `idf.py size` + `cargo bloat --target riscv32imc-esp-espidf` por símbolo antes de mover.

## Riscos / Notas

- Nunca mover: eFuse BLOCK7/BLOCK8, `pin_hash`, nonce-12, `sign`, TRNG-32, `check_up`/`authorize_vendor_op`. Qualquer PR que toque esses caminhos exige `@security-auditor`.
- `address.rs` documenta "encodings only — no private material"; mover é seguro **se** o caller passar só pubkey (validar no boundary, rejeitar curva errada com `BadEnvelope` já existente).
- GATT: manter `GATT_REVISION 0x01`, framing §3 `[op,len_hi,len_lo]`, sem NACK que quebre §9.6 (`BAD_ENVELOPE 0x04` sem retry).
- Classic: priorizar MOVER `address.rs` + formatação display primeiro (maior alívio opt-z); S3 usa a mesma lista para abrir folga OTA.
- Sem mudança de layout NVS/journal nem CBOR IDs nesta wave.

## Delta Wave2 Step4c + plumbing (2026-10-20, branch fd/finalizacao-linux)

- **Bridge move executado**: `wallet_address(network, pubkey_hex)` no
  `uniffi-bridge` (UDL + `InvalidAddress`) — BTC/ETH/SOL por vetores
  conhecidos (G BIP-173/EIP-55, zero-seed Solana), rejeita rede/hex/tamanho
  ruins. App calcula endereço local de pubkey pública; device nunca é
  perguntado. Testes bridge 13→15 verdes. Kotlin regenera no build do app
  (SDK ausente aqui).
- **SIZE medido**: release S3 2.646.512 → **2.646.400 B (−112 B)**. Ganho
  não vem do move (firmware nunca linkou os encodings — morto no link),
  e sim da fiação; código test-mode (`TEST_LED_*`, D1b) soma **0 bytes**
  na release (cfg fora). Classic: bin 1.987.072 B pronto, sem COM8 p/ flash.
- **Plumbing ClientPIN→killswitch**: `ClientPinState::has_valid_pin_uv_session`
  + fiação nos 3 transportes (`main.rs` BLE/USB/serial). Prova viva na
  serial: killswitch remoto sem UP/PIN → `status=0x04`
  (`tools/killswitch_deny_probe.py` DENY_OK); teste core
  `killswitch_plumbing_clientpin_session_gates_remote`.

## Delta Wave2 Step3 (2026-10-20, commitado em fd/finalizacao-linux)

Roteamento rescue `0x2E` ligado nos 3 transportes sem mudar framing:
`main.rs` USB-C + serial-D (`CMD_MSG [0x2E, frame...]` via
`serial_ctaphid::{is_rescue_msg, dispatch_serial_rescue}`) e BLE
(`OP_MSG` com primeiro byte `0x2E`, reassembler intacto). UP vem do latch
BOOT (uso único); PIN via plumbing ClientPIN→`set_pin_uv_authenticated`
  (sessão viva = PIN verificado; sem ela o remoto nega fail-closed,
  `RESCUE_STATUS_CONFIRMATION_FAILED`, provado vivo na serial). Hold físico→
`request_physical_killswitch` pendente: o hold 5s é compartilhado com o
pareamento, então o gesto de armar exige decisão de UX antes de fiar.
Fronteira intacta: `GATT_REVISION 0x01`, NVS/CBOR sem mudança.
