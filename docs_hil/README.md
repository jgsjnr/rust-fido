# docs_hil — HIL USB/BLE/WiFi/SIM (lane fd/hil-usb-tests)

Escopo de escrita da lane: `python_hil/` + `docs_hil/` (nao tocar o principal).

## Mapa

| Arquivo | Papel |
|---|---|
| `python_hil/link_serial.py` | UART 115200 COM7 sem DTR/RTS; CTAPHID 64B INIT/CONT + texto TEST_* drenado; PING, GetInfo/MC/GA, TEST_PAIRING_OPEN/TEST_UP/TEST_LED_STATE/LIFETIME_DUMP |
| `python_hil/link_usb.py` | HID VID 0x303A PID 0xAE61; INIT→CID, PING 64B, CBOR GetInfo 0x04, vendor 0x20-0x27 / wallet 0x35-0x37 / rescue 0x2E / fw-log 0x38; probes CCID/KBD/WinUSB read-only |
| `python_hil/link_ble_wifi.py` | BLE scan 0xFFFD FFF1-FFF4 + frag [op\|len]+[seq] 244/512 B; WiFi POST /ctap AEGN + GET /oath/code (timeout curto, falha documentada sem HW) |
| `python_hil/app_usb_sim.py` | App USB (connect_usb→INIT→exchange_ctaphid; GetInfo/MC/GA sem claim, fw-log livre, OATH/Wallet/PIV/OTA-gated USB-only), menus 0-18 |
| `python_hil/sim_pilot.py` | Piloto Renode/QEMU (TCP 127.0.0.1:5678) ou COM7; boot-check ONLINE&ACTIVE; SIM-COVERED vs HW-ONLY |
| `python_hil/tests/test_l1_sim.py` | L1 sim (loopback + vetores offline; live so com `--tcp`) |
| `python_hil/tests/test_l2_uart.py` | L2 UART (so com `--uart`; sem HW = skip) |
| `python_hil/tests/test_l3_usb.py` | L3 USB (vetores offline + live com HW enumerado; sem HW = skip) |
| `python_hil/tests/test_l4_app.py` | L4 app (self-test offline + live USB; sem HW = skip) |
| `python_hil/tests/test_l5_ctap.py` | L5 CTAP (MC 0x01/GA 0x02 com UP+janela, GetInfo 0x04, ClientPIN 0x06, hmac-secret, credMgmt 0x0A; CBOR minimo => `0x14`, sem HW = skip) |
| `python_hil/tests/test_l5_oath.py` | L5 OATH (PUT/LIST/CODE vendor 0x24-0x27; HOTP RFC4226 + TOTP ±1 offline; live LIST/CODE read-only, PUT/DELETE nunca live; gate => `0x01` skip) |
| `python_hil/tests/test_l5_wallet.py` | L5 wallet (GEN/ADDR/LIST 0x35-37; slots 0-31 prefixo `wallet:`, storage-only sem sign-tx; GEN nunca live; sem HW = skip) |
| `python_hil/tests/test_l5_piv_otp.py` | L5 PIV+OTP (SELECT/VERIFY/GEN-AUTH+strip-FF, typer 6-8 digitos+presenca; CCID nunca claimed; sem HW = skip) |
| `python_hil/tests/test_l5_mgmt.py` | L5 mgmt (gates binding→UP→PIN, pairing 60/300 s, fw-log livre, AEGN parse cabeçalho, OTA begin/chunk/verify SEM COMMIT, walkaway; COMMIT bloqueado sem `--confirm`) |
| `docs_hil/falha-L5-usb-mudo-pos-init-2026-10-24.md` | Falha real L5 (INIT+PING ok, CBOR/MSG mudo persistente; retry nao recuperou) |
| `docs_hil/falha-TEMPLATE.md` | Template de falha real documentada (copiar por ocorrencia) |

Contratos herdados do recon: report 64B+ID00, CTAPHID INIT 0x86/PING 0x81/CBOR 0x90,
UART 115200 COM7 sem DTR/RTS (DTR reseta), BLE 0xFFFD FFF1-FFF4 frag max 244/512 B
teto 7609 B, WiFi AP AegisKey-XXXX 192.168.4.1 POST /ctap, TEST_* so test-mode,
gates binding→UP→PIN, BOOT GPIO0/KEY GPIO14. Referencias: `tools/host_sdk/*.py`
(tlv, framing 64B, gates) e `tools/sim_ctap_init.py`.

## Como rodar

```powershell
python -m venv .venv; ./.venv/Scripts/Activate.ps1
pip install -r python_hil/requirements.txt
pytest python_hil/tests -v                        # sem HW: offline passa, HW skipa
pytest python_hil/tests -v --uart COM7            # L2 com HW UART + L5 pairing/UP
pytest python_hil/tests/test_l5_ctap.py python_hil/tests/test_l5_mgmt.py -v --uart COM7  # L5 CTAP+mgmt com janela
pytest python_hil/tests/test_l1_sim.py -v --tcp 127.0.0.1:5678   # L1 no sim
python -m python_hil.sim_pilot --self-test        # loopback (nao e HW)
python -m python_hil.sim_pilot --tcp 127.0.0.1:5678
python -m python_hil.app_usb_sim --self-test      # offline, sem HW
```

Multiprocesso E2E (quando aplicavel): `pytest -n auto --test-threads=1`;
reporte o resultado focado exato (1 linha por teste). Nesta bancada o
plugin xdist/test-threads NAO esta instalado (`unrecognized arguments:
-n --test-threads=1`); E2E multiprocesso N/A aqui — rodar serial.

## Onde estavam os testes funcionais (principal `E:\projetos\fido`)

Resposta a "cade os testes das funcionalidades" — inventariado em
2026-10-24 no principal (espelhado nesta worktree). `cargo test` = 810.

### crates/aegis-fido-core (credential, crypto, CTAP, oath, otp, wallet, vault)

| Path | O que prova |
|---|---|
| `src/credential/store.rs` + `record.rs` + `key_manager.rs` + `non_resident.rs` | CRUD de credencial, wrap nao-residente, RK |
| `src/crypto/curves.rs` | 5 curvas: P-256 (ES256/-7), P-384 (ES384/-35), P-521 (ES512/-36), K-256 (secp256k1), Ed25519 (EdDSA/-8) |
| `src/crypto/aead.rs` + `aes_cbc.rs` | AES-GCM seal/open + vetor NIST; AES-CBC |
| `src/crypto/cose.rs` + `ecdh.rs` + `pin_protocol.rs` + `kdf.rs` + `hash.rs` + `bip39.rs` | COSE, ECDH PIN-UV, KDF, hash, mnemonico |
| `src/ctap/make_cred.rs` (0x01) + `get_assertion.rs` (0x02) + `info.rs` (0x04) + `client_pin.rs` (0x06) | CTAP 0x01/02/04/06 fim-a-fim |
| `src/ctap/cred_mgmt.rs` + `large_blobs.rs` + `config.rs` + `reset.rs` + `attestation.rs` + `cbor.rs` + `status_code.rs` | CredMgmt, blobs, config, reset, erros |
| `src/oath/applet.rs` + `crypto.rs` + `tlv.rs` + `types.rs` + `presence.rs` | OATH applet/TLV/HOTP-TOTP+presenca |
| `src/otp/mod.rs` + `yubikey_otp.rs` + `challenge_response.rs` + `ykman.rs` + `nitrokey.rs` + `modhex.rs` + `scancodes.rs` + `rescue.rs` | OTP modhex/YubiOTP/challenge/rotas |
| `src/wallet/store.rs` + `address.rs` + `types.rs` | Wallet 32 slots, prefixo `wallet:`, enderecos btc/eth, metadados-only |
| `src/vault/store.rs` + `secrets.rs` + `policy.rs` | Vault selado + politica |
| `src/policy.rs` + `src/lifetime.rs` | Politica UP/PIN + contadores `lt_*`/dump |
| `tests/ctap_tests.rs` | E2E engine: GetInfo golden CBOR, PIN v1+v2, MC/GA todas curvas, reset, blobs, credMgmt+RK, auth-config |
| `tests/e2e_vectors.rs` | Vetores MC/GA impressos |

### crates/aegis-fido-usb (ctaphid/ccid/piv/keyboard/winusb)

| Path | O que prova |
|---|---|
| `src/ctaphid.rs` | Framing INIT/CONT 64 B, INIT/PING/CBOR/MSG/WINK/KEEPALIVE |
| `src/ccid.rs` + `src/ccid_parse.rs` | CCID + parse (PIV/OpenPGP por tras) |
| `src/piv/piv_applet.rs` + `piv_cmd.rs` + `apdu.rs` | PIV SELECT/VERIFY/GEN-AUTH, APDU curto |
| `src/keyboard.rs` + `src/kbd_gate.rs` | HID keyboard typer + gate (so com UP) |
| `src/winusb.rs` | WinUSB bulk (envelopes AEGN) |
| `src/transport.rs` | Roteamento de transporte |

### crates/aegis-fido-firmware (device: button/led/pairing/binding/...)

| Path | O que prova |
|---|---|
| `src/button.rs` + `src/led.rs` + `src/led_policy.rs` + `src/pairing_led.rs` | Botao/hold, LED, politica |
| `src/pairing.rs` + `pairing_flow.rs` | Pairing 60 s / TEST 300 s, janelas |
| `src/binding.rs` + `src/up_policy.rs` | Binding + gates UP/PIN |
| `src/recovery.rs` + `src/backup_envelope.rs` | Recovery + envelope AEGN |
| `src/proximity.rs` + `proximity/` + `proximity_sched.rs` + `proximity_crypto.rs` | Proximidade BLE walkaway/K_prox |
| `src/ota.rs` + `ota_store.rs` + `stores/ota_store.rs` + `anti_rollback.rs` | OTA staged (begin/chunk/verify/COMMIT) + anti-rollback |
| `src/fw_log.rs` + `lifetime_trace.rs` | fw-log livre + trace `lt_*` |
| `src/pin_uv.rs` + `src/dkek.rs` + `src/cred_store.rs` + `oath_store.rs` + `piv_store.rs` + `vault_store.rs` + `vault_aead.rs` + `nvs_backend.rs` + `persistence.rs` | PIN-UV, DKEK, stores NVS |
| `src/vendor_exec.rs` + `wallet_exec.rs` + `oath_cmd.rs` + `piv_cmd.rs` + `ctap_cmd.rs` + `ctap_state.rs` + `ctap_ext.rs` | Execucao vendor/wallet/OATH/PIV/CTAP + hmac-secret |
| `tests/proximity_freertos.rs` + `otakey_provider_t6.rs` + `applets_t9.rs` + `netwifi_t10.rs` + `namespaced_store_t5.rs` + `freertos_tasks.rs` + `migration_tests.rs` | Testes device: proximidade, OATH, applets, WiFi, stores, migracoes |

### tools/host_sdk (gates/ops — espelho usado pelo HIL)

| Path | O que prova |
|---|---|
| `tools/host_sdk/gates.py` | Ordem binding→UP→PIN (`NEED_BINDING 0x05`, `NEED_UP 0x01`, `NEED_PIN 0x02`), fw-log |
| `tools/host_sdk/ops.py` | Builders wallet/vendor/OATH/OTA/PIV/OTP/prox/killswitch (stdlib, sem I/O) |
| `tools/host_sdk/tlv.py` | TLV canonico byte-identico ao `tlv.rs` |
| `tools/host_sdk/transport.py` + `cli.py` | Transporte + CLI |

## Regras

- Sem provedores de test-double em codigo de producao (`python_hil/*.py` fora de `tests/`); testes nao usam doubles — sem HW = skip, nunca aprova sem evidencia.
- Falha real documentada via `docs_hil/falha-TEMPLATE.md` (1 arquivo por ocorrencia).
- Log sanitizado: nomes de evento + contagens; segredo (CBOR/TLV hex, TOTP, PIN/senha) nunca.
- Builds, trafego simulado, portas, screenshots, emuladores e handshakes NAO sao aceite fisico; `SIM-COVERED` nao substitui HW.

## Matriz L0-L4 — 2026-10-24 17:10 UTC (rodada hil-subagent)

| Item | Resultado | Detalhe |
|---|---|---|
| L0 offline/vetores | PASS | framing 64B, text-chunk, dump-parser, BLE-frag, pilot loopback, ranges vendor/wallet, report 64B, app self-test |
| L1 live (`--tcp 127.0.0.1:5678`) | SKIP | QEMU :5678 mudo (0 bytes); Renode trava em `System bus created` + 1234 em uso; ver `falha-L1-live-sim-sem-boot-2026-10-24.md` |
| L2 UART (`--uart COM7`) | FAIL (harness) | open sem DTR/RTS PASS; INIT/PING/GetInfo/TEST-gates FAIL `unexpected continuation` — logs `[FREERTOS]` nao-alinhados quebram janelas 64B; prova eletrica com resync: INIT->CID 0x00000003 + PING OK; PAIRING_OPEN/TEST_UP/DUMP OK, LED sem resposta; ver `falha-L2-uart-acesso-negado-2026-10-24.md` §7 |
| L3 USB (AEGIS-S3-0002) | PASS | INIT->CID, PING eco, GetInfo, iface probes (10/10 com L4; 1 SKIP transiente de enumerate recuperado no retry) |
| L4 app USB | PASS | GetInfo, fw-log livre, wallet LIST read-only |
| BLE scan 5 s | SKIP | `ble_scan` OK, `[]` (sem radio/dispositivo 0xFFFD) |
| WiFi AP 192.168.4.1 | SKIP | `HwMissingError` timeout (fora do SSID AegisKey-XXXX; WiFi ligado em outro SSID) |
| TEST_UP/PAIRING_OPEN_300/LED_STATE/LIFETIME_DUMP | PARCIAL | via COM7: PAIRING OK, UP OK (`paring=Arming`), DUMP OK (363 B, `lt_end`), LED sem resposta |

Suite completa `pytest python_hil/tests -v`: 15 passed, 5 skipped (sem flags).
Focados: `--uart COM7` => 1 passed, 3 failed (framing, doc §7);
L3+L4 com HW => 10 passed; `--tcp` => 5 passed, 1 skipped.
Nenhum destrutivo executado (sem OTA-COMMIT/wipe/killswitch); nenhum segredo em log.

## Matriz L5 — 2026-10-24 18:30 UTC (rodada hil-subagent, com HW USB + COM7)

HW: USB AEGIS-S3-0002 enumerado (303A:AE61); UART COM7 livre (open sem
DTR/RTS PASS; `TEST_PAIRING_OPEN_300` PASS). Nenhum destrutivo executado
(sem `--confirm`; COMMIT/PUT/GEN/wipe nunca enviados); nenhum segredo em log.

| Item | Resultado | Detalhe |
|---|---|---|
| L5 offline (43 testes: opcodes, TOTP±1 RFC4226, gates, AEGN, OTA/walkaway builders, PIV/OTP formatos) | PASS | 32 passed na focada L5 (com HW); `pytest --collect-only` 43 itens |
| L5 CTAP live (GetInfo versions/pinUvAuthToken) | FAIL (HW) | INIT ok + CBOR mudo `0/64 bytes`; ver `falha-L5-usb-mudo-pos-init-2026-10-24.md` |
| L5 CTAP gates (MC/GA/ClientPIN/hmac-secret/credMgmt, CBOR minimo) | SKIP doc | device responde `status=0x14` (erro CTAP esperado sem CBOR real) |
| L5 OATH live (LIST 0x25 / CODE 0x26 read-only) | SKIP doc | device responde `status=0x01` (gate binding→UP→PIN); PUT/DELETE nunca live |
| L5 wallet live (LIST 0x36 / ADDR 0x37 slot0 read-only) | SKIP doc | device responde `status=0x01` (gate/vazio); GEN nunca live (sem `--confirm WALLET-WRITE`) |
| L5 PIV/OTP live (enumerate read-only + builders) | PASS | `probe_interfaces` + SELECT/VERIFY/GEN-AUTH/strip-FF/typer offline+builder |
| L5 mgmt pairing (TEST_PAIRING_OPEN_300 via COM7) | PASS | `pairing_open` (com `--uart COM7`) |
| L5 mgmt fw-log/AEGN/walkaway live | FAIL (HW) | mesma assinatura CBOR-mudo pos-INIT; ver falha-L5 |
| L5 mgmt OTA begin/chunk/verify sem COMMIT | SKIP doc | gate do device (`0x01`); abort de limpeza enviado; COMMIT nunca (sem `--confirm OTA-COMMIT`) |

Suite completa `pytest python_hil/tests --tb=line -q` (com HW USB presente):
`7 failed, 40 passed, 16 skipped` — os 7 FAIL sao todos a mesma assinatura
(INIT+PING ok, 2o comando CBOR/MSG mudo `0/64 bytes`: L3 get_info, L4
get_info/fwlog, L5 getinfo/fwlog/AEGN-header/walkaway-builder); todos os
SKIP sao gates documentados (`0x14` CBOR / `0x01` gate) ou sem-flag
(`--tcp`/`--uart`). Focada L5 sem `--uart`: `32 passed, 11 skipped`;
com `--uart COM7`: `16 passed, 6 skipped` (pairing PASS antes do wedge).
Multiprocesso `-n auto --test-threads=1`: N/A (xdist nao instalado).
