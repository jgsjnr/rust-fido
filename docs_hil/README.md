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
| `docs_hil/falha-L5-usb-mudo-pos-init-2026-10-24.md` | Falha real L5 (INIT+PING ok, CBOR/MSG mudo persistente; retry nao recuperou; re-ocorrencia pos-210e980 §7) |
| `docs_hil/falha-L2-uart-wedge-invalid-channel-2026-10-24.md` | Falha real L2 (INIT UART -> ERROR 0x0B persistente + TEST_* mudo; ponto fixo de desalinho no firmware pre-fix; USB saudavel em T0) |
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

## Matriz L0-L5 — 2026-10-24 (rodada pos-210e980, HEAD da983da)

HW da rodada: USB AEGIS-S3-0002 enumerado (303A:AE61 `count=1`); UART COM7
livre (ponte CP210x `VID_10C4&PID_EA60`, 115200, open exclusivo ok).
Firmware gravado no device = pre-fix (sem MAPA-FIX §2/§3; reflash pendente).
Nenhum destrutivo executado (sem `--confirm`); nenhum segredo em log
(so contagens + bytes de erro de protocolo).

### L0 (offline/vetores/self-tests)

| Item | Resultado | Detalhe |
|---|---|---|
| `cargo test --workspace` | FLAKE (timing) | default: 1 FAIL intermitente `freertos_sched::demo_freertos_end_to_end` (`presses>=1`/`drained==3` sob carga paralela; PASS isolado e PASS com `--no-fail-fast`: firmware-lib 481 passed; soma ~818 passed, 0 failed) |
| `cargo clippy --all-targets -- -D warnings` | PASS | zero warnings |
| `tools/host_sdk/cli.py --self-test` | PASS | `0 failed` (gates_order, rescue_frame, no_hardcoded_secrets, port_default, ota_vectors, f3_vectors) |
| `tools/app_simulator.py --self-test` | PASS | `24/24 passed` |
| `tools/emulate_app_session.py` (novo) | PASS | `29/29` (S1-S5; UP foi SIMULADO — referencia offline app-via-servidor, nao evidencia HW) |
| `tools/usb_ctap_probe.py --help` (novo) | SEM FLAG `--help` | sem `--live` roda self-test fake local: `USB_INIT_OK` + `USB_PING_OK` + `USB_PROBE_OK`, exit 0; `--live` (pyusb real) NAO executado nesta rodada |

### L1-L5 (pytest: collect + offline + HW)

| Item | Resultado | Detalhe |
|---|---|---|
| `pytest --collect-only` | 63 itens | sem erro de import |
| suite sem flags, device saudavel (T0) | 47 passed, 16 skipped, 0 failed | baseline pos-MAPA-FIX reproduzida |
| suite sem flags, apos wedge (T3) | **7 failed, 40 passed, 16 skipped** | todos os 7 = INIT ok + 2o comando CBOR/MSG mudo `0/64 bytes` (retry+reenumerar NAO recupera): L3 get_info, L4 get_info+fwlog, L5 ctap-getinfo + 3 mgmt; ver `falha-L5-usb-mudo-pos-init-2026-10-24.md` §7 |
| L1 `--tcp 127.0.0.1:5678` | 5 passed, 1 skipped | tcp-live SKIP (nada escuta :5678; QEMU mudo + Renode travado seguem externally blocked, ver falha-L1) |
| L2 `--uart COM7` | **1 failed, 3 passed** | open/init_ping/get_info PASS; `test_mode_gates` FAIL com assinatura NOVA: INIT -> ERROR `0xBF/0x0B` persistente (7/7) + TEST_* mudo (so ticks); ver `falha-L2-uart-wedge-invalid-channel-2026-10-24.md` |
| L3+L4 focados (T0) | 10 passed | INIT->CID, PING eco, GetInfo, probes, fw-log livre, wallet LIST read-only |
| L5 focados (T0) | 22 passed, 9 skipped | gates documentados (`0x14` CBOR minimo, `0x01` OATH/WALLET sem binding); GEN/PUT/COMMIT nunca live (sem `--confirm`) |
| BLE scan 5 s | SKIP | `BLE_SCAN_COUNT=0` (sem radio/dispositivo 0xFFFD) |
| WiFi AP 192.168.4.1 | SKIP | `HwMissingError` (fora do SSID AegisKey-XXXX) |

Multiprocesso E2E (`-n auto --test-threads=1`): N/A (xdist/test-threads nao
instalados). Novidades do HEAD incorporadas: `emulate_app_session.py` como
referencia offline (tabela L0 acima); parse BLE `[op,status,pay]` (44702f0) e
mapa F2/F3 sem contraparte HIL — documentados como gap no MAPA-FIX §7
(exigem radio BLE / rota USB-Linux + reflash; sem HW nao ha o que espelhar).

## Matriz L0-L5 — 2026-10-24 (rodada desta lane: fixes host-prováveis, HW wedged)

HW: USB 303A:AE61 `AEGIS-S3-0002` enumerado (`count=1`); COM7 ponte CP210x
presente. Firmware do device = pré-fix (MAPA-FIX §2/§3 + §9 ainda não
reflasheados). Nenhum destrutivo (sem `--confirm`); nenhum segredo em log.
Fixes desta worktree provados no host (cargo + offline); HW pede passo físico.

### L0 (host)

| Item | Resultado | Detalhe |
|---|---|---|
| `cargo fmt --check` | PASS | após `cargo fmt` |
| `cargo check --workspace --all-targets` | PASS | real |
| `cargo clippy -p aegis-fido-firmware -p aegis-fido-usb --all-targets -- -D warnings` | PASS | zero warnings (real) |
| `cargo clippy --workspace` | BLOQUEADO (pré-existente) | `uniffi-bridge` gerado quebra (`OtpAuthParsed` ausente; crate intocada) |
| `cargo test -p core+usb+firmware+sdk` | PASS (real) | core 108+9+1, firmware-lib 484, usb 94, sdk 51 (+5 testes novos §9) |
| `cargo test --workspace` | BLOQUEADO (mesma causa) | `uniffi-bridge` pré-existente |
| `pytest offline` | PASS (real) | 33 passed (vetores/framing/loopback) |
| `sim_pilot --self-test` | PASS (simulado) | loopback; camada, não HW |

### L1-L5 (pytest com HW presente e wedged)

| Item | Resultado | Detalhe |
|---|---|---|
| suite com HW | **5 failed, 42 passed, 16 skipped** | INIT-ok + 2º CBOR/MSG mudo `0/64 bytes` (retry+reenumerar+20 s NÃO recupera); ver falha-L5 §8 |
| L2 `--uart COM7` | **3 failed, 1 passed** | INIT → `0xBF/0x0B` persistente (purge/retry host sem efeito no FIFO do device); ver falha-L2-wedge §7 |
| L1 `--tcp 127.0.0.1:5678` | 5 passed, 1 skipped | tcp-live SKIP (nada escuta; holder listado, nenhum kill; QEMU/Renode externally blocked) |
| BLE / WiFi | SKIP | sem radio 0xFFFD / fora do SSID (HwMissingError) |

Prescrição física (comandos prontos, NÃO executados sem confirmação):
power-cycle/re-plug → canário `test_l3_usb_get_info` → reflash test-mode
(`.\scripts\build-esp32s3-devkitc.ps1 -Test` + `-Flash -Port COM7` confirmado)
→ repetir suite (alvo 47 passed + L2 4 passed). Ver MAPA-FIX §9.
## Matriz L0-L5 — 2026-10-24 (rodada reflash autorizado, bin `board-devkitc` 6573736B, sem test-mode)

Flash: tentativa-script FALHOU (sem soft-entry + `no_reset` sem sync);
retry esptool reset padrao OK (2.013.888 B @0x10000, 17,8 s, hash ok).
Boot `16:50:16` (bin novo); canario L3 PASS 0,16 s.

| Item | Resultado | Detalhe |
|---|---|---|
| Build `-Test` | PASS | firmware-lib 484 passed; release 5m19s; bin+SHA+size acima |
| L0 `cargo test -p core+usb+firmware+sdk` | PASS | 802 passed, 0 failed (1 ignored); workspace bloqueado p/ `uniffi-bridge` pre-existente |
| Suite sem flags (device saudavel) | **3 failed, 46 passed, 14 skipped** | vitimas estaveis INIT-mute: oath_challenge, wallet_list, wallet_addr (ponto alterna INIT/MSG; rerun sob carga: 6/43/14; pos-reboot: 3/46/14) |
| Suite `--uart COM7` | **4 failed, 49 passed, 10 skipped** | trio USB + L2 gates FAIL por desenho (bin sem test-mode); com device degradado: 9/44/10 |
| L3 canario / L4 app / L5 CTAP+mgmt | PASS c/ ressalva | GetInfo/fw-log/PING ok isolados; gates `0x14`/`0x01` com semantica; fw-log livre |
| Wedge progressivo | RESIDUAL (falha real) | USB+UART degradam sob trafego ate travar (`0x0B` UART, 2o-mudo USB); reboot limpa; ver falha-L5 §9, falha-L2 §8 |
| L2 TEST_* / LED | N/A por desenho | bin sem test-mode ignora TEST_*; validar §1/§3 exige reflash `freertos+test-mode` (nao executado) |

Estado: **flash OK; 0-failed NAO atingido** (residuais acima + prescricao no MAPA-FIX §10).
Proxima rodada comeca por power-cycle (device deixado wedged-parcial).
## Matriz L0-L5 - 2026-10-24 (rodada reflash `freertos+test-mode` AUTORIZADO)

Aprovacao: reflash freertos+test-mode + sonda (usuario). Power-cycle presumido;
COM7 sem disputa (open exclusivo ok, sem holder, sem WinError 5).
Bin: `C:\t\aegis-app-freertos-s3-testmode.bin` 2.011.696 B SHA256
`E9ACDA958D579A6EB4661E55C0CE222DDFBA381D526FC57808D65F5B84924622`
(proveniencia `C:\t\aegis-app-da983da1.bin`). Flash esptool reset padrao
0x10000 OK 18,0 s hash verificado (`C:\t\logs\flash-freertos-testmode-COM7-20261024.log`).
Desvio: script testmode sem `-OnlyFlash`; device sem test-mode inviabilizava
`TEST_DOWNLOAD`+`no_reset` (precedente MAPA-FIX p.10/p.12).

| Item | Resultado | Detalhe |
|---|---|---|
| Host `cargo test -p firmware --features test-mode` | PASS | 504 passed, 0 failed |
| Build freertos+testmode | PASS | ELF 51,6 s; bin+SHA+size acima; factory ok |
| L2 `--uart COM7` | **4 passed** | INIT/PING/GetInfo/gates (alvo; era 1F/3P) |
| L3+L4 focados | **10 passed** | INIT->CID, PING, GetInfo, probes, fw-log, wallet LIST |
| Suite sem flags | **47 passed, 16 skipped, 0 failed** | alvo exato reproduzido com bin novo |
| Suite `--uart COM7` | **3 failed, 49 passed, 11 skipped** | wedge MSG sob trafego (fwlog/backup/proximity live_usb); os 3 passam isolados pos-reboot (3 passed 0,29 s) |
| LED fix p.11 no HW | CURADO (ack) / visual pendente | `TEST_LED_ON` = so ack sem RED; R/G/B/OFF ok; pairing BLE adv on; UP latch; `TEST_LED_STATE screen=freertos`; olhos = REAL_IMPLEMENTED_NOT_RUN |
| Wedge MSG acumulado | RESIDUAL (falha real) | INIT/PING ok + MSG `0x90` mudo; `TEST_USB_RECONNECT` nao recupera; reboot RTS limpa; ver MAPA-FIX p.12.5 |

Nenhum destrutivo (sem `--confirm`); nenhum segredo em log.

## Rodada 2026-10-24 18:20 (bin 923FCC86, stall-TX-nonblock + LED-ON-ack)
- Build+flash: OK (2011968 B, esptool direto COM7 EXIT 0, log flash-freertos-testmode-COM7-20261024-1820.log).
- L2 --uart COM7: 4/4 passed. BLE live: scan HIT 3C:84:27:C7:17:7A (AegisKey/fffd), GATT FFF1-FFF4 OK, ping SKIP gate 0x01.
- Suite --uart COM7: 54 passed, 13 skipped, 7 failed (todas USB GetInfo/fw-log multi-pacote 0/64 bytes; UART viva; residual L5-usb-mudo, nao curado).
- LED: TEST_LED_ON ack `led` sem latch (contrato PingAck); cores fisicas REAL_IMPLEMENTED_NOT_RUN (sem observador).
## Matriz L0-L6 - 2026-10-24 (rodada subagent verif, HEAD da983da, bin freertos+test-mode stall-TX-nonblock + LED-ON-ack gravado)

HW: USB 303A:AE61 AEGIS-S3-0002 enumerado; COM7 CP210x presente, sem holder (open exclusivo ok, sem WinError 5).
Bin do device = freertos+test-mode (L2 4/4 prova test-mode ativo). Nenhum destrutivo (sem --confirm); nenhum segredo em log (so contagens).

### L0 (host)

| Item | Resultado | Detalhe |
|---|---|---|
| `cargo test -p core+usb+firmware --lib` | PASS | core 108 passed + firmware 484 passed + usb 99 passed = 691 passed, 0 failed |
| `cargo clippy -p firmware -p usb --all-targets -- -D warnings` | PASS | exit 0, zero warnings |
| `tools/host_sdk/cli.py --self-test` | PASS | 0 failed (gates_order, rescue, ota_vectors, f3_vectors) |
| `tools/app_simulator.py --self-test` | PASS | 24/24 passed |
| `tools/emulate_app_session.py` | PASS | 29/29 (S1-S5; UP SIMULADO, referencia offline) |

### L1-L6 (pytest, collect + offline + HW)

| Item | Resultado | Detalhe |
|---|---|---|
| `pytest --collect-only` | 74 itens | sem erro de import (baseline 63 + 11 L6-BLE expandidos) |
| suite sem flags | 7 failed, 49 passed, 18 skipped | os 7 = mesma assinatura residual INIT-ok + 2o CBOR/MSG mudo 0/64 bytes (L3 get_info, L4 get_info+fwlog, L5 ctap-getinfo + 3 mgmt); ver falha-L5-usb-mudo-pos-init-2026-10-24.md; canario isolado pos-suite ainda FAIL (wedged, pede power-cycle) |
| L1 `--tcp 127.0.0.1:5678` | 5 passed, 1 skipped | tcp-live SKIP (nada escuta :5678) |
| L2 `--uart COM7` | 4 passed | alvo exato reproduzido (era baseline 4/4) |
| L6 BLE `--ble-addr 3C:84:27:C7:17:7A` (janela TEST_PAIRING_OPEN_300 aberta via COM7, `pairing_open` ok) | 8 passed, 3 skipped | scan/GATT/ping live; 3 SKIP = gates documentados (0x01 presence / 0x05 binding) |
| suite `--uart COM7` | 7 failed, 54 passed, 13 skipped | mesmos 7 USB residuais; UART viva (L2 4/4 dentro da suite) |
| Multiprocesso `-n auto --test-threads=1` | N/A | xdist/test-threads nao instalados (`unrecognized arguments`) |

Comparacao com baseline (47 passed/16 skipped/0 failed, L2 4/4): L2 4/4 REPRODUZIDO; offline +2 passed (novos testes L6); sem-flags 49P/18S + 7F residuais (nao novos - mesma assinatura L5-usb-mudo; sem arquivo falha-* novo). L2 sugere device saudavel no UART; USB pede power-cycle + rerun canario antes de reflash.

## Matriz L0-L6 - 2026-10-24 (rodada subagent fd/hil-usb-tests: reboot RTS NAO limpou o wedge USB)

HW: USB 303A:AE61 AEGIS-S3-0002 enumerado (`count=1`); COM7 CP210x presente, sem holder (sem WinError 5).
Bin do device = freertos+test-mode (L2 4/4 prova test-mode ativo). Nenhum destrutivo (sem `--confirm`); nenhum segredo em log (so contagens + `cmd`/`op`).

| Item | Resultado | Detalhe |
|---|---|---|
| Reboot 1: `esptool --port COM7 --after hard_reset chip_id` | OK (EXIT 0) | `ESP32-S3 ... MAC 3c:84:27:c7:17:78`, `Hard resetting via RTS pin...`; USB re-enumerou `count=1` |
| Reboot 2: `esptool --port COM7 --before default_reset --after hard_reset chip_id` | OK (EXIT 0) | mesma saida/MAC; sem flash, sem download-mode, sem DTR-toggle no harness |
| Boot +5-10 s | UART sem banner (esperado tardio) | `sim_pilot --uart COM7` => `boot-check UART falhou bytes=0` (banner ONLINE&ACTIVE ja passou; abrir apos boot nao captura banner) |
| Canario `test_l3_usb_get_info` isolado (3x: pos-reboot1, +idle, pos-reboot2) | **FAIL (3/3)** | mesma assinatura: INIT ok (`USB_RESPONSE bytes=17`, `CID_ALLOCATED`) + MSG `cmd=90` mudo `0/64 bytes`, retry+re-enumerar+INIT novo nao recupera |
| L2 `--uart COM7` | **4 passed** | alvo 4/4 REPRODUZIDO (open/init_ping/get_info/gates); UART 100% viva |
| Suite sem flags (2 rodadas p/ flakes) | **6 failed, 47 passed, 21 skipped** / **7 failed, 46 passed, 21 skipped** | fails = mesma assinatura residual (L3 get_info; L4 get_info+fwlog; L5 ctap-getinfo + 3 mgmt fwlog/AEGN-header/walkaway); `test_l4_app_fwlog_usb_free` alterna (flake); passed bate o alvo 47 |
| Multiprocesso `-n auto --test-threads=1` | N/A | `unrecognized arguments: -n --test-threads=1` (exit 4); xdist/test-threads nao instalados |
| L6 BLE em janela (`TEST_PAIRING_OPEN_300`) | NAO executado | gated no canario PASS (canario FAIL); sem `--ble-addr` os testes L6 skipam elegante na suite sem flags |

Leitura: **residual persiste (falha real)** — desta vez o reboot RTS/esptool (que limpou 2x no precedente MAPA-FIX p.12.5) **NAO recuperou o path USB CBOR/MSG**; UART prova device vivo e saudavel. Workaround restante = **power-cycle / re-plug fisico** do AEGIS-S3-0002 (fora do alcance desta lane), depois canario isolado. Ver `falha-L5-usb-mudo-pos-init-2026-10-24.md` §10. Nenhum destrutivo; nenhum segredo em log.
## Matriz L0-L6 - 2026-10-24 22:22 UTC (rodada pos-RE-PLUG FISICO AEGIS-S3-0002, lane fd/hil-usb-tests)
HW: USB 303A:AE61 AEGIS-S3-0002 enumerado (count=1, MI_00); COM7 CP210x presente.
Bin do device = freertos+test-mode (presumido, sem reflash nesta rodada). Nenhum destrutivo (sem --confirm); nenhum segredo em log (so contagens + cmd/op).
| Item | Resultado | Detalhe |
| Canario test_l3_usb_get_info -v | FAIL residual NAO curado | INIT ok (USB_CONNECTED, SENT cmd=86 bytes=8, RESPONSE bytes=17, CID_ALLOCATED) + MSG cmd=90 mudo 0/64 bytes; RETRY_REENUMERATE + INIT novo nao recupera; TimeoutError op=get_info 0/64 bytes; duracao 4.92 s |
| Suite sem flags / --uart COM7 / L6 BLE em janela | NAO executados gated | prescricao: so prosseguir Se canario PASS; canario FAIL bloqueia suites (alvos 47/16/0 e L2 4/4 nao re-tentados) |
| USB enumerate | OK | USB_ENUM_COUNT=1 AegisKey S3 Authenticator 303A:AE61 |
| COM7 | OK | Silicon Labs CP210x presente |
| Multiprocesso -n auto --test-threads=1 | N/A | unrecognized arguments (xdist nao instalado); rodar serial |
| Collect-only | 74 itens | sem erro de import (baseline 63 + 11 L6-BLE) |
Leitura: residual persiste apos RE-PLUG FISICO; mesma assinatura falha-L5 (INIT ok + 2o CBOR/MSG mudo); reboot RTS ja havia falhado 2/2; agora re-plug fisico tambem falha 1/1. Wedge exclusivo do path USB CBOR/MSG. Ver falha-L5 S11. Proximo: power-cycle com descarga / troca cabo-porta / reflash; depois canario isolado.
## Matriz L0-L6 - 2026-10-24 19:54 UTC (rodada flash-bloqueado COM7, bin novo 3F6528EB pronto)
HW: USB 303A:AE61 AEGIS-S3-0002 enumerado (count=1); COM7 CP210x presente MAS ocupada (WinError 5, handle.exe sem match, retry 5 s + 20 s sem liberar).
Bin gravado no device = anterior (pre-3F6528EB, wedged USB CBOR/MSG). Bin novo 3F6528EB (2013168 B) pronto em C:\t, NAO flasheado. Nenhum destrutivo (sem --confirm); nenhum segredo em log.
| Item | Resultado | Detalhe |
| Build freertos-s3-testmode | PASS | EXIT 0, SHA 3F6528EB (diferente de 923FCC86 OK), 2013168 B, log build-freertos-testmode-20261024-1948.log |
| Host | PASS | usb 100 passed, firmware 484 passed, check freertos/test-mode PASS (proximity ctr privado pre-existente, sem edicao) |
| Flash COM7 esptool reset-padrao | BLOQUEADO | WinError 5 persistente, EXIT 2, log flash-freertos-testmode-COM7-20261024-1954.log |
| Canario PING-200B | FAIL (esperado pre-flash) | INIT CID 0x0B ok + PING 4 B PASS, PING-200B 4 pkts 0/64 bytes |
| Canario get_info | FAIL residual | INIT ok + MSG 0x90 mudo 0/64 bytes, retry+reenumerar nao recupera (falha-L5) |
| Suite sem flags | 7 failed, 46 passed, 21 skipped | mesma assinatura 7 residuais USB |
| L2 --uart COM7 | 4 failed | HwMissingError COM7 inacessivel (alvo 4/4 NAO atingido) |
| L6 BLE | 6 passed, 5 skipped | scan live SKIP sem radio 0xFFFD |
Leitura: build OK prova fix no host; flash+validacao gated em COM7 livre + power-cycle. Proximo: liberar COM7, `esptool --chip esp32s3 --port COM7 --baud 921600 --before default_reset --after hard_reset write_flash 0x10000 C:\t\aegis-app-freertos-s3-testmode.bin`, canarios, suites (alvos PING-200B PASS, GetInfo PASS, 47+/16/0, L2 4/4).

## Matriz L0-L6 - 2026-10-24 ~20:20 (2a rodada flash-bloqueado COM7, bin 3F6528EB pronto)
HW: USB 303A:AE61 AEGIS-S3-0002 enumerado (Composite + HID FIDO MI_00 + CCID MI_01); COM7 CP210x presente MAS ocupada (WinError 5 T0 + retry +20 s, esptool EXIT 2).
Bin gravado no device = anterior (pre-3F6528EB, wedged USB CBOR/MSG). Bin novo 3F6528EB (2013168 B, SHA confere) pronto em C:\t, NAO flasheado. Nenhum destrutivo (sem --confirm); nenhum segredo em log.
| Item | Resultado | Detalhe |
| Flash COM7 esptool reset-padrao 921600 | BLOQUEADO (2a vez) | WinError 5 persistente T0 + retry +20 s, EXIT 2, log flash-freertos-testmode-COM7-20261024-2030.log; ver falha-flash-COM7-ocupada-2026-10-24-2030.md (recorrencia do doc 2001) |
| Canario USB INIT+PING-4B | PASS (esperado pre-flash) | INIT ok CID 0x42, PING 4 B eco ok |
| Canario USB PING-200B | FAIL (esperado pre-flash) | `USB_SENT cmd=81 pkts=4 bytes=200` -> `0/64 bytes`; fix TX multipacote ainda nao no device |
| Canario USB get_info | FAIL residual | INIT ok + MSG `cmd=90` mudo `0/64 bytes`, RETRY_REENUMERATE + INIT novo nao recupera (falha-L5) |
| Suite sem flags | 7 failed, 46 passed, 21 skipped | mesma assinatura 7 residuais USB (L3 get_info, L4 get_info+fwlog, L5 ctap-getinfo + 3 mgmt) |
| L2 --uart COM7 | 4 failed | HwMissingError COM7 inacessivel (GetCommState failed; alvo 4/4 NAO atingido) |
| L6 BLE (sem --ble-addr, fora de janela) | 6 passed, 5 skipped | live skipam elegante sem radio/janela (TEST_PAIRING_OPEN_300 gated no UART) |
| Multiprocesso -n auto --test-threads=1 | N/A | xdist nao instalado; rodar serial |
Leitura: flash+validacao seguem gated em COM7 livre + power-cycle. Proximo (mesmo do doc 2001): liberar COM7, `esptool --chip esp32s3 --port COM7 --baud 921600 --before default_reset --after hard_reset write_flash 0x10000 C:\t\aegis-app-freertos-s3-testmode.bin`, canarios PING-200B + get_info (alvos PASS), suites (alvos 47+/16/0, L2 4/4).

## Matriz stress — 2026-10-24 (lane fd/hil-usb-tests, device com bin 3F6528EB saudavel)

HW: USB 303A:AE61 AEGIS-S3-0002 enumerado; COM7 CP210x livre (`COM7_OPEN_OK`);
bridge externo RELIGADO e concorrente via USB_HID (`connected=true status=online`
em `:5678/bridge/info`). Bin do device = 3F6528EB (freertos+test-mode).
Nenhum destrutivo (sem `--confirm`); nenhum segredo em log (so contagens + cmd/op).
Sem edicao de codigo nesta rodada (so execucao + docs_hil).

| Rodada | Resultado | Detalhe |
|---|---|---|
| Canario pre-stress `test_l3_usb_get_info` | PASS (0,91 s) | INIT->CID + MSG `cmd=90` com resposta; device saudavel em T0 |
| R1 suite sem flags | **53 passed, 21 skipped, 0 failed** (49,9 s) | verde, igual ao pos-flash 53/21/0 |
| R2 suite sem flags | **3 failed, 50 passed, 21 skipped** (63,9 s) | `backup_envelope_header` + `proximity_walkaway_builder` + 1 do mesmo trio (fwlog/getinfo); assinatura conhecida INIT-ok + 2o CBOR/MSG mudo `0/64 bytes` |
| R3 suite sem flags (`-rf`) | **7 failed, 46 passed, 21 skipped** (80,3 s) | set residual exato conhecido: L3 get_info, L4 get_info+fwlog, L5 ctap-getinfo + 3 mgmt (fwlog/backup/walkaway); mesma assinatura falha-L5 |
| Retry canario pos-R3 (1x) | **FAIL (wedge confirmado)** | INIT ok (`CID_ALLOCATED`, `USB_SENT cmd=90`) + MSG mudo `0/64 bytes`; retry+reenumerar interno nao recuperou |
| R4 suite `--uart COM7` | **61 passed, 13 skipped, 0 failed** (74,7 s) | VERDE — wedge drenado entre canario e R4 (idle + retry de re-enumeracao do canario); inclui L2 4/4 (UART viva) |
| Canario pos-R4 | PASS (0,93 s) | device entregue SAUDAVEL, sem wedge |
| Multiprocesso `--test-threads=1` | N/A | `error: unrecognized arguments: --test-threads=1` (exit 4); xdist/test-threads nao instalados; E2E serial |

### Sims de app (jornada sem celular)

| Item | Resultado | Detalhe |
|---|---|---|
| `tools/emulate_app_session.py` | PASS | `29/29` (S1-S5; UP SIMULADO, referencia offline) |
| `tools/app_simulator.py --self-test` | PASS | `24/24 passed` |
| `python_hil/app_usb_sim.py --self-test` | PASS | 5 grupos (framing_usb, wallet_vectors, vendor_range, rescue_fwlog_ops, no_hw_claim), `0 failed` |

### LED ack-level (via UART COM7, test-mode)

| Comando | Resposta textual | Detalhe |
|---|---|---|
| `TEST_LED_RED` / `GREEN` / `BLUE` / `OFF` / `ON` | `led` (3 B cada) | acks de politica; `ON` = ack sem latch (contrato PingAck, precedente MAPA-FIX p.12.6) |
| Visual fisico | REAL_IMPLEMENTED_NOT_RUN | sem observador diante do device; acks provam politica, matriz HW segue pendente de olhos |

### Veredito estabilidade

Progressao 0 -> 3 -> 7 fails sob trafego acumulado confirma o residual
conhecido (falha-L5-usb-mudo: INIT/PING ok + path CBOR/MSG trava; UART 100%
viva). Novidade desta rodada: wedge DRENADO sem power-cycle (canario retry +
idle entre R3 e R4; R4 61/13/0 verde + canario final PASS). Sem assinatura
nova => **nenhum arquivo falha-*.md criado** (R2/R3 = re-ocorrencia da
assinatura documentada). Concorrencia do bridge USB_HID nao impediu verdes
(R1 e R4). Se wedge voltar e retry+idle nao drenar, prescricao: power-cycle /
re-plug fisico (fora do alcance desta lane — reportar, nao executar).

## Matriz destrutivos AUTORIZADOS - 2026-10-25 (AEGIS-S3-0002, sem wipe/commit; detalhe em relatorio-destrutivos-2026-10-25.md)
| Passo | Resultado | Detalhe |
|---|---|---|
| 1 BACKUP | PARTIAL-OK | UART GetInfo 0x00/479 B + fw-log 0x00/660 B (hashes em C:\t\logs\hil-backup-20261025.txt); wallet 0 slots; keys 132 B presentes; OATH gated; DKEK/AEGN sem opcode wire (Unsupported) |
| 2 OTA | BLOQUEADO (sem commit) | BEGIN 0x01 USB+UART (freertos sem dispatch OTA; engine responde invalid-command); falta dispatch+reflash+sig-release+version-maior; log C:\t\logs\hil-ota-20261025.txt |
| 3 WIPE/RECOVERY | NAO EXECUTADO (bloqueado) | Reset 0x30 (janela 10 s); reboot esptool ok mas COM7 com bridge (WinError 5, nao tocado); UP sem maos/COM7 impossivel; rescue-wipe so RAM + exige PIN; NVS intacta |
| 4 POWER-LOSS | GAP | requer corte fisico, nao simulavel por software |
| Estado final | SAUDAVEL | bin 3F6528EB, suite 60 passed/21 skipped/0 failed pos-reboot; wedge residual sob sondas (re-ocorrencia falha-L5) |

## Matriz janela fisica AUTORIZADA - 2026-10-25 (bin 578450D8, detalhe em relatorio-janela-fisica-2026-10-25.md)
| Passo | Resultado | Detalhe |
|---|---|---|
| 1 BUILD | PASS | testmode EXIT 0, 2024352 B, SHA 578450D8 (difere 3F6528EB) |
| 2 Bridge | PAUSADO/RELIGADO | PIDs re-descobertos 3x; COM7 livre p/ UART; religado (21004+41444) online |
| 3 FLASH | PASS | esptool 0x10000 18,2 s hash ok; L2 4/4 + canario USB PASS |
| 4 BACKUP-EXPORT 0x3A | PASS | pairing+UP+PIN1234; 0x01 0x00/744 B + 0x02 0x00/79 B, header AEGN/0x01 |
| 5 OTA COMMIT | BLOQUEADO sem commit | BEGIN real 0x04 over-budget (2 MB > 896 KB); BEGIN pequeno 0x00; VERIFY 0x04; ABORT 0x00 |
| 6 WIPE+RECOVERY | PARCIAL+recovery | Reset 0x00 na janela; PIN/binding/wallet zerados; key_slots 132 B sobrevive (0x03 NoSlot); CLAIM+PIN+MC/GA PASS |
| 7 FINAL | VERDE | bridge online; canario PASS; L2 4/4 PASS |
Estado final: bin 578450D8 saudavel; NVS com PIN teste+binding+MC e2e; chaves pre-wipe preservadas (divergencia).

## Matriz janela fisica FINAL AUTORIZADA (retry) - 2026-10-25 (bin 3C509444, detalhe em relatorio-janela-fisica-3C509444-2026-10-25.md)
| Passo | Resultado | Detalhe |
|---|---|---|
| 1 Bridge | JA PARADO (nada morto) | busca fresca 0 proc; COM7 livre; USB 303A:AE61 OK |
| 2 FLASH | PASS | esptool 0x10000 EXIT 0, 2030448 B, SHA 3C509444, 17,8 s hash ok; boot-check ONLINE |
| 3 RESET-WIPE | PASS (wipe real) | CBOR 0x07 0x00/1 B em 0,4 s; KEY/WALLET/OATH_LIST 0x00/0 B; GEN5 0x00; credMgmt 0x14 vazio |
| 4 BACKUP-EXPORT 0x3A | PASS c/ ressalva | PIN1234 (set 0x00+token 0x00/36 B); 0x01 0x00/95 B AEGN/0x01; 0x02 0x04 absent-store (OATH vazio) |
| 5 OTA BLE->USB | BLOQUEADO sem commit | BLE BEGIN/CHUNK/VERIFY/ABORT 0x01 presence (UP fisico, sem maos); COMMIT-USB+UP 0x04 motivado |
| 6 RE-PROV+SUITES | VERDE c/ wedge recuperado | CLAIM 0x00 + PIN 1234; offline 62/19/0; --uart L2 4/4; full 60+66 pass, 7+2 wedge -> 7/7+2/2 pos-reboot; L6 BLE 8/3/0 |
| 7 FINAL | VERDE | bridge PID 8236 mesma cmdline --port COM7; /bridge/info connected=true UART online |
Estado final: bin 3C509444 saudavel; NVS com PIN 1234 teste + binding claimed + 1 chave slot 5 (prova GEN); wallet/OATH vazios.
