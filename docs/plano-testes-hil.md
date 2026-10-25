# Plano de testes HIL — L0 a L4

Status: plano (nao e evidencia de execucao). Nenhuma camada substitui outra.
Ordem obrigatoria: L0 -> L1 -> L2 -> L3 -> L4. Falha em camada inferior bloqueia a superior.

## Matriz L0-L4

| Camada | Meio | O que prova | O que NAO prova |
|---|---|---|---|
| L0 host offline | `cargo test`, `cli --self-test`, `app_simulator --self-test` | logica pura: TLV BER, framing CTAPHID 64B, gates binding->UP->PIN, vetores congelados | nada de device, USB, radio ou botoes |
| L1 sim | tscircuit dummy, QEMU ESP32-S3, Renode `fido-s3-v3.resc` | protocolo/topologia (dummy), firmware real em Xtensa emulado via UART TCP `127.0.0.1:5678` (QEMU), boot+UART+GPIO+botoes clicaveis (Renode) | USB nativo, BLE/RSSI, timing exato, BOOT fisico, ATECC real |
| L2 UART | `COM7` 115200, sem DTR/RTS | serial real, INIT/PING/MSG, gates com TEST-hooks, pairing e UP | USB nativo, BLE, teclado HID, WinUSB |
| L3 USB nativo | VID `0x303A` PID `0xAE61`, 4 IFs: IF0 CTAPHID / IF1 CCID / IF2 kbd / IF3 WinUSB | enumeracao, descritores, endpoints, drivers (WinUSB no Windows) | app-via-USB fim a fim, radio, comportamento fisico completo |
| L4 app-via-USB | app real sobre USB nativo | jornada do app contra hardware real | radio/BLE, destrutivos sem backup, eFuse/lock |

Referencias de implementacao verificadas no codigo: VID/PID e 4 IFs em `usb_descriptors.rs` (`USB_VID`/`USB_PID`, IF0 HID CTAPHID, IF1 CCID bulk+int, IF2 kbd, IF3 WinUSB bulk); BOOT GPIO0 e KEY GPIO14 em `button.rs` (BOOT confirma, KEY cancela, timeout UP 15s, long-press 3s); framing 64B INIT 57B/CONT 59B e teto 7609B em `transport.py`; ordem binding->UP->PIN e `NEED_BINDING 0x05` em `gates.py`; TLV BER short/long-form e vetores em `tlv.py`/`ops.py`/`cli.py`; TEST-hooks somente `test-mode` em `test-hooks.md`.

## L0 — host offline (sem device)

Pre-condicoes: repo limpo, toolchain Rust + Python stdlib, sem hardware conectado.
Comandos:

```powershell
cargo test
cargo clippy --all-targets -- -D warnings
python -m tools.host_sdk.cli --self-test
python tools/app_simulator.py --self-test
```

Gates fisicos: nenhum (tudo simulado; UP/botoes via `MockButtonInput`).
Esperado: exit 0 em tudo; `self-test: 0 failed`.
Riscos: falso-verde (passar no host e quebrar no device); vetores congelados mascarando drift TLV/CBOR se alguem mudar `tlv.rs` sem atualizar `tlv.py`.

## L1 — sim (dummy + QEMU + Renode)

Pre-condicoes: artefatos do dia construidos; QEMU Xtensa instalado; Renode fora do PATH via caminho completo; sim sem Renode cai em dummy (SKIP honesto).
Comandos previstos `python_hil/`:

```powershell
python python_hil/hil_l1_dummy.py --headless
python python_hil/hil_l1_qemu.py --tcp 127.0.0.1:5678 --phase base
python python_hil/hil_l1_qemu.py --tcp 127.0.0.1:5678 --phase pairing
python python_hil/hil_l1_renode.py --resc sim/fido-s3-v3.resc --check boot,uart,gpio
```

Gates: no QEMU usar `TEST_UP` / `TEST_PAIRING_OPEN` (test-mode) como UP/janela de software; no Renode usar botoes clicaveis BOOT/RESET; abrir serial reseta a placa (uma sessao por fase); marca `SIM-COVERED` onde o gate for so-fisico.
Esperado: INIT/PING/TEST via TCP OK; e2e base/pairing/all-safe verde onde simulavel.
Riscos: dummy usa CPU RiscV32 e ATECC deterministico (nao e cripto real); QEMU sem USB nativo/BLE-RF e tick com folga; Renode e stub (sem LX7), sem USB-HID/timing real. Nenhum emulador conta como verificacao real.

## L2 — UART COM7 115200 sem DTR/RTS

Pre-condicoes: firmware `test-mode` (diag) flashada; bench na `COM7`; `AEGIS_PORT=COM7`; terminal 115200 8N1 sem DTR/RTS (abrir a porta reseta a placa); backup integro antes de qualquer destrutivo.
Comandos previstos `python_hil/`:

```powershell
python python_hil/hil_l2_base.py --port COM7 --phase base
python python_hil/hil_l2_pairing.py --port COM7 --phase pairing
python python_hil/hil_l2_hooks.py --port COM7 --check TEST_UP,TEST_PAIRING_OPEN,TEST_LED_STATE,TEST_USB_RECONNECT
```

Gates fisicos: BOOT GPIO0 = confirma UP; KEY GPIO14 = cancela; hold fisico 5s abre janela produto; janela software `TEST_PAIRING_OPEN` dura 60s (`TEST_PAIRING_OPEN_300` dura 300s); `TEST_UP` = 1 toque via software (latch 1x/1.5s); `TEST_LED_STATE/RED/GREEN/BLUE/OFF/RELEASE` para olhos; `TEST_USB_RECONNECT` = drop + re-enumera sem replug; `TEST_PAIRING_CLOSE` volta a `Locked`.
Esperado: T01-T10 base (gates negam: `0x01` NEED_UP, `0x05` NEED_BINDING); T11-T22 pairing com UP+janela (MC/GA, wallet `bc1q...`, OATH, PIN).
Riscos: DTR/RTS ligado reseta a placa no open; janela residual entre fases contamina `--only` isolado; destrutivos/wipe/OTA-COMMIT proibidos sem `--confirm`+backup; release (`test-mode` OFF) ignora TEST-hooks — se responder, e bug de vazamento.

## L3 — USB nativo (VID 0x303A PID 0xAE61, 4 IFs)

Pre-condicoes: L2 verde; cabo de dados (nao so-carga); firmware com USB nativo; Windows com WinUSB via MS OS 2.0 ou driver assistido; saber re-enumerar apos `TEST_USB_RECONNECT`/replug.
Comandos previstos `python_hil/`:

```powershell
python python_hil/hil_l3_enum.py --vid 0x303A --pid 0xAE61 --check 4ifs,strings,bos
python python_hil/hil_l3_ctaphid.py --usb --ping --init
python python_hil/hil_l3_ccid.py --usb --select-aid
python python_hil/hil_l3_kbd.py --usb --check-presente
python python_hil/hil_l3_winusb.py --usb --mgmt-ping
```

Gates: replug fisico ou `TEST_USB_RECONNECT`; BOOT/KEY continuam validos; LED confirma enumeracao.
Esperado: 1 device, 4 IFs (IF0 CTAPHID int 64B; IF1 CCID bulk `0x03`/`0x83`+int `0x84`; IF2 kbd int `0x85` 8B; IF3 WinUSB bulk `0x02`/`0x82`); strings AegisKey; HID report CTAPHID 34B; PING/INIT respondem por IF0.
Riscos: coex `USB>WiFi>BLE` (subir USB pode derrubar radio); hub/cabo ruim causa re-enumeracao parcial; Windows prende driver (precisa Zadig/WUDF); CCID T=1 short-APDU ate 1024B; teclado exige foco de janela no host.

## L4 — app-via-USB (HidLink INIT→CID, GetInfo/MC/GA, fw-log, PoC proxy 10.0.2.2:8888)

Pre-condicoes: L3 verde; app real (nao simulador); binding/claim feito; janela aberta quando a op exigir; proxy PoC `10.0.2.2:8888` so em lab isolado.
Comandos previstos `python_hil/`:

```powershell
python python_hil/hil_l4_app.py --usb --flow connect,init,getinfo
python python_hil/hil_l4_app.py --usb --flow creds,oath,wallet,piv
python python_hil/hil_l4_app.py --usb --flow fw-log --require-bonded
python python_hil/hil_l4_app.py --usb --flow ota --usb-only --lab-proxy 10.0.2.2:8888
```

Gates: app faz `connect_usb` -> `cmd_init` (CID novo) -> `exchange_ctaphid`; toda op privilegiada exige UP fisico (BOOT) dentro do timeout; pairing 60s (hold 5s ou TEST em lab); `fw-log` exige bonded senao `0x05`; OTA COMMIT so por USB com UP.
Esperado: GetInfo `0x00`; MC `0x01`+UP gera attestation; GA `0x02`+UP gera assertion; wallet GEN/LIST/ADDR coerentes; OATH PUT/LIST/CODE; PIV SELECT+VERIFY; `fw-log` retorna `EV=`; OTA lab ciclo BEGIN+CHUNKs+VERIFY+COMMIT+ABORT.
Riscos: BLE MTU 512B vs CTAPHID 7609B (fragmentacao/estouro); TLV BER strict (rejeita `0x80`/truncado/overrun); `NEED_BINDING 0x05` fail-closed sem claim; proxy fora do lab vaza metadados; PIN com tentativas — zerar trava (getRetries antes de D03+).

## Riscos transversais (todas as camadas)

- DTR/RTS: qualquer terminal com controle de fluxo reseta a placa no open. Fixar 115200 sem DTR/RTS.
- Coex: prioridade `USB>WiFi>BLE`; radio cai primeiro sob carga.
- MTU: BLE/controle 512B por chunk; CTAPHID monta ate 7609B; testar borda 57/59/512/7609/7610.
- TLV BER strict: `0x80` indefinido proibido; long-form `0x81`/`0x82`; truncado/overrun nega.
- Gates: ordem binding -> UP -> PIN; `NEED_BINDING 0x05`, `NEED_UP 0x01`, `NEED_PIN 0x02`; `fw-log` exige bonded; usage (LIST/CODE) exige so UP.
- Botoes: BOOT GPIO0 confirma, KEY GPIO14 cancela; debounce 50ms; UP timeout 15s; long-press 3s; so-fisico nunca e verde em sim.
- Test-mode: TEST-hooks e bypasses (`binding_bypass`, `release_bypass`, `devkey_persist`, `ota_test_key`) existem so com `test-mode`; release ignora linhas e nunca faz bypass. Vazamento = bug critico.
- Destrutivos: killswitch real (jig+HSM), factory_reset fisico, OTA-COMMIT e eFuse nunca em rotina; so com backup + confirmacao explicita.

## Template docs/falha-*.md

Copiar este bloco para `docs/falha-<ID>.md` (um arquivo por falha). Veredito unico.

```markdown
# Falha <ID> — <titulo curto>
- Camada: L0/L1/L2/L3/L4
- Comando: <comando exato + args, porta, fase>
- Esperado: <status/payload, ex. MSG 0x35 -> 0x05 NEED_BINDING>
- Obtido: <status/payload, ex. MSG 0x35 -> 0x00>
- Logs minimos: <trecho serial/USB/app, CID/op, `EV=` se houver; sem segredos, so contagens/tamanhos>
- Veredito: SIM-COVERED / HW-ONLY / BLOQUEADO
- Motivo: <por que o veredito; se BLOQUEADO, dizer o desbloqueio externo>
```

Regras do veredito: `SIM-COVERED` = so reproduz em sim, HW pendente + motivo; `HW-ONLY` = so reproduz no hardware (USB/BLE/fisico); `BLOQUEADO` = depende de externo (peca, driver, rede, permissao) — nomear o item.

## Checklist simulacao app-via-USB (o que o app faz)

Marcar cada item PASS/DIVERGENTE/FAIL/BLOCKED conforme `teste-ponta-a-ponta.md`. Simulador nao conta como app real.

- [ ] `connect_usb`: abre VID `0x303A` PID `0xAE61`, confere 4 IFs e strings.
- [ ] `cmd_init`: nonce -> CID novo; PING ecoa.
- [ ] `exchange_ctaphid`: monta INIT 57B + CONT 59B ate 7609B; rejeita 7610B.
- [ ] GetInfo (`MSG 0x04`): `0x00` + bytes; PIN getRetries leitura.
- [ ] Creds: MC `0x01`+UP gera; GA `0x02`+UP autentica; sem UP da `0x01`.
- [ ] OATH: PUT com janela+PIN; LIST/CODE so com UP; formato 6-8 digitos.
- [ ] Wallet: GEN/LIST/ADDR coerentes; rede invalida da `0x04`; sem janela da `0x05`.
- [ ] PIV: SELECT AID + VERIFY + PUT/GET/DEL/LIST; fora do escopo responde `6D00`.
- [ ] OTA USB-only: BEGIN+CHUNKs+VERIFY+COMMIT com UP, ABORT limpa; COMMIT fora do USB nega.
- [ ] `fw-log` (`MSG 0x38`): bonded retorna `EV=`; sem binding da `0x05`.
- [ ] PoC proxy `10.0.2.2:8888`: so lab isolado; registra o que passou pelo proxy sem segredos.
- [ ] Gates negativos: LIST sem UP `0x01`; GEN sem janela `0x05`; DELETE sem PIN `0x02`; rescue sem magic `0x01`.
