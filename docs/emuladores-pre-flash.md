# Emuladores pre-flash — protocolo oficial (memoria)

> Ordem obrigatoria antes de qualquer flash: host → tscircuit dummy → QEMU ESP32-S3 → (Renode opcional) → HW COM7.
> Nenhuma etapa pula a anterior. Emulador nunca conta como RealVerified (ver R11).

## 0. Mapa rapido

| Etapa | Onde roda | Prova o que | Nao prova (fica p/ HW) |
|---|---|---|---|
| 1. Host | lane, sem device | logica pura, TLV/CBOR/gates, vetores congelados | nada de device |
| 2. tscircuit dummy | E:\projetos\tscircuit\sim, sem Renode | framing CTAPHID, INIT/nonce/CID, topologia | timing, USB HID, BLE, ATECC real |
| 3. QEMU ESP32-S3 | C:\qemu-esp + scripts/qemu-s3.ps1 | firmware REAL em Xtensa emulado, UART TCP, CTAPHID serial, e2e base/pairing/all-safe | USB nativo, BLE/RSSI, BOOT fisico, timing exato |
| 4. Renode (opcional) | E:\projetos\tscircuit\sim + Renode 1.16/1.17 | boot, UART/I2C/GPIO, botoes clicaveis, ATECC virtual | Xtensa real (stub RiscV32), USB HID, timing/perifericos |
| 5. HW COM7 | device real | tudo (USB, BLE, botoes, LEDs, wipe, OTA) | — |

## 1. Host (sempre primeiro)

```powershell
cargo test --workspace
cargo clippy --all-targets -- -D warnings
python tools/app_simulator.py --self-test
python -m tools.host_sdk.cli --self-test
```
Gates: exit 0 em tudo. Sem device.

## 2. tscircuit dummy (sem Renode instalado = SKIP Renode, roda dummy)

```powershell
cd E:\projetos\tscircuit
python sim/menu.py --headless   # smoke CTAP dummy offline (run_ctap_smoke dummy PASS)
python sim/menu.py --atecc       # ATECC virtual puro (deterministico, NAO e cripto real)
```
Fontes: sim/AGENT.md, sim/README_SIM.md, sim/COM_TESTES.md. Limites honestos: CPU RiscV32 e stub (sem Xtensa LX7); USB OTG/HID real nao emulado; ATECC usa SHA-256 encadeado deterministico (bom p/ teste, nunca seguro fora da sim). Botoes clicaveis (sim/interactive/server.py + miniapp/sim-interactive.html, BOOT/RESET/CTAP INIT/ATECC Info) exigem Renode rodando — sem ele, endpoints retornam fallback.

## 3. QEMU ESP32-S3 (firmware real, sem flash)

Pré-requisitos (já instalados): C:\qemu-esp\qemu\bin\qemu-system-xtensa.exe, scripts/qemu-s3.ps1, tools/sim_ctap_init.py, tools/qemu_tcp_log.py.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/qemu-s3.ps1 -BuildImage  # monta flash 16MB dos artefatos do dia
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/qemu-s3.ps1              # sobe QEMU, UART TCP 127.0.0.1:5678
python tools/sim_ctap_init.py            # INIT/PING/TEST via TCP
python tools/app_simulator.py --self-test
# e2e com porta TCP onde o gate for simulavel (fisico => SIM-COVERED + motivo)
```
Fonte: docs/qemu-s3.md. UART virtual nunca toca as COMs. Limites: sem BLE/WiFi/RF (fail-closed), sem USB nativo (CTAPHID só UART), tick com folga.

## 4. Renode (PRIORITÁRIO p/ hardware — INSTALADO, fora do PATH)

Instalado: `C:\Program Files\Renode\Renode.exe` — usar caminho completo ou adicionar ao PATH; `py -m pip install -r sim/requirements-sim.txt` p/ pyrenode3 (opcional, sem ele cai em dummy). Com Renode: executar do diretorio E:\projetos\tscircuit `& "C:\Program Files\Renode\Renode.exe" -e '$BIN=C:\t\aegis-app-....bin include @sim/fido-s3-v3.resc'` (v3 = fêmea USB-C 16P), UART TCP :5678, monitor :9999, botoes via sim/interactive (BOOT/RESET/CTAP INIT/ATECC Info). Prioridade máxima pre-flash: boot real do binário + UART + I2C/GPIO + ATECC virtual + botoes clicaveis. Limites honestos: stub RiscV32 (sem LX7), sem timing/periféricos/USB-HID reais.

## 5. HW COM7 (gate final, apos 1-4 verdes)

`device_ops.py boot-check` ONLINE → bateria (`test_aegiskey_rust.py`, e2e phases, probes deny) → flash só com bin validado + backup. Proibido sem R11+R13: sem burn/lock, re-flash sempre possível.

## Regras

- QEMU cobre firmware real; tscircuit cobre protocolo/topologia; Renode cobre interação (quando instalado). Nenhum substitui o HW.
- ATECC virtual e dados dummy NUNCA entram em release nem em evidência de segurança.
- Botoes fisicos só existem no HW (e no Renode instalado); no QEMU use TEST_* (test-mode) como gatilho de software.
