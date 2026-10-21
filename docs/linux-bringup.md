# Continuar no Linux — bring-up

## 1. Preparar a máquina

```bash
# toolchain ESP (uma vez)
espup install -t esp32,esp32s3   # gera ~/export-esp.sh
pip install esptool bleak pyserial   # bleak/agents-BLE, pyserial/monitor
sudo usermod -aG dialout $USER       # acesso serial (relogin)
```

Regra udev (AegisKey S3 `303a:ae61`), `/etc/udev/rules.d/99-aegiskey.rules`:

```
SUBSYSTEM=="tty", ATTRS{idVendor}=="303a", ATTRS{idProduct}=="ae61", MODE="0660", GROUP="dialout", SYMLINK+="aegiskey"
```

## 2. Mapeamento Windows → Linux

| Windows | Linux |
|---|---|
| COM7 (UART CP210x) | `/dev/ttyUSB0` (ou `ttyACM0`; confira `dmesg \| grep tty`) |
| `C:\t` (target-dir) | `./target` (padrão; `.cargo/config.toml` do repo aponta `C:/t` — no Linux o cargo usa `./target` automaticamente? **Não**: o `target-dir` está fixo. Ajuste local: `CARGO_TARGET_DIR=$PWD/target cargo ...` ou edite `.cargo/config.toml`. O script `linux-bringup.sh` usa `cargo metadata` e funciona com qualquer target-dir) |
| `.\scripts\*.ps1` | `./scripts/linux-bringup.sh` |
| `python` | `python3` |
| `COM7` nos tools | `--port /dev/ttyUSB0` |

## 3. Bring-up em um comando

```bash
./scripts/linux-bringup.sh                 # gates + build release
./scripts/linux-bringup.sh --diag          # + build diag test-mode
PORT=/dev/ttyUSB0 ./scripts/linux-bringup.sh --flash        # flash release
PORT=/dev/ttyUSB0 ./scripts/linux-bringup.sh --flash --diag # flash diag
```

Equivalências manuais: `cargo test --workspace`,
`cargo clippy --all-targets -- -D warnings`,
`cargo +esp build -p aegis-fido-firmware --target
xtensa-esp32s3-espidf --release --no-default-features --features
board-devkitc -Zbuild-std=std,panic_abort`,
`python3 -m esptool --chip esp32s3 --port /dev/ttyUSB0 --baud 921600
write_flash 0x10000 target/aegis-app-esp32s3-devkitc.bin`.

## 4. Ritual de pareamento no hardware (60s)

```bash
python3 tools/app_simulator.py --port /dev/ttyUSB0 --test-mode
# menu 11 = TEST_PAIRING_OPEN (diag) — ou hold BOOT 5s (qualquer build)
# menu scan no app Android em 60s → UP no BOOT no prompt → verde sólido
python3 tools/live_monitor.py --port /dev/ttyUSB0 --self-test
```

Sem monitor serial aberto durante o pareamento pelo app: abrir a porta
reseta a placa e mata a janela (parece flicker/sumiço).

## 5. Agents de proximidade no Linux

```bash
python3 tools/host/linux/proximity_agent.py --self-test
python3 tools/host/linux/proximity_agent.py --fob-id AA:BB:CC:DD:EE:FF
```

Ver `tools/host/linux/README.md` (BlueZ, bonding, unit systemd).
