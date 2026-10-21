#!/usr/bin/env bash
# AegisKey — bring-up no Linux (espelho de scripts/*.ps1).
# Uso:
#   ./scripts/linux-bringup.sh                 # gates host + build release S3
#   ./scripts/linux-bringup.sh --diag          # + build diag (test-mode,debug-terminal)
#   ./scripts/linux-bringup.sh --flash         # + flash release em /dev/ttyUSB0
#   PORT=/dev/ttyACM0 ./scripts/linux-bringup.sh --flash --diag
# Requisitos: rust (stable + toolchain esp via espup), python3,
#   esptool (pip install esptool), ~/export-esp.sh (gerado pelo espup).
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${PORT:-/dev/ttyUSB0}"
CHIP="esp32s3"
TARGET="xtensa-esp32s3-espidf"
OFFSET="0x10000"
BAUD="921600"
DO_DIAG=0
DO_FLASH=0
for a in "$@"; do
  case "$a" in
    --diag) DO_DIAG=1 ;;
    --flash) DO_FLASH=1 ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "FALTA: $1"; exit 1; }; }
need cargo; need rustc; need python3

if [ -f "$HOME/export-esp.sh" ]; then
  # shellcheck disable=SC1090
  source "$HOME/export-esp.sh"
  echo "[OK] export-esp.sh aplicado."
else
  echo "[WARN] ~/export-esp.sh ausente; rode 'espup install -t esp32,esp32s3' primeiro."
fi
export IDF_PATH="${IDF_PATH:-$HOME/.embuild/espressif/esp-idf/v5.3.1}"
export ESP_IDF_VERSION="${ESP_IDF_VERSION:-v5.3.1}"
export ESP_IDF_SDKCONFIG_DEFAULTS="$REPO/sdkconfig.defaults.esp32s3"

cd "$REPO"
echo "=== gates host ==="
cargo test --workspace
cargo clippy --all-targets -- -D warnings
python3 tools/test_aegiskey_rust.py
python3 tools/test_killswitch.py
python3 tools/test_ota_server_smoke.py
python3 tools/host/win/test_proximity_agent.py
python3 tools/host/linux/test_proximity_agent.py
python3 tools/host/macos/test_proximity_agent.py
python3 tools/live_monitor.py --self-test
python3 tools/app_simulator.py --self-test

build_fw() { # $1 = features(csv) $2 = out bin name
  cargo +esp build -p aegis-fido-firmware --target "$TARGET" --release \
    --no-default-features --features "$1" -Zbuild-std=std,panic_abort
  ELF="$(cargo metadata --format-version 1 --no-deps 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/$TARGET/release/aegis-fido-firmware"
  BIN="$REPO/target/$2"
  python3 -m esptool --chip "$CHIP" elf2image --flash_size 4MB -o "$BIN" "$ELF"
  python3 -c "import hashlib; d=open('$BIN','rb').read(); print('BIN $BIN', len(d), 'SHA256', hashlib.sha256(d).hexdigest())"
}
echo "=== build release S3 ==="
build_fw "board-devkitc" "aegis-app-esp32s3-devkitc.bin"
if [ "$DO_DIAG" = "1" ]; then
  echo "=== build diag (test-mode,debug-terminal) ==="
  build_fw "board-devkitc,test-mode,debug-terminal" "aegis-app-esp32s3-diag.bin"
fi
if [ "$DO_FLASH" = "1" ]; then
  [ -e "$PORT" ] || { echo "Porta $PORT ausente. Conecte a placa (dmesg | grep tty)."; exit 2; }
  BIN="$REPO/target/aegis-app-esp32s3-devkitc.bin"
  [ "$DO_DIAG" = "1" ] && BIN="$REPO/target/aegis-app-esp32s3-diag.bin"
  python3 -m esptool --chip "$CHIP" --port "$PORT" --baud "$BAUD" write_flash "$OFFSET" "$BIN"
  echo "[OK] flash em $PORT. Monitor: python3 tools/live_monitor.py --port $PORT"
fi
echo "BRINGUP OK."
