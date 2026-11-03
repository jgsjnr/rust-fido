#!/usr/bin/env bash
# Seletor de capability preset do firmware AegisKey (build + checagem de orcamento).
# Paridade com scripts/select-capability.ps1: menu interativo ou args sobre
# scripts/capability-catalog.json (fonte unica). Monta o `cargo +esp build`
# correto, converte ELF->.bin via esptool, compara com a factory do layout e
# RECUSA continuar em overflow (exit 1). Nunca grava hardware.
# Portavel: so caminhos relativos ao repo; TargetDir via --target-dir, env ou
# .cargo/config.toml. Requer python3 (parse do catalogo), toolchain `esp` e
# ambiente ESP-IDF exportado (export.sh) no PATH.
#   ./scripts/select-capability.sh --list-caps
#   ./scripts/select-capability.sh --cap fido-only --board devkitc --release
#   ./scripts/select-capability.sh   # menu interativo
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CATALOG="$REPO_ROOT/scripts/capability-catalog.json"
TARGET_DIR_OVERRIDE=""
PROFILE="release"
LIST_CAPS=0
LIST_POOLS=0
CAP_ARG=""
BOARD_ARG=""

usage() {
  echo "Uso:"
  echo "  select-capability.sh [--cap fido-only|fido-totp|full] [--board devkitc|tdisplay|ttgo-classic] [--release|--debug]"
  echo "                         [--list-caps] [--list-pools] [--catalog PATH] [--target-dir DIR] [--help]"
  echo ""
  echo "  Sem --cap/--board abre o menu interativo. --list-caps/--list-pools imprimem"
  echo "  o catalogo e saem. PASS continua, FAIL (overflow) sai 1 e recusa continuar."
}

while [ $# -gt 0 ]; do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --list-caps) LIST_CAPS=1 ;;
    --list-pools) LIST_POOLS=1 ;;
    --release) PROFILE="release" ;;
    --debug) PROFILE="debug" ;;
    --cap) shift; CAP_ARG="${1:?--cap exige valor}" ;;
    --board) shift; BOARD_ARG="${1:?--board exige valor}" ;;
    --catalog) shift; CATALOG="${1:?--catalog exige valor}" ;;
    --target-dir) shift; TARGET_DIR_OVERRIDE="${1:?--target-dir exige valor}" ;;
    -*) echo "[ERRO] arg desconhecido: $1" >&2; usage; exit 1 ;;
    *) echo "[ERRO] arg desconhecido: $1" >&2; usage; exit 1 ;;
  esac
  shift
done

if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERRO] EXTERNAL_BLOCKED: python3 ausente (exigido p/ ler o catalogo JSON)." >&2
  exit 2
fi
if [ ! -f "$CATALOG" ]; then echo "[ERRO] catalogo nao encontrado: $CATALOG" >&2; exit 1; fi

fmt_bytes() {
  python3 -c 'b=int(__import__("sys").argv[1]);
print(f"{b/1048576:.2f} MiB" if b>=1048576 else (f"{b/1024:.1f} KiB" if b>=1024 else f"{b} B"))' "$1"
}

list_caps() {
  echo "== CAPABILITIES (fonte: scripts/capability-catalog.json) =="
  echo "Custos flash sao ESTIMATIVAS (modulo-fonte proporcional, calibrado no build full medido);"
  echo "modulos compartilhados aparecem em cada capability (nao somar). Totais de preset sao MEDIDOS."
  python3 - "$CATALOG" <<'EOF'
import json,sys
def fmt(b):
    return ("%.2f MiB" % (b/1048576)) if b>=1048576 else (("%.1f KiB" % (b/1024)) if b>=1024 else ("%d B" % b))
d=json.load(open(sys.argv[1]))
for c in d["capabilities"]:
    cost = "(compartilhado, ver notas)" if c["flash_cost_est_bytes"]==0 else "~%s est." % fmt(c["flash_cost_est_bytes"])
    print("  %-24s presets=[%-22s] feature: %-46s %s" % (c["id"], ",".join(c["presets"]), c["feature"], cost))
EOF
}

list_pools() {
  echo "== STORAGE POOLS (fonte: scripts/capability-catalog.json) =="
  python3 - "$CATALOG" <<'EOF'
import json,sys
d=json.load(open(sys.argv[1]))
def fmt(b):
    return ("%.2f MiB" % (b/1048576)) if b>=1048576 else (("%.1f KiB" % (b/1024)) if b>=1024 else ("%d B" % b))
for p in d["pools"]:
    if p["kind"]=="budget":
        print("  [budget] %s: %s" % (p["id"], fmt(p["est_total_bytes"])))
    else:
        cons = "(sempre residente/transiente)" if not p["consumed_by"] else ",".join(p["consumed_by"])
        print("  [%s] %-18s %-34s ~%-12s consome: %s" % (p["kind"], p["id"], p["slot_limit"], fmt(p["est_total_bytes"]), cons))
EOF
}

[ "$LIST_CAPS" = 1 ] && { list_caps; exit 0; }
[ "$LIST_POOLS" = 1 ] && { list_pools; exit 0; }

cap_id="$CAP_ARG"
if [ -z "$cap_id" ]; then
  echo ""; echo "PRESET DE CAPABILITY:"
  i=1; for p in full fido-only fido-totp; do
    echo "  [$i] $p — $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["presets"][sys.argv[2]]["blurb"])' "$CATALOG" "$p")"
    i=$((i+1))
  done
  while true; do
    printf "Escolha [1-3]: "; read -r r
    case "$r" in 1) cap_id="full";; 2) cap_id="fido-only";; 3) cap_id="fido-totp";; *) continue;; esac
    break
  done
fi
if ! python3 -c 'import json,sys; assert sys.argv[2] in json.load(open(sys.argv[1]))["presets"], "bad preset"' "$CATALOG" "$cap_id" 2>/dev/null; then
  echo "[ERRO] preset invalido: use full|fido-only|fido-totp" >&2
  exit 1
fi

board_id="$BOARD_ARG"
if [ -z "$board_id" ]; then
  echo ""; echo "PLACA:"
  echo "  [1] devkitc — ESP32-S3 DevKitC-1 (2 MB flash fisica)"
  echo "  [2] tdisplay — LilyGO T-Display-S3 (16 MB flash, LCD 170x320)"
  echo "  [3] ttgo-classic — LilyGO TTGO T-Display Classic (ESP32 4 MB, LCD 135x240)"
  while true; do
    printf "Escolha [1-3]: "; read -r r
    case "$r" in 1) board_id="devkitc";; 2) board_id="tdisplay";; 3) board_id="ttgo-classic";; *) continue;; esac
    break
  done
fi
if ! python3 -c 'import json,sys; assert sys.argv[2] in json.load(open(sys.argv[1]))["boards"], "bad board"' "$CATALOG" "$board_id" 2>/dev/null; then
  echo "[ERRO] placa invalida: use devkitc|tdisplay|ttgo-classic" >&2
  exit 1
fi
if ! python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert sys.argv[3] in d["presets"][sys.argv[2]]["boards"], "board not allowed"' "$CATALOG" "$cap_id" "$board_id" 2>/dev/null; then
  echo "[ERRO] preset '$cap_id' so serve a placa: devkitc (diet = devkitc/2MB; display exige full)." >&2
  exit 1
fi

# --- detalhe includes/excludes + pools (gerado do catalogo) ---
python3 - "$CATALOG" "$cap_id" "$board_id" "$PROFILE" <<'EOF'
import json,sys
d=json.load(open(sys.argv[1])); cap,board,prof=sys.argv[2],sys.argv[3],sys.argv[4]
p=d["presets"][cap]; b=d["boards"][board]
def fmt(n):
    return ("%.2f MiB" % (n/1048576)) if n>=1048576 else (("%.1f KiB" % (n/1024)) if n>=1024 else ("%d B" % n))
caps={c["id"]:c for c in d["capabilities"]}
print("\nPreset: %s  |  Placa: %s  |  Profile: %s" % (p["name"], b["name"], prof))
print("Inclui:")
for i in p["includes"]:
    c=caps[i]
    cost="(custo contado no grupo)" if c["flash_cost_est_bytes"]==0 else "~%s est." % fmt(c["flash_cost_est_bytes"])
    print("  + %-24s [%s] %s" % (i, c["feature"], cost))
if p["excludes"]:
    print("Exclui (0x06 UNSUPPORTED_FEATURE fail-closed onde for comando):")
    for i in p["excludes"]:
        print("  - %s" % i)
res=[q for q in d["pools"] if q["kind"]=="resident" and (q["always"] or any(x in p["includes"] for x in q["consumed_by"]))]
tot=sum(q["est_total_bytes"] for q in res)
print("Pools NVS residentes do preset:")
for q in res:
    print("  %-16s %-30s ~%s" % (q["id"], q["slot_limit"], fmt(q["est_total_bytes"])))
bud=b["storage_bytes"]
pct=100.0*tot/bud
print("  NVS residente: ~%s / %s (%.1f%%) %s" % (fmt(tot), fmt(bud), pct, "PASS" if tot<=bud else "WARN: excede o storage do layout!"))
stg=[q for q in d["pools"] if q["id"]=="ota-staging"][0]
if stg["est_total_bytes"]<=bud:
    print("  OTA staging (transiente): ~%s cabe no storage PASS" % fmt(stg["est_total_bytes"]))
else:
    print("  OTA staging (transiente): ~%s NAO cabe no storage (%s) WARN: no layout 2MB o fluxo precisa transmitir por streaming, sem estagiar a imagem cheia." % (fmt(stg["est_total_bytes"]), fmt(bud)))
print("  Layout: %s | factory 0x%X (%s)" % (b["partition_file"], bud and b["factory_bytes"], fmt(b["factory_bytes"])))
if p.get("goal_bytes"):
    print("  Meta do preset: <=%s (info; o gate e a factory)" % fmt(p["goal_bytes"]))
EOF

if [ -z "$CAP_ARG" ] || [ -z "$BOARD_ARG" ]; then
  printf "Confirmar build com este orcamento? [S/n] "; read -r ok
  case "$ok" in ""|s|S|y|Y) ;; *) echo "Cancelado."; exit 1;; esac
fi

# --- ambiente ESP (usa o env atual/export.sh; sem paths hardcoded) ---
CARGO_BIN="$(command -v cargo || command -v cargo.exe || true)"
if [ -z "$CARGO_BIN" ]; then echo "[ERRO] EXTERNAL_BLOCKED: cargo ausente no PATH." >&2; exit 2; fi
if ! "$CARGO_BIN" +esp --version >/dev/null 2>&1; then
  echo "[ERRO] EXTERNAL_BLOCKED: toolchain \`esp\` ausente (\`cargo +esp --version\` falhou). Instale via espup." >&2
  exit 2
fi
if [ -z "${IDF_PATH:-}" ] && ! command -v idf.py >/dev/null 2>&1; then
  echo "[ERRO] EXTERNAL_BLOCKED: ambiente ESP-IDF nao exportado (IDF_PATH vazio e idf.py fora do PATH). Rode \`source \$IDF_PATH/export.sh\` (v5.3.1 shell-local)." >&2
  exit 2
fi
export ESP_IDF_SDKCONFIG_DEFAULTS="$REPO_ROOT/sdkconfig.defaults.esp32s3"
export CARGO_WORKSPACE_DIR="$REPO_ROOT"
export ESP_IDF_TOOLS_INSTALL_DIR="fromenv"

resolve_target_dir() {
  if [ -n "$TARGET_DIR_OVERRIDE" ]; then echo "$TARGET_DIR_OVERRIDE"; return; fi
  cfg="$REPO_ROOT/.cargo/config.toml"
  if [ -f "$cfg" ]; then
    td="$(sed -n 's/^[[:space:]]*target-dir[[:space:]]*=[[:space:]]*"\(.*\)"[[:space:]]*$/\1/p' "$cfg" | head -n1)"
    if [ -n "$td" ] && [ -d "$td" ]; then echo "$td"; return; fi
  fi
  echo "$REPO_ROOT/target"
}
TARGET_DIR="$(resolve_target_dir)"
echo "TargetDir: $TARGET_DIR"
if [ -n "$TARGET_DIR_OVERRIDE" ]; then export CARGO_TARGET_DIR="$TARGET_DIR_OVERRIDE"; fi

FEATURES="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); p=d["presets"][sys.argv[2]]; b=d["boards"][sys.argv[3]]; print(b["board_feature"] + ("," + ",".join(p["extra_features"]) if p["extra_features"] else ""))' "$CATALOG" "$cap_id" "$board_id")"
TARGET_TRIPLE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["boards"][sys.argv[2]]["target"])' "$CATALOG" "$board_id")"
CHIP="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["boards"][sys.argv[2]]["chip"])' "$CATALOG" "$board_id")"
BIN_PREFIX="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["boards"][sys.argv[2]]["bin_prefix"])' "$CATALOG" "$board_id")"
IS_DIET="$(python3 -c 'import json,sys; print("1" if json.load(open(sys.argv[1]))["presets"][sys.argv[2]]["diet"] else "")' "$CATALOG" "$cap_id")"
BIN_NAME="${BIN_PREFIX}$([ -n "$IS_DIET" ] && echo "-$cap_id").bin"

if [ "$board_id" = "ttgo-classic" ]; then export CARGO_PROFILE_RELEASE_OPT_LEVEL=z; fi
echo ""
echo "Build: "$CARGO_BIN" +esp build -p aegis-fido-firmware --target $TARGET_TRIPLE --$PROFILE --no-default-features --features $FEATURES -Zbuild-std=std,panic_abort"
if [ "$PROFILE" = "release" ]; then PROF_FLAG="--release"; else PROF_FLAG=""; fi
# shellcheck disable=SC2086
"$CARGO_BIN" +esp build -p aegis-fido-firmware --target "$TARGET_TRIPLE" $PROF_FLAG \
  --no-default-features --features "$FEATURES" -Zbuild-std=std,panic_abort
echo "[OK] firmware ELF compilado."

# --- elf2image ---
ELF_PATH="$TARGET_DIR/$TARGET_TRIPLE/$PROFILE/aegis-fido-firmware"
OUT_BIN="$TARGET_DIR/$BIN_NAME"
if [ ! -f "$ELF_PATH" ]; then echo "[ERRO] ELF nao encontrado: $ELF_PATH" >&2; exit 1; fi
if command -v esptool >/dev/null 2>&1; then ESPTOOL="esptool";
elif command -v esptool.exe >/dev/null 2>&1; then ESPTOOL="esptool.exe";
elif command -v esptool.py >/dev/null 2>&1; then ESPTOOL="esptool.py";
else ESPTOOL="python3 -m esptool"; fi
echo "Convertendo ELF->bin ($CHIP)..."
# shellcheck disable=SC2086
$ESPTOOL --chip "$CHIP" elf2image --flash_size 4MB -o "$OUT_BIN" "$ELF_PATH" || {
  echo "[ERRO] EXTERNAL_BLOCKED: esptool falhou/ausente (PATH, IDF Scripts ou python3 -m esptool)." >&2; exit 2; }
if command -v sha256sum >/dev/null 2>&1; then SHA="$(sha256sum "$OUT_BIN" | cut -d' ' -f1)";
elif command -v shasum >/dev/null 2>&1; then SHA="$(shasum -a 256 "$OUT_BIN" | cut -d' ' -f1)";
else SHA="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$OUT_BIN")"; fi
echo "$SHA  $(basename "$OUT_BIN")" > "$OUT_BIN.sha256"
SIZE="$(wc -c < "$OUT_BIN" | tr -d ' ')"
FACTORY="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["boards"][sys.argv[2]]["factory_bytes"])' "$CATALOG" "$board_id")"
GOAL="$(python3 -c 'import json,sys; g=json.load(open(sys.argv[1]))["presets"][sys.argv[2]].get("goal_bytes"); print(g if g else "")' "$CATALOG" "$cap_id")"
PARTFILE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["boards"][sys.argv[2]]["partition_file"])' "$CATALOG" "$board_id")"
echo ""
echo "SHA256: $SHA"
echo "SIZE:   $SIZE bytes ($(fmt_bytes "$SIZE"))"
echo "BUDGET: $FACTORY bytes ($(fmt_bytes "$FACTORY")) [factory $PARTFILE]"
if [ -n "$GOAL" ] && [ "$SIZE" -gt "$GOAL" ]; then
  echo "WARN: acima da meta do preset ($(fmt_bytes "$GOAL"))."
fi
if [ "$SIZE" -gt "$FACTORY" ]; then
  echo "FAIL: imagem ($SIZE B) nao cabe na factory ($FACTORY B). Recusando continuar." >&2
  exit 1
fi
echo "PASS: $(basename "$OUT_BIN") cabe na factory ($(fmt_bytes "$SIZE") de $(fmt_bytes "$FACTORY"))."
echo ""
echo "Flash continua manual (exige placa + aprovacao):"
echo "  Layout: $PARTFILE (factory offset 0x10000)"
echo "  ./scripts/build-esp32s3-devkitc.sh -Flash   # exemplo (placa devkitc, quando existir)"
exit 0