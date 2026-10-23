#!/usr/bin/env bash
# AegisKey - avaliacao de leitura com a master (sem merge). Paridade do sync-master.ps1.
# Uso: ./scripts/sync-master.sh [--gate] [--json <path>]
set -u
GATE=0; JSON=""
while [ $# -gt 0 ]; do case "$1" in --gate) GATE=1;; --json) JSON="$2"; shift;; *) echo "uso: $0 [--gate] [--json <path>]"; exit 1;; esac; shift; done
cd "$(dirname "$0")/.." || exit 1
git fetch origin main fd/finalizacao-linux 2>&1 | sed 's/^/[fetch] /'
BR=$(git branch --show-current)
AHEAD=$(git rev-list --count origin/main..HEAD); BEHIND=$(git rev-list --count HEAD..origin/main)
echo "[branch] $BR vs origin/main: ahead=$AHEAD behind=$BEHIND"
if [ "$BEHIND" -gt 0 ]; then
  echo "[WARN] origin/main tem $BEHIND commits fora da lane:"
  git log --oneline "HEAD..origin/main" | head -20 | sed 's/^/  [novo] /'
  echo "[INFO] hotspots:"; git diff --name-only HEAD origin/main | awk '
    /^crates\//{f++} /^tools\/host\//{h++} /^docs\//{d++} /^plans\//{p++}
    /^tools\//||/^scripts\//{t++} /^app-android\//{a++} {n++}
    END{printf "  firmware=%d host=%d docs=%d plans=%d tools=%d android=%d total=%d\n",f,h,d,p,t,a,n}'
else echo "[OK] lane contem 100% da origin/main (behind=0)."; fi
if [ "$GATE" -eq 1 ]; then
  cargo test -p aegis-fido-firmware --features freertos,proximity 2>&1 | grep "test result"
  cargo clippy -p aegis-fido-firmware --all-targets --features freertos,proximity -- -D warnings 2>&1 | grep -E "error|Finished"
fi
if [ -n "$JSON" ]; then printf '{"branch":"%s","ahead":%s,"behind":%s}\n' "$BR" "$AHEAD" "$BEHIND" > "$JSON"; echo "[OK] relatorio em $JSON"; fi
[ "$BEHIND" -gt 0 ] && exit 2 || exit 0
