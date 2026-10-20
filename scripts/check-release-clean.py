#!/usr/bin/env python3
"""Prova que o release (sem test-mode) NAO contem comportamento de teste.

1. Compila a lib `aegis-fido-firmware` para host SEM `test-mode`.
2. Escaneia os artefatos (rlib) por marcadores de runtime dos hooks
   (respostas que só handler test-mode emite).
3. Falha se qualquer marcador aparecer; passa limpo caso contrário.

Os NOMES dos hooks (strings inertes em test_hooks.rs) podem aparecer —
o que não pode aparecer é COMPORTAMENTO (resposta/efeito).
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CRATE = "aegis-fido-firmware"

# Respostas/efeitos que só existem dentro de #[cfg(feature = "test-mode")].
FORBIDDEN = [
    b"source=software",      # TEST_UP / TEST_PAIRING_OPEN ack
    b"up_latched",           # TEST_UP ack
    b"download_mode",        # TEST_DOWNLOAD ack (nunca em release)
    b"pairing_open",         # TEST_PAIRING_OPEN ack
    b"led_set ",             # TEST_LED_* ack (+ espaço p/ não pegar led_setting*)
    b"led_state screen=",    # TEST_LED_STATE
    b"lt_dump v=1",          # TEST_LIFETIME_DUMP
    b"binding-bypass",       # ltrace de bypass
    b"dev_master_key",       # chave-dev test-mode (nunca em release)
    b"dev_salt",             # sal dev test-mode (nunca em release)
    b"aegisdev",             # namespace dev test-mode (nunca em release)
    b"OTA_TEST_PUBKEY",      # chave OTA lab test-mode (nunca em release)
    b"TEST-OTA-KEY",         # marcador chave OTA lab (nunca em release)
]

# Arquivos-fonte autorizados a conter literais TEST_ (consts gated,
# bloco D1 gated, manifesto inerte, testes unitários).
ALLOW_TEST_LITERAL = {
    "src/test_hooks.rs",
    "src/pairing.rs",
    "src/lifetime_trace.rs",
    "src/main.rs",
}


def run(cmd):
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def main():
    print("== build lib sem test-mode (release-like) ==")
    # Lib para host, sem features (test-mode OFF por default).
    code, out = run(["cargo", "build", "-p", CRATE, "--lib", "--offline"])
    if code != 0:
        print(out[-2000:])
        print("BUILD FALHOU")
        return 1
    # Acha a rlib mais nova do crate.
    libs = sorted((ROOT / "target" / "debug").glob("libaegis_fido_firmware*.rlib"),
                  key=lambda p: p.stat().st_mtime)
    if not libs:
        print("rlib não encontrada")
        return 1
    blob = libs[-1].read_bytes()
    print("artefato: %s (%d B)" % (libs[-1].name, len(blob)))
    bad = [m for m in FORBIDDEN if m in blob]
    if bad:
        print("VAZAMENTO: %s" % [m.decode() for m in bad])
        return 1
    print("== literais TEST_ fora de lugar? ==")
    src = ROOT / "crates" / CRATE / "src"
    offenders = []
    for f in sorted(src.glob("*.rs")):
        text = f.read_text(encoding="utf-8", errors="replace")
        if '"TEST_' not in text:
            continue
        rel = "src/" + f.name
        if rel in ALLOW_TEST_LITERAL:
            continue
        # Fora da lista: só vale dentro de `mod tests` (unitário).
        head = text.split("mod tests")[0]
        if '"TEST_' in head:
            offenders.append(rel)
    # Arquivos da lista (menos o manifesto inerte) precisam citar o gate.
    for rel in sorted(ALLOW_TEST_LITERAL - {"src/test_hooks.rs"}):
        text = (src / rel[4:]).read_text(encoding="utf-8", errors="replace")
        if 'feature = "test-mode"' not in text:
            offenders.append(rel + " (sem gate visível)")
    if offenders:
        print("SUSPEITOS: %s" % offenders)
        return 1
    print("RELEASE CLEAN: nenhum comportamento de teste no artefato")
    return 0


if __name__ == "__main__":
    sys.exit(main())
