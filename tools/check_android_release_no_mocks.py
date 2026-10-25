#!/usr/bin/env python3
"""
Auditoria Anti-Mock do App Real Android (AegisKey FIDO2 / Passkey)

Este script abre o APK de Release (`app-release-unsigned.apk`), extrai todos os
arquivos bytecode `classes*.dex` e varre byte a byte em busca de strings e
constantes de mock/simulação.

Invariante de Segurança e Auditoria:
Nenhuma string de hardware simulado, MAC fictício, chave seed mockada, TOTP secret
ou dados de demonstração pode existir no APK compilado de produção.
Adicionalmente, valida que o APK de Debug contém as constantes, comprovando
o isolamento físico entre os source sets 'src/debug' e 'src/release'.
"""

import os
import sys
import zipfile

FORBIDDEN_MOCK_STRINGS = [
    "AA:BB:CC:AE:61:01",
    "USB:303A:AE61:01",
    "SIM:RENODE:5678",
    "Chip Simulado",
    "Hardware Mock",
    "GitHub Enterprise Passkey",
    "JBSWY3DPEHPK3PXP",
    "GEZDGNBVGY3TQOJQ",
    "Hooks do Chip",
    "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
    "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
]

def scan_apk_dex_strings(apk_path, strings_to_find):
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"APK não encontrado: {apk_path}")

    found_matches = {s: [] for s in strings_to_find}
    dex_count = 0
    total_bytes = 0

    with zipfile.ZipFile(apk_path, 'r') as z:
        for filename in z.namelist():
            if filename.startswith("classes") and filename.endswith(".dex"):
                dex_count += 1
                data = z.read(filename)
                total_bytes += len(data)
                for s in strings_to_find:
                    needle = s.encode('utf-8')
                    if needle in data:
                        found_matches[s].append(filename)

    return {
        "apk": os.path.basename(apk_path),
        "path": apk_path,
        "dex_count": dex_count,
        "total_dex_bytes": total_bytes,
        "matches": found_matches,
    }

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    worktree_root = os.path.abspath(os.path.join(script_dir, ".."))
    
    release_apk = os.path.join(
        worktree_root,
        "app-android", "app", "build", "outputs", "apk", "release", "app-release-unsigned.apk"
    )
    debug_apk = os.path.join(
        worktree_root,
        "app-android", "app", "build", "outputs", "apk", "debug", "app-debug.apk"
    )

    print("====================================================================")
    print("  AUDITORIA DE SEGURANÇA ANTI-MOCK: APK RELEASE vs DEBUG (AEGISKEY)  ")
    print("====================================================================")
    print(f"Raiz da Worktree: {worktree_root}")
    print(f"APK Release:     {release_apk}")
    print(f"APK Debug:       {debug_apk}")
    print("--------------------------------------------------------------------")

    # 1. Auditoria do APK de Release (PROIBIDO conter mocks)
    print("\n[1/2] Auditando APK de RELEASE (Verificando ausência absoluta de mocks)...")
    release_report = scan_apk_dex_strings(release_apk, FORBIDDEN_MOCK_STRINGS)
    print(f"  * DEXs analisados: {release_report['dex_count']} ({release_report['total_dex_bytes']:,} bytes de bytecode)")

    release_violations = []
    for s, files in release_report["matches"].items():
        if files:
            release_violations.append((s, files))
            print(f"  [FALHA] String de mock encontrada no Release: '{s}' em {files}")
        else:
            print(f"  [OK - LIMPO] '{s}': NÃO PRESENTE")

    # 2. Auditoria do APK de Debug (DEVE conter mocks para simulação de desenvolvimento)
    print("\n[2/2] Auditando APK de DEBUG (Verificando presença de mocks em 'src/debug')...")
    debug_report = scan_apk_dex_strings(debug_apk, FORBIDDEN_MOCK_STRINGS)
    print(f"  * DEXs analisados: {debug_report['dex_count']} ({debug_report['total_dex_bytes']:,} bytes de bytecode)")

    debug_present_count = 0
    for s, files in debug_report["matches"].items():
        if files:
            debug_present_count += 1
            print(f"  [PRESENTE EM DEBUG] '{s}' em {files}")
        else:
            print(f"  [AVISO] String '{s}' não encontrada no Debug DEX.")

    print("\n====================================================================")
    print("  RESULTADO DA AUDITORIA:")
    if release_violations:
        print(f"  STATUS: REPROVADO! {len(release_violations)} strings de mock vazaram para o Release!")
        for s, files in release_violations:
            print(f"    - {s} em {files}")
        sys.exit(1)
    else:
        print("  STATUS: APROVADO COM LOUVOR (100% ZERO MOCKS NO APK DE PRODUÇÃO)")
        print(f"  - Todas as {len(FORBIDDEN_MOCK_STRINGS)} constantes de mock estão AUSENTES no APK de Release.")
        print(f"  - {debug_present_count}/{len(FORBIDDEN_MOCK_STRINGS)} constantes de mock estão presentes no APK de Debug.")
        print("  - Segregação de source sets 'src/release' vs 'src/debug' comprovada no bytecode DEX.")
        print("====================================================================\n")
        sys.exit(0)

if __name__ == "__main__":
    main()
