import os
import time
from PIL import Image

TARGET_DIR = r'C:\Users\junior\.gemini\antigravity\brain\2c20599d-0b33-4731-8f76-87f40aa8d4d7'
SHOTS = [
    ('06_hub_key_vault.png', 'Cofre Físico Atualizado (Hardware, Chips e Cartões)'),
    ('10_key_detail_passkey.png', 'Gestão Personalizada de Passkey FIDO / Assinatura'),
    ('11_key_detail_crypto_wallet.png', 'Gestão Personalizada de Smartcard PIV / Carteira Cripto'),
    ('07_hub_totp_codes.png', 'Central de Códigos TOTP / HOTP Hardware'),
    ('09_hub_settings_themes.png', 'Central de Gestão de Hardware & Ajustes'),
]

print("=" * 75)
print("  AUDITORIA DE QUALIDADE DOS SCREENSHOTS - WAVE 11C")
print("=" * 75)

all_passed = True
now = time.time()

for fname, desc in SHOTS:
    fpath = os.path.join(TARGET_DIR, fname)
    if not os.path.exists(fpath):
        print(f"[FALHA] Arquivo não encontrado: {fname}")
        all_passed = False
        continue
    
    mtime = os.path.getmtime(fpath)
    age_s = now - mtime
    sz = os.path.getsize(fpath)
    
    img = Image.open(fpath)
    w, h = img.size
    gray = img.convert('L')
    pixels = list(gray.getdata())
    mean_val = sum(pixels) / len(pixels)
    var_val = sum((p - mean_val) ** 2 for p in pixels) / len(pixels)
    std_val = var_val ** 0.5
    
    # Validações
    dim_ok = (w == 1080 and h == 2400)
    std_ok = (std_val >= 10.0)
    mean_ok = (10.0 <= mean_val <= 245.0)
    recent_ok = (age_s < 3600)  # Menos de 1 hora
    
    passed = dim_ok and std_ok and mean_ok and recent_ok
    status_tag = "APROVADO [VISIBLE OK]" if passed else "REPROVADO"
    if not passed:
        all_passed = False
        
    print(f"\n* {fname} ({desc}):")
    print(f"  - Resolução: {w}x{h} (esperado 1080x2400) -> {'OK' if dim_ok else 'ERRO'}")
    print(f"  - Luminância Média: {mean_val:.2f} | Desvio Padrão: {std_val:.2f} -> {'OK' if (std_ok and mean_ok) else 'ERRO'}")
    print(f"  - Tamanho: {sz:,} bytes ({sz / 1024:.1f} KB) | Idade: {age_s:.1f}s")
    print(f"  - Status: {status_tag}")

print("\n" + "=" * 75)
print(f"RESULTADO GERAL: {'TODOS OS 5 SCREENSHOTS APROVADOS COM SUCESSO!' if all_passed else 'FALHA NA AUDITORIA'}")
print("=" * 75)
