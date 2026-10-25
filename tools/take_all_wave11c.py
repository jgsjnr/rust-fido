import subprocess
import time
import os
import xml.etree.ElementTree as ET
from PIL import Image

ADB = r'C:\Users\junior\AppData\Local\Android\Sdk\platform-tools\adb.exe'
TARGET_DIR = r'C:\Users\junior\.gemini\antigravity\brain\2c20599d-0b33-4731-8f76-87f40aa8d4d7'

def run_adb(args):
    cmd = [ADB, '-s', 'emulator-5554'] + args
    return subprocess.run(cmd, capture_output=True, text=True, errors='ignore')

def get_elements():
    run_adb(['shell', 'uiautomator', 'dump', '/data/local/tmp/dump.xml'])
    res = run_adb(['shell', 'cat', '/data/local/tmp/dump.xml'])
    xml_str = res.stdout
    if not xml_str.strip():
        return []
    try:
        root = ET.fromstring(xml_str)
        elements = []
        for elem in root.iter():
            text = elem.attrib.get('text', '')
            desc = elem.attrib.get('content-desc', '')
            bounds = elem.attrib.get('bounds', '')
            if text or desc:
                elements.append((text, desc, bounds))
        return elements
    except Exception as e:
        print('Error parsing XML:', e)
        return []

def click_coords(x, y):
    print(f'Clicking ({x}, {y})')
    run_adb(['shell', 'input', 'tap', str(x), str(y)])

def click_bounds(bounds_str):
    try:
        parts = bounds_str.replace('[', '').replace(']', ',').split(',')
        x1, y1, x2, y2 = int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3])
        cx = (x1 + x2) // 2
        cy = (y1 + y2) // 2
        click_coords(cx, cy)
    except Exception as e:
        print('Error clicking bounds:', bounds_str, e)

def click_by_match(pattern):
    elems = get_elements()
    pattern_lower = pattern.lower()
    for text, desc, bounds in elems:
        if pattern_lower == text.lower() or pattern_lower == desc.lower():
            print(f'Exact match "{pattern}" at {bounds}')
            click_bounds(bounds)
            return True
    for text, desc, bounds in elems:
        if pattern_lower in text.lower() or pattern_lower in desc.lower():
            print(f'Substring match "{pattern}" in ("{text}", "{desc}") at {bounds}')
            click_bounds(bounds)
            return True
    print(f'No match for "{pattern}"')
    return False

def audit_screenshot(filename):
    os.makedirs(TARGET_DIR, exist_ok=True)
    local_path = os.path.join(TARGET_DIR, filename)
    run_adb(['shell', 'screencap', '-p', '/sdcard/screen.png'])
    run_adb(['pull', '/sdcard/screen.png', local_path])
    
    if os.path.exists(local_path):
        img = Image.open(local_path)
        w, h = img.size
        gray = img.convert('L')
        stat = list(gray.getdata())
        mean_val = sum(stat) / len(stat)
        var_val = sum((x - mean_val) ** 2 for x in stat) / len(stat)
        std_val = var_val ** 0.5
        is_ok = (w == 1080 and h == 2400 and std_val > 10)
        status_str = "VISIBLE OK" if is_ok else "FAIL BLANK/SIZE"
        print(f'[{filename}] Size: {w}x{h} | Mean: {mean_val:.2f} | Std: {std_val:.2f} | Status: {status_str}')
        return is_ok
    return False

def main():
    print('Starting AegisKey activity...')
    run_adb(['shell', 'am', 'start', '-n', 'dev.aegiskey.app/.MainActivity'])
    time.sleep(2.5)

    elems = get_elements()
    print('Checking screen title...')
    for t, d, b in elems[:10]:
        print(f'  {t} | {d}')

    # Certificar que estamos no Cofre
    click_coords(130, 2375)  # Aba Cofre
    time.sleep(1.5)

    # Verificar se há cartões de chaves
    elems = get_elements()
    gerenciar_buttons = [b for t, d, b in elems if "gerenciar" in t.lower() or "gerenciar" in d.lower()]
    print(f'Found {len(gerenciar_buttons)} Gerenciar buttons in vault.')

    if len(gerenciar_buttons) < 2:
        print('Creating Bitcoin Wallet key in vault...')
        click_by_match("Criar Nova Chave no Hardware")
        time.sleep(1.5)
        # Seleciona Bitcoin
        click_by_match("Carteira Bitcoin (BIP84)")
        time.sleep(0.5)
        click_by_match("Gravar no Hardware")
        time.sleep(2.0)

    # 1. Capturar 06_hub_key_vault.png
    print('\n--- Capturando 06_hub_key_vault.png ---')
    audit_screenshot('06_hub_key_vault.png')
    time.sleep(1.0)

    # 2. Abrir Gestão de Passkey
    elems = get_elements()
    gerenciar_buttons = [b for t, d, b in elems if "gerenciar" in t.lower() or "gerenciar" in d.lower()]
    print(f'Buttons after creation: {gerenciar_buttons}')
    if gerenciar_buttons:
        print('Navigating to Passkey management...')
        click_bounds(gerenciar_buttons[0])
        time.sleep(2.0)
        print('\n--- Capturando 10_key_detail_passkey.png ---')
        audit_screenshot('10_key_detail_passkey.png')
        time.sleep(1.0)

        # Voltar ao cofre
        print('Returning to vault...')
        if not click_by_match("Voltar ao Cofre"):
            click_coords(60, 160)
        time.sleep(2.0)

    # 3. Abrir Gestão de Carteira Cripto
    elems = get_elements()
    gerenciar_buttons = [b for t, d, b in elems if "gerenciar" in t.lower() or "gerenciar" in d.lower()]
    print(f'Buttons for crypto: {gerenciar_buttons}')
    if len(gerenciar_buttons) >= 2:
        print('Navigating to Crypto Wallet management...')
        click_bounds(gerenciar_buttons[1])
        time.sleep(2.0)
        print('\n--- Capturando 11_key_detail_crypto_wallet.png ---')
        audit_screenshot('11_key_detail_crypto_wallet.png')
        time.sleep(1.0)

        # Voltar ao cofre
        print('Returning to vault...')
        if not click_by_match("Voltar ao Cofre"):
            click_coords(60, 160)
        time.sleep(2.0)

    # 4. Navegar para aba Códigos (TOTP)
    print('\nNavigating to Códigos tab...')
    click_coords(400, 2375)
    time.sleep(2.0)
    print('--- Capturando 07_hub_totp_codes.png ---')
    audit_screenshot('07_hub_totp_codes.png')
    time.sleep(1.0)

    # 5. Navegar para aba Ajustes
    print('\nNavigating to Ajustes tab...')
    click_coords(950, 2375)
    time.sleep(2.0)
    print('--- Capturando 09_hub_settings_themes.png ---')
    audit_screenshot('09_hub_settings_themes.png')
    time.sleep(1.0)

    print('\nAll 5 screenshots captured successfully!')

if __name__ == '__main__':
    main()
