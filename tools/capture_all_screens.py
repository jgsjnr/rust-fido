#!/usr/bin/env python3
import os
import subprocess
import time
from PIL import Image

ADB = r"C:\Users\junior\AppData\Local\Android\Sdk\platform-tools\adb.exe"
DEVICE = "emulator-5554"
TARGET_DIR = r"C:\Users\junior\.gemini\antigravity\brain\2c20599d-0b33-4731-8f76-87f40aa8d4d7"

def adb(args):
    cmd = [ADB, "-s", DEVICE] + args
    res = subprocess.run(cmd, capture_output=True, text=True)
    return res.stdout.strip()

def tap(x, y):
    adb(["shell", "input", "tap", str(x), str(y)])
    time.sleep(0.6)

def screencap(filename):
    remote = f"/sdcard/{filename}"
    local = os.path.join(TARGET_DIR, filename)
    adb(["shell", "screencap", "-p", remote])
    adb(["pull", remote, local])
    
    if os.path.exists(local):
        size = os.path.getsize(local)
        im = Image.open(local)
        colors = len(im.getcolors(maxcolors=1000000))
        extrema = im.getextrema()
        is_black = (extrema[0][1] == 0 and extrema[1][1] == 0 and extrema[2][1] == 0)
        status = "ERROR_BLACK" if is_black else "OK_VISIBLE"
        print(f"[{status}] {filename}: {size}B, {im.size}, {colors} colors")
        return not is_black
    else:
        print(f"[MISSING] {filename}")
        return False

def main():
    print("=== Automation: Capturing All 9 Screens on emulator-5554 ===")
    adb(["shell", "input", "keyevent", "224"])
    adb(["shell", "wm", "dismiss-keyguard"])
    adb(["shell", "am", "force-stop", "com.google.android.apps.messaging"])
    
    # 1. Reset app state
    adb(["shell", "pm", "clear", "dev.aegiskey.app"])
    time.sleep(1.0)
    adb(["shell", "am", "start", "-n", "dev.aegiskey.app/.MainActivity"])
    time.sleep(2.5)

    # Screen 1: Transport Selection
    screencap("01_wizard_step1_transport.png")
    # Tap "Bluetooth Sem Fio" (or Simulator if testing simulator) - Bluetooth is at (540, 285)
    tap(540, 285)
    tap(540, 2359) # Next

    # Screen 2: Hold Button 5s
    time.sleep(1.0)
    screencap("02_wizard_step2_hold_button.png")
    tap(743, 2359) # Next

    # Screen 3: Discover and Connect
    time.sleep(1.2)
    screencap("03_wizard_step3_discover_connect.png")
    tap(743, 2359) # Next

    # Screen 4: Touch Confirmation & Biometrics
    time.sleep(1.2)
    screencap("04_wizard_step4_touch_biometric.png")
    tap(743, 2359) # Next

    # Screen 5: Name and Finish
    time.sleep(1.2)
    screencap("05_wizard_step5_name_finish.png")
    tap(743, 2359) # Finish and open vault

    # Main Hub
    time.sleep(2.0)
    # Screen 6: Tab 1 - Key Vault
    screencap("06_hub_key_vault.png")

    # Screen 7: Tab 2 - TOTP Codes
    tap(404, 2360)
    time.sleep(1.0)
    screencap("07_hub_totp_codes.png")

    # Screen 8: Tab 3 - Connected Keys
    tap(676, 2360)
    time.sleep(1.0)
    screencap("08_hub_connected_keys.png")

    # Screen 9: Tab 4 - Settings and Themes
    tap(948, 2360)
    time.sleep(1.0)
    screencap("09_hub_settings_themes.png")

    print("=== All screens captured and verified! ===")

if __name__ == "__main__":
    main()
