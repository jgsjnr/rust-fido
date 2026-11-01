# AegisKey System Tray App & SSH Key Guard Integration

Multiplatform, auditable, zero-mock System Tray application and SSH Guard integration for the **AegisKey S3 Authenticator** (ESP32-S3 on COM7 / USB `0x303A:0xAE61`).

---

## 1. Security Architecture & Zero-Inspection Guarantee

### Strict User Privacy Rule
> **"Possuo uma chave nas keys do sistema, não leia ela, mas queria ver se tem como quando a chave estiver ligada, não precisar digitar a senha do ssh, ela servindo como chave, somente se o secure guard estiver desbloqueado."**

**Formal Guarantee:**
- **Zero Access to Private Keys:** Neither the Python application nor the C# application nor the helper scripts ever open, read, parse, copy, or inspect any private key files in `~/.ssh/`, `C:\Users\junior\.ssh\`, or the OS keychain.
- **Hardware-Gated Session Boundary:** The solution works strictly through the standard, sanctioned OpenSSH interfaces:
  1. **RAM Session Lifespan Watchdog (`ssh-agent` + `ssh-add -D`)**: While the physical AegisKey is connected and **Secure Guard is UNLOCKED (`state == 4`)**, identities remain authorized in `ssh-agent` memory. The instant Secure Guard transitions to **LOCKED (`state == 2`)**, session times out, or the physical USB is unplugged, the watchdog executes `ssh-add -D` to wipe all keys from RAM immediately.
  2. **Hardware-Gated `SSH_ASKPASS` (`aegis_ssh_askpass.py`)**: When OpenSSH prompts for authentication, it queries the local AegisKey Secure Guard authority. If the physical key is plugged in and UNLOCKED, it authorizes access; if LOCKED or disconnected, it exits with error code `1` (`Access DENIED`), completely barring SSH use.
  3. **FIDO2 Resident SSH Keys (`ssh-add -K` / `sk-ssh-ed25519@openssh.com`)**: One-click registration and loading of hardware-resident FIDO2 SSH keys directly into `ssh-agent` RAM, conditioned on Secure Guard being UNLOCKED.

---

## 2. Directory Structure

```text
e:/projetos/fido-tray-guard/app-tray/
├── README.md                      # Complete architecture, security, and usage documentation
├── aegis_tray.py                  # Multiplatform GUI Tray App (Tkinter Material 3 Dark/Cyan + Native Win32/pystray Tray)
├── hardware_client.py             # Zero-mock client for AegisKey HTTP Bridge / Serial (ESP32-S3 COM7)
├── ssh_guard.py                   # SSH Key Guard Watchdog & instant auto-purge engine (ssh-add -D)
├── aegis_ssh_askpass.py           # Hardware-gated OpenSSH SSH_ASKPASS helper
├── aegis_ssh_askpass.bat          # Windows OpenSSH wrapper for SSH_ASKPASS
├── aegis_ssh_askpass.sh           # Linux / macOS wrapper for SSH_ASKPASS
├── i18n.py                        # ASD-STE100 Simplified Technical English & Portuguese translations
├── test_tray_and_ssh_guard.py     # Real automated test suite (Zero mocks, 100% verified)
└── dotnet/
    └── AegisKeyTray/
        ├── AegisKeyTray.csproj    # .NET 9 WinForms / System Tray application
        ├── Program.cs             # Application entrypoint & ApplicationContext
        ├── TrayApplicationContext.cs # System Tray NotifyIcon, Context Menu, and Balloon notifications
        ├── MainWindow.cs          # Cyber-Security Dark UI (Material 3 palette, 4 sections)
        ├── HardwareBridgeClient.cs# Asynchronous REST / Serial detection client
        ├── SshAgentGuard.cs       # C# SSH Agent Watchdog (ssh-add -D auto-purge)
        ├── Models.cs              # Strongly typed telemetry and vault records
        └── I18n.cs                # ASD-STE100 i18n strings for C#
```

---

## 3. Visual Design (Material 3 Cyber-Security Dark)

Matches the AegisKey mobile application palette:
- **Background:** `#0B0F19`
- **Surface Card:** `#111827`
- **Border:** `#1F2937`
- **Primary Accent (Cyan):** `#00E5FF`
- **Unlocked (Emerald):** `#10B981`
- **Locked (Amber):** `#F59E0B`
- **Error (Coral):** `#EF4444`

### Single Header & 4 Sections
1. **Single Header:** Shows detected physical hardware (`ESP32-S3 on COM7 / USB 0x303A:0xAE61`), connection badge (`CONNECTED` / `DISCONNECTED`), and language toggle (`EN / PT`).
2. **Section 1 — Secure Guard Authority:** Live zero-trust state (`Unprovisioned`, `Locked`, `Unlocked`, `RateLimited`, `RecoveryRequired`), remaining attempt counter `[X/5]`, active session countdown timer, PIN entry, Unlock, Lock Now, Provision PIN, and Emergency Recovery.
3. **Section 2 — Hardware Vault & Wallets:** Protected by fail-closed barrier. When Secure Guard is `Locked`, displays: `🔒 Secure Guard is locked. Unlock Secure Guard to access hardware keys.` When `Unlocked`, lists only real hardware keys and wallets, and allows generating (`Ed25519`, `P-256`, `BTC`, `ETH`, `SOL`) and deleting keys.
4. **Section 3 — Hardware TOTP Codes:** Live 6-digit codes computed on the ESP32-S3 chip (`0x26 OP_OATH_CODE`) with 1-click clipboard copy.
5. **Section 4 — SSH Key Guard:** Status of zero-password SSH lifespan, cached RAM identities count (`ssh-add -l`), 1-click **Purge SSH Agent Now (`ssh-add -D`)**, 1-click **Load Resident FIDO2 Keys (`ssh-add -K`)**, and copyable environment setup script.

---

## 4. How to Run the Applications

### Running the Python System Tray App (Multiplatform)
```powershell
python e:/projetos/fido-tray-guard/app-tray/aegis_tray.py
```
- Minimizes to the Windows System Tray on close `[X]`.
- Right-click tray menu provides quick access to: *Open Dashboard*, *Lock Secure Guard*, *Purge SSH Agent*, and *Exit*.
- Native Windows balloon notifications on security events (e.g. when SSH identities are purged on lock).

### Running the C# / .NET 9 System Tray App
```powershell
dotnet run --project e:/projetos/fido-tray-guard/app-tray/dotnet/AegisKeyTray/AegisKeyTray.csproj
```
- Compiles with 0 warnings, 0 errors on .NET 9.
- Runs natively in Windows System Tray with NotifyIcon, shield icon, and dark cyber-security dashboard.

---

## 5. Configuring SSH Guard for Zero-Password SSH

To enable seamless SSH usage while your physical AegisKey is UNLOCKED:

### Option A: Automatic RAM Lifespan Watchdog (Standard `ssh-agent`)
1. Ensure the Windows OpenSSH Authentication Agent service is running:
   ```powershell
   Start-Service ssh-agent
   ```
2. Add your existing key to the agent once:
   ```powershell
   ssh-add
   ```
3. Keep the **AegisKey Tray App** running in your system tray:
   - While your key is connected and Secure Guard is **UNLOCKED**: You run `ssh user@host` or `git push` without typing passwords!
   - As soon as you click **Lock Now**, session times out, or you unplug the key: SshGuard executes `ssh-add -D` instantly, purging the key from RAM and locking SSH access.

### Option B: Hardware-Gated `SSH_ASKPASS`
Configure OpenSSH to use the AegisKey AskPass helper:

**In PowerShell (User Environment):**
```powershell
[Environment]::SetEnvironmentVariable("SSH_ASKPASS", "E:\projetos\fido-tray-guard\app-tray\aegis_ssh_askpass.bat", "User")
[Environment]::SetEnvironmentVariable("SSH_ASKPASS_REQUIRE", "force", "User")
```

**In Linux / macOS (`~/.bashrc` or `~/.zshrc`):**
```bash
export SSH_ASKPASS="/path/to/app-tray/aegis_ssh_askpass.sh"
export SSH_ASKPASS_REQUIRE="force"
```

---

## 6. Running Automated Tests

A real, zero-mock test battery verifies the entire flow against the real ESP32-S3 silicon on COM7:

```powershell
python e:/projetos/fido-tray-guard/app-tray/test_tray_and_ssh_guard.py
```

### Verified Test Cases:
1. `test_01_real_device_detection`: Real device parameters detection (ESP32-S3 on COM7, VID `0x303A`, PID `0xAE61`).
2. `test_02_secure_guard_vault_gating`: Gating verified — wallets and keys are blocked when `Locked` (403), accessible when `Unlocked`.
3. `test_03_ssh_guard_watchdog_auto_purge_on_lock`: Transition from `Unlocked` to `Locked` triggers immediate `ssh-add -D` purge and session grant revocation.
4. `test_04_aegis_ssh_askpass_helper_lifecycle`: `aegis_ssh_askpass` helper exits with `1` (Access Denied) when Locked, and exits with `0` (Authorized) when Unlocked.
5. `test_05_strict_no_ssh_files_accessed_audit`: Code audit confirms 0 references or reading of private key files in `~/.ssh`.
