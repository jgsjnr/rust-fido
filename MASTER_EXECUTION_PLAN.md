# MASTER EXECUTION PLAN — AegisKey FIDO2 & Secure Guard Ecosystem
**Worktree:** `e:/projetos/fido-tray-guard` (`feat/responsive-guard-tray-ssh`)  
**Target Repository Root:** `e:/projetos/fido`  
**Date:** 2026-11-01  
**Author:** Agente 0 (Low — Planejador Mestre da Fase 0 e Criador do Plano na Raiz da Worktree)

---

## 1. Visão Geral e Escopo Estrutural

Este documento estabelece o **Plano Mestre de Execução (Fases 0 a 5)** para a consolidação, blindagem de segurança e expansão de recursos do ecossistema **AegisKey** (FIDO2 Authenticator, Secure Guard, ESP32-S3 Firmware, Python Bridge, Desktop System Tray / OpenSSH Native Agent, Android App e Suporte a Clear Signing Web3).

---

## 2. Mapeamento dos 7 Gaps de Segurança (`GAP-01` a `GAP-07`)

| ID | Vulnerabilidade / Gap Técnico | Severidade | Vetor de Ameaça | Remediação Canônica / Proteção no Código |
|---|---|---|---|---|
| **GAP-01** | Flash Encryption & Secure Boot v2 inativos em modo de laboratório | **CRÍTICA** | Dump físico da flash SPI (`esptool.py` via UART/USB) | Código completo em `efuse_irreversible_guard.rs` travado por macro/feature irreversível e avisos claros de brick. |
| **GAP-02** | PIN em texto claro em CBOR serial/USB no opcode `0x3B` | **ALTA** | Sniffing de USB/UART no host local | Canal Criptografado Ponta-a-Ponta ECDH P-256 + HKDF-SHA256 + AES-256-GCM (`secure_channel.rs`). |
| **GAP-03** | 2.000 iterações PBKDF2 na MCU sem âncora em silício | **ALTA** | Ataque offline de dicionário em GPU contra dump NVS | KDF Híbrido com ganchos de hardware HMAC (`HMAC_UP` em eFuse `BLOCK7`), com fallback determinístico seguro em dev. |
| **GAP-04** | Presença física emulável por comando serial (`TEST_UP`) | **ALTA** | Malware no PC simula toque e dispara assinaturas | Trava estrita `#[cfg(feature = "prod-strict")]` com `compile_error!` se `test-mode` estiver ativo; ISR física no GPIO 0. |
| **GAP-05** | Bridge HTTP local (`127.0.0.1:5678`) sem autenticação de sessão | **ALTA** | DNS Rebinding / CSRF / processos locais disparam opcodes | Bearer Token por sessão (`X-Aegis-Token`) + suporte a Named Pipe ACL (`\\.\pipe\aegis_bridge`). |
| **GAP-06** | Decisões de autorização vulneráveis a Fault Injection / Glitching | **MÉDIA / ALTA** | Glitching de tensão / EMFI no branch de verificação | Double-check redundante com inversão lógica (`cond && !inv_cond`) + jitter TRNG anti-glitching. |
| **GAP-07** | Anti-rollback baseado em chave NVS na flash | **ALTA** | Regravação física de versão antiga via programador SPI | Módulo de eFuse `SECURE_VERSION` monotônico em silício com validação em bootloader. |

---

## 3. Mapeamento das 6 Oportunidades de Produto (`OPP-01` a `OPP-06`)

| ID | Oportunidade / Recurso de Produto | Módulo Alvo / Caminho | Descrição Funcional / Arquitetura |
|---|---|---|---|
| **OPP-01** | **Provedor Nativo OpenSSH Agent** | `app-tray/openssh_native_agent.py` + C# Pipe | Servidor local compatível com `sk-ssh-ed25519@openssh.com` e Windows Named Pipe (`\\.\pipe\openssh-ssh-agent`) delegando assinaturas Ed25519 para o ESP32-S3. |
| **OPP-02** | **CTAP 2.1 `hmac-secret` & `largeBlobKey`** | `crates/aegis-fido-core/src/extensions/` | Suporte a senhas de cofre (KeePassXC/LUKS) e blobs de até 4 KiB na partição NVS/storage protegidos pelo Secure Guard. |
| **OPP-03** | **Cofre de Senhas / Seeds BIP-39 com Periférico DS/HMAC** | `crates/aegis-fido-core/src/crypto/bip39.rs` | Cifragem KEK ancorada em hardware para sementes de 24 palavras, com limpeza imediata (`zeroize`) em SRAM. |
| **OPP-04** | **Windows Hello CDF & Linux PAM (`pam_u2f`)** | `app-tray/os_login_companion.py` | Walk-Away Auto-Lock por RSSI BLE (< -80 dBm) e Touch Unlock sem senha (`LockWorkStation()` / PAM). |
| **OPP-05** | **Backup Shamir Secret Sharing (SLIP-0039) 2-de-3** | `crates/aegis-fido-core/src/crypto/shamir_backup.rs` | Divisão de semente em 3 partes (Key 1 + Key 2 + Papel) em GF(256), exigindo quórum de 2 partes para recuperação. |
| **OPP-06** | **Display OLED I2C SSD1306 128x64 Clear Signing** | `crates/aegis-fido-firmware/src/oled_clear_sign.rs` | Parser de transações Web3 (EIP-1559, BTC, SOL) e formatação de frames gráficos desacoplados (sem exigir display físico conectado). |

---

## 4. REGRA INVIOLÁVEL DE SEGURANÇA FÍSICA (`DO NOT EXECUTE / OTP EFUSE LOCK WARNING`)

> [!CAUTION]
> **AVISO CRÍTICO DE SEGURANÇA FÍSICA — OTP eFuse / Secure Boot / Flash Encryption**
> 
> * **NENHUM SCRIPT OU CÓDIGO NESTE REPOSITÓRIO DEVE EXECUTAR COMANDOS DE QUEIMA DE eFUSE AUTOMATICAMENTE (`esptool.py burn_efuse`, `SPI_BOOT_CRYPT_CNT`, `BLOCK7`, `SECURE_VERSION`)**.
> * Todos os módulos relativos a `GAP-01`, `GAP-03` e `GAP-07` foram desenvolvidos estritamente como **código estático, drivers de simulação ou rotinas de provisionamento com trava de segurança inegociável** (`#[cfg(feature = "burn-efuse-irreversible-do-not-enable")]` e checagem booleana explícita retornando `Err(EfuseBlockedInDevMode)`).
> * O objetivo é manter o hardware de desenvolvimento (`COM7`) inteiramente livre de travamento permanente, permitindo reprogramações e testes contínuos sem risco de brick por eFuse.

---

## 5. Arquitetura de Execução por Agente (Fases 1 a 5)

### Agente 1A — Core Criptográfico (`aegis-fido-core`)
* Implementação do canal seguro ECDH P-256 + HKDF + AES-256-GCM (`secure_channel.rs`).
* KDF Híbrido com suporte a hardware HMAC (`crypto/pin_kdf.rs`).
* Verificações redundantes com jitter TRNG anti-glitching (`crypto/security_gates.rs`).
* Extensões CTAP 2.1 (`hmac-secret`, `largeBlobKey`).
* Backup Shamir SLIP-0039 2-de-3 (`shamir_backup.rs`).
* Parser de Clear Signing Web3 (`clear_signing.rs`).

### Agente 1B — Firmware ESP32-S3 (`aegis-fido-firmware`)
* Módulo `efuse_irreversible_guard.rs` (travado por defeito).
* Envelopamento ECDH no `secure_guard_exec.rs`.
* Guarda `prod-strict` em `lib.rs` contra `test-mode`.
* Opcodes para Shamir e Clear Signing OLED SSD1306 desacoplado (`oled_ssd1306.rs`).

### Agente 1C — Bridge, Tray App, OpenSSH & Windows Hello / PAM
* Autenticação por Bearer Token (`X-Aegis-Token`) + Named Pipe ACL (`host_hardware_android_bridge.py`).
* Provedor Nativo OpenSSH Agent (`app-tray/openssh_native_agent.py` + C# Pipe).
* Módulo Windows Hello CDF & Linux PAM (`os_login_companion.py`).

### Agente 1D — Android App Clean + Atomic + SOLID
* Telas e componentes para Shamir Backup 2-de-3, Clear Signing Preview, status `hmac-secret` e avisos de eFuse somente-leitura.
* Suporte multilíngue completo (`strings.xml` em EN ASD-STE100 e PT).

---

## 6. Sincronização Canônica e Verificação
* Atualização dos arquivos canônicos:
  * `docs/project/PROJECT.md`
  * `docs/plans/PLANS.md`
  * `docs/tasks/TASKS.md`
  * `docs/evaluation/EVALUATION.md`
  * `docs/project/ARCHITECTURE-MAP.html`
* Testes unitários e verificação léxica/sintática em Rust (`cargo check`, `cargo test`) e Python sem acionar hardware destruidor de eFuse.
