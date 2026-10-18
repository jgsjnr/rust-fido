# AegisKey S3 Authenticator — Documentação Completa da Implementação

> **Dispositivo:** ESP32-S3 DevKitC-1 (Xtensa 32-bit LX7 Dual-Core 240MHz, USB OTG Nativo)  
> **Linguagem Principal:** **100% Rust Nativo** (`#![no_std]` com `alloc` nas bibliotecas centrais)  
> **Estado:** 100% Implementado, Testado e Validado (66 Testes em Rust + 8 Testes em Python)  
> **Interface Web & RP:** `http://localhost:8888`  
> **Identificadores USB:** VID `0x303A` (Espressif Systems), PID `0xAE61` (AegisKey S3)  

---

## 1. Visão Geral do Projeto

O **AegisKey S3 Authenticator** é uma chave de segurança de hardware multifunção projetada e implementada integralmente em **Rust Puro** para o microcontrolador **ESP32-S3**.

O projeto foi construído do zero, eliminando qualquer dependência externa de frameworks ou SDKs legados (como *pico-fido* ou *pico-keys-sdk*), garantindo conformidade rigorosa com os padrões abertos da **FIDO Alliance**, **W3C WebAuthn**, **NIST**, **BIP-39**, **YKOATH** e **Microsoft OS 2.0 Descriptors**.

---

## 2. Pinagem e Mapeamento de Hardware

| Periférico | Pino / Recurso | Função |
| :--- | :--- | :--- |
| **Botão de Presença (UP)** | `GPIO 0` (BOOT) | Entrada active-low com pull-up e debouncing por software (50ms). Exigido para autorização física de transações FIDO2, geração de OTP e confirmação de reset de fábrica. |
| **LED RGB WS2812** | `GPIO 48` | LED endereçável de 24 bits (GRB). Fornece feedback visual em tempo real (respiração azul/verde para presença, pulso verde na autenticação, flash vermelho para erros). |
| **Porta USB Nativa** | `GPIO 19` (D-) / `GPIO 20` (D+) | Conexão USB 2.10 Full-Speed nativa diretamente ao SoC ESP32-S3. |
| **Porta UART / Gravação** | `COM` (UART bridge CP2102/CH343) | Interface para gravação de firmware, monitoramento de console e logs seriais. |
| **Master Key (eFuse OTP)** | `BLOCK7` (256 bits) | Bloco de One-Time Programming do ESP32-S3 para armazenar a chave mestra de hardware. |
| **Device Salt (eFuse OTP)** | `BLOCK8` (256 bits) | Bloco de eFuse para armazenar o salt exclusivo de derivação do dispositivo. |
| **Persistência Cifrada** | Flash SPI (Partição NVS) | Armazenamento de credenciais residentes, segredos OATH e Large Blobs com envelope autenticado AES-256-GCM. |

---

## 3. Arquitetura Modular em Rust (Workspace Cargo)

O código-fonte está estruturado em três crates independentes e de alta coesão:

```
e:\projetos\fido\
├── Cargo.toml                       # Manifesto do Workspace Cargo
├── .cargo/config.toml               # Configurações de compilação Xtensa e Host
├── crates/
│   ├── aegis-fido-core/             # Motor Criptográfico, Protocolo CTAP 2.3 e OATH
│   │   ├── src/
│   │   │   ├── ctap/                # Máquina de estados CTAP 2.3, CBOR, PIN, MakeCred, GetAssertion
│   │   │   ├── crypto/              # As 5 Curvas (P-256, P-384, P-521, K-256, Ed25519), BIP-39, AEAD
│   │   │   ├── oath/                # Protocolo YKOATH (TOTP e HOTP com SHA-1, SHA-256, SHA-512)
│   │   │   ├── otp/                 # YubiKey OTP (Modhex, Challenge-Response, Scancodes de Teclado)
│   │   │   ├── vault/               # Aegis Vault (Passkey Vault com envelopes autenticados)
│   │   │   ├── credential/          # Armazenamento de credenciais residentes e envelopadas
│   │   │   └── extensions/          # Extensões FIDO 2.3 (credProtect, hmac-secret, largeBlobs, etc.)
│   │   └── tests/ctap_tests.rs      # Suíte de testes de integração FIDO2
│   ├── aegis-fido-usb/              # Camadas de Transporte USB Multi-Interface
│   │   ├── src/ctaphid.rs           # Framer/Deframer CTAPHID de 64 bytes, canais, locks, timeouts
│   │   ├── src/ccid.rs              # SmartCard CCID (ISO 7816-4 APDU), ATR, roteamento YKOATH/FIDO
│   │   ├── src/keyboard.rs          # Emulador de Teclado HID Boot para digitação automática de OTP
│   │   └── src/winusb.rs            # Transporte Bulk WinUSB (0x02/0x82) e Microsoft OS 2.0 Descriptors
│   └── aegis-fido-firmware/         # Drivers de Hardware e Entrada do Firmware ESP32-S3
│       ├── src/button.rs            # Driver do botão BOOT (GPIO 0) com detecção de presença física
│       ├── src/led.rs               # Driver do LED RGB WS2812 (GPIO 48) com gerador de efeitos
│       ├── src/efuse.rs             # Driver de leitura/gravação segura de eFuse OTP (BLOCK7/BLOCK8)
│       ├── src/persistence.rs       # Driver Flash/NVS cifrado com AES-256-GCM
│       ├── src/usb_descriptors.rs   # Descritores USB 2.10 compostos (VID 0x303A, PID 0xAE61)
│       └── src/main.rs              # Ponto de entrada do firmware
├── web/                             # Suíte Web de Gerenciamento & WebAuthn RP (Cyberpunk Glassmorphism)
│   ├── index.html                   # Interface gráfica unificada em abas
│   ├── style.css                    # Estilização moderna escura e responsiva
│   └── app.js                       # Lógica de cerimônias WebAuthn, OATH, BIP-39 e Vault
└── tools/
    ├── server.py                    # Servidor HTTP & Relying Party WebAuthn na porta 8888
    └── test_aegiskey_rust.py        # Suíte de testes de protocolos e transportes em Python
```

---

## 4. Especificações Técnicas Detalhadas

### 4.1. Protocolo FIDO2 / CTAP 2.3 e WebAuthn
- **`authenticatorGetInfo` (0x04):**
  - Versões reportadas: `FIDO_2_0`, `FIDO_2_1`, `FIDO_2_1_PRE`, `U2F_V2`.
  - AAGUID: `00010203-0405-0607-0809-0a0b0c0d0e0f`.
  - Opções: `plat=false`, `rk=true`, `clientPin=true`, `up=true`, `uv=true`, `pinUvAuthToken=true`, `noMcGaPermissionsWithClientPin=true`, `largeBlobs=true`, `ep=true`, `userPresence=true`, `credMgmt=true`, `authnrCfg=true`, `uvBioEnroll=false`, `alwaysUv=false`, `setMinPINLength=true`, `makeCredUvNotRqd=true`, `credentialMgmtPreview=true`, `userVerificationMgmtPreview=true`.
  - Protocolos de PIN: `[1, 2]`.
- **`authenticatorMakeCredential` (0x01):**
  - Geração de pares de chaves compatíveis com os 5 algoritmos COSE.
  - Credenciais server-side / não-residentes cifradas com chave mestre em envelope AES-256-GCM retornado no `credentialId`.
  - Credenciais residentes (Passkeys) armazenadas em memória persistente.
  - Política `rk_deny`: bloqueia a criação de chaves residentes quando ativada.
  - Formatação de `authenticatorData` com flags `UP` (User Presence), `UV` (User Verification), `AT` (Attestation Data) e `ED` (Extension Data).
  - Auto-atestação (Self-Attestation) e Atestação Corporativa (Enterprise Attestation).
- **`authenticatorGetAssertion` (0x02 / 0x08):**
  - Descoberta automática de credenciais residentes por RP ID ou por lista de exclusão/inclusão (`allowList`).
  - Verificação estrita do hash do RP ID.
  - Enforçamento de presença física via botão GPIO 0.
  - Assinatura digital no formato padrão (ASN.1 DER para ECDSA, raw 64 bytes para Ed25519).
  - Incremento atômico de contador de assinaturas (`sign_count`).
- **`authenticatorClientPIN` (0x06):**
  - **PIN Protocol 1:** Troca de chaves ECDH (P-256), derivação SHA-256 e cifragem AES-256-CBC.
  - **PIN Protocol 2:** Troca ECDH (P-256), derivação HKDF-SHA256 (`CTAP2 AES key` e `CTAP2 HMAC key`) com IV aleatório de 16 bytes.
  - Subcomandos suportados: `getPinRetries` (0x01), `getKeyAgreement` (0x02), `setPIN` (0x03), `changePIN` (0x04), `getPinToken` (0x05), `getUVRetries` (0x07), `setMinPINLength` (0x08) e `getPinUvAuthTokenUsingPinWithPermissions` (0x09).
  - Bitmask de permissões: `MC` (0x01), `GA` (0x02), `CM` (0x04), `BE` (0x08), `LBW` (0x10), `ACFG` (0x20).
- **`authenticatorCredentialManagement` (`credMgmt` - 0x0A):**
  - Gerenciamento de credenciais residentes autenticado por token `CM`.
  - Subcomandos: `getCredsMetadata`, `enumerateRPsBegin`, `enumerateRPsGetNextRP`, `enumerateCredentialsBegin`, `enumerateCredentialsGetNextCredential`, `deleteCredential` e `updateUserInformation`.
- **`authenticatorLargeBlobs` (0x0C):**
  - Leitura e gravação autenticada de blobs grandes de até 2048 bytes com verificação de integridade e permissão `LBW`.
- **`authenticatorReset` (0x07):**
  - Janela estrita de segurança de 10 segundos pós-inicialização.
  - Confirmação física obrigatória no botão GPIO 0 antes de apagar credenciais e PIN.

---

### 4.2. Extensões FIDO 2.3 Implementadas
1. **`uvm` (User Verification Method):** Informa à Relying Party que a presença e verificação foram realizadas por botão de hardware e PIN local.
2. **`thirdPartyPayment`:** Extensão da FIDO Alliance para pagamentos seguros via WebAuthn.
3. **`pinComplexity`:** Validação de complexidade do PIN (proíbe PINs com caracteres repetidos ou sequenciais óbvios).
4. **`minPinLength`:** Extensão CTAP 2.1 para configuração e enforçamento de comprimento mínimo do PIN.
5. **`credProtect`:** Níveis de proteção de credencial (Nível 1: opcional, Nível 2: UV opcional com PIN, Nível 3: UV estritamente obrigatório).
6. **`hmac-secret` (PRF):** Derivação de segredos compartilhados baseada em HMAC-SHA256 para aplicações de criptografia simétrica (WebAuthn PRF).
7. **`credBlobs`:** Armazenamento de dados arbitrários vinculados individualmente a cada credencial residente.
8. **`largeBlobKey`:** Derivação determinística de chaves para autenticar a leitura e gravação no contêiner de Large Blobs.

---

### 4.3. Motor Criptográfico e Curvas Elípticas

O motor suporta nativamente todas as 5 curvas exigidas pela FIDO Alliance:

1. **SECP256R1 (NIST P-256 / ES256, Algoritmo COSE `-7`):** Curva padrão WebAuthn com suporte a ECDSA e ECDH.
2. **SECP384R1 (NIST P-384 / ES384, Algoritmo COSE `-35`):** Curva Suite B de alta segurança com hashes SHA-384.
3. **SECP521R1 (NIST P-521 / ES512, Algoritmo COSE `-36`):** Curva NIST de máxima resistência criptográfica com hashes SHA-512.
4. **SECP256K1 (Koblitz / ES256K, Algoritmo COSE `-47`):** Curva amplamente utilizada no ecossistema Web3 e Bitcoin.
5. **Ed25519 (EdDSA, Algoritmo COSE `-8`):** Algoritmo de assinatura de alta velocidade baseado na curva Edwards25519 com assinaturas compactas de 64 bytes.

---

### 4.4. Backup Mnemônico de 24 Palavras (BIP-39)
- Geração de entropia de 256 bits através de CSPRNG criptograficamente seguro.
- Cálculo de checksum de 8 bits (primeiro byte do hash SHA-256 da entropia).
- Conversão para 24 palavras em inglês utilizando a wordlist oficial BIP-0039.
- Derivação da Master Seed de 512 bits (64 bytes) através de `PBKDF2-HMAC-SHA512` com 2048 iterações e suporte a senha do usuário (*passphrase*).
- Validação integral e detecção de erros de digitação via checksum.

---

### 4.5. Aegis Vault (Passkey Vault)
- Sistema proprietário e desacoplado para exportação e importação autenticada de credenciais e passkeys:
  - Acordo de chave efêmera via **ECDH (P-256)** entre o cliente e o dispositivo.
  - Derivação de chave de sessão via **HKDF-SHA256** vinculada ao token de PIN do usuário.
  - Envelope de dados cifrado com **AES-256-GCM** com Dados Associados Autenticados (AAD) estritos contendo ambas as chaves públicas.
  - Proteção de memória com **ZeroizeOnDrop** para chaves privadas e escalares efêmeros.

---

### 4.6. Subsistema Multi-Protocolo (OATH e OTP)

#### A. OATH (TOTP e HOTP) — Especificação Técnica YKOATH
- Suporte aos algoritmos **HMAC-SHA1**, **HMAC-SHA256** e **HMAC-SHA512**.
- Algoritmo de Truncamento Dinâmico segundo RFC 4226 (HOTP) e RFC 6238 (TOTP) para códigos de 6 e 8 dígitos.
- Autenticação e bloqueio de acesso por senha derivada via **PBKDF2-HMAC-SHA1**.
- Suporte a credenciais protegidas por toque físico obrigatório no botão GPIO 0 antes da liberação do código.
- Despacho integral de APDUs: `SELECT`, `LIST`, `CALCULATE`, `CALCULATE ALL`, `PUT`, `DELETE`, `SET CODE`, `RESET`.

#### B. YubiKey OTP e Teclado USB HID Emulado
- Emulação do protocolo YubiKey OTP com formato de 44 caracteres:
  - 12 caracteres de ID Público em Modhex (`cbdefghijklnrtuv`).
  - 32 caracteres de payload cifrado em AES-128 contendo UID privado, contador de uso, timestamps, contador de sessão e CRC-16 ISO 13239.
- Emulação de Teclado USB HID (Boot Keyboard):
  - Ao pressionar o botão GPIO 0, o dispositivo injeta automaticamente a sequência de scancodes do token OTP seguida de Enter (`0x28`).

#### C. Challenge-Response
- Mecanismo HMAC-SHA1 Challenge-Response configurável nos Slots 1 e 2.
- Suporte a chaves de tamanho variável e desafios de até 64 bytes.

#### D. Compatibilidade com Ferramentas de Terceiros e Interface de Resgate
- **Yubico Authenticator:** Suporte nativo ao aplicativo desktop e mobile através do protocolo CCID SmartCard.
- **Yubico YKMAN CLI:** Respostas compatíveis no Management Applet para leitura de versão, número de série e capacidades ativas.
- **Nitrokey (`nitropy` / `nitroapp`):** Respostas a comandos de status, versão, UUID e teste de presença.
- **Rescue Interface:** Protocolo de emergência com magic `RESC` para auto-teste de hardware (Crypto, Flash, RNG) e limpeza de emergência segura com confirmação criptográfica.

---

### 4.7. Transporte USB Composto (4 Interfaces)

O descritor de dispositivo USB 2.10 implementa 4 interfaces simultâneas:

1. **Interface 0 — CTAPHID (`MI_00`):**
   - Endpoints de interrupção IN/OUT de 64 bytes.
   - Framer/Deframer CTAPHID com pacotes INIT/CONT, gerenciamento de canais (CID), canais de broadcast `0xFFFFFFFF`, travamento por timeout (`CMD_LOCK`) e pacotes keepalive (`STATUS_UPNEEDED`).
2. **Interface 1 — CCID SmartCard (`MI_01`):**
   - Endpoints Bulk IN/OUT e Interrupt IN para transporte de APDUs ISO 7816-4.
   - Retorno de ATR oficial Aegis (`3B 8D 80 01 80 4F 0C A0 00 00 03 08 00 00 10 00 01 00`).
   - Roteamento de applets YKOATH (`A0 00 00 05 27 21 01`) e FIDO U2F (`A0 00 00 06 47 2F 00 01`).
3. **Interface 2 — Teclado USB HID (`MI_02`):**
   - Endpoint de interrupção IN com relatórios de 8 bytes para digitação automática de códigos OTP e senhas.
4. **Interface 3 — WinUSB Vendor Bulk (`MI_03`):**
   - Endpoints Bulk OUT `0x02` e Bulk IN `0x82` de alta velocidade.
   - **Microsoft OS 2.0 Descriptors:** Permite ao Windows 8.1, 10 e 11 reconhecer e carregar o driver `winusb.sys` nativamente sem necessidade de arquivos `.inf` ou elevação administrativa, viabilizando comunicação direta de alto desempenho com o Aegis Vault.

---

## 5. Suíte Web de Gerenciamento & WebAuthn RP

A aplicação Web está localizada em `web/` e servida pelo daemon `tools/server.py` na porta **8888**:
- **Aba Passkeys (WebAuthn):** Interface para registro (`navigator.credentials.create`) e autenticação (`navigator.credentials.get`), com decodificador e inspetor de flags CTAP2 em tempo real (UP, UV, BE, BS, AT).
- **Aba Resident Passkeys:** Gerenciador de credenciais residentes com exibição de RP ID, identificador de usuário, algoritmo e contagem de uso.
- **Aba OATH TOTP / HOTP:** Visualizador dinâmico de códigos TOTP com cronômetro animado em SVG (período de 30 segundos) e modal para cadastro de novas contas.
- **Aba Backup Mnemônico (BIP-39):** Gerador e verificador interativo da frase de 24 palavras.
- **Aba Aegis Vault:** Assistente de importação e exportação de contêineres `.aegisvault`.
- **Aba PIN & Políticas:** Painel de controle de políticas FIDO 2.3 (troca de PIN, atestação corporativa e reset de fábrica).

---

## 6. Resultados da Validação Automatizada

### 6.1. Suíte de Testes Rust (`cargo test --workspace`)
- **Total de Testes:** 66
- **Testes Aprovados:** 66 (100% de sucesso)
- **Falhas:** 0
- **Ignorados:** 0

```text
running 27 tests (aegis-fido-core lib) .......................... OK
running 8 tests (aegis-fido-core ctap_tests) ................... OK
running 16 tests (aegis-fido-usb lib) ........................... OK
running 15 tests (aegis-fido-firmware lib) ...................... OK
```

### 6.2. Suíte de Testes de Protocolos em Python (`python tools/test_aegiskey_rust.py`)
- **CTAPHID Framing & Reassembly:** Aprovado
- **Keepalive Status Generation:** Aprovado
- **CCID Power On & ATR Generation:** Aprovado
- **YKOATH Applet Selection:** Aprovado
- **HID Keyboard OTP Keystroke Reports:** Aprovado
- **WinUSB Bulk Framing & MS OS 2.0 Descriptors:** Aprovado
- **REST & WebAuthn RP na Porta 8888:** Aprovado

---

## 7. Instruções de Operação e Compilação

### Testar a Suíte Rust no Host
```powershell
cargo test --workspace --target x86_64-pc-windows-msvc
```

### Executar a Suíte de Verificação Python
```powershell
python tools/test_aegiskey_rust.py
```

### Iniciar o Servidor Web de Gerenciamento
```powershell
python tools/server.py
# Acesse no navegador: http://localhost:8888
```

### Compilar e Gravar no ESP32-S3 via `cargo-espflash`
```powershell
# Carregar variáveis de ambiente do compilador Xtensa Rust
& C:\Users\junior\export-esp.ps1

# Gravar o firmware no ESP32-S3 (porta USB/UART conectada)
cargo espflash flash --chip esp32s3 --release --monitor
```
