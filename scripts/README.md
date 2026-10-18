# 🛠️ Scripts de Build, Testes & Gravação (PowerShell)

Esta pasta contém o ecossistema automatizado em PowerShell para compilar, testar e gravar o firmware **AegisKey S3** em todas as placas ESP32 e ESP32-S3 suportadas.

---

## 📋 Resumo dos Scripts

| Script | Placa / Alvo | Chip | Display / Periféricos |
| :--- | :--- | :--- | :--- |
| [`menu.ps1`](file:///e:/projetos/fido/scripts/menu.ps1) | **Painel Interativo Geral** | Todos | Menu CLI navegável com opções de build, flash e testes |
| [`build-esp32-ttgo.ps1`](file:///e:/projetos/fido/scripts/build-esp32-ttgo.ps1) | LilyGO TTGO T-Display Classic | ESP32 | Tela ST7789 IPS (135x240) + Botões GPIO 0 e 35 |
| [`build-esp32s3-devkitc.ps1`](file:///e:/projetos/fido/scripts/build-esp32s3-devkitc.ps1) | ESP32-S3 DevKitC-1 | ESP32-S3 | USB Nativo FIDO2 + LED RGB WS2812 (GPIO 48) |
| [`build-esp32s3-tdisplay.ps1`](file:///e:/projetos/fido/scripts/build-esp32s3-tdisplay.ps1) | LilyGO T-Display-S3 | ESP32-S3 | USB Nativo + Tela ST7789 IPS (170x320) + Botões GPIO 0 e 14 |
| [`test-all.ps1`](file:///e:/projetos/fido/scripts/test-all.ps1) | Todas as crates | Host | Executa testes unitários de criptografia, CTAP, USB e UI |
| [`flash.ps1`](file:///e:/projetos/fido/scripts/flash.ps1) | Utilitário rápido de Flash | Qualquer | Grava qualquer binário `.bin` com autodeteção de porta |
| [`common.ps1`](file:///e:/projetos/fido/scripts/common.ps1) | Módulo compartilhado | - | Funções de ambiente, esptool, portas COM e logging |

---

## 🚀 Como Usar

Abra o terminal do PowerShell na raiz do projeto ou dentro da pasta `scripts/`.

### 1. Modo Menu Interativo (Recomendado)
A forma mais simples e visual de operar:
```powershell
.\scripts\menu.ps1
```
Um painel colorido é exibido permitindo selecionar a placa e a ação (Build, Teste, Flash, Monitor Serial).

---

### 2. Uso Direto por Linha de Comando

Cada script de placa aceita parâmetros flexíveis:

#### Compilar Apenas (Gera o binário `.bin` em `C:\t`):
```powershell
.\scripts\build-esp32-ttgo.ps1
.\scripts\build-esp32s3-devkitc.ps1
.\scripts\build-esp32s3-tdisplay.ps1
```

#### Compilar e Gravar (Autodetectando a porta COM):
```powershell
.\scripts\build-esp32-ttgo.ps1 -Flash
```

#### Compilar, Gravar e Abrir Monitor Serial:
```powershell
.\scripts\build-esp32-ttgo.ps1 -Flash -Monitor
```

#### Especificar uma porta COM específica:
```powershell
.\scripts\build-esp32-ttgo.ps1 -Port COM8 -Flash
```

#### Executar testes unitários antes de compilar:
```powershell
.\scripts\build-esp32-ttgo.ps1 -Test -Flash
```

#### Limpar cache e recompilar do zero:
```powershell
.\scripts\build-esp32-ttgo.ps1 -Clean -Flash
```

#### Gravar binário existente sem recompilar:
```powershell
.\scripts\build-esp32-ttgo.ps1 -OnlyFlash -Port COM8
```

---

### 3. Executar Todos os Testes Unitários
Para validar os motores criptográficos (NIST P-256, P-384, P-521, Secp256k1, Ed25519), BIP-39, CTAPHID e o renderizador gráfico:
```powershell
.\scripts\test-all.ps1
```

---

## ⚙️ Variáveis de Ambiente & Requisitos
Os scripts gerenciam automaticamente:
- `$env:IDF_PATH`: Apontado por padrão para `C:\.embuild\espressif\esp-idf\v5.3.1`.
- `target-dir`: Configurado em `C:\t` para contornar o limite de 260 caracteres do Windows.
- `esptool`: Detectado automaticamente no ambiente virtual Python ou no PATH do sistema.
