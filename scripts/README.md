# Scripts de build e teste (PowerShell)

Automacao de build do firmware ESP32-S3 (FreeRTOS) e testes no host. Caminhos relativos a `scripts/`.

## Suportados (usar somente estes)

| Script | Finalidade |
| :--- | :--- |
| [`build-freertos-s3.ps1`](./build-freertos-s3.ps1) | Build device ESP32-S3, FreeRTOS + proximity (`board-devkitc,freertos,proximity`). Aceita `-Clean`. Gera `aegis-app-freertos-s3.bin`. |
| [`build-freertos-s3-testmode.ps1`](./build-freertos-s3-testmode.ps1) | Mesmo build com `test-mode` (`board-devkitc,freertos,proximity,test-mode`). Aceita `-Clean`. |
| [`test-all.ps1`](./test-all.ps1) | Testes unitarios Rust no host (`cargo test -p <crate> --lib`). |
| [`common.ps1`](./common.ps1) | Modulo compartilhado dos builds: ambiente ESP-IDF, build, ELF para BIN, logging. Nao executar diretamente. |

## NAO USAR (em remocao)

Nao recebem suporte nem correcoes. Serao removidos. Nao usar em fluxo novo:

- [`build-esp32-ttgo.ps1`](./build-esp32-ttgo.ps1)
- [`build-esp32s3-devkitc.ps1`](./build-esp32s3-devkitc.ps1)
- [`build-esp32s3-tdisplay.ps1`](./build-esp32s3-tdisplay.ps1)
- [`build-diag.ps1`](./build-diag.ps1)
- [`build-matrix.ps1`](./build-matrix.ps1)
- [`build-all.ps1`](./build-all.ps1)
- [`build-android-so.ps1`](./build-android-so.ps1)
- [`flash-diag.ps1`](./flash-diag.ps1)

Demais arquivos da pasta sao utilitarios avulsos, fora do fluxo suportado.

## Como usar

Na raiz do repositorio:

```powershell
.\scripts\build-freertos-s3.ps1
.\scripts\build-freertos-s3.ps1 -Clean
.\scripts\build-freertos-s3-testmode.ps1
.\scripts\test-all.ps1
```

## Requisitos

Via `common.ps1`:

- `$env:IDF_PATH`: padrao `C:\.embuild\espressif\esp-idf\v5.3.1`.
- Diretorio de build: `C:\t`.
