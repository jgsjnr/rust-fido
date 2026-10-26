# MACHINE — registro do ambiente de build/flash (verificado em 2026-10-20)

> Gerado por `scripts/env-check.ps1`. Revalide com esse script após qualquer
> mudança de toolchain. Nada aqui é suposição: cada linha foi observada.

## Portas seriais

| Porta | Descrição | Papel |
|---|---|---|
| COM7 | Silicon Labs CP210x USB to UART Bridge | Flash + console UART das placas ESP |
| COM3/COM4 | Serial padrão por link Bluetooth | Ignorar (não é a placa) |

## ESP-IDF (C)

- Projeto fixa `v5.3.1` em `C:\.embuild\espressif\esp-idf\v5.3.1` (ver `.cargo/config.toml`).
- Existe também `C:\esp\v6.0.3\esp-idf` (IDF_PATH do ambiente) — NÃO usar para este build.
- `sdkconfig.defaults.esp32s3` no root (NimBLE BLE-only, 1 conexão).
- GCC Xtensa: `C:\.embuild\espressif\tools\xtensa-esp-elf\esp-13.2.0_20240530` (+ cópia `esp-15.2.0_20251204` em `%USERPROFILE%\.espressif\tools`).
- clang: `toolchains\esp\xtensa-esp32-elf-clang\esp-clang\bin\libclang.dll`.
- esptool: `C:\.embuild\espressif\python_env\idf5.3_py3.12_env\Scripts\esptool.exe`; python 3.12.10.

## Rust

- Estável padrão: `1.97.1` (host gates: test/clippy).
- ESP fork: `cargo +esp` responde `1.97.0-nightly (c980f4866 2026-06-30)`, mas o
  diretório `toolchains\esp` só tem std do host — **sem std Xtensa**
  (`E0463: can't find crate for core` em `xtensa-esp32s3-espidf`).
  `rustup` não gerencia esse toolchain (`does not support components`).
- `ldproxy.exe` e `cargo-espflash 4.6.0` presentes em `~/.cargo/bin`; `espup.exe` presente.

## Receita de ambiente (obrigatória nesta ordem)

1. `. C:\Users\junior\export-esp.ps1` (PATH do clang/gcc ESP).
2. `$env:IDF_PATH='C:\.embuild\espressif\esp-idf\v5.3.1'` — o IDF_PATH da
   máquina (`C:\esp\v6.0.3`) QUEBRA o build (esp-idf-sys 0.36 não suporta IDF v6).
3. `$env:ESP_IDF_SDKCONFIG_DEFAULTS='<repo>\sdkconfig.defaults.esp32s3'` —
   sem isso o NimBLE fica desligado e `aegis_ble_nimble.c` não compila.
4. `cargo +esp ... -Zbuild-std=std,panic_abort` (std vem do fonte; não existe
   rustlib Xtensa pré-compilada — isso é normal).

`scripts/common.ps1` (Initialize-EspEnvironment) já aplica 1–3
automaticamente; `scripts/env-check.ps1` valida tudo (exit 0 = pronto).

## Placa na COM7 (identificada)

ESP32-S3 QFN56 rev v0.2, 8 MB PSRAM, 40 MHz, MAC 80:65:99:df:4b:cc
(esptool `chip_id`, 2026-10-20). Imagem S3 gravada e validada:
`aegis-app-esp32s3-devkitc.bin`, 2.646.256 B, SHA256
`930f47c553441287f33f8cda1d83c594b4c4c3ef1ec1c6b710fa6d1ed564ff45`,
`Hash of data verified`, boot ONLINE & ACTIVE via monitor serial.

## Placas

- ESP32-S3 DevKitC-1 (USB OTG nativo, WS2812 GPIO 48, BOOT GPIO 0) — `board-devkitc`, target `xtensa-esp32s3-espidf`.
- LilyGO TTGO T-Display Classic (ESP32, display ST7789, serial) — seção D serial, target `xtensa-esp32-espidf`.
- Qual placa está na COM7: identificar pelo monitor serial após flash (VID/PID USB `0x303A:0xAE61` no S3) ou etiqueta física.
