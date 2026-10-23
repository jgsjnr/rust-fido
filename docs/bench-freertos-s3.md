# Bancada FreeRTOS + proximity no ESP32-S3 (roteiro de validacao em hardware)

Variante: `crates/aegis-fido-firmware`, features `board-devkitc,freertos,proximity`,
target `xtensa-esp32s3-espidf`. Placa principal: ESP32-S3 DevKitC-1 na COM7
(UART CP210x para flash/monitor; funcao FIDO2 na porta USB nativa USB-OTG).
Referencia secundaria: LilyGO TTGO T-Display Classic (ESP32, serial UART0
115200 8N1) na COM8 — nao recebe este binario; serve so como contraste
serial quando citado.

Fontes deste roteiro (nada aqui e suposicao alem do citado):
`scripts/build-freertos-s3.ps1`, `scripts/common.ps1`, `scripts/flash.ps1`,
`scripts/env-check.ps1`, `crates/aegis-fido-firmware/Cargo.toml`,
`crates/aegis-fido-firmware/src/freertos.rs`,
`crates/aegis-fido-firmware/src/main.rs` (`run_authenticator_freertos`),
`crates/aegis-fido-firmware/src/button.rs` (BOOT GPIO 0),
`crates/aegis-fido-firmware/src/led.rs` (`WS2812_GPIO_PIN = 48`),
`crates/aegis-fido-firmware/src/identity.rs` (VID `0x303A`, PID `0xAE61`),
`tools/test_aegiskey_rust.py`, `tools/server.py` (porta 8888),
`tools/host/{win,linux,macos}/proximity_agent.py`, `docs/MACHINE.md`,
`docs/validacao-usb-telas.md`, `docs/freertos-rust.md`,
`plans/STATE.md` (registro do build da variante).

Artefato esperado desta variante (registrado em `plans/STATE.md` no build de
referencia; re-anotar hash/tamanho no dia, nunca reutilizar estes numeros
como prova): `C:\t\aegis-app-freertos-s3.bin`, SHA256
`13B9A3C20D0495F7A85F37E421BD93FB435FAD93A76131F147DBC7A08D86267B`,
483936 bytes (teto factory 3145728). O `.sha256` sidecar e gerado por
`Test-FirmwareArtifact` a cada build (`scripts/common.ps1`).

Regra de seguranca da bancada: LAB-ONLY, sem secure boot. Nenhum segredo
(K_prox, PIN, fob real, semente) entra em log, foto ou arquivo salvo.
`K_prox` vai so via flag `--k-prox-hex` / env `FIDO_PROX_KEY_HEX` na linha
de comando local, nunca colada neste roteiro depois de usada.

## 0. Pre-requisitos (ambiente + hardware)

- Windows 10/11 com Bluetooth ligado (agente proximity de referencia e o
  `tools/host/win/proximity_agent.py`; Linux/macOS tem espelhos em
  `tools/host/linux|macos/proximity_agent.py`).
- ESP-IDF v5.3.1 em `C:\.embuild\espressif\esp-idf\v5.3.1`
  (`scripts/common.ps1`, `docs/MACHINE.md`). Nao usar o IDF v6 da maquina.
- `export-esp.ps1` no `%USERPROFILE%` (PATH do clang/gcc ESP) + esptool
  (`C:\.embuild\espressif\python_env\idf5.3_py3.12_env\Scripts\esptool.exe`
  ou `python -m esptool` como fallback). `scripts/common.ps1`
  (`Initialize-EspEnvironment`) aplica os tres automaticamente.
- Toolchain Rust ESP (`cargo +esp`) com `xtensa-esp32s3-espidf`.
- Portas: COM7 = S3 DevKitC-1 (CP210x); COM8 = TTGO classic (serial).
  COM3/COM4 sao link Bluetooth — ignorar (`docs/MACHINE.md`).
- Placa S3 identificada: ESP32-S3 QFN56 rev v0.2, 8 MB, MAC
  `80:65:99:df:4b:cc` (`docs/MACHINE.md`, `docs/HANDOFF-2026-10-20.md`).
- Gate antes de tocar no hardware:

```powershell
.\scripts\env-check.ps1            # exit 0 = pronto
cargo test -p aegis-fido-firmware --features freertos,proximity
cargo clippy -p aegis-fido-firmware --all-targets --features freertos,proximity -- -D warnings
python tools/host/win/proximity_agent.py --self-test
```

## 1. Flash da S3 (COM7)

Comando (build + flash + monitor opcional):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-freertos-s3.ps1
.\scripts\flash.ps1 -BinPath C:\t\aegis-app-freertos-s3.bin -Chip esp32s3 -Port COM7 -Baud 921600 -Monitor
```

O que o script faz (`scripts/common.ps1`): tenta download-mode por software
via `TEST_DOWNLOAD` (placa diag responde `download_mode`, sem botoes); se o
app nao responder (release sem test-mode, porta ocupada ou placa travada),
cai no fallback manual — segurar BOOT, apertar+soltar EN, continuar
segurando BOOT e teclar ENTER. Flash em `0x10000`, `--before no-reset`
`--after hard-reset`, retry a 115200 se 921600 falhar. Se a placa nao
bootar sozinha, apertar EN.

O que anotar na hora (evidencia da etapa): SHA256 + tamanho impressos por
`Test-FirmwareArtifact`, linha `Wrote N bytes ... Hash of data verified`
do esptool, porta usada.

PASS da etapa 1: esptool sai com exit 0, `Hash of data verified`, tamanho
<= teto factory (ler `crates/aegis-fido-firmware/partitions.csv`, sem
hardcode). FAIL: qualquer erro de escrita, hash divergente, ou placa muda
sem `Hard resetting via RTS pin` / sem boot seguinte (voltar ao fallback
BOOT+EN).

## 2. Boot + monitor serial (o que esperar no log)

Abrir monitor SEM derrubar a placa (armadilha DTR documentada em
`docs/validacao-usb-telas.md` §5: `pyserial` com DTR=True reseta a placa e
DTR preso no close segura o chip em reset):

```powershell
.\scripts\flash.ps1 -BinPath C:\t\aegis-app-freertos-s3.bin -Chip esp32s3 -Port COM7 -Monitor
python tools/live_monitor.py --port COM7 --log lt-boot.log
```

Linhas esperadas (fontes: `src/main.rs::run_authenticator_freertos`,
`src/freertos.rs::log_boot_info`):

- `[FREERTOS] AegisKey FreeRTOS variant booting (usb+button+housekeeping).`
- `[FREERTOS] boot tasks=<N> stack_high_water=<B>B core=<C>` (contadores
  via `uxTaskGetNumberOfTasks` / `uxTaskGetStackHighWaterMark`; sem
  segredos).
- Tarefas (`docs/freertos-rust.md`, `src/freertos.rs`): `usb_ctaphid`
  prio 5 / 8 KiB, `ui_button` prio 4 / 4 KiB, `housekeeping` prio 2 / 4 KiB.
  Ordem efetiva USB (5) > botao (4) > housekeeping (2); idle = 0.
- Bootloader IDF v5.3.1, app em `0x10000`, `ONLINE & ACTIVE` no super-loop;
  na variante freertos o loop do dispatcher drena a fila de 32
  (`DEFAULT_QUEUE_DEPTH`) + EventGroup.
- TWDT: cada `spawn_*` subscreve a tarefa (`esp_task_wdt_add(NULL)`) e
  alimenta por iteracao (`esp_task_wdt_reset()`); no log, ausencia de
  `task_wdt` / `TWDT` / `Task watchdog got triggered` e ausencia de reboot
  em loop. Qualquer `TWDT ... reset` = FAIL da etapa.
- Sem `panic`, sem `abort`, sem `undefined reference` em runtime, uptime
  monotonico.

PASS da etapa 2: as duas linhas `[FREERTOS]` presentes, tasks/prio/stack
conferindo com a tabela acima, zero reset TWDT em >= 90 s de monitor.
FAIL: panic, reboot loop, `Task watchdog got triggered`, ou placa muda
apos abrir o monitor (revisar DTR/RTS: usar `SerialLink` sem DTR/RTS ou
`setDTR(False)+setRTS(False)` no open E no close).

## 3. USB nativo (enumeracao + cerimonia WebAuthn)

A funcao FIDO2 vive na porta USB NATIVA (USB-OTG, TinyUSB HID
Usage Page `0xF1D0`); a COM7 (UART/CP210x) e logs + flash + monitor
(`docs/validacao-usb-telas.md` §5). Nao sao a mesma porta fisica.

3a. Enumeracao: ligar a S3 pela porta nativa e conferir no Gerenciador de
Dispositivos / PnP VID `0x303A` PID `0xAE61` (`src/identity.rs`
`DEFAULT_USB_VID`/`DEFAULT_USB_PID`; `components/aegis_usb/aegis_usb.c`
loga `VID: 0x%04X, PID: 0x%04X`). Problema (Problem code) deve ser 0.

3b. Sanidade de protocolo sem hardware (sempre verde antes do teste real):

```powershell
python tools/test_aegiskey_rust.py
```

Cobre CTAPHID (INIT 64 B, remontagem multi-pacote, keepalive), CCID/ATR,
roteamento YKOATH, scancodes OTP, WinUSB bulk + MS OS 2.0, e sobe
`tools/server.py` sozinho para testar `GET /api/status` (espera
`vid 0x303A`, `pid 0xAE61`, `transports` com `WinUSB`), register options
(`rp.id localhost`, `residentKey required`), credentials, PIN status e
`index.html`.

3c. Cerimonia WebAuthn de ponta a ponta no hardware:

```powershell
python tools/server.py   # sobe em http://localhost:8888, serve web/
```

Abrir `http://localhost:8888` no Chrome/Edge, criar credencial (MC) e
entrar (GA) com a S3 na porta nativa, tocando BOOT quando o navegador
pedir presenca. Referencia de ordem de grandeza (serial E2E anterior):
MC ~740 B, GA ~170 B (`docs/teste-ponta-a-ponta.md`).

PASS da etapa 3: VID/PID `0x303A:0xAE61` enumerados, Problem 0;
`test_aegiskey_rust.py` 8/8; MC+GA via browser OK com UP no BOOT.
FAIL: enumeracao com VID/PID errado, `test_aegiskey_rust.py` < 8/8, ou
MC/GA falhando com a chave na porta nativa (anotar se o erro e UP
nao tocado, RP id diferente de `localhost`, ou transporte errado).

## 4. UP fisico + LED (dedo no hardware)

- UP = botao fisico BOOT em GPIO 0 (active-low com pullup, `src/button.rs`).
  Toque = autoriza a transacao pendente (uso unico no latch legado).
  Hold BOOT 5 s = janela de pareamento 60 s (`src/pairing.rs`
  `LONG_PRESS_MS=5000`); LED respira azul na janela
  (`docs/HANDOFF-2026-10-20.md` adendo madrugada).
- LED = WS2812 em GPIO 48 (`src/led.rs::WS2812_GPIO_PIN`), efeito por
  estado: idle ciano respirando, pareamento azul, bonded verde solido,
  locked vermelho solido + radio mudo (ground-truth via
  `TEST_LED_{RED,GREEN,BLUE,OFF}` + `TEST_LED_STATE` na imagem diag;
  ver `docs/led-diagnostico.md`).
- KEY secundaria: GPIO 14 (T-Display) / GPIO 35 (TTGO classic)
  (`src/button.rs`, `src/main.rs` §4) — cancela/rejeita; nao usar como UP.

Checklist manual (olhos do operador):

- [ ] H1: hold BOOT 5 s -> LED azul respirando + janela 60 s.
- [ ] H2: tap BOOT durante MC/GA pendente -> operacao destrava.
- [ ] H3: cores idle ciano / pairing azul / bonded verde / locked vermelho.
- [ ] Sem UP, operacao privilegiada nega (gates `NEED_UP`/`NEED_PIN`/`NEED_BINDING`
  do E2E, `docs/teste-ponta-a-ponta.md` fases BASE).

PASS da etapa 4: H1+H2+H3 observados e anotados (cor + gesto + resultado);
operacao sem UP negada. FAIL: LED apagado/travado numa cor fora do mapa,
UP sem efeito (possivel stub: na variante freertos o botao real e
`is_pressed_raw` via `EspBootButtonInput`; se o dispatcher rodar stub
`false/false` de host, UP nunca chega — conferir qual imagem foi
flashada), ou hold 5 s sem abrir janela.

## 5. BLE bond + walk-away (proximity lock-only)

Politica implementada (`src/proximity.rs`, `docs/freertos-rust.md` loop 2,
`docs/proximity-worktree-handoff.md`): RSSI < -75 dBm por 10 s = `Away`
(`PROXIMITY_LOCK_RSSI_DBM`, `PROXIMITY_LOCK_SECS`); histerese 5 dB — volta
a `Near` so acima de -70 dBm; `Locked` so via `confirm_lock()`; sair de
`Locked` exige presenca fisica + PIN (`unlock`); `None` conta como fraco;
USB ativo veta amostra (`authorize_proximity_sample(bonded, usb_active) =
bonded && !usb_active`, `coex USB > BLE`); bonding obrigatorio.

5a. Self-test offline (sem hardware, sem radio):

```powershell
python tools/host/win/proximity_agent.py --self-test
python tools/host/win/test_proximity_agent.py
```

5b. Bond: com a janela aberta (hold BOOT 5 s ou `TEST_PAIRING_OPEN` na
imagem diag), parear/bond no SO do host (Windows: JustWorks; o firmware
responde `link seguro sem UP: toque no BOOT` e segura `pairing=0` ate o
toque — fail-closed por desenho). Anotar o MAC bonded do fob (sera o
`--fob-id`).

5c. Walk-away (agente lock-only, nunca auto-unlock):

```powershell
python tools/host/win/proximity_agent.py --fob-id <MAC-BONDED> --k-prox-hex <K_PROX> --lock-secs 10 --poll-secs 2
```

Sinais esperados: RSSI forte perto (`Near`), afastar o fob ate RSSI
sustentado < -75 dBm -> apos 10 s o agente chama `LockWorkStation`
(lock-only; login manual depois). Vetor de interop conhecido
(`K = 0x42*16`, fob `AA:BB:CC:DD:EE:FF`, ctr 7, VER `0x01` => TAG
`660d4941`) serve para conferir TAG sem hardware.

5d. Contra-provas obrigatorias:

- Volta NAO destrava: trazer o fob de volta apos o lock — a estacao
  continua bloqueada (sem auto-unlock por desenho).
- USB ativo silencia BLE: com USB montado (`aegis_usb_is_mounted`), o
  beacon/anuncio proximity e vetado (`USB` veta, `WiFi` desacelera).
- Calibracao: repetir o walk-away em 2 distancias e anotar o RSSI de
  transicao; se o ambiente exigir, ajustar `-75`/`5 dB` e registrar o
  novo par com motivo (nunca abaixar o limiar sem medir).

PASS da etapa 5: bond OK + walk-away trava em <= 15 s (10 s de dwell +
margem de poll), volta nao destrava, USB ativo veta anuncio, par
RSSI/histerese anotado. FAIL: lock sem `Away` sustentado (falso positivo),
volta destravando sozinha (viola lock-only), anuncio BLE com USB montado,
ou agente em `ticks-exhausted` sem lock apos 3 erros consecutivos de fonte
(watchdog fail-closed deve tracvar, nao silenciar).

## 6. Coleta de logs (o que salvar ao final)

Salvar juntos, com data/hora no nome, sem segredos (revisar antes de
arquivar — segredo em log = descartar o arquivo e repetir a captura):

- `esptool-flash-<data>.log`: transcript completo do flash (comando,
  `Wrote N bytes`, `Hash of data verified`).
- `C:\t\aegis-app-freertos-s3.bin.sha256` (sidecar gerado no build) +
  saida `Get-FileHash -Algorithm SHA256` do bin flashado.
- `monitor-boot-<data>.log`: captura serial crua do boot (>= 90 s,
  via `Invoke-SerialMonitor` ou `live_monitor.py --log`).
- `lt-boot.log` / `live-monitor-<data>.log`: eventos `[LT]` filtrados.
- `fw-log.txt`: dump do `FwLog` via op `0x38` (`EV_BOOT` marca o zero;
  anel e RAM, perde-se no reboot — coletar antes de qualquer reset).
- `test_aegiskey_rust-<data>.log`: saida do 8/8.
- `server-webauthn-<data>.log` + anotacao MC bytes / GA bytes / UP usado.
- `proximity-agent-<data>.log`: console do agente (RSSI, `away_secs`,
  `locked`, motivo `Unavailable/Unsupported/Replay/BadTag/Reverify`).
- `criterios-<data>.md`: para cada etapa abaixo, PASS/FAIL + evidencia
  (linha de log ou numero observado).

Comandos de apoio:

```powershell
Get-FileHash -LiteralPath C:\t\aegis-app-freertos-s3.bin -Algorithm SHA256
python tools/live_monitor.py --port COM7 --log lt-boot.log
python tools/live_monitor.py --self-test
```

## 7. Criterios de aceite por etapa (PASS/FAIL objetivos)

| Etapa | PASS | FAIL |
|---|---|---|
| 0 pre-req | `env-check` exit 0; testes host + clippy + `--self-test` verdes | qualquer gate vermelho (nao tocar no hardware) |
| 1 flash | exit 0, `Hash of data verified`, tamanho <= factory | erro esptool, hash divergente, placa sem boot |
| 2 boot | linhas `[FREERTOS] booting` + `boot tasks/high-water/core`; prio/stack da tabela; 90 s sem TWDT/panic/reboot | panic, reboot loop, `Task watchdog got triggered`, placa muda ao abrir monitor |
| 3 USB | VID `0x303A` PID `0xAE61` Problem 0; `test_aegiskey_rust.py` 8/8; MC+GA via `localhost:8888` com UP | VID/PID errado, suite < 8/8, MC/GA falhando na porta nativa |
| 4 UP+LED | H1/H2/H3 observados; sem UP nega | LED fora do mapa, UP sem efeito, hold 5 s sem janela |
| 5 BLE | bond OK; walk-away trava <= 15 s; volta nao destrava; USB veta anuncio; `-75/5 dB` anotados | falso lock, auto-unlock, anuncio com USB, watchdog silencioso |
| 6 logs | 9 arquivos/coletas da secao 6 arquivados, sem segredos | coleta incompleta ou com segredo (descartar e repetir) |

Etapa seguinte so comeca com a anterior em PASS. Qualquer FAIL vira
entrada no diario (sintoma, comando exato, trecho do log, hipotese) antes
de regravar ou trocar de placa/imagem. A variante classic da COM8 nao e
tocada por este roteiro.
