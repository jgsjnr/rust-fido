# Bonding + Walk-away — runbook turnkey da sessao fisica

Runbook da sessao fisica de bonding + walk-away. Nao executa nada sozinho:
cada passo tem comando + readback esperado para o operador na bancada.
Base provada no repo (build over-air `0217C145`, commit `bf81701`); o que
nao foi provado no device esta marcado `A CONFIRMAR`.

Referencias normativas (nao duplicadas aqui): `docs/ble-protocol.md`
(contrato de fio §1-§4 + §11-§13), `docs/ble-nimble.md` (radio),
`docs/binding.md` (claim/challenge), `docs/test-hooks.md` (TEST-*),
`docs/bench-freertos-s3.md` §5 (bond + walk-away), `docs/estado-final-firmware.md`.

## 1. Pre-requisitos

1. Placa ESP32-S3 em `COM7` com build over-air `0217C145` ou posterior.
   Prova da base nesse build: preinit `rc=0`, `adv on` em janela, scan
   achou `AegisKey` a -30 dBm, GATT `0xFFFD` via bleak (FFF1-FFF4),
   GetInfo `83000104` -> `8301` sem UP -> `8300` + 251 B com UP, close
   mudo sem OOM/abort. (`docs/estado-final-firmware.md`).
2. Peer BLE: um celular com nRF Connect **OU** uma segunda board como
   central. `A CONFIRMAR`: cobertura GATT completa com 2a board como
   central nao foi provada no device; nRF Connect e o caminho provado.
3. Presenca fisica: operador ao alcance do botao BOOT (GPIO0) para o
   hold de 5 s e para os toques de UP. Sem presenca a sessao nao anda
   (fail-closed por desenho).
4. Serial 115200 8N1 aberta para leitura do console (`UART0`). Nao abrir
   `COM7` de outro processo ao mesmo tempo (porta ocupada = monitor mudo).
5. Imagem: para `TEST_PAIRING_OPEN` / `TEST_UP` / `TEST_BLE_PREINIT` a
   imagem precisa ser `test-mode` (diag). Release ignora `TEST_*`
   (linha desconhecida, sem resposta). `A CONFIRMAR`: qual binario esta
   flashado na placa antes de comecar (checar pelo boot log).
6. Proximidade (etapa walk-away): agente host em
   `tools/host/<win,linux,macos>/proximity_agent.py`, MAC bonded do fob
   anotado (`--fob-id`), `K_prox` do pareamento (`--k-prox-hex`).
   `A CONFIRMAR`: valor corrente de `K_prox` no device (rekey no Paired,
   `ctr=0`; ver `[PROX] rekey pos-pareamento` no console).

Constantes que o runbook assume (codigo, nao decorar):

- `LONG_PRESS_MS = 5000`, debounce 50 ms (`config.rs`, `pairing.rs`).
- `PAIRING_WINDOW_SECS = 60` (`PAIRING_WINDOW_MS = 60000`).
- GATT `0xFFFD`, chars `FFF1` (write), `FFF2` (notify), `FFF3` (len `u16 LE`),
  `FFF4` (revisao `0x01`). (`docs/ble-protocol.md` §1).
- fw-log op `0x38`: linha ASCII `SEQ EV=cc ARG=aa T=ms` (`fw_log.rs`).
  BLE exige vinculo (sem vinculo -> `0x05`); serial fisica e livre.
- `BIND_CHALLENGE` op `0x29`: req 0 B -> resp 32 B TRNG; exige Claimed
  (senao `NEED_BINDING 0x05`); cada challenge novo invalida o anterior.

## 2. Passo a passo (comando + readback esperado)

1. Boot sano. Comando: resetar a placa e ler o console serial.
   Readback: linha de boot sem panic. `A CONFIRMAR`: texto exato do
   boot desta variante (ex.: `[FREERTOS] AegisKey ... booting`).
2. Sanidade BLE (imagem diag). Comando (serial): `TEST_BLE_PREINIT`.
   Readback: linhas `[BLE] heap antes ...`, `[TEST] ble preinit rc=0 ...`,
   `[BLE] preinit ok; ...` e resposta `ble_preinit rc=0`. `rc != 0`
   = parar aqui (ver tabela §3).
3. Abrir a janela de pareamento — caminho fisico (preferido).
   Comando: segurar BOOT por 5 s ate entrar em pareamento.
   Readback: fw-log (op `0x38` via serial) ganha `EV=4` (`EV_PAIR_OPEN`);
   console mostra subida do advertising; AP fallback sobe durante o
   pareamento. Alternativa diag: `TEST_PAIRING_OPEN` -> ack exato
   `pairing_open window_s=60 source=software` (variante lenta
   `TEST_PAIRING_OPEN_300` -> `pairing_open window_s=300 source=software`).
   Software abre a janela mas NAO confirma presenca nem bonding.
4. Ver o advertising. Comando: scan no peer (nRF Connect: scan).
   Readback: aparece `AegisKey` (UUID `0xFFFD` + flag pairing `0x01`,
   nome `AegisKey`, `<= 31 B`). Referencia provada: `-30 dBm` a curta
   distancia no build `0217C145`. Sem `AegisKey` no scan = parar (ver §3).
5. Conectar. Comando: conectar no `AegisKey` pelo peer.
   Readback no console: `[BLE] central conectou (aguardando bonding).`
   Descoberta GATT deve listar `FFF1`-`FFF4` sob `0xFFFD`, `FFF4 = 0x01`.
6. Bonding. Comando: parear/bond no SO do peer (Windows: JustWorks).
   Readback caminho feliz: `[BLE] bonding ok: advertising parado,
   pareamento encerrado.` + fw-log `EV=6` (`EV_BOND_OK`) + tela
   `DISPOSITIVO PAREADO` + LED verde solido. `A CONFIRMAR` no device:
   ordem exata dessas tres saidas nesta placa/imagem.
   Readback caminho sem UP no latch: `[BLE] link seguro sem UP: toque
   no BOOT para confirmar.` e `ble_bond_pending` segura `pairing=0`
   (fail-closed correto). Acao: tocar no BOOT dentro da janela; ai cai
   no caminho feliz. Fora da janela: `[BLE] link seguro fora da janela:
   ignorado.` -> reabrir a janela (passo 3).
   `A CONFIRMAR`: byte/ff exato do `EV_BOND_OK` nesta sessao (esperado
   `SEQ EV=6 ARG=0 T=<ms>`).
7. `BIND_CHALLENGE` over-GATT. Pre-condicao: vinculo Claimed
   (`0x28 CLAIM` feito antes com pareamento + UP; ver `docs/binding.md`).
   Comando: escrever no `FFF1` o framing `§3` com op `0x29` e payload 0 B.
   Readback: resposta `[0x29, 0x00, challenge[32]]` (`status 0x00`).
   Sem Claimed o esperado e `0x05` (`NEED_BINDING`), sem vazar nada.
   `A CONFIRMAR` no device: sequencia CLAIM -> CHALLENGE nesta sessao
   nunca foi rodada over-air com release (bypass `test-mode` desliga a
   cripto de transporte; release exige prova real).
8. GetInfo autenticado. Comando: `FFF1` com `MSG 0x83` encapsulando CTAP
   `authenticatorGetInfo (0x04)` — bytes de fio provados `83000104`.
   Readback sem UP: `8301` (`NEED_UP`). Acao: tocar no BOOT (latch 1x,
   1,5 s; ou `TEST_UP` -> `up_latched source=software` na imagem diag)
   e repetir. Readback com UP: `8300` + GetInfo (~251 B no build
   `0217C145`). Esse e o padrao de todo op com gate UP: negar sem toque
   e passar com toque dentro do latch.
9. Ler o fw-log. Comando serial (posse fisica, livre): op `0x38`
   (resposta `0x00 + ASCII`); over-BLE o mesmo `0x38` exige vinculo
   (sem vinculo -> `0x05`, nunca UP nem PIN).
   Readback: linhas `SEQ EV=cc ARG=aa T=ms`, com pelo menos
   `EV=1` (BOOT), `EV=4` (PAIR_OPEN), `EV=6` (BOND_OK),
   `EV=9/10` (`OP_RX`/`OP_RESP`). `EV=17` (`EV_ADV_NOMEM`) so aparece
   no caso `rc=519` (ver §3). Anel e RAM (64 entradas): coletar antes
   de qualquer reset.
10. Fechar a janela. Comando: `TEST_PAIRING_CLOSE` (diag) -> ack exato
    `pairing_closed source=software`; ou deixar expirar (60 s) ou novo
    hold. Readback: fw-log `EV=5` (`EV_PAIR_CLOSE`) + radio mudo
    (`EV=3`, `EV_ADV_STOP`) + `[WIFI] AP off (pairing fechado).`
    `A CONFIRMAR`: latencia exata do `AP off` nesta imagem.
11. Walk-away. Comando (host):
    `python tools/host/win/proximity_agent.py --fob-id <MAC-BONDED> --k-prox-hex <K_PROX> --lock-secs 10 --poll-secs 2`
    (linux/macos: mesmo caminho no seu SO).
    Readback: perto = `Near` com RSSI forte; afastar o fob ate RSSI
    sustentado `< -75 dBm` por 10 s -> agente chama `LockWorkStation`
    (lock-only; login manual depois). Vetor de interop sem hardware:
    `K=0x42*16`, fob `AA:BB:CC:DD:EE:FF`, `ctr=7`, `VER=0x01` =>
    `TAG=660d4941` (py == rs). `A CONFIRMAR`: par `-75/5 dB` no ambiente
    real (calibrar em 2 distancias; ver §4).
12. Contra-provas do walk-away (obrigatorias, mesma sessao):
    a) voltar NAO destrava (estacao segue bloqueada; sem auto-unlock);
    b) USB montado veta o anuncio proximity (`coex USB > BLE`);
    c) watchdog: 3 erros consecutivos de fonte -> lock (fail-closed),
    nunca silenciar. Qualquer desvio = FAIL da etapa.
13. Voltar (reconnect sem nova cerimonia?). Comando: trazer o fob/peer
    de volta para perto e observar o anuncio de reconnect.
    Readback esperado pelo codigo (`should_advertise_reconnect`:
    `Idle` + confiavel com flag de pareamento APAGADA — so reconecta,
    parear de novo exige janela). `A CONFIRMAR` no device: que o
    reconnect recifra e reemite SECURED sem pedir hold novo, e que o
    desbloqueio continua exigindo presenca + PIN (nunca RSSI sozinho).

## 3. Falhas conhecidas e o que cada sintoma significa

| Sintoma (texto/linha) | Significado | Acao |
|---|---|---|
| `rc=519` / `EV=17` (`EV_ADV_NOMEM`) | HCI Memory Capacity Exceeded: controller recusou o adv com instancia residual. Nao consome retry do gate (`BleStartGate::on_nomem`); backoff ate nova borda. Historico real, comportamento esperado. | Aguardar nova borda/janela; nao forcar retry cego. |
| `AP start rc=-4 NO_MEM` / `[WIFI] AP skip (heap curto).` | Sem bloco contiguo para o driver WiFi (guarda de heap). Terminal ate nova borda, sem retry. Historico real. | Fechar pareamento/AP e tentar em nova borda; nao insistir no poll. |
| AP seguia `Active` apos close + OOM/abort; `close` com spam `lt.transport.close=576` | Bug real ja corrigido: faltava `shutdown_after_config` + `esp_ap_stop` no close, e o `else` chamava stop a cada poll. Fix: edge-trigger (`ap_poll_action`) + shutdown no `EV_PAIR_CLOSE`. | Se reaparecer, coletar fw-log + console e abortar a sessao (regressao). |
| Adv mudo apos `TEST_PAIRING_OPEN` (so AP subia) | Bug real ja corrigido: gate BLE olhava so `pairing_mgr`, e a janela TEST vive em `freertos_test`. Fix: OR das duas janelas no poll. | Se reaparecer, confirmar que a janela TEST esta aberta (`EV=4` presente) e reportar. |
| `LoadProhibited` no boot BLE / duplo `gatts_start` | Root-cause historica ja removida (preinit idempotente + null-guards). Build `0217C145` prova `rc=0`. | `rc != 0` em `TEST_BLE_PREINIT` = parar; anexar heap antes/depois. |
| `Malloc failed` / Interrupt WDT no primeiro pareamento | Heap curto com retry a cada poll realocando o controller por cima. Fix: gate 1 tentativa/5 s, max 3 por borda. | Nao desabilitar o gate; coletar `heap livre/maior bloco`. |
| `[BLE] link seguro sem UP: toque no BOOT` + `pairing=0` | Fail-closed correto (UP ausente), nao bug. | Tocar no BOOT dentro da janela e repetir. |
| `[BLE] link seguro fora da janela: ignorado.` | Bonding fora da janela de 60 s. | Reabrir a janela (passo 3) e parear de novo. |
| `[PROX] fob_id via placeholder (FFI rc=-1)` | FFI do MAC real indisponivel; fallback documentado. Release proibe XOR-fold. | Anotar; nao usar o vetor placeholder como prova de fob real. |
| `[PROX] sem K_prox fail-closed` | Sem chave proximity (ainda sem `rekey` no Paired). Beacon vetado por desenho. | Parear/bond primeiro; `K_prox` so nasce no Paired (`ctr=0`). |
| `0x05` em op CONFIG/BLE (inclui `0x38` via BLE sem vinculo) | `NEED_BINDING`: app alheio / sem claim. Ordem canonica binding -> UP -> PIN. | Fazer CLAIM + UP antes; via serial o `0x38` continua livre. |
| `8301` no GetInfo | `NEED_UP`: latch ausente/expirado (1x, 1,5 s). | Tocar BOOT (ou `TEST_UP` na diag) e repetir dentro do latch. |
| Agente em `ticks-exhausted` sem lock apos 3 erros | Watchdog fail-closed deve travar, nao silenciar. Se silenciou, e FAIL. | Repetir com fonte de scan valida; registrar motivo (`Unavailable/Unsupported/Replay/BadTag/Reverify`). |
| `COM7` ocupada / monitor mudo | Outro processo com a porta (simulador, outro monitor) ou baud errado. | Fechar o outro lado, conferir 115200 8N1, reabrir so-leitura. |

## 4. Checklist de aceite da sessao fisica

- [ ] Janela abriu (hold 5 s ou `TEST_PAIRING_OPEN` com ack) e `EV=4` esta no fw-log.
- [ ] Scan achou `AegisKey` (`0xFFFD`, flag `0x01`) e GATT listou `FFF1`-`FFF4` (`FFF4 = 0x01`).
- [ ] Bonding concluiu: console `bonding ok ...` + `EV=6` + `DISPOSITIVO PAREADO` + LED verde; ou pendencia de UP tratada com toque dentro da janela.
- [ ] `0x29 BIND_CHALLENGE` over-GATT devolveu 32 B (`0x00`); sem claim o device negou `0x05`. (`A CONFIRMAR` em release.)
- [ ] GetInfo `83000104` negou `8301` sem UP e entregou `8300` + GetInfo com UP.
- [ ] Fechamento registrado: `EV=5` + `EV=3` + `[WIFI] AP off (pairing fechado).`
- [ ] Walk-away travou em `<= 15 s` (10 s dwell + margem de poll), volta nao destravou, USB montado vetou anuncio, par RSSI/histerese anotado.
- [ ] Reconnect observado sem nova cerimonia de pareamento, sem auto-unlock. (`A CONFIRMAR`.)
- [ ] Logs salvos juntos (sem segredos): console do flash/boot, fw-log `0x38` antes de qualquer reset, console do agente (`RSSI`, `away_secs`, `locked`, motivo), criterios PASS/FAIL por etapa.
