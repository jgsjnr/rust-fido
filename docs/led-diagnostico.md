# LED — diagnóstico flickering / ordem / verde (20/10)

Relato: app não lista o device; LED com flickering, fora de ordem, nunca
verde sólido; vermelho misturado com verde piscando.

## Ordem esperada (jornada)

`Idle` sem bond = CYAN respirando → `PairingBle` = AZUL respirando →
bond ok = VERDE sólido → `Locked`/timeout = VERMELHO sólido.
Verde **só** existe após bonding (`complete_pairing` + UP); sem bond
completo, verde sólido nunca aparece — por design.

## Achados (diag COM7, sem chute)

1. **App não lista = janela expirada.** Dump vivo: `lt.pairing.arming=3`,
   `lt.pairing.pairing=0` (bond nunca completou), `lt.pairing.timeout=1`
   → estado `Locked` → `should_advertise=false` → rádio mudo → scan com
   filtro 0xFFFD não acha nada. Com janela reaberta, scan achou
   `AegisKey` no MAC do device. Ação: reabrir (`TEST_PAIRING_OPEN` ou
   hold BOOT 5s) e escanear dentro dos 60s.
2. **Lógica do LED está correta no firmware.** `TEST_LED_STATE` pós-boot:
   `screen=IdleStandby pairing=Idle bonded=0 ... effect=Breathing CYAN
   2000ms` — exatamente o esperado. Escritores mapeados: `set_screen`
   (por tela) + override da jornada no B-block (só em `IdleStandby`) +
   `tick(elapsed)` com tempo absoluto — sem briga que explique
   vermelho+verde alternando.
3. **Em `Locked`, o firmware manda VERMELHO sólido.** Se o olho vê
   vermelho+verde piscando onde deveria ser vermelho sólido, o suspeito
   passa a ser o driver WS2812 (bit-bang por contagem de ciclos com
   `vTaskSuspendAll`, mas **sem** travar interrupções — WiFi/BLE/UART
   preemptam o trem de 30 µs e corrompem cor/timing) ou droop de
   alimentação com rádio ligado. Não mexido ainda — aguardando prova.

## Prova pendente (precisa dos seus olhos)

Com a diag atual, rode e me diga o que o LED mostra em cada passo:

```powershell
python tools/led_probe.py
# trava VERMELHO, VERDE, AZUL, OFF (2s cada) e solta no final
```

- Se RED/GREEN/BLUE/OFF aparecerem corretos e sólidos → driver OK;
  o blink anterior era estado `Locked` + efeito mal interpretado.
- Se alguma cor sair errada/piscando → corrijo o driver (seção crítica
  com interrupções desabilitadas + checagem da ordem GRB) e faço reflash.

Comandos manuais: `TEST_LED_STATE`, `TEST_LED_{RED,GREEN,BLUE,OFF}`,
`TEST_LED_RELEASE` (linhas ASCII via UART, test-mode only, sem
persistência, sem wipe).

## Achado 20/10 — driver endurecido (idle alternando azul/verde)

Olhos do usuário: idle alterna azul/verde separados (não ciano fundido)
= anomalia real de render. Causa raiz em duas camadas:
1. Timings na borda inferior da spec (T0H~200ns/T1H~550ns): qualquer
   jitter (ISR UART/systick, flash cache) virava bit → cor errada.
   Fix: centro da spec (T0H 400ns / T1H 800ns / período 1400ns).
2. Flicker correlacionado com tráfego UART confirma preempção por ISR
   no trem de 30 µs. Tentativa de `xt_ints_off/on` **brickou o boot
   (loop WDT, 7 resets/15s, morre no splash)** — revertida; sem trava
   de IRQ nos bindings (só `vPortExitCritical` existe, par assimétrico).
A validar: idle deve voltar a ciano fundido; `led_probe.py` nas primárias.
