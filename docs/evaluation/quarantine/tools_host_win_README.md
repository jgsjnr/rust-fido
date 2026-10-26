# Fido BLE proximity agent (Windows)

Host-only, lock-only. Trava a estação (`LockWorkStation` via `ctypes`)
quando o fob BLE fica AWAY por ≥ `lock_secs`. Sem auto-unlock: após
travar, só login manual destrava. Fail-closed: BLE com erro, leitura
perdida ou agente morto → conta como AWAY e trava após o timeout;
nunca fail-open silencioso. Zero firmware (host-only).

## Decisão de linguagem

Python (stdlib only, sem `bleak` em Wave 1). Duas linhas: `tools/` já é
Python com padrão stdlib+`ctypes`+`argparse` (`live_monitor.py`,
`app_simulator.py`), então o agente roda sem toolchain ESP/Rust e sem
`pip install`; Rust std-only não resolveria sem novas deps de BLE no
Windows, o que quebraria o requisito offline desta step.

## Pairing BT (fob ↔ Windows)

1. Ligue o fob (firmware com NimBLE `bleprph`).
2. Windows → Configurações → Bluetooth e dispositivos → Adicionar
   dispositivo → Bluetooth.
3. Selecione o fob (`fido-*` / endereço do provisionamento) e conclua o
   pareamento/bond.
4. Anote o endereço (ex.: `AA:BB:CC:DD:EE:FF`) — é o `--fob-id` do agente.
5. Opcional: `Configurações → Bluetooth → Mostrar endereço` ou
   `getmac /v` para confirmar que o bond persiste após reboot.

> Segurança (H-2): Wave 1 aceita qualquer anúncio com o `--fob-id`
> para fins de *lock-only*; validar identidade bonded (MAC/IRK +
> pairing) e anti-replay (nonce/desafio) é TODO Wave 2 — ver
> `make_polling_source()`. Sem canal autenticado, o agente NUNCA
> destrava nada.

## Instalação

- Requisito: Windows 10/11 + Python 3.10+ (stdlib only, sem pip).
- Nenhuma dependência: copie `tools/host/win/` ou rode da worktree.
- (Opcional) agendar no logon: Agendador de Tarefas → `python
  tools\host\win\proximity_agent.py --fob-id AA:BB:CC:DD:EE:FF`.

## Uso

```bat
python tools\host\win\proximity_agent.py --fob-id AA:BB:CC:DD:EE:FF
python tools\host\win\proximity_agent.py --fob-id AA:BB:CC:DD:EE:FF --threshold-db -75 --lock-secs 10 --poll-secs 2
python tools\host\win\proximity_agent.py --simulate
python tools\host\win\proximity_agent.py --self-test
python tools\host\win\test_proximity_agent.py
```

| Flag | Padrão | Efeito |
|---|---|---|
| `--fob-id` | — | endereço/ID bonded do fob (obrigatório sem `--simulate`) |
| `--threshold-db` | `-75` | RSSI < valor = AWAY; volta a NEAR em valor+5 dB (histerese) |
| `--lock-secs` | `10` | AWAY contínuo até travar |
| `--poll-secs` | `2` | intervalo de polling |
| `--simulate` | off | fonte offline p/ demo sem hardware |
| `--self-test` | off | checagem offline sem hardware |

## Teste manual (afastar o fob ≤ 15 s)

1. Pareie o fob e rode o agente com `--lock-secs 10 --poll-secs 2`.
2. Com o fob ao lado do PC, confirme que NÃO trava (NEAR).
3. Afaste o fob (> 5 m / outro cômodo, ou desligue o BT do fob).
4. Em ≤ ~15 s a estação deve travar (10 s de AWAY + 1 poll de margem).
5. Traga o fob de volta: continua travada (sem auto-unlock) — faça
   login manual. Reabra o agente se ele já saiu após o lock.

## Backend BLE real (TODO Wave 2)

`make_polling_source()` hoje levanta `OSError` (fail-closed) porque o
ambiente desta step é offline. Wave 2: implementar com `bleak`
(`BleakScanner` filtrado pelo `fob-id` bonded + leitura RSSI por poll),
validar identidade bonded e documentar anti-replay. Enquanto isso, o
loop aceita qualquer fonte RSSI injetável (`run_loop(read_rssi, ...)`)
— é assim que os testes automatizados rodam sem hardware.
