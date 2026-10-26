# Live Monitor (Wave7)

Terminal colorido, **somente leitura**, para as linhas `ltrace!` do firmware
com o feature `debug-terminal` (stdlib only, sem dependencias).

Le cada linha `[LT][<categoria>] <evento> detail=<detalhe>`, filtra, colore,
conta e calcula taxa (ev/s). Release sem `ltrace` = **"sem eventos"**
(esperado, nao erro).

## Contrato de leitura

- Win32 COM abre com `GENERIC_READ` apenas (sem `GENERIC_WRITE`).
- POSIX abre com `O_RDONLY` (sem `O_RDWR`).
- `tools/live_monitor.py` nao tem metodo `write` de proposito.
- Detalhes sao metadados (slot id, label OATH, retries, transporte, clock) --
  NUNCA segredo, chave, PIN ou codigo (mesma regra de `lifetime-debug.md`).

## Habilitar (dev only, nunca release)

```sh
cargo run -p aegis-fido-firmware --features debug-terminal
```

Release / auditoria usa features padrao: nenhum `ltrace` compilado,
monitor mostra `sem eventos`.

## Uso

```sh
python tools/live_monitor.py --port COM7
python tools/live_monitor.py --port /dev/ttyUSB0 --baud 115200
python tools/live_monitor.py --port COM7 --cat pin,oath --event retry,put
python tools/live_monitor.py --port COM7 --count 50 --log lt.log
python tools/live_monitor.py --input capture.txt --no-color
type capture.txt | python tools/live_monitor.py
python tools/live_monitor.py --self-test   # offline, sem hardware
```

| flag | efeito |
|---|---|
| `--port COM7` | abre serial **somente leitura** (omitido = stdin/`--input`) |
| `--baud 115200` | baud (default 115200 8N1) |
| `--cat pin,oath` | filtra categorias (csv, default todas) |
| `--event retry,put` | filtra eventos (csv, default todos) |
| `--count 50` | para apos N eventos filtrados |
| `--log lt.log` | anexa linhas `[LT]` cruas ao arquivo |
| `--input file` | replay offline de arquivo (sem hardware) |
| `--no-color` | saida plain, sem ANSI |
| `--self-test` | 10 checks offline, saida `10/10 passed` |

## Formato

```
[LT][key_slot] create detail=3
[LT][oath] put detail=GitHub:alice
[LT][pin] retry detail=7
```

Categorias: `key_slot`, `oath`, `pairing`, `pin`, `transport`.
Ver tabela completa evento -> quando -> exemplo em `docs/lifetime-debug.md`.

Linhas sem `[LT]` sao ignoradas e contadas como `ignored lines`.

## Stats

Ao final (ou Ctrl+C) o monitor imprime:

```
--- stats ---
total lines: 120
ltrace events: 15
ignored lines: 105
rate (5s window): 3.00 ev/s
pin.retry=7
...
```

Se `ltrace events: 0`, imprime tambem:

```
sem eventos (release sem ltrace ou filtro zerou tudo)
```

Isso significa: firmware release (feature off), filtro zerou tudo, ou
porta errada -- verifique `debug-terminal` e `--cat/--event`.

## Seguranca

- Nao envia nada ao dispositivo (sem `write`, sem comandos).
- Nao armazena detalhes: contadores guardam so contagens.
- `--log` grava so linhas `[LT]` cruas (metadados, nunca segredos).
- Audite com `python tools/live_monitor.py --self-test` (verde obrigatorio).

## Troubleshooting

| sintoma | causa provavel | acao |
|---|---|---|
| `sem eventos` | firmware release (sem `debug-terminal`) | rode com `--features debug-terminal` |
| `sem eventos` | filtro `--cat/--event` zerou | remova filtros, rode sem `--cat` |
| `cannot open COM7` | porta ocupada/errada | liste portas, feche `app_simulator.py` |
| cores quebradas | terminal sem ANSI | use `--no-color` |
| taxa 0.00 ev/s | rajada fora da janela 5s | normal em idle, force evento (ex. retry) |
