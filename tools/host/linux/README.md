# Proximity agent — Linux (logind)

Walk-away lock via BLE RSSI. Lock-only: trava com `loginctl lock-session`
quando o fob fica AWAY (RSSI < -75 dBm, histerese 5 dB) por 10s. Nunca
auto-destrava; erros de leitura contam como AWAY (fail-closed).

## Requisitos

- BlueZ + fob pareado/bonded com o host (`bluetoothctl pair/bond`).
- Python stdlib apenas; para scan real: `pip install bleak`.
- Sessão gerida por logind (GNOME/KDE/systemd).

## Uso

```bash
python tools/host/linux/proximity_agent.py --self-test
python tools/host/linux/proximity_agent.py --simulate
python tools/host/linux/proximity_agent.py --fob-id AA:BB:CC:DD:EE:FF
python tools/host/linux/test_proximity_agent.py   # 21 testes, sem hardware
```

## Autostart (systemd --user)

```ini
[Unit]
Description=AegisKey proximity lock
[Service]
ExecStart=/usr/bin/python3 %h/projetos/fido/tools/host/linux/proximity_agent.py --fob-id AA:BB:CC:DD:EE:FF
Restart=always
[Install]
WantedBy=default.target
```
