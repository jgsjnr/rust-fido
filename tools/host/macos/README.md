# Proximity agent — macOS (CGSession)

Walk-away lock via BLE RSSI. Lock-only: suspende para a tela de login com
`CGSession -suspend` (melhor API disponível; equivale a fast-user-switch
para o login window) quando o fob fica AWAY (RSSI < -75 dBm, histerese
5 dB) por 10s. Nunca auto-destrava; erros de leitura contam como AWAY
(fail-closed).

> Nota: macOS não tem API pública de "lock workstation" para terceiros;
> `CGSession -suspend` é o mecanismo documentado pela comunidade e usado
> aqui. Comportamento validado por inspeção; travar exige sessão gráfica.

## Requisitos

- Fob pareado/bonded no Bluetooth do macOS.
- Python stdlib apenas; para scan real: `pip install bleak`.
- Permissão de Bluetooth para o terminal/IDE que roda o agente.

## Uso

```bash
python tools/host/macos/proximity_agent.py --self-test
python tools/host/macos/proximity_agent.py --simulate
python tools/host/macos/proximity_agent.py --fob-id AA:BB:CC:DD:EE:FF
python tools/host/macos/test_proximity_agent.py   # 21 testes, sem hardware
```

## Autostart

Use um LaunchAgent (`~/Library/LaunchAgents/dev.aegiskey.proximity.plist`)
chamando o comando com `--fob-id` acima.
