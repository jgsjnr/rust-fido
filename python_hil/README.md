# python_hil

HIL USB/BLE/WiFi/SIM — links + app + piloto + testes (lane `fd/hil-usb-tests`).

## Ativacao

```powershell
python -m venv .venv; ./.venv/Scripts/Activate.ps1; pip install -r python_hil/requirements.txt
```

## Como rodar

```powershell
pytest python_hil/tests -v                          # sem HW: offline passa, HW skipa
pytest python_hil/tests -v --uart COM7              # L2 com HW UART (COM7 115200, sem DTR/RTS)
pytest python_hil/tests/test_l1_sim.py -v --tcp 127.0.0.1:5678     # L1 no sim (Renode/QEMU)
pytest python_hil/tests/test_l1_sim.py -v --tb=short --tcp 127.0.0.1:5678
python -m python_hil.sim_pilot --self-test          # loopback local (prova camada, nao e HW)
python -m python_hil.sim_pilot --tcp 127.0.0.1:5678 # piloto Renode (`sim fido-s3-v3.resc` :5678) / QEMU (bins C:\t\*.bin)
python -m python_hil.sim_pilot --uart COM7          # piloto via UART fisica
python -m python_hil.app_usb_sim --self-test        # vetores offline, sem HW
python -m python_hil.app_usb_sim                    # menus 0-18 (exige USB 303A:AE61)
```

Flags extras do pytest (ver `python_hil/conftest.py`): `--uart COM7`,
`--tcp 127.0.0.1:5678`, `--ap-base http://192.168.4.1`, `--ble-addr <addr>`.

Multiprocesso E2E (quando aplicavel): `pytest -n auto --test-threads=1`;
reporte o resultado focado exato (1 linha por teste). Builds, trafego
simulado, portas, screenshots, emuladores e handshakes nao sao aceite fisico.

## Falha sem HW

Sem UART/USB/BLE/AP/sim a suite faz SKIP com motivo documentado
(`HwMissingError`/`PilotFail` viram `pytest.skip`); copie
`docs_hil/falha-TEMPLATE.md` para registrar. Detalhes em `docs_hil/README.md`.
Log sanitizado: contagens, nunca segredo.
