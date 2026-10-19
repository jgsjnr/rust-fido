# Validacao USB + telas — matriz e modificacoes necessarias

**Data:** 2026-10-19 · **Topic:** validacao-usb-telas · **Status:** parcial (COM7 ausente)

## 1. Emulador (sem hardware) — 22/22 PASS
Todas as telas abrem sem crash e sem FATAL; sem device mostram vazio/erro amigável.
Permissão BT negada: abre normal, sem SecurityException. FLAG_SECURE confirmado
(screenshots pretos são proteção, não bug — validar por dumpsys/hierarquia).

## 2. Serial E2E COM8 (classic, UART0 115200 8N1)
- Link OK (heartbeat ~3s, `USB Mounted: true`, uptime crescente, sem reboot).
- CTAPHID via serial: FAIL — firmware fala texto heartbeat, não framing 64B
  (`unexpected continuation`; roteamento serial→CtapHidManager é follow-up).
- Jornada display: defeito conhecido (OOM 64KB) — fix por bandas já commitado,
  aguardando flash + validação IRL.
- Monitor: 0 linhas `[LT]` em 60s (firmware sem `debug-terminal`).

## 3. Serial E2E COM7 (S3) — placa viva, protocolo ausente
- S3 viva: heartbeat 3s, uptime 207→234s, `USB Mounted: false`.
- Serial fala texto heartbeat, NÃO CTAPHID-64B (`unexpected continuation` /
  timeouts de 3/64 bytes); firmware sem test-mode (dump sem resposta).
- Ops privilegiadas corretamente negadas sem hold físico (5s + menu 9).
- Live capture: 0 eventos `[LT]` em 45s (só heartbeat).
- Mesmo diagnóstico da COM8: falta roteamento serial→CtapHidManager no firmware.
Placa desplugada no momento (sem COM7, sem ROM PID 1001). Reagendar ao reconectar:
`app_simulator --port COM7 --test-mode` + `live_monitor --port COM7 --log`.

## 4. Ponte ADB→proxy→serial — VEREDITO: VIÁVEL
Emulador alcança host via `http://10.0.2.2:8888` (sem `adb forward`; app já tem
base URL configurável). Proxy = `http.server` + framing 64B de `app_simulator.py`.
Firmware: zero mudanças. Checar cleartext policy antes do PoC.

## 5. Qual USB usar na S3
- **UART** (CP210x/CH9102, vira COM): logs, monitor, flash via esptool.
- **NATIVA USB-OTG**: função FIDO2 HID (VID 0x303A/PID 0xAE61, aparece como HID,
  não como COM) + JTAG-serial + download.
- Uso no PC/celular como chave = porta NATIVA. Monitor/teste = UART 115200.

## 6. Modificacoes necessarias (por prioridade)
1. [ ] Flash classic com build de bandas + validar fim do OOM (COM8).
2. [ ] Reconectar S3, rodar bateria COM7 completa.
3. [ ] PoC ponte `10.0.2.2:8888` (checar cleartext no manifest).
4. [ ] Firmware com CTAPHID-serial + test-mode + refazer baterias com hold 5s humano.
4. [ ] Roteamento serial→CTAPHID no firmware (follow-up; hoje só heartbeat).
5. [ ] `firmware` com `debug-terminal` nos devices de teste (para `[LT]`).
6. [ ] Tela preta no emulador: já explicado (FLAG_SECURE); sem ação.
