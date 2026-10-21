# Próximos passos — o que ainda não foi implementado

Estado: `main@0743cbb` + branch `fd/finalizacao-linux` (Wave2-Step3 +
diag LED + agents linux/mac + docs). Gates verdes (406 + suítes).

## P0 — hardware imediato (precisa da placa)

1. **Flash release + boot** — bin pronto (`71FDF318…`, 2.646.512 B);
   travou sem COM7. No Linux: `./scripts/linux-bringup.sh --flash`.
   Critério: `Hash verified` + `ONLINE & ACTIVE`.
2. **Olhos no LED** (`docs/led-diagnostico.md`, `tools/led_probe.py`):
   confirmar primárias RED/GREEN/BLUE/OFF. Se falhar → fix driver
   (seção crítica sem IRQ + ordem GRB) + reflash + re-teste.
3. **COM8 classic** — build pronto (1.987.072 B); flashar + validar OOM
   por bandas + bateria serial.

## P1 — pareamento fim-a-fim no app

4. Bond JustWorks + UP + `pairing=1` com janela aberta (ritual em
   `docs/linux-bringup.md` §4). Se o app não listar com adv confirmado
   no scan → investigar filtro 0xFFFD/permissões (logs do app).
5. Proximidade em campo: parear fob e rodar agents (win/linux/mac).

## P2 — código pendente

6. **Killswitch**: commit atômico; plumbing ClientPIN→
   `pin_uv_authenticated`; gesto hold 5s (decisão UX); kill real exige
   jig+HSM (roteiro: `--confirm` hoje aborta em 4 por desenho).
7. **Carteira BLE fim-a-fim** (R-07): transporte BLE wallet + NVS
   rede→slot + UI rede/endereço + web buscando firmware. Base
   (`wallet/` store-only + aba web) existe; falta transporte + telas.
8. **App**: telas Bitcoin, menus por operação, jornada (parcial na
   árvore). **Bloqueio comum 7–8: sem Android SDK neste host** —
   fazer na máquina com SDK (`./gradlew assembleDebug`).
9. **Firmware fina** (R-09): mover getters públicos p/ `uniffi-bridge`,
   medir SIZE antes/depois (auditoria em `docs/firmware-fina.md` done).

## P3 — processo

10. PoC ponte ADB (`10.0.2.2:8888`, checar cleartext no manifest).
11. Unificação: integrar na `fd-integracao-unificada` cada frente quando
    marcada "finalizada" + paridade (test+clippy+AEGN+Python).
12. Push da branch (ver §push) + PR para `main` após Step 5 de
    `validacao-usb-telas` (gate + merge).

## Push

Branch local `fd/finalizacao-linux` (sem push — auth não confirmada):

```bash
git push -u origin fd/finalizacao-linux
```
