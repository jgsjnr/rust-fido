# Plano — tudo que está em amarelo

Legenda: [U] precisa do usuário/hardware · [A] executável pelo agente.
Ordem por dependência. Comandos prontos para copiar.

## Fase 1 — hardware vivo (COM7 + device + app)

### 1. Olhos no LED [U, 5 min]
```powershell
python tools/led_probe.py
```
Critério: RED/GREEN/BLUE/OFF sólidos. Se falhar → fix driver (IRQ +
GRB) + reflash + re-teste. Doc: `docs/led-diagnostico.md`.

### 2. Bond BLE + ops privilegiadas com UP [U+A]
```powershell
python tools/app_simulator.py --port COM7 --test-mode   # menu 11 abre 60s
python tools/ble_connect_test.py --mac 80:65:99:DF:4B:CE
```
Usuário segura/pressiona BOOT quando pedir UP. Critério: log com
scan→connect→bond→discover 0xFFFD→FFF4→subscribe FFF2→write FFF1→notify
+ GEN/DELETE com UP. Fecha `conexao-ble-fim-a-fim`.

### 3. Walk-away ≤15s [U+A]
```powershell
python tools/host/win/proximity_agent.py --fob-id <MAC-DO-FOB> --lock-secs 10
```
Afastar o fob; cronometrar lock (meta ≤15s); voltar NÃO destrava.
Critério: 3 ciclos lock sem auto-unlock. Fecha R-03 de proximidade.

### 4. OTA real no hardware [A+U]
```powershell
python tools/ota_server.py            # registro AEGIS-S3-*
python tools/factory_provision.py --dry-run --serial AEGIS-S3-TEST001
# fluxo: manifesto → CTAPHID 0x30+ → stage → verify → commit → boot
```
Critério: versão nova no boot + NVS (credenciais/OATH) intacta +
negativo (sig errada) com rollback sem brick. Fecha `sistema-ota`.

### 5. Vault roundtrip em placa [A]
Credencial residente → reboot físico → GetAssertion OK + dump
(`lt.pairing.*`, contadores) + `parity-report.md` em `snapshots/`.
Fecha `vault-cofre-flash-seguro`.

### 6. PIV no Windows (USB NATIVA, não UART) [U]
Conectar a porta nativa → Device Manager "AegisKey CCID" →
`certutil -scinfo` lendo CHUID/CCC + cert 9A. Fecha `piv-ble-proximity`.

### 7. APK em device [U+A]
```powershell
adb install -r app-android/app/build/outputs/apk/debug/app-debug.apk
```
Bond pelo app → tela Carteira: GEN Bitcoin (UP) + preview de endereço
+ lista `wallet:`; telas OATH/vault/smoke. Fecha R-07/R-08 (campo).

### 8. Step 5 validacao [A]
Preencher matriz tela×device com as evidências 1–7 + gate + merge.
Fecha `validacao-usb-telas`.

## Fase 2 — código

### 9. Transporte BLE da carteira [A, design primeiro]
Firmware hoje não instancia `WalletStore` (só core). Proposta:
instanciar + NVS (usar o codec `export/import_routing` já pronto) +
ops GATT novas em faixa livre (0x28–0x2D e 0x30+ ocupados; propor
0x34+), sem tocar AEGN/CBOR/GATT 0x01. Critério: GEN/LIST carteira via
BLE + NVS sobrevive reboot + app lista endereço. Testes host + serial.

### 10. Firmware-fina resto [A]
Decidir com medida (não por palpite): reassemble GATT (congelar —
framing §9.6), formatação display (ficar — LCD físico), retry WiFi
(medir `idf.py size` diff e mover só se >S). Registrar na tabela.

### 11. Killswitch: gesto + kill real [U/ext]
Gesto hold 5s colide com pareamento — **decisão de UX do usuário**
(opções: hold 10s / duplo-hold / só remoto). Kill real exige jig+HSM
(externo). Sem isso, item fica em "código pronto, gatilho pendente".

### 12. Auditoria formal [A]
`scripts/ci-grep-mocks.ps1` (ou grep) zerando mocks fora de
`#[cfg(test)]` + validar migração AEGN v1→v2 com teste de ida/volta +
paridade input→output documentada. Fecha `fido-auditoria`.

## Fase 3 — fechamento

### 13. Unificação + PR [A]
Relatório por frente (baseline `4b28aa4`, commits, decisão) na
`fd-integracao-unificada` + paridade final + PR para `main`.

## Resumo de bloqueios externos

Hardware/usuário: LED (1), UP físico (2), fob (3), placa p/ OTA/vault
(4–5), USB nativa + Windows (6), instalar APK (7). Externos: jig+HSM
(11), decisão UX do gesto (11). Todo o resto é executável aqui.
