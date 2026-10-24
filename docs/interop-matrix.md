# interop-matrix - cliente x capacidade (T-FX-01)

> Task: T-FX-01 (plans/MATRIZ-TODO.md). Scope: docs/interop-matrix.md (NOVO).
> Regra: PROVADO exige evidencia verificavel (teste/log/commit). Sem isso
> e NAO-TESTADO. Sem par HW e ExternalBlocked. Nenhuma linha deste arquivo
> declara conformidade/certificacao FIDO: so ha evidencia funcional descrita
> abaixo; conformidade oficial exigiria teste oficial (nao executado aqui).
> ASCII puro. Sem flash/COM7 nesta lane (so leitura + consistencia).

## Legenda

- PROVADO: evidencia verificavel citada (ID de teste + onde conferir).
- NAO-TESTADO: caminho existe no contrato mas sem rodada registrada.
- ExternalBlocked: depende de par/HW/jig ausente nesta lane; nao fingir.
- Evidencias reutilizadas (nao reexecutadas aqui):
  - E1 = docs/teste-ponta-a-ponta.md (diario 20/10-23/10, T01-T22, D01-D08, B01-B04, H7/F4).
  - E2 = tools/e2e_user_test.py (fases base/pairing/all-safe/destructive/wipe/bench/usb).
  - E3 = tools/app_simulator.py --self-test (offline, sem hardware).
  - E4 = tools/host_sdk/cli.py --self-test (vetores TLV/gates/framing + F3).
  - E5 = docs/COMMS-map.md secao 1-8 (contrato fio: serial/USB/BLE/WiFi/TLV/fw-log).
  - E6 = capturas citadas em E1 (UART log por transferencia, USBPcap C:\t\ccid-hub1.pcap, scripts fora do repo em C:\t\).

## Matriz cliente x capacidade

| Cliente / via | Capacidade | Status | Evidencia verificavel |
|---|---|---|---|
| Browser WebAuthn via USB HID (usb_webauthn_test.html em localhost:8137) | MakeCredential (MC) | PROVADO | E1 20/10 USB via browser: MC OK attBytes=178 credIdBytes=16 (UP no BOOT); serial T17 MC 0x00 742-744B repetido 20/10-23/10 |
| Browser WebAuthn via USB HID (idem) | GetAssertion (GA) | PROVADO | E1 20/10: GA OK authBytes=37 sigBytes=70; serial T18 GA 0x00 169-171B repetido 20/10-23/10 |
| Browser WebAuthn via USB HID | GetInfo/PING raw via hidapi | NAO-TESTADO | E1 U2: PnP OK + Problem 0, mas hidapi/pywinusb cegos no ambiente (19 outros HIDs listados); prova funcional vale via browser, raw fica p/ depuracao futura do host |
| Windows PnP (USB nativo) | Enumeracao HID (VID 0x303A / PID 0xAE61) | PROVADO | E1 U1: Windows PnP OK (HID-compliant fido, Problem 0) |
| Windows + UsbCcids.sys (MI_01) | CCID handshake (PowerOn ATR, SetParameters, SetDataRateAndClock) | PROVADO | E1 20/10 F4: ATR uTrust 3b:96:11:81:21:75:75:54:72:75:73:74:73; seqs 6-9 status 0x00; opensc-tool -l lista AegisKey S3 Authenticator 0 com cartao presente |
| Windows + WUDF/UsbCcids (esta maquina) | SCardTransmit XFR (SELECT PIV e seguintes) | ExternalBlocked | E1 20/10-21/10: primeiro XFR falha 0x45D/0x54F; USBPcap prova ZERO URB com APDU/0x6F no hub (morre no WUDF); tentativas host-side sem efeito (pnputil, TEST_USB_RECONNECT, rebind MI_01); discriminador: outra porta USB2/USB3 ou 2o PC limpo |
| Linux Debian WSL2 + usbipd + pcscd/libccid/opensc | SELECT PIV + VERIFY + GENERATE 9A P-256 + GENERAL AUTH sign | PROVADO | E1 21/10 noite: opensc-tool -l Card Yes; ATR idem; SELECT PIV 9000; VERIFY 9000 (Lc=06 cru, exige SELECT na sessao); GENERATE 9A P-256 9000; GENERAL AUTH sign 9000 (7C 42 82 40 + 64B sig); XFR direto via pyusb 9000 |
| Linux/OpenSC | VERIFY com PIN FF-padded 8B (padrao driver PIV real) | NAO-TESTADO (follow-up aberto) | E1 21/10: FF-padded da 63C2 (applet compara hash cru 6-8B); normalizar strip-FF no applet e follow-up pendente |
| Host serial (app_simulator Session, COM7/UART 64B) | INIT/PING/GetInfo/fw-log (T01-T04) | PROVADO | E1 23/10 11:23 base + 23/10 11:40 base: T01 CID novo, T02 eco, T03 0x00 480B, T04 0x00 linhas EV; E3 offline |
| Host serial | Gates fail-closed (KEY_LIST sem UP 0x01; WALLET_GEN sem janela 0x05; rescue lixo 0x01; killswitch sem UP/PIN 0x04) | PROVADO | E1 T05/T06/T06b/T07/T07c 23/10 11:23 all-safe; T08 OTA-BEGIN sem janela nega; T09 getRetries 0x00 a2030804f4; T10 BIND_CHALLENGE sem posse 0x05 |
| Host serial + janela 60s + UP diag | KEY_GEN/LIST, OATH_PUT pede PIN 0x02, OATH_CODE, WALLET GEN/LIST/ADDR, rede invalida 0x04 | PROVADO | E1 23/10 11:23 all-safe: T13 slot 9 0x00, T14 0x00 132B, T15 0x02, T16 0x03 lista vazia, T19-T21 slot 6 bc1q... igual=True, T22 0x04 |
| Host serial | ClientPIN set/change/getToken (D03/D03b/D04) + recovery SET (D05a) + CLAIM/CHALLENGE (D06/D06b) | PROVADO | E1 20/10 13:20 destructive + 23/10 11:54 destructive: setPIN 0x00, token 32B oculto, changePIN 0x00/0x00, CLAIM 0x00 + challenge 32B |
| Host serial | RELEASE/RECOVERY_UNLOCK wipe + prova (challenge pos-wipe 0x05) | PROVADO | E1 20/10 14:39 wipe + 23/10 11:55 wipe: D07 0x00, D07b 0x05, D06c re-claim 0x00, D05b 0x00, D05c 0x05 |
| Host serial | OTA lab (bad-sig nega, BEGIN+CHUNKs+FINISH verify, COMMIT sem UP nega, COMMIT com UP marker, ABORT) | PROVADO | E1 20/10 18:56 base only=D08: D08a 0x04, D08b 20480/20480, D08c 0x00, D08d 0x01 sessao preservada, D08e 0x00 body=00000002, D08f 0x00; COMMIT real JAMAIS via serial |
| Host serial bench | PING/GetInfo/MC/GA timings | PROVADO | E1 23/10 11:23 bench: B01 20ms, B02 480B 67ms, B03 MC 812ms 742B, B04 GA 948ms 170B; E2 phase=bench |
| ykman / Nitrokey / YubiOTP tools | Rotas ext (6D00 fora de escopo) / deny ExternalBlocked | NAO-TESTADO | E5 secao 7: MAPPED (host) builders + menu 15, resposta honesta 6D00; sem rodada registrada contra device nesta lane |
| OpenSC PIV via BLE/CCID + F4 helpers (strip-FF/gen_auth/verify_pin) | SELECT/VERIFY/GEN AUTH fora do app terminal | NAO-TESTADO | E5 secao 7: MAPPED (host) helpers + menu 17, norma strip-FF; prova fim-a-fim pendente (remover logs debug C + poll antes do merge F6) |
| Teclado USB HID (keyboard OTP modhex/scancodes) | Digitacao OTP so digitos 6-8 apos UP | NAO-TESTADO | E5 secao 7: MAPPED (host) validador + menu 14; sem rodada contra device registrada |
| Proximity BLE 0xFFFE (K_prox, adv, walkaway) | Bonded->UP->coex, walkaway desconecta longe | ExternalBlocked | E5 secao 7 + E1 H4/H6 TODO: sem peer BLE dedicado nesta lane; scan/advertising (H4) e walkaway (H6) nunca rodados; USB ativo veta BLE-proximidade por desenho |
| App mobile (BLE GATT 0xFFFD FFF1-FFF4) | GEN/LIST/ADDR + menus controle fim-a-fim | ExternalBlocked | E1 H5 TODO: scan na janela + bond pelo celular + wallet fim-a-fim pendentes; sem celular pareado nesta lane |
| Gestos fisicos (H1-H3) | Hold BOOT 5s janela 60s / tap UP / cores LED | NAO-TESTADO | E1 H1/H2/H3 TODO: janela provada so via TEST_PAIRING_OPEN + trigger 0x2F (T11/T12 PROVADO); gesto com dedo nao registrado |
| PIV enroll 0x39 / USB CCID pleno no Windows | H7 completo | NAO-TESTADO | E1 H7 TODO: so HID no ar + CCID em crates; enroll e ciclo PIV pendentes |
| Rescue killswitch real (cmd 0x06 / EMERGENCY_WIPE_TOKEN) | Wipe real com jig+HSM | ExternalBlocked | E5 secao 7 + E2: builder + menu 18 com --confirm WIPE-ACK; kill real = ExternalBlocked (jig+HSM), nunca executar aqui; denies provados (T07c 0x04) |
| eFuse / Secure Boot / flash encryption / JTAG | Gravacao irreversivel | ExternalBlocked | Proibido por desenho (R13): sem burn eFuse/secure-boot no automatico; re-flash sem jig tem que sempre funcionar |
| Firefox / Safari / macOS / Android nativo | WebAuthn por navegador/SO | NAO-TESTADO | Nenhuma rodada registrada; nao declarar suporte sem teste oficial |
| Extensoes CTAP (hmac-secret, credBlob, credProtect, largeBlob, minPinLength, authConfig, payment, enterprise attestation) | Por extensao | NAO-TESTADO | Sem rodada por extensao registrada; T-FD-05 cobre no plano, sem prova ainda |
| PKCS#11 / OpenPGP Card 3.4.1 / secure messaging / CVC emissao remota | Smartcard pleno | NAO-TESTADO | T-PI-02/T-PI-03 TODO no plano; sem vetores rodados |

## O que NAO afirmar

- Nenhum PROVADO acima equivale a certificacao FIDO Alliance / FIPS / CC.
- Conformidade FIDO2/CTAP/WebAuthn so pode ser declarada apos teste oficial
  (conformance suite + certificacao); este arquivo nao executa nem substitui isso.
- Interop Windows-CCID segue ExternalBlocked nesta maquina (WUDF 0x45D/0x54F
  com zero URB); a prova valida e a via Linux/WSL documentada em E1.

## Rollback / revalidacao

- Rollback: deletar docs/interop-matrix.md (write-scope exclusivo T-FX-01).
- Revalidar: `cargo test --workspace` + `cargo clippy --all-targets -- -D warnings`
  (gate T-FX-01) + consistencia (todo PROVADO cita E1-E6 verificavel; ASCII puro).
- ASCII check: python -c "d=open('docs/interop-matrix.md','rb').read(); print('non-ascii!' if any(b>127 for b in d) else 'ascii-ok')".
