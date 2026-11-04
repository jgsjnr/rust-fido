# IDEAS_BACKLOG — backlog implementavel (ESP32-S3)

Ordem: valor/esforco dentro do envelope do hardware. Sem hardware nesta sessao; tudo abaixo e trabalho de codigo/host.
Sem emojis por regra do repo.

## Envelope de hardware (nao negociar)

- Alvo principal: 16 MB flash (T-Display-S3), app full hoje ~1,9 MB (`scripts/capability-catalog.json:8-14`).
- Variante 2 MB (DevKitC-1): factory budget 1,5 MB; full ESTOURA, dieta passa:
  fido-only 1,13 MB, fido-totp 1,25 MB (`reports/refactoring/CAPABILITY_DIET.md:16-28`).
- Storage NVS: 448 KiB (layout 2 MB) / 896 KiB (layout 16 MB); residente full ~102 KiB (`CAPABILITY_DIET.md:111-124`).
- OTA staging (896 KiB) nao cabe no storage 2 MB: la o fluxo tem que ser streaming (`capability-catalog.json:443`).
- BLE: 1 bond max (`BLE_NIMBLE_MAX_BONDS=1`, `capability-catalog.json:405-409`); display so em board com LCD
  (devkitc usa stub headless, `crates/aegis-fido-firmware/src/display/mod.rs:7`).

Legenda: tamanho S (dias), M (1-3 semanas), L (mes+). Preset: onde cabe sem estourar a dieta.
Evidencias citam `arquivo:linha` verificado em 2026-11-03 no branch `fd/finalizacao-s3`.

## 1. FIDO / autenticacao (prioridade maxima)

1. [PARTIAL] UX completa de resident keys: listar/renomear/apagar por RP no app (S; full/fido-totp/fido-only).
   Falta a camada de apresentacao; o firmware ja tem quota de 32 slots e CredMgmt (`cred_store.rs:145`,
   `crates/aegis-fido-core/src/ctap/cred_mgmt.rs:70,139`). Dep: nada.
2. [PARTIAL] hmac-secret utilizavel de ponta a ponta (M; full/fido-only/fido-totp).
   Engine CTAP 2.1 pronto e testado (`ctap/extensions_ctap21.rs:1,151,398`), chave carimbada no wrap
   nao-residente (`credential/non_resident.rs:44,53`); falta expor fluxo no app/tray. Dep: item 1 (gestao de creds).
3. [OPEN] largeBlobs com UI (M; full, avaliar fido-totp).
   Tipos wire existem no SDK (`crates/universal-device-sdk/src/ctap21.rs:3`); falta executor + tela de leitura/escrita.
   Dep: item 1. Nao cabe em fido-only sem medir de novo (aumenta o grupo de flash do CTAP).
4. [PARTIAL] U2F em todos os transportes respeitando politica por credencial (S; full/fido-only/fido-totp).
   Transporte U2F existe (AID `crates/aegis-fido-usb/src/ccid.rs:54`, `U2F_V2` em `:286`, gate em
   `ctap_cmd.rs:403`); falta a lane U2F consultar `up_required_for_label` como a lane CTAP2 ja faz
   (`CAPABILITY_DIET.md:8.2`, `cred_store.rs:328`). Dep: politica UP (ja no firmware).
5. [OPEN] CredMgmt com protecao contra enumeracao na UI (S; full/fido-only/fido-totp).
   Firmware nega sem toque antes de listar (`CAPABILITY_DIET.md:8.2`); o app deve pedir toque antes de
   mostrar qualquer lista. Dep: item 1.
6. [PARTIAL] Windows Hello companion via PIV slot 9A (M; full/fido-only/fido-totp).
   Slot PIV 9A ja rotulado para logon corporativo no app (`strings.xml:508`); falta fluxo guiado de
   provisionamento + teste de logon documentado. Dep: item 8 (PIV).
## 2. PIV / OpenPGP (smartcard via CCID)

7. [OPEN] Completar PIV: Security Object com certs reais + GET DISCOVERY dedicado (M; full/fido-only/fido-totp).
   TODOs Wave 2 documentados no codigo (`crates/aegis-fido-usb/src/ccid.rs:72-73`); sem isso o PIV nao
   passa em validadores corporativos estritos. Dep: CCID (pronto).
8. [PARTIAL] OpenPGP applet completo (M; full/fido-only/fido-totp).
   Applet compila em todos os presets (`capability-catalog.json:166-176`); PIN/operacoes de chave no app
   existem, mas faltam curvas extras testadas de ponta a ponta e importacao de chave guiada. Dep: item 7 (testes CCID).

## 3. TOTP / OATH e OTP challenge-response

9. [DONE] Importacao de conta TOTP via QR Code (otpauth://) (S; full/fido-totp).
   Tela dedicada funcional + botao de leitura (`TotpDedicatedScreen`, `strings.xml:287,300`,
   `ANDROID_AUDIT.md:39-43`). Manter como referencia de UX para os itens abaixo.
10. [OPEN] Operacoes TOTP em lote: importar multiplo, apagar multiplo, renomear (S; full/fido-totp).
    Store suporta 64 slots (`capability-catalog.json:342-348`); a UI hoje e uma conta por vez. Dep: item 9.
11. [OPEN] UI de OTP challenge-response no app (S; full/fido-totp).
    Firmware serve via HOTP counter (`oath_cmd.rs`, `capability-catalog.json:203-214`, sem modulo proprietario);
    falta tela de desafio/resposta. Dep: item 10. Fora de fido-only (capabilidade dieta).
12. [PARTIAL] Tempo confiavel sem Wi-Fi: aplicar hora do host + ancora NVS com aviso visivel (S; full/fido-totp).
    SNTP e opcional por desenho (`capability-catalog.json:187`); o app deve mostrar "hora nao sincronizada"
    quando o codigo pode estar errado. Dep: nada.

## 4. Wallet (apenas full)

13. [PARTIAL] Fluxo de assinatura wallet com preview claro antes de assinar (M; full apenas).
    Preview existe no bridge (`HostUsbUartBridgeClient.kt:965`, OPP-06) e executor em `wallet_exec.rs`
    (`capability-catalog.json:217-226`); falta amarrar preview obrigatorio + confirmacao fisica em todas as
    moedas suportadas. Dep: display (item 27) para confirmacao em tela. Nunca em dieta (0x06 fail-closed).
14. [OPEN] Persistencia NVS da wallet com migracao (M; full apenas).
    Hoje a wallet e sessao em RAM; o pool `wallet-stores` ja esta dimensionado (`capability-catalog.json:373-384`).
    Dep: item 13. Risco de NVS: medir contra os 896 KiB antes de fundir.

## 5. Backup / restore + guardioes

15. [PARTIAL] Central de backup utilizavel por leigo: frase BIP-39 + envelopes AEGN (M; full).
    Telas e strings existem (`strings.xml:603-721`, `ANDROID_AUDIT.md:73-90`); falta teste de restauracao
    guiado (simulacao de perda) e verificacao de checksum antes de concluir. Dep: nada.
16. [PARTIAL] Quorum DKEK / Shamir 2-de-3 de ponta a ponta no app (M; full).
    Metodos no bridge (`HostUsbUartBridgeClient.kt:859`) e strings (`strings.xml:179-181,607,720`);
    falta cerimonia completa (gerar -> distribuir -> recuperar com 2 de 3) validada sem hardware dedicado.
    Dep: item 15. Seguranca: seguir `F-03` (proteger leitura do eFuse) ao persistir.
17. [OPEN] Exportacao AEGN com auto-limpeza da area de transferencia (S; app, todos os presets).
    Follow-up do audit `A-03 LOW` (`SECURITY_AUDIT.md:99-118`): limpar clipboard apos timeout + dialogo de
    confirmacao. Dep: item 15.

## 6. Auditoria e logs no device

18. [OPEN] Visualizador de audit log no app (FwLog) (S; full, leitura em dieta).
    Eventos ja gravados (`EV_UP_POLICY_SET=0x12`, `CAPABILITY_DIET.md:8.3`); o app tem `DeviceLog` mas nao
    decodifica o log do device. Incluir exportacao para suporte. Dep: nada.
19. [OPEN] Sanitizar mensagens de erro de transporte nos logs (S; app).
    Follow-up `A-02 LOW` (`SECURITY_AUDIT.md:99-109`): limitar a 64 chars e so nome da classe de excecao
    (`HostUsbUartBridgeClient.kt:135,673,693`). Dep: nada.
## 7. OTA de ponta a ponta

20. [PARTIAL] OTA com chave de release real provisionada (S; app+firmware, full).
    Engine e hook prontos (`ota2/`, `ANDROID_AUDIT.md:119-130`), mas a chave compilada e placeholder
    negado (todo-zeros, fail-closed). Sem a chave real nao ha rollout. Dep: ritual de provisionamento (item 28).
21. [OPEN] Servidor de manifests + rollout em estagios (canal/beta/estavel) (M; full).
    O botao "Check for Updates" hoje e canned (`FriendlySettingsAndThemeScreen.kt:958-971`,
    `ANDROID_AUDIT.md:79-83`); o caminho real (`net/OtaApi.kt` + `usb/OtaTransfer.kt`) funciona mas nao tem
    servidor nem politica de canais. Dep: item 20. Nota 2 MB: usar streaming, nunca stage completo.
22. [OPEN] Downgrade-protection visivel + confirmacao de versao no app (S; full).
    O device checa assinatura Ed25519; o app deve mostrar versao ativa vs candidata e recusar downgrade
    com mensagem clara. Dep: item 21.

## 8. BLE / proximidade (apenas full)

23. [PARTIAL] OOB-assisted pairing utilizavel (M; full).
    Executor firmware pronto (`ble/oob.rs:1`, op `0x42`, `CAPABILITY_DIET.md:10`); falta fluxo no app
    (ler TK via USB/serial apos UP+PIN e completar LESC). Isso resolve `F-01` sem enfraquecer MITM.
    Dep: janela de pareamento curta (dono: firmware BLE).
24. [PARTIAL] Gestao de bonds + politicas de auto-lock no app (S; full).
    Devices tab lista/desvincula (`ANDROID_AUDIT.md:44`), SecureGuard testa proximity lock em host
    (`SECURITY_AUDIT.md:11`); falta: exibir 1-bond-max claramente, expiracao de 30 dias visivel e politica
    walk-away configuravel por device. Dep: item 23.
25. [OPEN] Criptografia por sessao para `/oath/code` sobre Wi-Fi (M; full).
    Residual aceito do `A-01` (`ANDROID_AUDIT.md:8`): envelope por sessao alem do WPA2+envelope atual.
    Dep: firmware `net/`. Nao levar para dieta (Wi-Fi proibido com `cap-*`).

## 9. Energia (placas com bateria)

26. [OPEN] Suporte LiPo + deep sleep com wake por botao/toque (M; full em board com bateria).
    Nenhuma evidencia de deep-sleep/bateria no firmware hoje (grep vazio); pacote inclui: medicao de
    tensao, icone de bateria, sleep apos inatividade configuravel e wake que nao perde sessao alem do
    permitido. Dep: item 24 (politicas de lock). Irrelevante para 2 MB/devkitc.

## 10. Display (boards com LCD)

27. [OPEN] Sistema de menu no display: confirmacao de transacao, TOTP sem app, status (M; full + board LCD).
    Infra existe (`display/`, `oled_ssd1306_code_only.rs`, `ui_journey.rs`, `capability-catalog.json:263-274`);
    telas TOTP mostram NO_ACCOUNTS fail-closed na dieta. Falta menu navegavel real. Dep: item 13 (clear signing).
    Fora de dieta por desenho.

## 11. Fabrica / provisionamento

28. [OPEN] Ferramenta de provisionamento: serial por device + eFuse ritual (M; fabrica).
    Follow-ups `F-04` (serial estatico `AEGIS-S3-0002`, `usb_descriptors.rs:17-24`) e `F-03` (sem passo
    RD_DIS, `SECURITY_AUDIT.md:83-98`, `efuse.rs:24-33`): derivar serial do salt do device e adicionar
    read-protect ao `EfusePlan` com teste host. Dep: nada. Bloqueia qualquer claim "pronto para fabrica".
29. [OPEN] MDS + lote de atestacao (batch attestation) (M; full/fido-totp).
    Nenhum modulo MDS na arvore hoje; pacote inclui: gerar CSR de lote, publicar metadados e endpoint de
    estado (revogacao). Dep: item 28 (identidade por device).

## 12. Companheiros desktop e mobile

30. [OPEN] Profundidade Windows Hello: login PIV 9A + resolucao de problemas (S; docs+app).
    Rotulo ja existe (`strings.xml:508`); falta guia testado de enrollment e matriz de compatibilidade.
    Dep: item 7.
31. [OPEN] Provedor de passkey no Android (Credential Manager) (L; app).
    Strings de passkey existem (`strings.xml:105,326`), mas nao ha provedor Credential Manager; hoje o app
    gera/lista chaves proprias. Alto valor para adocao. Dep: itens 1-2.
32. [OPEN] Corrigir SecureChannel cross-session replay (S; firmware+SDK, todos os presets).
    Follow-up `F-02 MEDIUM` (`secure_channel.rs:138-166`, `SECURITY_AUDIT.md:70-82`): amarrar sessao no AD
    do tag ou base TRNG por handshake. Dep: nada. Fazer antes de qualquer claim de auditoria externa.
33. [OPEN] Backoff em `change_pin` igual ao unlock (S; firmware, todos os presets).
    Follow-up `F-05 LOW` (`engine.rs:880-886` vs `:507-562`, `SECURITY_AUDIT.md:133-140`). Dep: nada.

## 13. Experiencia do desenvolvedor

34. [OPEN] Mover `SimulatedRenodeTransport` para source set debug (S; app).
    Follow-up `A-04 INFO` (`SECURITY_AUDIT.md:141-150`): material demo deterministico hoje compila no APK
    release (inacessivel mas presente). Dep: nada.
35. [PARTIAL] Biometria Android com `CryptoObject` ligado a KeyStore (S; app).
    Unico TODO no main set (`BiometricGate.kt:24`, `ANDROID_AUDIT.md:95-101`); callers ja fazem fallback
    para senha. Dep: nada.
36. [PARTIAL] App lock com tela de bloqueio ligada (S; app).
    Implementado mas flag OFF e sem UI (`AppLock.kt`, `FeatureFlags.kt:22`, `ANDROID_AUDIT.md:103-108`).
    Dep: item 35 (mesma tela de desbloqueio pode servir aos dois).
37. [OPEN] Simulador Renode/firmware + test-mode documentado para CI sem hardware (M; todos).
    Infra parcial: `SimulatedRenodeTransport.kt:44-52`, `test-hooks` (`capability-catalog.json:311-322`,
    proibido na dieta). Falta: cenario matriz (reset, pareamento, OTA abortada) rodando em CI. Dep: nada.
38. [OPEN] Localizar mensagens de ViewModel/repo via chaves UiText (M; app).
    Divida documentada (`ANDROID_AUDIT.md:5`, testes pinam texto em `SecureGuardRepositoryAndCborTest.kt:106,143`):
    migrar para eventos com chave e resolver com `stringResource` no call site. Dep: nada (nao misturar com item 36).

## Contagem

- Total: 38 | OPEN: 23 | PARTIAL: 14 | DONE: 1.
- Regra: DONE so com evidencia de codigo+teste no branch; PARTIAL = caminho real com ramo degradado/follow-up.
- Proximo passo sugerido (menor esforco, maior risco abatido): 32 (F-02) + 33 (F-05) + 19 (A-02) + 17 (A-03),
  depois 20 (chave OTA real) que destrava 21-22.
