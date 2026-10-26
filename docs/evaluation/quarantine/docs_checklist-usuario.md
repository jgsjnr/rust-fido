# Checklist do usuário — passo a passo físico (H1–H7 + trava + WUDF)

Só você pode fazer (dedo, celular, 2º PC). Cada fase diz o esperado e o que me
trazer de volta. Nada aqui apaga a placa nem queima eFuse.

## Fase 0 — preparo (5 min, sem tocar em nada)

- [ ] Placa ligada, USB nativo plugado no PC, COM7 livre.
- [ ] APK pronto: `app-android\app\build\outputs\apk\debug\app-debug.apk` (56,5 MB).
- [ ] Anote o MAC BLE do fob (vale para a Fase 4): ele aparece no scan da Fase 2.

## Fase 1 — instalar o APK

- [ ] Copie o `app-debug.apk` para o celular e instale (permita "fontes desconhecidas").
- [ ] Abra o app, confira as telas (OATH, Carteira, Log, PIV).

## Fase 2 — gestos e LED (H1–H4)

- [ ] **H1**: segure BOOT 5 s → LED azul "respirando" + janela de pareamento 60 s.
- [ ] **H4**: com a janela aberta, scan BLE no celular → `AegisKey` aparece; fora da janela, some.
- [ ] **H3**: confira as cores — idle ciano / pairing azul / bonded verde / locked vermelho.
- [ ] **H2**: com operação pendente, tap no BOOT → destrava (UP).
- [ ] Me traga: o que divergiu (cor, tempo, nome no scan).

## Fase 3 — bond + carteira (H5)

- [ ] No app, parear/bond com o fob (JustWorks + bond).
- [ ] Criar GEN/LIST/ADDR de carteira e navegar os menus de controle.
- [ ] Me traga: print ou relato do que funcionou/falhou.

## Fase 4 — walk-away e lock real (H6) — BLOQUEADO, leia antes

- [ ] **H6 simples (só app)**: com o app conectado, afaste-se ~10 m → app mostra
      desconexão; volte → reconecta (sem auto-unlock de nada).
- [ ] **Lock real do PC**: TRAVA O WINDOWS DE VERDADE. Só rode quando estiver
      pronto para digitar a senha de novo:
      `python tools/host/win/proximity_agent.py --fob-id <MAC> --lock-secs 10 --poll-secs 2`
- [ ] **BLOQUEADOR**: o agente precisa da mesma `K_prox` que o fob gerou no
      pareamento (`--k-prox-hex`), e hoje ela não é exportada (follow-up
      provisionamento). Sem ela, o lock real NÃO valida TAG. Me diga e eu
      implemento a exportação via enroll antes — ou fazemos só o H6 simples.

## Fase 5 — PIV no USB nativo (H7)

H7 (tabela antiga dizia "falta implementação") está implementado e provado no
Linux. Neste Windows o driver se recusa (sem byte no fio). Para fechar no Windows:
- [ ] Opção A (5 min): espetar o USB nativo num **2º PC limpo**, instalar OpenSC,
      `opensc-tool -l` (espera "AegisKey S3 Authenticator" + cartão), SELECT + VERIFY.
- [ ] Opção B: reinstalar o stack smartcard deste Windows (te guio na hora).
- [ ] Me traga: print do `opensc-tool -l` + VERIFY do 2º PC (ou o erro exato).

## Fase 6 — decisão hold-gesture

- [ ] Teste o hold 5 s no GPIO0 e me diga: manter 5 s, mudar o tempo, ou outro gesto?
      (Fase pairing 14/14 cobre o protocolo; falta só o UX.)

## Fase 7 — me chamar de volta com

1. Divergências H1–H4 (LED/scan/nomes/tempos).
2. Resultado H5 (bond + carteira).
3. H6 simples ok? + decisão sobre o lock real (com ou sem K_prox).
4. H7 no 2º PC (print) ou "vamos de reinstall".
5. Decisão do hold-gesture.
