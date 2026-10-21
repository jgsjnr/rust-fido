# Task: Conexão BLE fim-a-fim via Windows/Python

**Created:** 2026-10-19

## Requirements
- R-01: Conectar via Windows+bleak até acesso total (scan→connect→bond JustWorks→discover 0xFFFD→ler FFF4→subscribe FFF2→escrever FFF1)
- R-02: Diagnosticar o LED estranho (estados pairing→bonding→paired vs observados)
- R-03: Testar ops privilegiadas com UP físico (gen/delete chaves, OATH put/delete, WiFi)
- R-04: Limpar estado prévio (unpair/reset) sem assumir estado inicial
- R-05: Registrar causa raiz do "aparece mas não conecta" + fix ou workaround

## Out of Scope
- Mudanças no app Android (só diagnóstico); secure boot; medições RF

## Acceptance Criteria
- [ ] Conexão completa com bond + subscribe + write + notify provados em log
- [ ] Causa do não-conecta identificada e corrigida (ou workaround documentado)
- [ ] Ops privilegiadas executadas com UP físico
- [ ] Script reutilizável em `tools/ble_connect_test.py`

## Constraints
- Device de teste (destrutivas liberadas); janela de pareamento 60s; UP físico exigido; firmware atual com test-mode

## Open Questions
- none

## Suppressed Questions
- "Estado inicial do device?" → answered by: usuário não sabe — assumir sujo e limpar (sessão atual)
- "Stack de teste?" → answered by: bleak no Windows + NimBLE no device (pesquisa Step 2)
