# Task: Seis implementações do produto

**Created:** 2026-10-19

## Requirements
- R-01: FIDO2/Passkey — já pronto; só regressão (USB HID, CTAP2.1, 5 curvas, CBOR)
- R-02: PIV seguro — VERIFY/AUTH/PUT/GEN-KEY, slots 9A/9C/9D/9E, PIN/PUK em NVS, mscp/certs, agents Linux/mac
- R-03: Proximidade — integrar BLE (bonding, advertise separado, coexistência) + agents restantes
- R-04: Cofre/TOTP — já pronto; só regressão (RFC 6238/4226, display real)
- R-05: Killswitch — opcode dedicado (CDC serial + HID), gatilho botão físico E comando remoto UP+PIN, scripts SO (PowerShell/PAM/udev)
- R-06: Dongle Ed25519 — challenge-response via WinUSB bulk + envelope AEGN + verificação no app (só Ed25519, sem RSA)
- R-07: Carteira completa — ops BLE wallet + NVS rede→slot + UI rede/endereço + web buscando firmware
- R-08: App atualizado — corrigir controle pós-pareamento; telas de salvamento de carteira Bitcoin; menu por operação; jornada melhorada
- R-09: Firmware fina — terceirizar computação pública para o bridge; hardware só info sob chamada

## Out of Scope
- Secure boot; RF calibrado; enrollment AD produção; BIP-32/HD; broadcast de TX; mudar bytes CTAP/USB/CBOR existentes
- Mover para o app qualquer coisa com segredo, chave, assinatura, RNG ou gates

## Acceptance Criteria
- [ ] FIDO2 + cofre: regressão verde, sem mudança de comportamento
- [ ] PIV: SELECT/VERIFY/AUTH/PUT/GEN com vetores + PIN/PUK com lockout
- [ ] Proximidade trava walk-away ≤15s, nunca auto-destrav
- [ ] Killswitch apaga via botão e via comando (ambos com confirmação)
- [ ] Dongle assina/verifica via WinUSB com Ed25519
- [ ] Carteira fim-a-fim pelo app com dados no NVS
- [ ] App controla pós-pareamento; telas Bitcoin; menus por operação; jornada sem becos
- [ ] S3 menor que atual (SIZE antes/depois); bridge computa público; auditoria ficar-vs-mover

## Constraints
- Reuso máximo; devices de teste, destrutivas liberadas; test-mode só em dev
- Textos simples PT-BR; sem Log com PII; sem permissão nova
- Fronteira rígida: segredo/chave/assinatura/RNG/gates ficam no firmware

## Open Questions
- none

## Suppressed Questions
- "RSA-3072?" → answered by: usuário (só Ed25519, sessão atual)
- "Killswitch por onde?" → answered by: usuário (os dois, sessão atual)
- "Carteira completa ou mínima?" → answered by: usuário (completa, sessão atual)
- "Menus por operação + jornada?" → answered by: usuário (sim, sessão atual)
- "O que pode sair do firmware?" → answered by: usuário (gerações no celular; hardware só info, sessão atual)
