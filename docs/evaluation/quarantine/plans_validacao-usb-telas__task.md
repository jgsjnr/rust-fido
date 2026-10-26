# Task: Validação USB + telas nos dois devices

**Created:** 2026-10-19

## Requirements
- R-01: Validar conexão USB via app físico/OTG e via simulador Python serial nos dois devices (S3 COM7, classic COM8)
- R-02: Validar fluxos de app sem hardware no emulador (22 telas, permissões negadas, fallbacks)
- R-03: Testar todas as telas (app + jornada firmware Boot/Home/Pairing/Vault/Locked/Busy)
- R-04: Anotar modificações necessárias em `docs/validacao-usb-telas.md` (dentro do repo)
- R-05: Validar debugs e outputs do monitor (`ltrace`, `live_monitor`, `DeviceLog`, LogScreen)
- R-06: Investigar ponte ADB→Python→serial como intermediário emulador→device
- R-07: Ativar funções e testar dentro dos devices, inclusive destrutivas (delete/wipe/reset — autorizado, é só teste)

## Out of Scope
- Flash de bootloader/partition table; secure boot (sempre off); medições RF de BLE

## Acceptance Criteria
- [ ] Matriz tela×device preenchida (pass/fail com evidência de log)
- [ ] `docs/validacao-usb-telas.md` commitado com modificações necessárias
- [ ] Outputs de monitor conferem com eventos executados
- [ ] Veredito da ponte ADB registrado (viável/adiado)
- [ ] Aviso final aqui no chat

## Constraints
- Emulador não tem USB host (limite de plataforma comprovado no mapeamento)
- Ops destrutivas liberadas; devices são de teste
- COMs podem mudar; pareamento tem janela de 60s; firmware dev tem bypass test-mode

## Open Questions
- none

## Suppressed Questions
- "Quais COMs/limites?" → answered by: sessão atual (COM7 S3, COM8 classic, emulador aberto)
- "Pode operação destrutiva?" → answered by: usuário ("pode fazer tudo, é só teste")
- "Onde anotar?" → answered by: usuário ("dentro" do repo)
