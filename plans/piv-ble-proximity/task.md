# Task: piv-ble-proximity — PIV completo + Walk-Away Lock multi-OS

**Created:** 2026-10-19

## Requirements
- R-01 (PIV completo NIST SP 800-73-4): SELECT AID `A0 00 00 03 08`, VERIFY (PIN), CHANGE REFERENCE DATA, RESET RETRY (com PUK), GENERAL AUTHENTICATE, GET DATA, PUT DATA, GENERATE ASYMMETRIC KEY PAIR. Slots 9A (PIV-Auth), 9C (Digital-Signature), 9D (Key-Management), 9E (Card-Auth). Objetos: CHUID `5F C1 02`, CCC `5F C1 07`, X.509 slots `5F C1 05`, fingerprints.
- R-02 (PIN/PUK mais seguro): PIN 6–8 dígitos numéricos, 3 tentativas (trava exige PUK), PUK 8 dígitos, 3 tentativas (trava exige wipe/re-issuance), retry counter em NVS cifrada (AES-256-GCM), zeroize em RAM via `zeroize` crate. Sem PIN default documentado.
- R-03 (Windows Logon-capable): ATR já existente mantido; PIV expõe containers `mscp` + cert com SAN/UPN para BaseCSP/minidriver; guia de enrollment PKI/AD (self-signed para lab + CSR para CA real). WinSCard enumera como leitor.
- R-04 (Proximidade firmware, seguro): novo `proximity.rs` no firmware — threshold RSSI com histerese (lock < -75 dBm por 10s, unlock exige presença física + PIN, nunca auto-unlock por RSSI), bonding BLE obrigatório, advertise separado do GATT `0xFFFD`, coexistência BLE/WiFi mutuamente exclusiva mantida.
- R-05 (Hosts multi-OS): `tools/host/` com 3 agents — `win/` (Dynamic Lock + `LockWorkStation`), `linux/` (`logind`/`loginctl` + BlueZ), `macos/` (melhor API disponível + doc). Windows primeiro.
- R-06 (Isolamento total / SOLID / atomic): tudo em worktree `fd-piv-ble-proximity-<fase>`, nunca na main. PIV = `crates/aegis-fido-usb/src/piv.rs` + `handle_piv_apdu`, sem tocar OATH/FIDO. Proximidade = `crates/aegis-fido-firmware/src/proximity.rs` atrás de feature `proximity` default-off. Commits atômicos por slot/objeto.
- R-07 (Legibilidade + continuação): `docs/piv-ble-proximity.md` em português, passo a passo (CONFIRM → fd-review → fd-execute em worktree → testes → merge). Cada função pública com rustdoc.

## Out of Scope
- Flash de bootloader/partition table; secure boot (sempre off).
- Medições RF calibradas de BLE; enrollment real em AD de produção (só guia + lab).
- Mudança de bytes CTAP/USB/CBOR/APDU existentes.
- Auto-unlock por proximidade (explicitamente proibido — só lock).

## Acceptance Criteria
- [ ] `cargo test -p aegis-fido-usb` verde incluindo SELECT/VERIFY/AUTH/GET-DATA PIV com vetores NIST.
- [ ] `cargo clippy -- -D warnings` zero warnings nos arquivos novos.
- [ ] Windows com WinSCard lista "AegisKey CCID SmartCard" e `certutil -scinfo` lê CHUID/CCC + cert 9A.
- [ ] Walk-away: afastar o phone/fob além do threshold trava a estação em ≤15s; voltar NÃO destrava sozinho.
- [ ] Com features `ble/proximity` off, binário = baseline.
- [ ] `fd-verify` + aval humano antes de qualquer merge na main.

## Constraints
- `ble/wifi/menu/proximity` default-off; binário baseline idêntico com tudo off.
- Coexistência BLE/WiFi mutuamente exclusiva.
- NVS cifrada para PIN retry/PUK; `zeroize` em todo segredo em RAM.
- Worktree obrigatória; testes verdes antes do merge; paridade input→output no CCID.
- Note: criado COM pesquisa de codebase (ccid.rs 498 linhas, ble_gatt 0xFFFD, gates fido-auditoria).

## Open Questions
- none (defaults seguros assumidos a seu pedido)

## Suppressed Questions
- "Quais acceptance criteria?" → answered by: gates fido-auditoria (testes+clippy+verify+humano) + NIST vectors
- "Quais riscos agudos?" → answered by: R1-R10 fido-auditoria + política PIN/PUK restritiva + lock-only
- "BLE bonding dedicado ou reuse 0xFFFD?" → answered by: mais seguro = bonding obrigatório, advertise proximidade separado, GATT 0xFFFD intacto
