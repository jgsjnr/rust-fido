# RELEASE checklist industrial - dev to HIL to nightly to pre-release to release

> Lane: `.slim/worktrees/modular-solid-atomic`. Parte offline da T13 (sem hardware).
> Nesta lane nenhum comando com hardware foi executado: sem flash, sem COM7, sem burn.
> Comandos exatos abaixo sao para a lane de execucao; aqui ficam registrados, nao executados.
> Base normativa: `docs/REGRAS-automacao.md` (R1-R14), `plans/TASKS-microdetalhe.md` (T0-T13),
> `docs/COMMS-map.md` (secao 8 validacao da dona), `docs/test-hooks.md`, `docs/MACHINE.md`,
> `plans/risk-acceptance-secureboot.md`. Sem codigo. Texto sem emoji.

## 1. Escopo

Consolidar o caminho industrial executavel de release sem tocar hardware:

- Sequencia fechada dev -> HIL -> nightly -> pre-release -> release, com comandos exatos e gates bloqueantes.
- Separar o que e automatico (orquestrador) do que e `EXTERNAL_BLOCKED` (flash COM7, burn eFuse,
  COMMIT real, tag/COMMIT com push) com aprovacoes explicitas.
- Congelar o contrato wire e de test-mode: manifesto OTA 104 B, `check-release-clean.py`,
  `factory_provision --dry-run`, tag + SHA256 + rollback ensaiado.
- Nao editar nesta lane: `crates/`, `tools/`, `scripts/`, `docs/COMMS-map.md`,
  `docs/REGRAS-automacao.md`. Escrita exclusiva desta lane: este arquivo +
  `docs/size-wave1.md`.

## 2. Contrato

1. R1-R14 de `docs/REGRAS-automacao.md` valem integralmente; violacao aborta a lane.
   R6 (zero warnings), R7 (test-mode gated), R11 (doc + build + flash COM7 + bateria por mudanca grande),
   R12 (tudo mutavel com stub `NotCompiled`), R13 (secure-boot/eFuse stub-only no caminho automatico),
   R14 (hardware-first em reescrita) sao gates de release, nao aspiracoes.
2. T0-T13 de `plans/TASKS-microdetalhe.md` na ordem `T0 -> T1 -> T2 -> (T3..T12) -> T13`;
   nenhuma T fecha sem `doc + build + flash COM7 + bateria` (R11).
3. Wire congelado a partir de T4: opcodes/status (`0x05 NEED_BINDING` nunca no USB, `6D 00` honesto),
   `0x2E` rescue, `0x39` PIV enroll, manifesto OTA 104 B (`OTA_MANIFEST_LEN` em
   `crates/aegis-fido-firmware/src/ota.rs`), slots PIV 24-27, TLV canonico.
   Mudanca wire = major + migracao em `src/migrations/` + HIL.
4. `TEST_*` so existe com feature `test-mode` (`crates/aegis-fido-firmware/src/test_hooks.rs`,
   `docs/test-hooks.md`); release e provado por `scripts/check-release-clean.py`.
5. `docs/COMMS-map.md` secao 8 e a validacao da dona desta parte offline: self-tests + lint markdown,
   sem flash/COM7. QEMU-S3 e so fumaca, nunca conta como verificacao em hardware real.

## 3. Pipeline executavel (comandos exatos da lane de execucao)

Parametrizacao global: porta default `COM7` (override `%AEGIS_PORT%` / `--port COMx`),
baud `115200`, AP `http://192.168.4.1`. Destrutivos exigem `--confirm` (sem ele = `PermissionDenied`).

### 3.1 dev - `local check`

```powershell
cargo test
cargo clippy --all-targets -- -D warnings
python tools/app_simulator.py --self-test
python tools/host_sdk/cli.py --self-test
```

Gate bloqueante: suite verde + zero warnings em todas as fases (R6). Warning = FAIL,
sem `allow` novo sem task dedicada. Self-tests offline verdes antes de qualquer flash.

### 3.2 HIL - `flash COM7 + bateria` (EXTERNAL_BLOCKED, ver secao 7)

```powershell
powershell scripts/env-check.ps1
python scripts/aegis_auto.py full --port COM7
```

O orquestrador (`scripts/aegis_auto.py`, subcomandos `full | hil-only | release-check`)
executa nesta ordem: env-check -> `cargo test` -> `clippy -D warnings` -> gates de cobertura
offline T5-T9 + self-test do host-sdk + ref COMMS-map -> build S3 -> flash ->
`read-mac` -> boot-check `ONLINE & ACTIVE` -> demo/baterias -> probes -> `validate` ->
relatorio PASS/FAIL + SHA256 do artefacto.

Bateria padrao pos-flash (tambem invocavel avulsa):

```powershell
python tools/app_simulator.py --port COM7 --demo
python tools/test_aegiskey_rust.py --port COM7
python tools/e2e_user_test.py --port COM7
python tools/e2e_zero_press.py --port COM7
python tools/wallet_gate_probe.py --port COM7
python tools/ota_deny_probe.py --port COM7
python tools/killswitch_deny_probe.py --port COM7
python tools/validate_aegiskey.py --port COM7
```

Build/flash S3 de referencia (receita `docs/MACHINE.md` + `scripts/common.ps1`):

```powershell
. C:\Users\junior\export-esp.ps1
$env:IDF_PATH = 'C:\.embuild\espressif\esp-idf\v5.3.1'
$env:ESP_IDF_SDKCONFIG_DEFAULTS = '<repo>\sdkconfig.defaults.esp32s3'
cargo +esp build -Zbuild-std=std,panic_abort --target xtensa-esp32s3-espidf
esptool --port COM7 write-flash 0x10000 <bin>
```

Alternativa suportada: `cargo-espflash --port COM7` (cf. `plans/TASKS-microdetalhe.md`).
Gate bloqueante: bateria verde no device real (R11). `hil-only` pula env-check/cargo,
mantem o resto.

### 3.3 nightly - `nightly/bench`

HIL completo mais:

```powershell
python tools/live_monitor.py --port COM7
python tools/stability_watch.py --port COM7
```

Mais bench de latencia + coex/TWDT (receita `scripts/bench-freertos.ps1` onde aplicavel).
Gate bloqueante: sem regressao de latencia USB, watchdog/TWDT limpo, `USB > WiFi > BLE`
observado (coex). Falha aqui bloqueia pre-release.

### 3.4 pre-release - `size + release-clean + provision dry-run` (sem burn)

```powershell
python scripts/aegis_auto.py release-check --port COM7
python scripts/check-release-clean.py <artefacto>
python tools/factory_provision.py --serial AEGIS-S3-XXXX --dry-run
```

Detalhe:

- `size`: teto binario (receita `idf.py size`; serie historica em `docs/size-wave1.md`;
  fabrica maxima 3145728 B registrada em `plans/STATE.md`). Sem regressao de RAM/flash
  sem justificativa; envelope AEGN, CBOR IDs e layout NVS preservados.
- `check-release-clean.py`: compila `aegis-fido-firmware` sem `test-mode` e escaneia o
  artefacto por marcadores de runtime (`source=software`, `up_latched`, `pairing_open`,
  `lt_dump v=1`, `OTA_TEST_PUBKEY`, namespaces dev). Qualquer vazamento = FAIL (R7).
- `factory_provision.py --dry-run`: plano + fingerprints SHA256, sem tocar hardware,
  sem gravar, sem imprimir chaves. `--serial` e obrigatorio (`AEGIS-S3-<id>`);
  escrita real exige `--confirm` + `--port` e e EXTERNAL_BLOCKED (secao 7).
- Manifesto OTA 104 B valido: `OTA_MANIFEST_LEN = 104` em
  `crates/aegis-fido-firmware/src/ota.rs` (`Idle -> Staged -> Verified -> Applying -> Committed`
  + `rollback()`), servido por `tools/ota_server.py` com registro exemplo em
  `tools/ota_registry.json.example`. Nunca commitar `ota_registry.json` real nem chaves.

Gate bloqueante: `release-check` verde + `release-clean` verde + dry-run sem burn.
`release-check` recusa `--confirm`/`--confirm-release` (exit 2): release nunca faz wipe.

### 3.5 release - `tag + manifesto OTA 104B + rollback`

1. Congelar artefacto: SHA256 publicado (linha `SHA256` do relatorio do orquestrador;
   referencia historica de formato em `docs/MACHINE.md`).
2. Tag assinada (lane de execucao, apos aprovacao secao 7): `git tag -s <versao> -m <nota>` + push.
3. `tools/ota_server.py` servindo o manifesto 104 B para seriais registrados.
4. Rollback ensaiado em HIL com `--confirm`: snapshot NVS antes de `Applying`
   (`NVS_READ_MAX 8192`, `verify-after-write`) + `rollback()` / snapshot restore.
   OTA-COMMIT final e USB-only (limite registrado nos Gaps T13); COMMIT via BLE/WiFi nao existe.
5. Re-flash da imagem anterior precisa funcionar sem jig apos todo flash HIL (R13);
   placa travada = FAIL critico.

Gate bloqueante: tag assinada + SHA256 do artefacto + manifesto 104 B valido +
rollback demonstrado em HIL. Sem isso nao ha release.

## 4. Gates bloqueantes (resumo auditavel)

- [ ] `cargo test` verde.
- [ ] `cargo clippy --all-targets -- -D warnings` com zero warnings.
- [ ] Self-tests offline verdes (`app_simulator --self-test`, `host_sdk/cli --self-test`).
- [ ] HIL: `aegis_auto.py full --port COM7` OVERALL PASS + bateria verde no device real.
- [ ] Nightly: monitores + bench sem regressao, TWDT limpo, coex `USB > WiFi > BLE`.
- [ ] Pre-release: teto `size` respeitado + `check-release-clean.py` verde + `--dry-run` sem burn.
- [ ] Manifesto OTA 104 B valido (`ota.rs` x `ota_server.py` x registry exemplo).
- [ ] Release: tag assinada + SHA256 + rollback ensaiado + re-flash sem jig OK.
- [ ] Ordem de gates no device preservada: `binding -> UP -> PIN` para CONFIG;
      USO nunca exige vinculo; USB/CTAP nunca ve `NEED_BINDING 0x05`.
- [ ] `SanitizedLog`: segredos nunca no fio/log (so metadados/contagens).
- [ ] Secure-boot continua desligado (aceite em `plans/risk-acceptance-secureboot.md`;
      guard `scripts/ci-guard-secureboot.ps1` deve continuar passando).

## 5. Test-mode gated (o que a release prova)

- Handlers de texto so em firmware `test-mode`: `TEST_UP`, `TEST_DOWNLOAD`,
  `TEST_PAIRING_OPEN` (60 s) / `TEST_PAIRING_OPEN_300` / `TEST_PAIRING_CLOSE`,
  `TEST_LIFETIME_DUMP`, `TEST_LED_*`, `TEST_USB_RECONNECT` (ver `docs/test-hooks.md`).
- Bypasses so com `cfg!(test-mode)`: `binding_bypass`, `release_bypass`,
  `devkey_persist`, `ota_test_key` (`OTA_TEST_PUBKEY`).
- Release (`test-mode` OFF, default): linhas desconhecidas ignoradas, bypass nunca,
  chave release zeros fail-closed (negam tudo).
- Prova: `cargo test -p aegis-fido-firmware --lib test_hooks` (manifesto x docs) +
  `python scripts/check-release-clean.py` (strings do artefacto) +
  `grep -rn 'TEST_' crates/aegis-fido-firmware/src` confinado a
  `src/test_hooks.rs`, `src/pairing.rs`, `src/lifetime_trace.rs`, `src/main.rs`.

## 6. OTA, tag, SHA256 e rollback (contrato minimo)

- Maquina `Idle -> Staged -> Verified -> Applying -> Committed`, anti-rollback impede
  downgrade, `zeroize` de PIN/salt/sessao antes de drop/reboot, tempo-constante em
  PIN/MAC/sig, TWDT ativo (R9).
- Manifesto fixo de 104 B (`OTA_MANIFEST_LEN`), validado antes de `Staged`;
  streaming sem carregar a imagem em RAM.
- Recovery com 8 tentativas NVS + wipe com UP; snapshot + rollback antes de `Applying`.
- Tag assinada + SHA256 do `.bin` + manifesto servido por `tools/ota_server.py`
  (registry exemplo em `tools/ota_registry.json.example`; jamais commitar chaves/seriais reais).
- Rollback = OTA rollback (snapshot restore HIL com `--confirm`) ou re-flash da imagem
  anterior; ambos ensaiados antes de declarar release.

## 7. EXTERNAL_BLOCKED (so com aprovacao explicita, fora do caminho automatico)

Nada abaixo roda nesta lane offline. Na lane de execucao, cada item exige aprovacao
humana previa e operador presente; o orquestrador nunca os faz sozinho.

| Item bloqueado | Por que e externo | Aprovacao / condicao |
|---|---|---|
| Flash COM7 (`esptool --port COM7 write-flash`, `cargo-espflash`, `scripts/flash.ps1`) | toca hardware, reseta a placa (reopen == reset), consome janela de pareamento 60 s | aprovacao humana + placa identificada (`scripts/env-check.ps1` exit 0, COM7 = CP210x, S3 identificado) |
| Bateria HIL completa (demo + `test_aegiskey_rust` + `e2e_*` + probes) | exige device real, UP fisico/latch 1,5 s, hold-5s BOOT para janela | operador presente; `e2e_zero_press` com `--timeout` parametrizado (hardcoded conhecido, ver Gaps) |
| Qualquer destrutivo: wipe/killswitch, OTA stage/apply/commit, provision load, recovery, `BIND_RELEASE`, PIV enroll `0x39`, wallet GEN, OATH PUT/DELETE, WiFi config | irreversivel ou com efeito de fabrica | `--confirm` obrigatorio; wipe de vinculo exige tambem `--confirm-release`; sem flags = `PermissionDenied` |
| OTA-COMMIT / apply final | USB-only por desenho; sem caminho serial/BLE/WiFi | COMMIT so via USB-HID, com snapshot + rollback pronto; probe `ota_deny_probe` deve continuar negando commit serial |
| Burn eFuse / `provision.load_device_keys` real (`tools/factory_provision.py` sem `--dry-run`) | OTP irreversivel (BLOCK7/BLOCK8 + lock permanente), leitura dupla supervisionada | procedimento manual assinado, fora do `aegis_auto.py` (R13/R8); pre-release e release auto usam so `--dry-run` + zeros fail-closed + prova de re-flash sem trava |
| Secure-boot / flash encryption, ligar qualquer trava permanente | risco de brickar a placa; aceite formal mantem desligado | NUNCA no caminho automatico; so via decisao humana que revogue `plans/risk-acceptance-secureboot.md` + atualize o guard; placa travada = FAIL critico |
| Tag assinada + push / publicacao do artefacto (`git tag -s`, push, `COMMIT` real) | ato de release, nao de CI | aprovacao humana pos gates secao 4 verdes; SHA256 registrado antes do push |
| Hardware ausente: T-Display, RF bonded, botao/UP fisico, walk-away aereo | sem bancada, sem prova | marcar `ExternalBlocked`, nunca `Success`; `t_display_simulator.py` e stub nao contam como prova em hardware |

## 8. Riscos

- `e2e_zero_press.py` com timeouts/sequencia fixos: fragil a variacao de boot; mitigar com
  `--port/--timeout` parametrizado e retry de boot `ONLINE & ACTIVE` (dono T1/T12).
- OTA-COMMIT so USB: stage/verify por BLE/WiFi nao concluem release; manual precisa dizer isso
  e o gate HIL precisa exigir COMMIT via USB (dono T13).
- T-Display ausente na bancada: telas ST7789 validadas por stub + espelho serial; nenhum teste
  display conta como prova em hardware (dono T3/T10).
- Burn eFuse manual: orquestrador para em `--dry-run`; burn real e checklist manual assinado (dono T13).
- Lab-mocks OFF no artefacto: mock ligado = `ExternalBlocked`, nunca `Success` (R4).
- Segredos: envelope unico AEGN v1 (AES-GCM + HKDF eFuse+salt + nonce unico),
  `verify-after-write`, `NVS_READ_MAX 8192`; zeros negam (R5/R8/R9).

## 9. Testes (validacao da dona - so leitura, sem hardware)

1. `python tools/app_simulator.py --self-test` (offline, sem hardware).
2. `python tools/host_sdk/cli.py --self-test` (vetores TLV/gates/framing).
3. Markdown consistente: tabelas com `|` de borda, caminhos citados existem no worktree,
   nenhum link quebrado para arquivo, sem segredos no texto.
4. Sem flash/COM7 nesta lane (proibido: sem hardware).
5. `cargo test` / `clippy` nao sao executados nesta lane offline (registrados para a lane
   de execucao); nao afirmar verde sem log.

## 10. Criterios de aceite desta parte offline

- `plans/RELEASE-checklist.md` existe e cobre dev->HIL->nightly->pre-release->release com
  comandos exatos, gates bloqueantes e tabela EXTERNAL_BLOCKED com aprovacoes.
- `docs/size-wave1.md` existe e registra a serie de tamanho sem inventar numero novo.
- Nenhum arquivo fora dos dois caminhos do escopo foi editado nesta lane.
- Markdown sem links quebrados para arquivos; sem afirmacao de verificacao em hardware;
  sem segredo/token/chave no texto.

## 11. Qualidade de evidencia

- Cada numero de tamanho citado em `docs/size-wave1.md` indica fonte (observado em
  `docs/MACHINE.md`, `plans/STATE.md` ou baseline 2026-10-18 ja commitada).
- Nenhum gate e dado como verde nesta lane: gates sao criterios para a lane de execucao,
  com o log exigido (`cargo`, `esptool`, bateria, SHA256) listado por fase.
- Divergencia conhecida e declarada: `plans/TASKS-microdetalhe.md` sugere
  `factory_provision.py --dry-run --port COM7`, mas o argparse atual exige `--serial`
  e ignora porta no dry-run; o comando canonico aqui inclui `--serial AEGIS-S3-XXXX`.

## 12. Bloqueadores externos desta lane

Nenhum: a parte offline e so leitura + escrita dos 2 markdowns. Todo item de hardware
(flash COM7, burn eFuse, COMMIT real, tag/push) e `EXTERNAL_BLOCKED` por desenho e aguarda
lane de execucao com aprovacoes da secao 7.

## 13. Rollback

- Apagar `plans/RELEASE-checklist.md`.
- Restaurar `docs/size-wave1.md` ao HEAD (`git checkout -- docs/size-wave1.md`), pois o
  arquivo ja existia antes desta lane e foi apenas expandido.
- Nenhum outro arquivo e tocado por esta lane.

## Referencias (arquivos verificados no worktree)

`docs/REGRAS-automacao.md`, `plans/TASKS-microdetalhe.md`, `docs/COMMS-map.md`,
`docs/test-hooks.md`, `docs/MACHINE.md`, `plans/risk-acceptance-secureboot.md`,
`plans/STATE.md`, `docs/size-wave1.md`, `sdkconfig.defaults.esp32s3`,
`scripts/common.ps1`, `scripts/env-check.ps1`, `scripts/check-release-clean.py`,
`scripts/aegis_auto.py`, `scripts/ci-guard-secureboot.ps1`,
`tools/app_simulator.py`, `tools/test_aegiskey_rust.py`, `tools/e2e_user_test.py`,
`tools/e2e_zero_press.py`, `tools/wallet_gate_probe.py`, `tools/ota_deny_probe.py`,
`tools/killswitch_deny_probe.py`, `tools/validate_aegiskey.py`,
`tools/factory_provision.py`, `tools/ota_server.py`, `tools/ota_registry.json.example`,
`tools/host_sdk/cli.py`, `tools/live_monitor.py`, `tools/stability_watch.py`,
`crates/aegis-fido-firmware/src/ota.rs`, `crates/aegis-fido-firmware/src/test_hooks.rs`.

---
Roda pe: parte offline T13, sem hardware tocado; `docs/size-wave1.md` pre-existia no HEAD
e foi expandido, nao criado do zero; prova em hardware segue EXTERNAL_BLOCKED.
