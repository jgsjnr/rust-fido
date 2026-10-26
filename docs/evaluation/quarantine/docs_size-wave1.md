# SIZE Wave1 - serie de tamanho do binario (offline, sem hardware)

> Lane: `.slim/worktrees/modular-solid-atomic`. Parte offline da T13.
> Nenhum build/flash foi executado nesta lane; todos os numeros abaixo sao
> baseline ja commitada ou observada em arquivos do worktree (fontes citadas).
> Texto sem emoji. Sem codigo. Sem segredos.

## 1. Escopo

Registrar a serie de tamanho (teto binario do pre-release) sem inventar numero novo:

- Preservar a baseline C 2026-10-18 ja commitada neste arquivo.
- Referenciar as medicoes S3 observadas em `docs/MACHINE.md` e `plans/STATE.md`.
- Fixar metodo, regra de nao-regressao e relacao com `plans/RELEASE-checklist.md`.

## 2. Baseline C 2026-10-18 (preservada do HEAD)

Comando host: `cargo build` + `cargo test` workspace. Comando alvo: `idf.py size`.

| Alvo | Bin (bytes) | Fonte |
|---|---|---|
| aegis-app-esp32 | 1786736 | baseline commitada neste arquivo em 2026-10-18 |
| devkitc (ESP32-S3) | 1785232 | baseline commitada neste arquivo em 2026-10-18 |
| tdisplay (ESP32 classic + ST7789) | 1824016 | baseline commitada neste arquivo em 2026-10-18 |

Medicao pos-Wave1 host: 77 testes verdes sem aumento de bin alem de poucas
centenas de bytes de logica (registro original do HEAD, sem alteracao).

## 3. Medicoes S3 observadas no worktree (nao sao desta lane)

| Artefacto | Tamanho | SHA256 | Fonte |
|---|---|---|---|
| `aegis-app-esp32s3-devkitc.bin` (release S3 validada) | 2646256 B | `930f47c553441287f33f8cda1d83c594b4c4c3ef1ec1c6b710fa6d1ed564ff45` | `docs/MACHINE.md` |
| `aegis-app-freertos-s3.bin` (device build S3 release, loop 3) | 483936 B | `13B9A3C20D0495F7A85F37E421BD93FB435FAD93A761F147DBC7B062D867B` | `plans/STATE.md` |
| `aegis-app-freertos-s3.bin` (device build S3 release com FFI, loop 4) | 821808 B | `15868719338E97AABC2B5BD50330E52201501B05FD4B4B4D32212111D7` | `plans/STATE.md` |

Teto de fabrica: 3145728 B (factory max, cf. `plans/STATE.md`). Todos os bins acima
estao com folga contra o teto; o crescimento de 483936 para 821808 veio do link C +
proximity, ainda com folga (registro de `plans/STATE.md`, sem juizo novo aqui).

## 4. Metodo (para a lane de execucao; nao executado aqui)

- Alvo C/S3: `idf.py size` sobre o `.elf`/`.bin` do perfil S3
  (receita de ambiente em `docs/MACHINE.md`: `export-esp.ps1`, `IDF_PATH` v5.3.1,
  `ESP_IDF_SDKCONFIG_DEFAULTS` apontando `sdkconfig.defaults.esp32s3`).
- Host: `cargo build` + `cargo test` no workspace; clippy continua bloqueante
  (`cargo clippy --all-targets -- -D warnings`), mas nao mede tamanho.
- Pre-release usa o teto binario como gate (detalhe em `plans/RELEASE-checklist.md`
  secao 3.4): estouro sem justificativa = FAIL.

## 5. Regra de nao-regressao

- Sem regressao de RAM/flash sem justificativa documentada na task dona.
- Envelope AEGN preservado; CBOR IDs preservados; journal NVS sem mudar layout flash.
- Qualquer mudanca de layout flash, de `NVS_READ_MAX` ou do manifesto OTA 104 B
  e mudanca de contrato: exige task dedicada + migracao + HIL (cf. `plans/TASKS-microdetalhe.md`).

## 6. Contrato com o release

- O teto `size` e gate do pre-release (`plans/RELEASE-checklist.md` secao 3.4 e 4).
- `python scripts/check-release-clean.py <artefacto>` e gate independente (R7);
  tamanho OK nao substitui release-clean verde.
- `python tools/factory_provision.py --serial AEGIS-S3-XXXX --dry-run` nao altera tamanho;
  burn real e EXTERNAL_BLOCKED (ver checklist secao 7).

## 7. Riscos e limitacoes

- Numeros C de 2026-10-18 usam toolchain da epoca; comparar series so com mesmo
  perfil/flags (S3 release vs S3 release, classic vs classic).
- Builds freertos-S3 de `plans/STATE.md` incluem variantes com/sem FFI e proximity;
  nao comparar 483936 contra 821808 como regressao (perfis diferentes, registrado na fonte).
- Placa T-Display ausente na bancada: numero `tdisplay` e baseline historica, sem
  revalidacao em hardware nesta lane.

## 8. Validacao da dona (so leitura)

1. Conferir que os 3 numeros da secao 2 sao identicos ao HEAD deste arquivo
   (`git diff docs/size-wave1.md` mostra so acrescimo, nunca alteracao de numero).
2. Conferir que cada linha da secao 3 cita fonte existente no worktree.
3. Markdown consistente: tabelas com `|` de borda, caminhos citados existem,
   nenhum link quebrado para arquivo, sem segredos no texto.
4. Sem flash/COM7 nesta lane.
5. Rollback: `git checkout -- docs/size-wave1.md` (o arquivo pre-existia no HEAD).

---
Roda pe: baseline 2026-10-18 preservada byte a byte (1786736 / 1785232 / 1824016);
secoes 3-8 sao consolidacao offline de fontes do worktree, sem medicao nova e sem hardware.
