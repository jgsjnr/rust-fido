# Password Manager Device-Only — Plano (sem codigo)

> REGRA PRINCIPAL Nº1 — INVIOLÁVEL: NUNCA queimar eFuse (BLOCK7/BLOCK8, SECURE_VERSION, anti-rollback) nem ativar Secure Boot / flash encryption em COM7 ou qualquer hardware de teste. `EFUSE_WRITE_HARD_LOCKED=true` + feature `burn-efuse-do-not-enable` sempre. Sem exceção "só para testar".
> Status: PLANEJAMENTO apenas. Nenhum codigo foi alterado nesta lane.
> Escopo de escrita: apenas este arquivo (+ opcional `PASSWORD_MANAGER_TASKS_ATOMIC.md`).
> Tema canonico: chave hardware FIDO2/CTAP2.1 + guardiao cripto 100% Rust `no_std` (ESP32-S3/ESP32).

## 0. Fontes relidas na worktree (integracoes existentes)

Lidos nesta worktree (branch `plan/password-manager-encrypted-device`):

- `docs/project/PROJECT.md:1-120` — visao AegisKey, mapa hardware (GPIO 0/48, USB GPIO 19/20, NVS + storage, eFuse BLOCK7/BLOCK8), arquitetura L1-L4.
- `docs/plans/PLANS.md:1-120` — Fases 0-5, 7 GAPs (GAP-01 a GAP-07) + 6 OPPs (OPP-01 a OPP-06), matriz TODO.
- `docs/tasks/TASKS.md:1-120` — T0-T20, HIL L0-L4, baterias seriais/bench, checklist H1-H7.

Evidencia de existencia (grep rapido, sem executar suite):

| Integracao | Evidencia na worktree |
|---|---|
| Vault existente | `crates/aegis-fido-core/src/vault/mod.rs`, `vault/store.rs`, `vault/secrets.rs`, `vault/policy.rs`; firmware `src/lib.rs` declara `vault_aead` + `vault_store`; firmware `src/config.rs` documenta slots `vault/<label>`; `src/migrations/vault_v7.rs` com prefixo `VAULT_LIVE_PREFIX = "vault/"` |
| SecureGuard engine | `crates/aegis-fido-core/src/secure_guard/` (`secure_channel.rs` GAP-02, `glitch_guard.rs` GAP-06, `crypto.rs` GAP-03); bridge UDL expoe `SecureGuardStatusDto`/`SecureGuardPolicyDto` em `crates/uniffi-bridge/src/aegis_bridge.udl` |
| CTAP / extensoes | `crates/aegis-fido-core/src/ctap/extensions_ctap21.rs`, `large_blobs.rs`, `crates/universal-device-sdk/src/ctap21.rs` (`hmac-secret`, `largeBlobs`); testes `ctap_tests.rs` asseveram `hmac-secret` + `largeBlobs` |
| CTAPHID 64B | `crates/aegis-fido-usb/src/ctaphid.rs`; firmware `freertos.rs`/`freertos_sched.rs` tarefa `usb_ctaphid` (prio 5, pacotes 64 B) |
| BLE GATT | firmware `src/ble_gatt.rs` (`authorize_vendor_op`, `OP_KEY_LIST/DELETE`, `OP_OATH_PUT/LIST`, erros `NeedBinding/PresenceRequired/PinRequired`); SDK `capabilities.rs` cita servico de proximidade (nunca o `0xFFFD` do plano original) |
| Wallet/Shamir/Clear-signing | `crates/aegis-fido-core/src/wallet/shamir_slip39.rs` (2-of-3 GF(256)), `clear_signing.rs`, `bip39.rs` em `crypto/` |
| NVS/OTA | NVS + storage dual-partition (`nvs` 24KB + `storage` 896KB) descritos em PROJECT.md; OTA/`nvs_backend` previstos na Fase 2 (PLANS.md T-OTA) |

## 1. Principios (contrato do produto)

1. **Zero persistencia no celular.** O celular e somente viewer + transporte cego. Nenhuma senha, chave, seed ou cache descriptografado persiste em app, disco, log ou backup de SO.
2. **Chave mestra nunca sai do dispositivo.** Geracao, derivacao e uso ocorrem dentro do ESP32-S3. O host recebe apenas blobs AEAD opacos ou campos pontuais apos UP + PIN + janela de binding.
3. **AEAD sempre.** Todo registro de senha e envelope selado (AES-GCM ou ChaCha20-Poly1305, conforme ja usado no crate) com AAD amarrando label + versao + contador anti-rollback.
4. **KDF ancorada em silicio.** PBKDF2/HKDF ja existentes (GAP-03) com sal de eFuse BLOCK8 e KEK de BLOCK7; fallback dev apenas com `TEST_*` em test-mode, nunca em release.
5. **Backup ja previsto, nao reinventar.** Shamir 2-of-3 (OPP-03/05) e BIP39 (OPP-03) sao o caminho de backup/restore. Nenhum export em claro.
6. **Clear-signing no OLED.** Toda liberacao sensivel (mostrar, copiar, exportar backup) exige confirmacao com resumo renderizado no driver SSD1306 code-only (OPP-06) + botao fisico GPIO 0.
7. **Falha fechada.** Sem binding, sem UP, sem PIN ou fora da janela de 60 s: negar com os mesmos codigos ja usados (`NeedBinding`, `PresenceRequired`, `PinRequired`).

## 2. Mudancas atomicas (F-PM0 a F-PM4)

Cada item e independente, verificavel e com nao-objetivos explicitos.

### F-PM0 — Spec de ameacas + contrato do protocolo cego

- **Objetivo:** congelar modelo de ameacas, atores, limites e o contrato CBOR do password manager antes de qualquer mudanca de comportamento.
- **SOLID:** SRP — documento de spec nao mistura decisao de transporte; OCP — novos campos CBOR entram como extensao sem quebrar decoders; DIP — app depende de DTOs do `universal-device-sdk`, nunca de structs internas do firmware.
- **Arquivos-alvo (planejados, nao tocados aqui):** este plano; futuro `universal-device-sdk/src/pm.rs` (DTOs); futura secao HIL em `docs/tasks/`.
- **Acceptance:** tabela ator x capacidade x negacao escrita; lista de opcodes vendor reservados sem colisao com `0x20-0x39` e `0x3A-0x3E`; limites (tamanho max por entrada, quota, rate-limit PIN) definidos.
- **Nao-objetivos:** nenhum codigo; nenhuma mudanca de wire existente; nenhum backup ainda.

### F-PM1 — Vault cifrado device-only (reuso, sem novo motor cripto)

- **Objetivo:** especializar o vault existente (`aegis-fido-core/src/vault/`, `vault_store`/`vault_aead` no firmware) para entradas de senha, mantendo selo em flash/NVS cifrada e `zeroize` apos uso.
- **SOLID:** SRP — `aegis-fido-core` decide envelope/politica, `aegis-fido-firmware` decide persistencia NVS; OCP — novo tipo de entrada entra como variante, sem alterar envelope AEGN v1; DIP — firmware consome traits de store, nao detalhes de AEAD.
- **Arquivos-alvo (planejados):** `crates/aegis-fido-core/src/vault/*` (tipo entrada senha + politica de quota); `crates/aegis-fido-firmware/src/vault_store.rs`, `vault_aead.rs`, `migrations/*` (slot novo sem migrar FIDO2/OATH).
- **Acceptance:** criar/listar/buscar/apagar operam com dispositivo isolado; dump bruto da flash nao revela etiqueta, usuario ou senha; reboot preserva apos EN; wipe escopado preserva FIDO2.
- **Nao-objetivos:** nao expor senha em claro em log/serial; nao mudar quota de `vault/` existente sem migracao A/B; nao tocar largeBlob FIDO2.

### F-PM2 — Protocolo cego do celular (viewer zero-knowledge)

- **Objetivo:** definir o fluxo em que o celular nunca ve o banco: pesquisa e descriptografia acontecem no dispositivo; o celular transporta CBOR opaco e exibe apenas o campo liberado apos UP.
- **SOLID:** SRP — `universal-device-sdk` define DTOs CBOR; `uniffi-bridge` faz JNI/BLE GATT sem logica de negocio; `aegis-fido-usb` move bytes CTAPHID 64 B sem interpretar segredo.
- **Arquivos-alvo (planejados):** `crates/universal-device-sdk/src/pm.rs` (requests/responses CBOR); `crates/uniffi-bridge/src/*` (mapeamento JNI, sem persistencia); `crates/aegis-fido-firmware/src/ble_gatt.rs` + `freertos_route.rs` (gates binding/UP/PIN, janela 60 s); `crates/aegis-fido-usb/src/ctaphid.rs` (fragmentacao, sem segredo em claro).
- **Acceptance:** sem binding retorna `NEED_BINDING`; fora da janela ou sem UP retorna `PresenceRequired`; sem PIN retorna `PinRequired`; nenhuma senha persiste em memoria/disco do host apos fechar a tela (criterio auditavel por teste host-only).
- **Nao-objetivos:** nao usar `largeBlob` padrao CTAP como canal principal sem decisao F-PM0; nao fazer autofill pelo host; nao cachear no app "por conveniencia".

### F-PM3 — Backup/restore via Shamir/BIP39 ja previstos (sem export em claro)

- **Objetivo:** reutilizar Shamir 2-of-3 (`wallet/shamir_slip39.rs`) e BIP39 para backup da chave do cofre de senhas, com restore assistido por OLED + UP.
- **SOLID:** SRP — `wallet/` divide/reconstroi segredo, `vault/` re-sela entradas sob nova KEK; OCP — formato de share SLIP-0039 estendido sem quebrar shares de wallet; DIP — backup depende de abstracao de share, nao de transporte (USB/BLE).
- **Arquivos-alvo (planejados):** `crates/aegis-fido-core/src/wallet/shamir_slip39.rs` (perfil PM, dominio separado da wallet); `crates/aegis-fido-core/src/vault/*` (re-envelope); firmware OLED code-only + `prod_strict_guard.rs` (confirmacao fisica).
- **Acceptance:** backup gera 3 shares, qualquer 2 restauram; 1 share sozinho nao revela nada (teste de forca); restore exige UP + resumo no OLED; nenhum material em claro atravessa USB/BLE.
- **Nao-objetivos:** nao imprimir QR/semente em claro no host; nao armazenar share no celular; nao misturar shares de wallet cripto com shares do cofre sem dominio separado.

### F-PM4 — HIL L0-L4 + gates (qualidade sem suite completa nesta lane)

- **Objetivo:** amarrar cada F-PM a um nivel HIL existente (TASKS.md L0-L4) e aos gates `cargo test` + `clippy -D warnings`, sem executar suite nesta lane de planejamento.
- **SOLID:** SRP — testes de politica vivem no crate dono (core vs firmware vs sdk vs bridge); OCP — novos testes entram como casos, sem reescrever harness; DIP — HIL L1/L2 consomem simulador/dummy, nunca hardware real como oraculo de unidade.
- **Arquivos-alvo (planejados):** testes unitarios por crate (`vault`, `pm` DTOs, `ble_gatt` gates); extensao futura de `docs/tasks/TASKS.md` (fora do escopo de escrita desta lane — proposta vai em `PASSWORD_MANAGER_TASKS_ATOMIC.md` se necessario).
- **Acceptance:** L0 verde por crate (`cargo test -p <crate>` + clippy sem warnings); L1 simulador cobre negar-sem-binding/sem-UP/sem-PIN; L3 COM7 cobre USB+BLE reais sem queimar eFuse; L4 so com `--confirm` e aprovacao explicita.
- **Nao-objetivos:** nao rodar `cargo test/clippy/gradlew` nesta lane (validacao focada abaixo); nao reivindicar `REAL_VERIFIED` sem evidencia adjacente; nao usar QEMU/Renode como prova de hardware.

## 3. Matriz de riscos

| Risco | Impacto | Mitigacao no plano |
|---|---|---|
| Queima acidental de eFuse ou ativação de Secure Boot / flash encryption (BLOCK7/BLOCK8, anti-rollback) | Brick irreversivel, trava flashing/debug em COM7 | REGRA PRINCIPAL Nº1: proibição total; `EFUSE_WRITE_HARD_LOCKED`, feature de guarda, gates `--confirm`, HIL L4 isolado |
| Proximidade/RF (BLE walk-away, RSSI spoof) | Sessao cega sequestrada a distancia | Reuso de gates bonded + janela 60 s + UP fisico; sem comando sensivel sem binding; walk-away fecha viewer |
| Drift docs-codigo (vault/NVS/GATT evoluem, plano descola) | Plano vira ficcao | F-PM0 congela contrato; cada F-PM cita arquivos-alvo reais verificados por grep; mudanca de wire exige major + migracao (regra T4 herdada) |
| Segredo em log/serial/screenshot | Vazamento pelo canal de debug | Proibicao de logar etiquetas/senhas/shares; `zeroize` apos uso; viewer sem persistencia; checklist de revisao de logs no F-PM4 |
| PIN fraco / brute-force offline via dump NVS | Abertura do cofre sem dispositivo | KDF ancorada em silicio (GAP-03) + retries com backoff + wipe escopado apos N falhas (padrao ja usado em `pin_hash`/retries) |
| Confusao wallet-vs-cofre (reuso descuidado de Shamir/largeBlob) | Share errado abre cofre errado | Dominio criptografico separado por perfil; F-PM1/F-PM3 proibem reuso de slot sem migracao A/B |
| Glitch/fault injection pulando UP/PIN | Bypass de presenca | Reuso de `glitch_guard.rs` (double-check + jitter TRNG) nos novos gates (GAP-06 herdado) |

## 4. O que NAO fazer (lista de vetos)

1. Nao queimar eFuse (BLOCK7/BLOCK8, SECURE_VERSION, anti-rollback) nem ativar Secure Boot / flash encryption em COM7 ou qualquer HW de teste, em nenhuma hipotese (nem "so para testar"). `TEST_*` só em test-mode.
2. Nao persistir senha, chave, seed, share ou plaintext em celular, log, analytics, screenshot ou backup de SO.
3. Nao criar novo motor cripto/AEAD/KDF — reusar `secure_guard`/`crypto`/`vault_aead` existentes.
4. Nao expor `TEST_*`, bypass de UP/PIN ou chave de dev em build release.
5. Nao mudar opcodes `0x20-0x39` / `0x3A-0x3E` ou formato AEGN v1 sem major + migracao + HIL (regra T4).
6. Nao reivindicar verificacao em hardware a partir de QEMU/Renode/dummy.
7. Nao escrever fora de `docs/plans/PASSWORD_MANAGER_PLAN.md` (+ opcional tasks atomico) nesta lane.

## 5. Validacao desta lane (focada, sem suite completa)

- `git status --short` mostra somente este `.md` novo (ate 2 arquivos se o tasks atomico for criado).
- Grep de prova executado: `vault/`, `vault_store`/`vault_aead`, `shamir`/`clear_signing`, `ble_gatt`/`ctaphid`, `hmac-secret`/`largeBlobs`, `SecureGuard` — todos com ocorrencias reais citadas na secao 0.
- Nao executado (por decisao de escopo): `cargo test`, `clippy`, `gradlew`, flash, HIL fisico.

## 6. Uso da crate `aegis-pm-vault` (F-PM1, lane isolada)

- Crate: `crates/aegis-pm-vault` (`no_std` + `alloc`; membro do workspace raiz).
  Reexporta `PasswordEntry` / `PmRecord`, `PmPolicy` / `PmGateState` / `PmError`,
  `PmVault` / `PmStore`, `PmShare` + `split_pm_master` / `recover_pm_master`.
- Selagem reusa o envelope AEGN v1 do `aegis-fido-core` (`seal_envelope` /
  `open_envelope`); o CBOR interno e `PmPayload { version: 1, records }`, de modo
  que novas variantes de `PmRecord` nao quebram o envelope.
- Persistencia e DIP: o firmware implementara `PmStore::{save_blob, load_blob,
  wipe}` sobre NVS (so blobs opacos); o celular e transporte cego (blobs +
  liberacao pontual `release_password` sob binding + UP + PIN + janela de 60 s).
- Backup Shamir 2-of-3 com dominio `Aegis-PM-Share-v1` (tipo `PmShare` separado
  do wallet); chave-mestra PM derivada por HKDF sob sal/info `AegisKey-PM-*`
  (dominio distinto do cofre FIDO e da wallet).
- Validacao focada da lane: `cargo test -p aegis-pm-vault` (17 L0 verdes) +
  `cargo clippy -p aegis-pm-vault --all-targets -- -D warnings` (limpo).
  REGRA Nº1 mantida: nenhum eFuse/Secure Boot/flash-encryption; sem `TEST_*`
  fora de `test-mode`; sem `unsafe`, sem `thread::sleep`, sem log de segredos.
