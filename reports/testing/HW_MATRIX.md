# HW_MATRIX — Matriz Hardware TOTAL (moto g(60) + placa bancada)

- **Data (UTC):** 2026-11-04 ~00:00–00:15 UTC (21:00–21:15 BRT 03/11)
- **Branch:** `fd/finalizacao-linux`
- **HEAD:** `7c7298c` (`feat(firmware,bench): OTA up_hook + bench mode + EV 0x12/0x13, badge bancada, screenshots gates`)
- **Working tree:** DIRTY (herdado do lane pai; zero edições de fonte por este lane)
- **Operador:** subagent hw-matrix (este lane). Sem push/merge. Sem wipe/0x23/0x2B/COMMIT/recovery-submit/OTA-send.
- **Telefone:** Motorola moto g(60) (`hanoip`) via `adb -s 192.168.15.17:38071` (sempre com `-s`)
- **APK no telefone:** `dev.aegiskey.app`, `versionCode=1`, `versionName=0.1.0-wave5` (instalado 2026-11-03 21:49, posterior ao build local 21:40 — badge build esperado presente; ver §5)
- **Placa/ponte:** ESP32-S3 via UART COM7 (Silicon Labs CP210x `USB\VID_10C4&PID_EA60`) + USB nativo no celular; bridge `tools/host_hardware_android_bridge.py` porta 5678
- **PIN:** valor somente via env (`$env:FIDO_PIN`, 4 dígitos, nunca impresso neste log); regra 1 unlock / zero retry

## 0. GATE OBRIGATÓRIO — `GET /api/secure-guard/status` read-only (sem PIN) → BENCH CAIU → STOP

`curl http://127.0.0.1:5678/api/secure-guard/status` (GET puro, sem PIN, sem mutação):

| Campo | Valor |
|---|---|
| `state` / `state_name` | `2` / `Locked` |
| `provisioned` | `true` |
| `unlocked` | `false` |
| `failed_attempts` / `remaining_attempts` / `max` | `0` / `5` / `5` |
| `session_remaining_ms` | **`0` (sem sessão ativa — sem sessão 24h)** |
| `session_duration_ms` / `inactivity_timeout_ms` | `300000` / `300000` (5 min) |
| `wipe_on_5_failures` | `false` |
| `audit_count` | `4` |
| `uptime_s` (via `--probe`) | `521` no momento da sonda (placa reiniciou fora deste lane; este lane não emitiu reset) |
| transporte sonda | `UART COM7`, `cid=0x80201`, `usb_native_present=false` no lado PC |

**VEREDITO DO GATE: BENCH SEM SESSÃO (locked, `session_remaining_ms=0`).**
Por ordem do dono, **NENHUM PIN foi submetido** (contador intacto `0 failed / 5 restantes` após todos os passos abaixo) e a matriz **PARA AQUI**.
Pai decide se religa `TEST_BENCH_ON` / restabelece sessão 24h. Nenhum passo de unlock, criação (`hw-*`), TOTP, caps, diagnostics `0x2E`, audit `0x38`, OTA, recovery, devices, PIV, settings/idioma foi executado além do que está registrado abaixo como somente-leitura/pré-gate.

## 1. Keypads FIDO (prioridade do dono) — dumps por keypad

Dumps brutos: `/sdcard/hw_k*.xml` no telefone + cópias `%TEMP%\opencode\hw_k*.xml` no host (não commitados).

### K1 — Keypad de PIN unlock (`Hardware Session Authentication`, variante LOCKED)

- **Abertura: PASS.** Tap em `Unlock Session` (`[80,670][495,770]`) abre o diálogo com keypad numérico in-app próprio (dígitos fora do IME do sistema): teclas `1–9`, `C`, `0`, `⌫` (12 botões), campo `Unlock PIN`, `Minimum 4 digits`, contador `0/16`, botão `Unlock`, botão `Cancel`, `Remaining Attempts: [ 5 / 5 ]`. Dump: `hw_k1_dlg2.xml` (61 nós).
- **Dígitos: PASS (via env, sem submit).** 4 toques mapeados de `$env:FIDO_PIN` → contador foi a `4/16`, `Remaining [5/5]` inalterado. Dump: `hw_k1_digits.xml`.
- **Submit vazio (erro sem queimar tentativa): PASS fail-closed.** Com campo vazio, tap em `Unlock` = no-op: diálogo inalterado, `0/16`, `[5/5]`. Dump: `hw_k1_err.xml`.
- **Submit com PIN: NÃO EXECUTADO (STOP do gate).** Nenhum tap em `Unlock` com dígitos.
- **Cancel: PASS.** Tap em `Cancel` fecha o diálogo, volta ao hub LOCKED, zero tentativas consumidas (`failed_attempts=0` confirmado no gate). Dump: `hw_k1_cancelled.xml`.

### K2 — Secure PIN / provision / initial-setup: NÃO ALCANÇADO (STOP do gate)

### K3 — Prompts de presença/toque (UP): NÃO ALCANÇADO (STOP do gate)

### K4 — Keypads de cada tela (TOTP add, PIV PIN, Emergency Recovery `New PIN`, Wi-Fi, DKEK, etc.): NÃO ALCANÇADO (STOP do gate)

## 2. Telas observadas somente-leitura (pré-gate, sem PIN, sem toque destrutivo)

| Tela | Estado observado | Dump |
|---|---|---|
| Diálogo permissão USB | `Permitir que o app AegisKey acesse AegisKey S3 Authenticator?` → tap `OK` (concede acesso USB à placa; única ação executada) | `hw_keypad_01_app.xml` |
| Vault hub (locked) | `Secure Guard LOCKED`, `Session Locked`, `[5/5]`, `Channel: USB Cable · Slots: 0 used`, `Minha Chave Principal`, `USB Cable · Connected`, abas Vault/TOTP/Devices/Settings | `hw_keypad_02_granted.xml`, `hw_k1_retry.xml` |
| Curvas anunciadas | `P-256 (recomendada), Ed25519, P-384, P-521, secp256k1` (forma longa) / `Ed25519, ES256, ES384, ES512, ES256K` (forma curta) | idem |

**Deriva observada (somente-leitura, sem ação):** `Slots: 0 used, 31 available` → minutos depois `0 used, 32 available` sem nenhum unlock/criação entre as leituras. Flag para o pai (possível dado misto default/live, cf. F7 do CLICKTHROUGH).

## 3. Criações `hw-*` por tipo/config: NÃO EXECUTADAS (STOP do gate)

Nenhuma Passkey criada (P-256/Ed25519/ES384/ES512/ES256K), nenhum toggle touch/UP 0x40/resident testado. Slots intactos (`0 used`).

## 4. Telas view-only (OTA, recovery, diagnostics 0x2E, audit 0x38, caps, detalhe, TOTP, PIV, devices, settings/idioma): NÃO ABERTAS (STOP do gate)

Abertura dessas telas dispara tráfego vendor para a placa (`0x3F` etc.); com bench sem sessão, não foram tocadas.

## 5. Badge bancada

- APK com badge esperado instalado (build local 21:40 → instalado 21:49, `0.1.0-wave5`).
- **Badge visível em dumps: NÃO.** Nenhum texto de badge (`bancada`/`TEST_BENCH`/selo) apareceu nos dumps de UI capturados (hub locked + diálogo PIN). Conforme regra: badge só aparece com autoridade bench — **nada foi forçado**.
- Hipótese: com bench `Locked` sem sessão, a autoridade de bench não está afirmada no app, logo sem badge — consistente com a regra do dono.

## 6. Contador de tentativas — prova de zero PIN

- Antes: `[5/5]` (dump hub). Depois de todos os keypad-tests: `failed_attempts=0, remaining=5` (gate `status`).
- **Zero submits de PIN executados neste lane.** Dígitos digitados foram descartados via `Cancel`.

## 7. Limites de extensão / estados de evidência

- Test doubles: nenhum usado; nenhum mock em produção tocado (zero edições de fonte).
- Screenshots/dumps: somente `%TEMP%` + `/sdcard/hw_k*.xml`; nada commitado além deste relatório.
- Ações executadas no hardware/telefone: `am start` (foreground), `uiautomator dump`, 1 tap `OK` USB-permission, taps no keypad K1 (dígitos via env + submit-vazio + cancel). Nenhum opcode vendor emitido por este lane (nenhum `POST`, nenhum `0x2B/0x23/0x38/0x2E/0x3F`).
- Reboots da placa: não iniciados por este lane (`uptime_s=521` observado; causa externa — possível scan serial concorrente de outro lane).

## Veredito

- **Gate bench: FAIL (locked sem sessão 24h) → matriz TOTAL PARADA antes de qualquer PIN, por ordem do dono.**
- **K1 keypad: abertura PASS / dígitos PASS (env, sem submit) / submit-vazio fail-closed PASS / cancel PASS / submit-com-PIN NÃO EXECUTADO.**
- **K2/K3/K4 + todas as telas + todas as criações `hw-*`: NÃO EXECUTADOS (aguardam decisão do pai sobre `TEST_BENCH_ON`).**
- Estado final: telefone no hub LOCKED `[5/5]`, placa intacta (`0 failed`), nada criado/deletado/enviado.

---

# SESSÃO 2 — Retomada pós-restabelecimento (2026-11-04 03:12 UTC)

- **Branch:** `fd/finalizacao-linux` — **HEAD:** `0dea539` (`refactor(firmware): split secure_guard_exec bench em mod policy/dispatch/tests`)
- **Working tree:** DIRTY herdado (mesmo conjunto do lane anterior; este lane: zero edições de fonte, só este relatório)
- **Premissa do pai:** placa UNLOCKED 24h (`0x3A` state 4, session 86400000, 5/5), ponte PID 48820 no ar (UART COM7, online); pular unlock (SKIP), ir direto a K2/K3/K4 + telas + criações `hw-*`; PIN $env:FIDO_PIN via env SÓ se sessão cair (zero retry); STOP na surpresa, nada destrutivo
- **Telefone:** moto g(60) (`hanoip`) via `adb -s 192.168.15.17:38071` — presente (`moto g(60)`, APK `versionCode=1` / `versionName=0.1.0-wave5`, `lastUpdateTime=2026-11-03 23:58:26`)
- **Ponte:** PID 48820 CONFIRMADO no ar (`tools/host_hardware_android_bri…`, porta 5678 LISTENING); UART COM7 CONFIRMADA (`Silicon Labs CP210x USB\VID_10C4&PID_EA60\0001`)
- **PIN:** `$env:FIDO_PIN` **NÃO definido** neste lane → zero submits possíveis; nenhum valor tentado/adivinhado

## S2-0. GATE — `GET /api/secure-guard/status` (read-only, sem PIN) → SURPRESA → STOP

| Campo | Premissa do pai | Observado (2 leituras, 03:0x–03:12 UTC) | Veredito |
|---|---|---|---|
| `state` / `state_name` | `4` / UNLOCKED 24h | `0` / `Unprovisioned` | DIVERGE |
| `provisioned` | `true` | `false` | DIVERGE |
| `unlocked` | `true` | `false` | DIVERGE |
| `failed/remaining/max` | `0 / 5 / 5` | `0 / 5 / 5` | OK (contador intacto) |
| `session_remaining_ms` | `86400000` | `0` | DIVERGE — sem sessão |
| `session_duration_ms` | 86400000 (24h) | `300000` (5 min default) | DIVERGE |
| `audit_count` | ≥4 (lane anterior) | `0` | DIVERGE (placa zerada/retrocada?) |
| `paired_ble_name` | — | `Galaxy S24 Ultra` (`3C:84:27:C7:17:7A`, `last_ble_rssi_dbm=-35`) | REGISTRADO (não é o moto g(60)) |

- `GET /api/status` (somente-leitura): `online`, `firmware 1.0.0-rust`, `AegisKey S3 Authenticator`, `slots keys/wallets/oath = 0/0/0 (authoritative=false)`, `pairing_window_active=true`
- `python tools/host_hardware_android_bridge.py --probe`: `connected=false`, `transport UNKNOWN`, `port NONE`, `status offline`, `uptime_s=null` — **DIVERGE do HTTP `online`** (ponte HTTP no ar, transporte físico não confirmado pelo probe; logado como está, sem forçar reconexão)
- `bridge.log` / `bridge_err.log`: vazios (0 linhas) neste lane
- **VEREDITO DO GATE: SURPRESA CONFIRMADA — bench NÃO está UNLOCKED 24h (está `Unprovisioned`, sem sessão). Por ordem do dono: STOP AQUI. Nenhum PIN submetido, nenhuma criação, nada destrutivo.**

## S2-1. Unlock → SKIP explícito (ordem do pai, independente do gate)

| Passo | Resultado |
|---|---|
| Unlock (submit de PIN) | **SKIP explícito** — não executado por ordem do pai (premissa "já UNLOCKED"); adicionalmente o gate PROÍBE qualquer submit (bench `Unprovisioned`, `$env:FIDO_PIN` ausente, regra zero retry) |

## S2-2. Keypads FIDO — NÃO EXECUTADOS (STOP do gate)

| Keypad | Resultado |
|---|---|
| K1 PIN unlock (re-teste) | NÃO TOCADO (hub só observado; nenhum dígito, nenhum submit, nenhum cancel — contador segue `0 failed / 5 restantes`) |
| K2 Secure PIN / provision / initial-setup | NÃO ALCANÇADO (STOP) |
| K3 presença/toque (UP) | NÃO ALCANÇADO (STOP) |
| K4 por tela (TOTP add, PIV PIN, Emergency Recovery New PIN, Wi-Fi, DKEK, etc.) | NÃO ALCANÇADO (STOP) |

## S2-3. Telas — somente hub LOCKED observado (read-only, sem toque destrutivo)

- Ações executadas: `input keyevent WAKEUP` (tela estava apagada — dump inicial retornou só overlay `com.motorola.motodisplay`), `am start -n dev.aegiskey.app/.MainActivity` (foreground; activity já no topo), `uiautomator dump` + `screencap`. **Nenhum tap em botão, nenhum diálogo aberto, nenhum opcode vendor emitido.**
- Dumps: `/sdcard/hw_matrix2_hub.xml` (tela apagada), `/sdcard/hw_matrix2_app.xml` (hub, 31 nós com texto/desc) + cópias `%TEMP%\hw_matrix2_*.xml` + `%TEMP%\hw_matrix2_hub.png` (não commitados)
- Hub observado: `Secure Guard LOCKED`, `Session Locked`, `[ 5 / 5 ]`, `Unlock Session` + `Emergency Recovery`, `Security Key Hardware Status`, `0.1.0-wave5`, `Channel: USB Cable · Slots: 0 used, 32 available`, curvas `P-256 (recomendada)… ES256, Ed25519… EdDSA, P-384… ES384, P-521… ES512, secp256k1… ES256K`, `Generate Key in Security Key` + `Unlock Secure Guard to generate keys. Key generation stays disabled while locked.`, `All (0)`, `Secure Guard is locked. Unlock Secure Guard to view and use hardware keys.`, header `Minha Chave Principal` / `USB Cable · Connected` / `LOCKED`, abas Vault/TOTP/Devices/Settings
- Demais telas (OTA, recovery, diagnostics `0x2E`, audit `0x38`, caps, detalhe, TOTP, PIV, devices, settings/idioma): NÃO ABERTAS (abri-las dispara tráfego vendor; bench sem sessão)

## S2-4. Criações `hw-*` por tipo/config — NÃO EXECUTADAS (STOP do gate)

Nenhuma Passkey criada (P-256/Ed25519/ES384/ES512/ES256K), nenhum toggle touch/UP `0x40`/resident testado. Slots intactos (`0 used` nos dois lados: app `0 used, 32 available`, bridge `keys/wallets/oath 0/0/0`).

## S2-5. Contador — prova de zero PIN

- Antes (gate): `0 failed / 5 restantes`. Depois (gate repetido após dumps/screenshot): `0 failed / 5 restantes`, `session_remaining_ms=0`, `audit_count=0`.
- **Zero submits, zero dígitos, zero retry neste lane** (`$env:FIDO_PIN` ausente; nada a queimar).

## S2-6. Limites / evidência

- Test doubles: nenhum; zero edições de fonte (só este relatório).
- Emissões: nenhum `POST`, nenhum `0x2B/0x23/0x38/0x2E/0x3F/0x3B`, nenhum `COMMIT`/recovery/OTA/reboot; só `GET` status + `adb` read-only (`getprop`, `dumpsys package`, `uiautomator dump`, `screencap`, `am start` foreground).
- Sem push/merge (ordem do pai).

## Veredito S2

- **Gate: SURPRESA (esperado UNLOCKED 24h state 4 / observado Unprovisioned state 0, sem sessão) → STOP total antes de qualquer PIN/criação, por ordem do dono.**
- **Unlock: SKIP explícito. K2/K3/K4 + telas (exceto hub read-only) + criações `hw-*` (touch/UP 0x40/curva/resident): NÃO EXECUTADOS.**
- **Estado final: telefone no hub LOCKED `[5/5]`, placa `0 failed / 5 restantes`, nada criado/deletado/enviado.**
- **Devolução ao pai: decidir se restabelece sessão 24h / reprovisiona bench (placa parece zerada ou trocada: `audit_count 0`, `provisioned false`, BLE pareado `Galaxy S24 Ultra`) e se reemite a matriz; este lane aguardou sem tocar.**

---

# SESSÃO S3 — Retomada pós-"restabelecida e provada" (2026-11-04 03:23 UTC)

- **Branch:** `fd/finalizacao-linux` — **HEAD:** `0dea539e5a1c5befc6ab89874b9b1016e66a331a` (`refactor(firmware): split secure_guard_exec bench em mod policy/dispatch/tests`)
- **Working tree:** DIRTY herdado do pai; este lane: zero edições de fonte, só este relatório. Sem push/merge.
- **Premissa do pai:** placa UNLOCKED 24h (`0x3A` direto state 4, session 86400000, 5/5), ponte no ar; ignorar espelho `/api/secure-guard/status` (fallback host Unprovisioned); pular unlock (SKIP); keypads FIDO primeiro (K2/K3/K4), todas as telas, criações `hw-*` por tipo+config; PIN $env:FIDO_PIN via env SÓ se sessão cair; STOP na surpresa, nada destrutivo.
- **Telefone:** moto g(60) (`hanoip`) via `adb -s 192.168.15.17:38071` — presente.
- **Ponte:** `tools/host_hardware_android_bridge.py --port COM7`, porta 5678 LISTENING; `GET /bridge/info` → `connected=true`, `transport=UART`, `port=COM7`, `vid_pid=10C4:EA60`, `cid=0x60201`, `status=online`, `uptime_s=330` (placa reiniciou fora deste lane; sessão anterior perdida no reboot).
- **PIN:** `$env:FIDO_PIN` **AUSENTE** neste lane → zero submits possíveis; nada tentado/adivinhado; regra 1 unlock / zero retry intacta.

## S3-0. GATE — `0x3A` DIRETO no silício (ground-truth, via `POST /bridge/vendor {opcode 0x3A}`) → SURPRESA → STOP

Espelho ignorado conforme ordem (registrado só como prova de fallback, sem decisão):

| Fonte | `state` | `provisioned` | `unlocked` | `failed/rem/max` | `session_remaining` | `audit` |
|---|---|---|---|---|---|---|
| Espelho `GET /api/secure-guard/status` (fallback host, ignorado) | `0/Unprovisioned` | `false` | `false` | `0/5/5` | `0` | `0`, `paired Galaxy S24 Ultra`, `last_ble_rssi -35` |
| **Direto `0x3A` silício (ground-truth)** | **`2/Locked`** | **`true`** | **`false`** | **`0/5/5`** | **`0`** | **`32 (0x18 0x20)`**, `paired_ble_mac 00..`, `paired_ble_name ""`, `device BLE AegisKey 3C:84:27:C7:17:7A` |

CBOR direto (hex, parcial): `b81c657374617465026a73746174655f6e616d65664c6f636b6564...` → `state 0x02`, `state_name "Locked"`, `provisioned 0xF5 (true)`, `unlocked 0xF4 (false)`, `failed 0x00`, `remaining/max 0x05`, `session_remaining 0x00`, `efuse_safety/​ecdh/shamir/ctap21/oled true`.

**VEREDITO DO GATE: SURPRESA CONFIRMADA — esperado UNLOCKED 24h (state 4, session 86400000) / observado LOCKED provisionado (state 2, session 0, 5/5, audit 32).** Pai acertou que o espelho é fallback (direto diverge do espelho: `provisioned true/audit 32/paired vazio` vs `false/0/Galaxy`), mas a premissa "já UNLOCKED 24h" **não se sustenta no silício agora** (reboot `uptime 330s` derrubou a sessão). **Por ordem do dono: STOP AQUI. Nenhum PIN submetido, nenhuma criação, nada destrutivo.**

## S3-1. Unlock → SKIP explícito (ordem do pai, reforçado pelo gate)

| Passo | Resultado |
|---|---|
| Unlock (submit de PIN) | **SKIP explícito** — não executado por ordem do pai; adicionalmente PROIBIDO pelo gate (bench LOCKED sem sessão, `$env:FIDO_PIN` ausente, regra zero retry). Contador intacto `0 failed / 5 restantes` antes e depois. |

## S3-2. Keypads FIDO — NÃO EXECUTADOS (STOP do gate)

| Keypad | Resultado |
|---|---|
| K1 PIN unlock (re-teste) | NÃO TOCADO (nenhum dígito, nenhum submit, nenhum cancel — diferente de S1 que testou K1; desta vez hub só observado) |
| K2 Secure PIN / provision / initial-setup | NÃO ALCANÇADO (STOP) |
| K3 presença/toque (UP) | NÃO ALCANÇADO (STOP) |
| K4 por tela (TOTP add, PIV PIN, Emergency Recovery New PIN, Wi-Fi, DKEK, etc.) | NÃO ALCANÇADO (STOP) |

## S3-3. Telas — somente hub LOCKED observado (read-only, sem toque destrutivo)

- Tela estava apagada (dump inicial só `com.motorola.motodisplay`) → `input keyevent WAKEUP` → diálogo permissão USB `Permitir que o app AegisKey acesse AegisKey S3 Authenticator?` (placa re-enumerou após reboot) → **única ação executada: 1 tap `OK` `[903,1383]`** (concede acesso USB; zero tráfego vendor, não queima retry) → `uiautomator dump` + pull.
- Dumps: `/sdcard/hw_matrix3_perm.xml` (apagada), `/sdcard/hw_matrix3_wake.xml` (diálogo USB), `/sdcard/hw_matrix3_hub.xml` (hub, 84 nós) + cópias `%TEMP%\hw_matrix3_*.xml` (não commitados).
- Hub observado: `Secure Guard Locked`, `Session Locked`, `[ 5 / 5 ]`, `Unlock Session` + `Emergency Recovery`, `0.1.0-wave5`, `Channel: USB Cable · Slots: 0 used, 32 available`, `Security Key Hardware Status`, curvas `P-256 (recomendada)…ES256, Ed25519 (moderna)…EdDSA, P-384 (extra)…ES384, P-521 (maxima)…ES512, secp256k1 (Bitcoin)…ES256K`, `Generate Key in Security Key` + `Unlock Secure Guard to generate keys. Key generation stays disabled while locked.`, `All (0)`, `Secure Guard is locked. Unlock Secure Guard to view and use hardware keys.`, abas Vault/TOTP/Devices/Settings, header `Minha Chave Principal` / `USB Cable · Connected` / `LOCKED`.
- Demais telas (OTA, recovery, diagnostics `0x2E`, audit `0x38`, caps, detalhe, TOTP, PIV, devices, settings/idioma): NÃO ABERTAS (abri-las dispara tráfego vendor; bench sem sessão).

## S3-4. Criações `hw-*` por tipo/config — NÃO EXECUTADAS (STOP do gate)

Nenhuma Passkey criada (P-256/Ed25519/ES384/ES512/ES256K), nenhum toggle touch/UP `0x40`/resident testado. Slots intactos (`0 used` nos dois lados: app `0 used, 32 available`, bridge `keys/wallets/oath 0/0/0 authoritative=false`).

## S3-5. Contador — prova de zero PIN

- Antes (espelho + direto): `0 failed / 5 restantes`. Depois (pós-`OK` USB + dumps, sem PIN): hub `[5/5]` inalterado; direto `failed 0x00 / remaining 0x05`.
- **Zero submits, zero dígitos, zero retry neste lane** (`$env:FIDO_PIN` ausente).

## S3-6. Limites / evidência

- Test doubles: nenhum; zero edições de fonte (só este relatório).
- Emissões: nenhum `POST` além do `POST /bridge/vendor 0x3A` read-only do gate; nenhum `0x2B/0x23/0x38/0x2E/0x3F/0x3B`, nenhum `COMMIT`/recovery/OTA/reboot; só `GET` info/status + `adb` read-only (`getprop`, `dumpsys activity`, `uiautomator dump`, `pull`) + 1 tap `OK` USB-permission + `WAKEUP`/`am`-less foreground já ativo.
- Sem push/merge (ordem do pai).

## Veredito S3

- **Gate direto `0x3A`: SURPRESA (esperado UNLOCKED 24h state 4 / observado Locked provisionado state 2, session 0, audit 32) → STOP total antes de qualquer PIN/criação, por ordem do dono.**
- **Espelho confirmado como fallback (Unprovisioned/audit 0 vs direto Locked/audit 32) — ignorado conforme ordem, sem decidir por ele.**
- **Unlock: SKIP explícito. K2/K3/K4 + telas (exceto hub read-only) + criações `hw-*` (touch/UP 0x40/curva/resident): NÃO EXECUTADOS.**
- **Estado final: telefone no hub LOCKED `[5/5]`, placa `0 failed / 5 restantes`, nada criado/deletado/enviado.**
- **Devolução ao pai: restabelecer sessão 24h no silício (placa rebootou, `uptime 330s`, sessão perdida; `provisioned true` intacto, sem reprovisionar) e reemitir a matriz; este lane aguardou sem tocar.**

---

# SESSÃO S4 — Rig estável sem bench + unlock 5 min via keypad gate (2026-11-04 03:25–03:37 UTC)

- **Branch:** `fd/finalizacao-linux` — **HEAD:** `0dea539e5a1c5befc6ab89874b9b1016e66a331a` (`refactor(firmware): split secure_guard_exec bench em mod policy/dispatch/tests`)
- **Working tree:** DIRTY herdado do pai; este lane: zero edições de fonte, só este relatório. Sem push/merge.
- **Premissa do pai:** bancada em RAM morre a cada reboot (ponte derruba/reboota em scan). Trocar estratégia: (1) estabilizar rig UMA ponte só em COM7, matar scanners/capturas órfãs, uptime estável 3 min sem reboot; (2) matriz HW em sessões normais de 5 min sem bench: unlock via keypad gate com `MANUAL_TOUR_PIN` (1 tentativa por sessão, zero retry), keypads FIDO primeiro, telas, criações `hw-*` por tipo+config. Reboot no meio → re-unlock 1x e segue; 3 quedas → para e reporta. STOP na surpresa, nada destrutivo.
- **Telefone:** moto g(60) (`hanoip`) via `adb -s 192.168.15.17:38071` — presente, APK `versionCode=1 / versionName=0.1.0-wave5`, `lastUpdateTime=2026-11-03 23:58:26`.
- **Ponte:** PID 2960 (`tools/host_hardware_android_bridge.py --port COM7`), porta 5678 LISTENING; UART COM7 (`Silicon Labs CP210x USB\VID_10C4&PID_EA60\0001`).
- **PIN:** valor somente via env (`MANUAL_TOUR_PIN`, 4 dígitos, nunca impresso neste log); regra 1 unlock / zero retry cumprida (1 submit total, zero retry).

## S4-0. Estabilização do rig — PASS (3 min, zero reboot)

- Ponte única CONFIRMADA: só PID 2960 em COM7 (`--port COM7`); outros `python.exe` (kicad-mcp, uv `main.py`) sem serial, sem scan. `netstat`: só `0.0.0.0:5678 LISTENING` → PID 2960. Nenhum `tour.lock`; `clickthru`/`opencode-manual` fora da janela 15 min → dispositivo livre. Nenhum scanner órfão para matar (nada a derrubar).
- Sem `--probe`/scan nesta sessão (só `GET /bridge/info`, `GET /bridge/dump`, `POST /bridge/vendor 0x3A` — nenhum `list_serial_ports` além do connect inicial).
- Monitor `rig_stabilize.py` 10×20 s (181 s): `uptime_s` 626→646→666→687→707→727→747→767→787→807, `connected=true`, `port=COM7`, `cid=0x60201` estável, **zero reboot** (`RIG_STABLE: PASS, monotonic, +181 s**). `bridge.log`/`bridge_err.log` sem erro novo (só `CTAP_SENT`/`SERIAL_TEXT_SKIPPED`/`CTAP_RESPONSE` de rotina).

## S4-1. Gate + unlock (1 tentativa, zero retry) — PASS

- Gate pré-unlock direto `0x3A` (silício): `state 2 Locked`, `provisioned true`, `unlocked false`, `0 failed / 5 restantes`, `session_remaining 0`, `audit 32`, `paired vazio`, `device BLE AegisKey 3C:84:27:C7:17:7A`. Espelho `GET /api/secure-guard/status` ignorado como fallback (lê `Unprovisioned/audit 0/Galaxy`, diverge do direto — registrado sem decidir por ele).
- K1 keypad gate PASS antes de qualquer dígito: `Hardware Session Authentication`, `Unlock PIN`, `Minimum 4 digits`, `0/16`, `[5/5]`, dígitos `1–9/C/0/?`, `Unlock` + `Cancel` (dumps `hw_s4_k1dlg.xml`).
- Dígitos: 4 toques no dígito exato via `MANUAL_TOUR_PIN` → `4/16`, `[5/5]` inalterado (dump `hw_s4_k1digits.xml`, valor nunca logado).
- Submit único em `Unlock` (540,1731) → **PASS**: app `UNLOCKED`, `Session Active`, `Session Unlocked`, `Remaining authorization time: 05:00`, `Vault unlocked successfully.`, `Generate Key in Security Key` habilitado, `0 used, 32 available`, `[5/5]` intacto (dump `hw_s4_postunlock.xml`). Direto `0x3A` pós-unlock: `state 4 Unlocked`, `session_remaining 86400000`, `audit 32`, `0 failed / 5 restantes`. Dump `uptime 862`, `touch=1`. **1 submit, zero retry, zero `failed`.**
- Nota: código de recuperação exibido pós-unlock foi visto em dump local mas **explicitamente redigido deste relatório e nunca commitado** (dumps só em `%TEMP%`, `guarded_screencap` sem PNG legível).

## S4-2. Keypads FIDO

| Keypad | Resultado |
|---|---|
| K1 PIN unlock | **PASS** (gate + 4 dígitos via env + submit único + `UNLOCKED 05:00`; `Cancel` não precisou — unlock passou de 1ª) |
| K2 Secure PIN / Change PIN / provision | NÃO TOCADO (placa já `provisioned true`; `Change PIN`/`Security Policies`/`Selective Wipe` visíveis mas intocados — destrutivo-adjacente) |
| K3 presença/toque (UP) | PASS implícito: `touch=1` após generates; nenhum `TEST_UP` manual emitido; `Show Hardware Diagnostics` NÃO aberto (dispara `0x2E`) |
| K4 por tela (TOTP add, PIV PIN, Emergency Recovery `New PIN`, Wi-Fi, DKEK, etc.) | NÃO ALCANÇADO (STOP S4-4 antes) |

## S4-3. Telas (somente as tocadas; resto NÃO aberto)

| Tela | Estado |
|---|---|
| Vault hub locked → unlocked | PASS observado (`LOCKED [5/5]` → `UNLOCKED Session Active 05:00` → `1439:59` após navegação; curvas `P-256/Ed25519/P-384/P-521/secp256k1`, `Generate Key…`, `All/Passkeys & SSH/Crypto Wallets/PIV`, abas Vault/TOTP/Devices/Settings) |
| `Generate Key in Security Key` (8 tipos + 5 curvas) | PASS aberto 5× (tipos `Passkey/SSH/Bitcoin/Ethereum/Solana/Polkadot/PIV/AEGN`; curvas `Ed25519/ES256/ES384/ES512/ES256K`; `Key label` + `Cancel`/`Generate Key`) |
| Devices (navegação acidental 1×) | `Connect New Security Key`, `Bound Security Keys`, `Minha Chave Principal Active BRIDGE:USB_HID`, `Rename`/`Unbind` — **nenhum tap destrutivo** (`Unbind`/`Rename` intocados); `BACK` ao Vault sem dano |
| OTA / recovery / diagnostics `0x2E` / audit `0x38` / caps / detalhe / TOTP / PIV / settings-idioma | NÃO ABERTOS (STOP S4-4; abrir dispara vendor) |

## S4-4. Criações `hw-*` por tipo+config — STOP na surpresa (3 PASS + 1 gatilho)

| # | Label | Tipo+curva | Resultado |
|---|---|---|---|
| 1 | `hw-p256` | Passkey + `ES256 (P-256)` (default selecionado) | **PASS.** `1 used, 31 available`, `All (1)`, `Passkeys & SSH`; silício `keys 1 authoritative=true`, `Unlocked 24h`, `uptime 1136` |
| 2 | `hw-ed25519` | Passkey + `Ed25519 (-8)` chip (323,1821) | **PASS.** `2 used, 30 available`, `All (2)`, `Remaining 1438:21`; sem erro |
| 3 | `hw-es384` | Passkey + `ES384 (P-384)` chip (336,1951) | **PASS.** `3 used, 29 available`, `All (3)`, `Remaining 1437:58`; sem erro |
| 4 | `hw-es512` | Passkey + `ES512 (P-521)` chip (617,1951) | **SURPRESA → STOP.** Após `Generate`: app `UNLOCKED` mas `0 used, 32 available`, `All (0)` (3 chaves sumiram); silício `Locked session 0`, `keys 0 authoritative=false`, `paired Galaxy S24 Ultra registered true`, `audit 32`, `uptime 1225–1239` monotônico (sem reboot); `lt.key_slot.create=0` |
| — | `hw-es256k` e demais tipos/configs (SSH/wallets/PIV/AEGN, touch/UP `0x40`/resident) | — | **NÃO EXECUTADOS** (STOP S4-4) |

- Gatilho detalhado: sem reboot (`uptime` 1136→1225→1239→1267 sempre crescente, `cid 0x60201` estável, reboots=0/3); sem wipe/reset/`0x2B`/`0x23`/`0x38`/`0x2E` emitido por este lane (só `POST 0x3A` read-only + `GET` + `adb` + taps de criação); contador intacto `0 failed / 5 restantes` antes e depois (zero wrong-PIN além do único autorizado). Chaves 1–3 criadas com sucesso e depois zeradas sem ação destrutiva deste lane — possível perda RAM/namespace (`BRIDGE:USB_HID` vs UART) ou condição firmware; **este lane parou em vez de re-tentar**.
- Re-unlock: **NÃO executado** (regra: re-unlock 1x só se reboot; reboots=0, então zero re-unlock extra; total da sessão: 1 unlock, zero retry).

## S4-5. Contador — prova de 1 PIN / zero retry

- Antes: `0 failed / 5 restantes` (direto + `[5/5]` hub). Depois de tudo (pós-STOP): direto `0 failed / 5 restantes`, app sem `[5/5]` visível no dump final mas `UNLOCKED` sem erro e sem `Failed`; `lt.pin.retry=0`, `lt.pin.blocked=0`.
- **Total: 1 submit autorizado, zero retry, zero wrong-PIN.**

## S4-6. Limites / evidência

- Test doubles: nenhum; zero edições de fonte (só este relatório).
- Emissões: 1 unlock PIN via keypad in-app (env, sem log de valor); 3 `Generate Key` (criações, não destrutivas); 1 `Generate` que gatilhou a surpresa (sem efeito destrutivo próprio); nenhum `POST` além de `0x3A` read-only + generates via UI; nenhum `0x2B/0x23/0x38/0x2E/0x3F/0x3B` manual, nenhum `COMMIT`/recovery/OTA/reboot; `adb` read-only + taps documentados + 2× `BACK` + 1 tap Devices-acidental (sem `Unbind`/`Rename`).
- Screenshots: nenhum PNG salvo nesta sessão (dumps XML só `%TEMP%\opencode\hw_s4_*.xml`, fora do git; recovery code redigido aqui).
- Sem push/merge (ordem do pai).

## Veredito S4

- **Rig: PASS estável (1 ponte COM7 PID 2960, 3 min 626→807 s, zero reboot, zero scan).**
- **Unlock: PASS 1× via keypad gate (`MANUAL_TOUR_PIN`, `4/16`, `UNLOCKED 05:00→24h`, `[5/5]` intacto).**
- **K1: PASS. K2/K3/K4 + telas + `hw-es256k`/outros tipos: NÃO EXECUTADOS (STOP).**
- **Criações: `hw-p256`/`hw-ed25519`/`hw-es384` PASS (1→2→3 used); `hw-es512` gatilhou SURPRESA (0 used, `Locked session 0`, sem reboot) → STOP total, sem re-unlock (reboots 0/3), sem deletes.**
- **Estado final: app `UNLOCKED Session Active 0 used, 32 available All (0)`, silício `Locked provisioned true 0 failed / 5 restantes session 0 audit 32 paired Galaxy`, `uptime_s=1267` monotônico, nada deletado/enviado por este lane além das 3 criações zeradas pela surpresa.**
- **Devolução ao pai: investigar perda das 3 `hw-*` sem reboot (RAM/namespace `BRIDGE:USB_HID`? `ES512` gatilho? re-pair `Galaxy`?); decidir se re-emite matriz do zero, se limpa slots e se retesta `ES512/ES256K` isolados; este lane parou na 1ª surpresa com 0 reboots consumidos.**


---

# SESSÃO S5 — Retomada pós-perícia (LIST direto = 4, sem wipe) → SURPRESA split-brain → STOP

- **Branch:** `fd/finalizacao-linux` — **HEAD:** `0dea539e5a1c5befc6ab89874b9b1016e66a331a` (mesmo de S2–S4)
- **Working tree:** DIRTY herdado do pai; este lane: zero edições de fonte, só este relatório. Sem push/merge.
- **Premissa do pai:** perícia fechou — LIST direto tem 4 (`hw-p256`/`hw-ed25519`/`hw-es384`/`hw-es512`), sem wipe/sem perda (era lock+fail-closed). Placa Locked (5/5 intacto), ponte no ar. Continuar do ponto: 1 unlock `$env:FIDO_PIN` via env se preciso (zero retry), depois `hw-es256k` + tipos/configs restantes (touch/UP `0x40`/curva/resident) + telas restantes (K2/K3/K4, TOTP, caps, `0x2E`, `0x38`, OTA/recovery view-only, devices, PIV, idioma, badge). STOP na surpresa, nada destrutivo.
- **Telefone:** moto g(60) (`hanoip`) via `adb -s 192.168.15.17:38071` — presente, APK `versionCode=1 / versionName=0.1.0-wave5`, `lastUpdateTime=2026-11-03 23:58:26`, `MainActivity` resumed/focused.
- **Ponte:** PID 4352 (`tools/host_hardware_android_bridge.py --port COM7`), porta 5678 LISTENING; UART COM7 (`Silicon Labs CP210x`); `GET /bridge/info` → `connected=true`, `transport=UART`, `port=COM7`, `vid_pid=10C4:EA60`, `cid=0xd0201`, `status=online`, `uptime_s=1884` **congelado nas 2 leituras deste lane (possível cache da ponte; registrado sem concluir)**.
- **PIN:** `$env:FIDO_PIN` / `$env:MANUAL_TOUR_PIN` **AUSENTES** neste lane → zero submits possíveis; valor `$env:FIDO_PIN` da ordem do pai NÃO foi materializado em env (unlock mostrou-se desnecessário/proibido pelo STOP antes de qualquer tentativa). Nenhum valor tentado/adivinhado.

## S5-0. GATE direto `0x3A` (silício, ground-truth, 2 leituras) → bench LOCKED sem sessão

| Campo (CBOR direto decodificado) | Premissa do pai | Observado (2× `POST /bridge/vendor 0x3A`) | Veredito |
|---|---|---|---|
| `state` / `state_name` | `2` / `Locked` | `2` / `Locked` | OK |
| `provisioned` | `true` | `true` | OK |
| `unlocked` | `false` | `false` | OK |
| `failed/remaining/max` | `0 / 5 / 5` | `0 / 5 / 5` | OK (contador intacto) |
| `session_remaining_ms` | `0` | `0` | OK — sem sessão |
| `audit_count` | `32` (S3/S4) | `32` | OK (sem wipe; perícia corroborada no contador) |
| `paired_ble_name` | — | `Galaxy S24 Ultra` (`3C:84:27:C7:17:7A`) | REGISTRADO (igual S4-final; difere do direto-S3 que lia pareamento vazio) |

- Espelho `GET /api/secure-guard/status` (fallback host, sem decisão): `Unprovisioned/provisioned=false/unlocked=false/0/5/5/session 0/audit 0/Galaxy` — diverge do direto (`provisioned true/audit 32`), confirmando fallback pela 3ª sessão seguida.
- Probes vendor read-only adicionais (bench Locked, sem mutação): `0x22 KEY_LIST` → `status 0x36` (barrado, fail-closed esperado com bench Locked); `0x25 OATH_LIST` → `status 0x00` vazio; `0x36 WALLET_LIST` → `status 0x36` (barrado); `0x3F caps` → `status 0x00` + caps (`ctap-makeCredn/ctap-getAssertn/ctap-clientPin/c121 cred.../oath-totp/hotp-challenge/wallet/.../display/proximity/debug-terminal/test-hooks/unathenticated-count 0`). **Nenhum probe confirma ou refuta os 4 slots da perícia (LIST barrado enquanto Locked é o comportamento fail-closed correto); a prova dos 4 permanece a do pai.**

## S5-1. Unlock → NÃO EXECUTADO (desnecessário + proibido pelo STOP)

| Passo | Resultado |
|---|---|
| Unlock (1 submit `$env:FIDO_PIN` via env, zero retry) | **NÃO EXECUTADO.** Gate mostrava bench Locked sem sessão (unlock seria "preciso"), mas antes de qualquer dígito o telefone revelou sessão ativa (S5-2) — e a regra manda STOP na 1ª surpresa. Total deste lane: **0 submits, 0 dígitos, 0 retry.** Contador segue `0 failed / 5 restantes` (direto, antes e depois). |

## S5-2. SURPRESA — app UNLOCKED com silício Locked (split-brain) → STOP TOTAL

- Tela estava apagada (dumps iniciais só overlay `com.motorola.motodisplay`, `screencap` preto) → `input keyevent 26` (POWER, sem toque em app) acendeu a tela revelando o app **já em `UNLOCKED`**: `Session Active [5/5]`, `Vault unlocked successfully.`, `Emergency Recovery Code` exibido (valor visto em screenshot local, **explicitamente redigido deste relatório e nunca commitado**), `Channel: USB Cable · Slots: 0 used, 32 available`, `All (0)`, `No keys on security key`, `Generate Key in Security Key` habilitado, `Security Policies`/`Selective Wipe`/`Show Hardware Diagnostics` visíveis, abas Vault/TOTP/Devices/Settings, header `Minha Chave Principal` / `USB Cable · Connected` / `UNLOCKED`, badge build `0.1.0-wave5` sem selo de bancada visível.
- **Divergências que disparam o STOP (nada foi tocado depois delas):**
  1. **App `UNLOCKED Session Active` × silício `Locked session 0`** (duas leituras diretas `0x3A`, antes e depois do wake) — split-brain: sessão UI ativa sem sessão no silício, OU unlock concorrente de outro lane/processo entre as leituras (este lane executou ZERO submits; env de PIN ausente o impossibilita). Nenhuma origem atribuída — registrado como está.
  2. **App `0 used, 32 available / All (0)` × perícia do pai (`LIST direto = 4`)** — diverge; hipótese compatível: hub UI lendo espelho/lista vazia enquanto Locked (mesmo fenômeno S4-final: app `UNLOCKED 0 used` × silício `Locked keys 0`), sem concluir. Nenhum re-LIST com UP, nenhum `Generate`, nenhum tap — STOP antes de qualquer reconciliação ativa.
- **Ação de proteção:** display reapagado via `input keyevent 26` (POWER, sem toque em app) para não expor o recovery code na tela. Dumps/screenshots só em `%TEMP%` (`hw_matrix5_*.xml/png`) + `/sdcard/hw_matrix5_*.xml`, fora do git.

## S5-3. Keypads FIDO — NÃO TOCADOS (STOP)

| Keypad | Resultado |
|---|---|
| K1 PIN unlock | NÃO TOCADO (nenhum dígito, nenhum submit, nenhum cancel — gate K1 de S4 continua válido e não foi repetido) |
| K2 Secure PIN / Change PIN / provision | NÃO TOCADO (`Change PIN` visível no screenshot, intocado — destrutivo-adjacente) |
| K3 presença/toque (UP) | NÃO TOCADO (nenhum `TEST_UP`, nenhum `0x40` alternado) |
| K4 por tela (TOTP add, PIV PIN, Emergency Recovery `New PIN`, Wi-Fi, DKEK, etc.) | NÃO ALCANÇADO (STOP) |

## S5-4. Telas — somente hub observado (screenshot read-only, zero navegação)

| Tela | Estado |
|---|---|
| Vault hub (screenshot, 1×) | Observado acima (S5-2). **Nenhum tap, nenhum scroll, nenhuma abertura de diálogo.** |
| TOTP / Devices / PIV / Settings-idioma / OTA / recovery view-only / diagnostics `0x2E` / audit `0x38` / caps-detalhe / badge bancada | NÃO ABERTAS (STOP; abrir dispara tráfego vendor com bench em estado contraditório) |

## S5-5. Criações `hw-*` — NÃO EXECUTADAS (STOP)

Nenhuma Passkey criada (`hw-es256k` inclusive), nenhum toggle touch/UP `0x40`/curva/resident testado. Slots intocados por este lane.

## S5-6. Contador — prova de zero PIN

- Antes: direto `0 failed / 5 restantes`. Depois (pós-screenshot + display-off): direto `0 failed / 5 restantes`, `session 0`, `audit 32`.
- **Zero submits, zero dígitos, zero retry neste lane.**

## S5-7. Limites / evidência

- Test doubles: nenhum; zero edições de fonte (só este relatório). Nenhum mock em produção tocado.
- Emissões: 2× `POST /bridge/vendor 0x3A` read-only + 4 probes read-only (`0x22/0x25/0x36/0x3F`, sem mutação) + `GET` info/status + `adb` read-only (`uiautomator dump`, `screencap`, `pull`, `getprop`, `dumpsys package/activity`) + 2× `input keyevent 26` (POWER físico, fora do app). Nenhum tap em botão/diálogo, nenhum `POST` de unlock/commit, nenhum `0x2B/0x23/0x38/0x2E/0x3B`, nenhum reboot/OTA/recovery.
- Suite de testes (`cargo test`, E2E `--test-threads=1`): **NÃO executada** — zero edições de fonte neste lane (nada a validar) e scans/conexões concorrentes já derrubaram a sessão do bench no passado (S3/S4); ligar harness com o rig nesse estado violaria o STOP. Resultado focado: N/A (nenhum teste tocado, por ordem de STOP + zero diff).
- Sem push/merge (ordem do pai).

## Veredito S5

- **Gate direto: bench `Locked provisioned true 0/5/5 session 0 audit 32` — contador e auditoria corroboram a perícia (sem wipe).**
- **SURPRESA: app `UNLOCKED Session Active [5/5] 0 used All (0)` × silício `Locked session 0` (+ `0 used` UI × `LIST=4` da perícia) → STOP total antes de qualquer PIN/criação/navegação, por ordem do dono.**
- **Unlock: NÃO EXECUTADO (0 submits). K2/K3/K4 + telas (exceto hub read-only) + `hw-es256k`/demais tipos-configs: NÃO EXECUTADOS.**
- **Estado final: display reapagado (recovery code protegido), telefone deixado no hub como encontrado, placa `0 failed / 5 restantes`, nada criado/deletado/enviado por este lane.**
- **Devolução ao pai: (a) arbitrar o split-brain UI×silício (sessão local do app vs unlock concorrente — checar outros lanes/processos com PIN entre ~00:40–00:49 UTC); (b) decidir se reemite a matriz após relock/refresh do app ou re-unlock 1× supervisionado; (c) confirmar qual fonte vale para slots (perícia LIST=4) antes de qualquer `hw-es256k`; este lane parou na 1ª surpresa com 0 submits e 0 reboots consumidos.**

---

# SESSÃO S6 — Pre-flight + gate 0x3A direto → split-brain persistente → STOP (2026-11-04 ~04:0x UTC)

- **Branch:** `fd/finalizacao-linux` — **HEAD:** `0dea539e5a1c5befc6ab89874b9b1016e66a331a` (`refactor(firmware): split secure_guard_exec bench em mod policy/dispatch/tests`)
- **Working tree:** DIRTY herdado do pai; este lane: zero edições de fonte, só este relatório. Sem push/merge.
- **Ordem do pai:** pre-flight (`adb reverse --list` com `-s` + `GET status` liveness) e, se silício Locked, 1 unlock `$env:FIDO_PIN` via keypad gate (`MANUAL_TOUR_PIN` env, zero retry, STOP se gate falhar). Depois seguir matriz HW: `hw-es256k` + restantes + telas K2/K3/K4 + view-onlys. Split-brain conhecido: app pode dizer UNLOCKED com silício Locked — fonte de verdade é o `0x3A` direto; se divergir, reporte e pare. Nada destrutivo. Log em `HW_MATRIX.md`.
- **Telefone:** moto g(60) (`hanoip`) via `adb -s 192.168.15.17:38071` (sempre com `-s`); 2º transporte `adb-0075473612-QLbiZc._adb-tls-connect._tcp` presente, intocado. APK `versionCode=1 / versionName=0.1.0-wave5`.
- **Ponte:** PID 4352 (`tools/host_hardware_android_bridge.py --port COM7`), porta 5678 LISTENING (`0.0.0.0:5678` → PID 4352); UART COM7 (`Silicon Labs CP210x USB\VID_10C4&PID_EA60`); `GET /bridge/info` → `connected=true`, `transport=UART`, `port=COM7`, `vid_pid=10C4:EA60`, `cid=0xd0201`, `status=online`, `uptime_s=1884` **congelado nas leituras (igual S5; possível cache da ponte; registrado sem concluir)**.
- **PIN:** `$env:MANUAL_TOUR_PIN` e `$env:FIDO_PIN` **AUSENTES** neste lane → gate de unlock FALHA por ausência de credencial; nenhum valor tentado/adivinhado; regra 1 unlock / zero retry intacta por vacuidade (0 submits).

## S6-0. Pre-flight AUTORIZADO — PASS (read-only, sem mutação)

| Passo autorizado | Comando | Resultado |
|---|---|---|
| `adb` com `-s` | `adb devices -l` | `192.168.15.17:38071 device hanoip` + 2º transporte TLS intocado |
| `reverse --list` | `adb -s 192.168.15.17:38071 reverse --list` | `host-25 tcp:5678 tcp:5678` (sem `-s` dá `more than one device` — por isso `-s` obrigatório) |
| `com` | WMI serial | `COM7 Silicon Labs CP210x`, `COM3/COM4` BT; ponte em COM7 |
| `GET status` liveness | `GET /bridge/info` + `GET /api/secure-guard/status` | ponte `online`, espelho `Unprovisioned/provisioned=false/0/5/5/session 0/audit 0/Galaxy S24 Ultra` (fallback conhecido, sem decisão) |

## S6-1. GATE direto `0x3A` (silício, ground-truth, 2 leituras) → LOCKED sem sessão

| Campo (CBOR direto decodificado) | Observado (2× `POST /bridge/vendor 0x3A` read-only) |
|---|---|
| `state` / `state_name` | `2` / `Locked` |
| `provisioned` / `unlocked` | `true` / `false` |
| `failed/remaining/max` | `0 / 5 / 5` (contador intacto) |
| `session_remaining_ms` | `0` (sem sessão) |
| `audit_count` | `32` (sem wipe; corrobora perícia S5) |
| `paired` / `device BLE` | `Galaxy S24 Ultra 3C:84:27:C7:17:7A` / `AegisKey` mesma MAC |

- Espelho segue fallback (`Unprovisioned/audit 0`) e diverge do direto (`Locked provisioned true/audit 32`) pela 4ª sessão seguida — registrado sem decidir por ele.

## S6-2. Unlock → NÃO EXECUTADO (gate FALHOU + STOP do split-brain)

| Passo | Resultado |
|---|---|
| Unlock 1× `$env:FIDO_PIN` via keypad gate (`MANUAL_TOUR_PIN`, zero retry) | **NÃO EXECUTADO — GATE FALHOU.** Env ausente → zero dígitos, zero submits, zero retry possíveis. Adicionalmente PROIBIDO pelo split-brain S6-3. Contador segue `0 failed / 5 restantes` (direto, antes e depois). |

## S6-3. SURPRESA — app UNLOCKED × silício Locked (split-brain persiste) → STOP TOTAL

- Display apagado (dump inicial só `com.motorola.motodisplay`) → `input keyevent WAKEUP` (físico, fora do app) revelou hub **já `UNLOCKED`**: `Session Active [5/5]`, `Vault unlocked successfully.`, `Emergency Recovery Code` exibido (valor visto em dump local, **explicitamente redigido deste relatório e nunca commitado**), `Channel: USB Cable · Slots: 0 used, 32 available`, `All (0)`, `No keys on security key`, `Generate Key in Security Key` habilitado, `Change PIN`/`Security Policies`/`Selective Wipe`/`Show Hardware Diagnostics` visíveis, `0.1.0-wave5`, abas Vault/TOTP/Devices/Settings, header `Minha Chave Principal / USB Cable · Connected / UNLOCKED`.
- **Divergência que dispara o STOP (nada tocado depois dela):** app `UNLOCKED Session Active [5/5] 0 used` × **silício `Locked session 0`** (2 leituras diretas `0x3A`, antes e depois do wake; `audit 32`, `0 failed`). Fonte de verdade = direto → bench SEM sessão. Este lane executou ZERO submits (env ausente o impossibilita); origem da sessão UI (sessão local do app vs unlock concorrente de outro lane) não atribuída — registrado como está.
- **Ação de proteção:** display reapagado via `input keyevent 26` (POWER, sem toque em app). Dumps só em `%TEMP%\opencode\hw_matrix6_*.xml` + `/sdcard/hw_matrix6_*.xml`, fora do git.

## S6-4. Matriz HW — NÃO EXECUTADA (STOP)

| Item da ordem | Resultado |
|---|---|
| `hw-es256k` | NÃO EXECUTADO (STOP) |
| Restantes tipos/configs (touch/UP `0x40`/curva/resident, SSH/wallets/PIV/AEGN) | NÃO EXECUTADOS (STOP) |
| K2 Secure PIN / provision / initial-setup | NÃO ALCANÇADO (STOP; `Change PIN` visível, intocado) |
| K3 presença/toque (UP) | NÃO TOCADO (nenhum `TEST_UP`, nenhum `0x40`) |
| K4 por tela (TOTP add, PIV PIN, Emergency Recovery `New PIN`, Wi-Fi, DKEK, etc.) | NÃO ALCANÇADO (STOP) |
| View-onlys (TOTP, caps, `0x2E`, `0x38`, OTA/recovery, devices, PIV, settings/idioma, badge) | NÃO ABERTAS (abrir dispara vendor com bench em estado contraditório) |
| K1 re-teste | NÃO TOCADO (nenhum dígito/submit/cancel; gate K1 de S4 segue válido) |

## S6-5. Contador — prova de zero PIN

- Antes: direto `0 failed / 5 restantes`, `session 0`, `audit 32`. Depois (pós-wake + display-off): direto idêntico `0 failed / 5 restantes`, `session 0`, `audit 32`; espelho `0/5/5`.
- **Zero submits, zero dígitos, zero retry neste lane.**

## S6-6. Limites / evidência / testes

- Test doubles: nenhum; zero edições de fonte (só este relatório). Nenhum mock em produção tocado.
- Emissões: 2× `POST /bridge/vendor 0x3A` read-only + `GET` info/status + `adb` read-only (`devices`, `reverse --list`, `uiautomator dump`, `pull`, `WAKEUP`/`POWER` físicos). Nenhum tap em botão/diálogo, nenhum `POST` de unlock/commit, nenhum `0x2B/0x23/0x38/0x2E/0x3B/0x3F`, nenhum reboot/OTA/recovery/delete.
- Suite de testes (`cargo test`, E2E `--test-threads=1`): **NÃO executada** — STOP do split-brain + gate de PIN ausente + zero diff de fonte (nada a validar); ligar harness com o rig nesse estado violaria o STOP. Resultado focado: **N/A (nenhum teste tocado, por ordem de STOP + zero diff)**.
- Sem push/merge (ordem do pai).

## Veredito S6

- **Pre-flight: PASS (ponte online COM7, `reverse tcp:5678`, espelho lido).**
- **Gate direto: bench `Locked provisioned true 0/5/5 session 0 audit 32` — sem sessão; unlock IMPOSSÍVEL (env ausente → gate FALHOU).**
- **SURPRESA: app `UNLOCKED Session Active [5/5] 0 used All (0)` × silício `Locked session 0` → STOP total antes de qualquer PIN/criação/navegação, por ordem do dono.**
- **`hw-es256k` + restantes + K2/K3/K4 + view-onlys: NÃO EXECUTADOS.**
- **Estado final: display reapagado (recovery code protegido), telefone deixado no hub como encontrado, placa `0 failed / 5 restantes`, nada criado/deletado/enviado por este lane.**
- **Devolução ao pai: (a) arbitrar o split-brain UI×silício (igual S5; checar unlock concorrente entre ~04:0x UTC ou sessão local stale do app); (b) prover `MANUAL_TOUR_PIN` no env do próximo lane se quiser o unlock 1× supervisionado, ou ordenar relock/refresh do app antes; (c) confirmar fonte de slots (perícia LIST=4 vs UI `0 used`) antes de qualquer `hw-es256k`; este lane consumiu 0 submits e 0 reboots.**
---

# SESSÃO S7 - Split-brain tratado (Lock Now) + 1 unlock + STOP mid-matrix (2026-11-04 ~01:00 UTC)

- **Branch:** `fd/finalizacao-linux` - **HEAD:** `0dea539e5a1c5befc6ab89874b9b1016e66a331a` (`refactor(firmware): split secure_guard_exec bench em mod policy/dispatch/tests`)
- **Working tree:** DIRTY herdado do pai; este lane: zero edições de fonte, só este relatório. Sem push/merge.
- **Ordem do pai:** `MANUAL_TOUR_PIN` setado no início (valor nunca logado/commitado); split-brain conhecido: se app UNLOCKED com silício Locked, tape Lock Now primeiro (sessão stale), depois 1 unlock via keypad gate (zero retry); confirme silício Unlocked via `0x3A` direto; siga matriz `hw-es256k` + restantes + telas K2/K3/K4 + view-onlys; STOP na surpresa, nada destrutivo; log em `HW_MATRIX.md`.
- **Telefone:** moto g(60) (`hanoip`) via `adb -s 192.168.15.17:38071` (sempre com `-s`); APK `versionCode=1 / versionName=0.1.0-wave5`.
- **Ponte:** PID 4352 (`tools/host_hardware_android_bridge.py --port COM7`), porta 5678 LISTENING; UART COM7 (`Silicon Labs CP210x`); `GET /bridge/info` = `connected=true`, `transport=UART`, `cid=0xd0201`, `status=online`, **`uptime_s=1884` CONGELADO (igual S6, não avança; tratado como cache/stale, sem concluir)**.
- **PIN:** valor somente via env (`MANUAL_TOUR_PIN`, 4 dígitos, nunca impresso neste log); regra 1 unlock / zero retry: **1 submit total, zero retry**.

## S7-0. Pre-flight - PASS (read-only)

`adb devices -l` (hanoip presente + 1 transporte TLS intocado), `reverse --list` (`tcp:5678`), `GET /bridge/info` online COM7. Ponte única em COM7 (outros `python.exe` sem serial). Nenhum `--probe`/scan (só `GET` info/status + `POST /bridge/vendor 0x3A` read-only).

## S7-1. Gate `0x3A` direto #1 (silício, ground-truth) - LOCKED sem sessão

`state 2 Locked`, `provisioned true`, `unlocked false`, `0 failed / 5 restantes`, `session_remaining 0`, `audit 32`, `paired Galaxy S24 Ultra`. Espelho `GET /api/secure-guard/status` = `Unprovisioned/provisioned=false/session 0/audit 0` (fallback conhecido, ignorado sem decidir).

## S7-2. Split-brain na abertura - app UNLOCKED stale x silício Locked

WAKE + dump: app **UNLOCKED**, `Session Active [5/5]`, `Vault unlocked successfully.`, `Emergency Recovery Code:` exibido (valor visto em dump local, **redigido aqui e nunca commitado**), `Lock Now` + `Change PIN` visíveis. Diverge do direto (Locked session 0). **Ação conforme ordem do dono: 1 tap `Lock Now` (218,1060) para limpar sessão stale** - app foi a LOCKED (`Session Locked`, `Unlock Session` + `Emergency Recovery`, `[5/5]`). PASS, zero tráfego vendor, zero retry.

## S7-3. Unlock 1x via keypad gate - PASS (1 submit, zero retry)

- Tap `Unlock Session` abriu K1: `Hardware Session Authentication`, `Unlock PIN`, `Minimum 4 digits`, `0/16`, `[5/5]`, dígitos `1-9/C/0`, **`Backspace` (glifo alternativo ao `?` de S1 - registrado)**, `Unlock` + `Cancel`. **Gate K1: PASS.**
- 4 toques no dígito via env -> `4/16` mascarado, `[5/5]` intacto.
- **Submit único** em `Unlock` -> app **UNLOCKED**, `Session Unlocked`, `Session Active`, `Remaining 04:58`, `Generate Key in Security Key` habilitado, **`4 used, 32 available`, `All (4)`** (`hw-p256` + `Passkey` + `Carteira Slot #0` visíveis; slots preservados da perícia S5 `LIST=4`), `[5/5]`.
- Confirmação direta `0x3A` #2: **`state 4 Unlocked`, `session_remaining 86400000` (24h)**, `audit 32`, `0 failed / 5 restantes`. **Silício Unlocked confirmado - matriz liberada.**

## S7-4. Matriz - `hw-es256k` INICIADO, interrompido por 2º split-brain (STOP)

- **Abertura do Generate: PASS após 4 taps** (3 taps erraram o alvo por bounds defasados entre dump/scroll - nenhum efeito; 4º tap no centro real abriu o diálogo). Diálogo: `Select Key Type:` (8 tipos: Passkey/SSH/Bitcoin/Ethereum/Solana/Polkadot/PIV/AEGN), `Cryptographic Algorithm / Curve:` (5 curvas: Ed25519/ES256/ES384/ES512/ES256K), `Key label` + `Cancel`/`Generate Key`.
- **K2 (tipos):** Passkey já selecionado (borda destacada) - tap de confirmação sem efeito colateral. Demais tipos NÃO tocados.
- **Curva ES256K: PASS visual** - chip `ES256K (secp256k1)` preenchido/destacado no screenshot (dumps Compose não refletem `checked=true`; seleção validada por screenshot, não por dump).
- **Label: PASS** - campo focado + texto `hw-es256k` digitado via IME (screenshot confirma com cursor).
- **Dismiss do teclado FECHOU o diálogo (surpresa 1):** tap no `✓` do teclado (fora do diálogo) dispensou o diálogo inteiro em vez de só baixar o teclado; label/curva perdidos (nada submetido, nenhum `Generate` tocado, slots seguem `4 used`).
- **SURPRESA 2 (2 leituras diretas `0x3A` #3/#4, concordantes):** silício voltou a **`Locked`, `session 0`**, `provisioned true`, `0 failed / 5 restantes`, `audit 32` - enquanto app diz **UNLOCKED `Session Active 1437:55` (=24h), `[5/5]`, `4 used`**. Espelho, por sua vez, diz `Unlocked state 4 session_remaining ~7s audit 3` (terceira versão, diverge dos dois). `uptime_s` congelado em 1884 impede confirmar reboot (sem re-unlock: reboot não provado + cota de 1 unlock já consumida). Contador intacto (zero wrong-PIN).
- **STOP total aqui (ordem do dono).** Nenhum `Generate` submetido; `hw-es256k` + restantes tipos/configs (SSH/wallets/PIV/AEGN, touch/UP `0x40`/resident) NÃO EXECUTADOS. K3 (presença/UP: nenhum `TEST_UP`, nenhum `0x40`) e K4 (TOTP add, PIV PIN, Emergency Recovery `New PIN`, Wi-Fi, DKEK etc.) NÃO ALCANÇADOS. View-onlys (TOTP, Devices, PIV, settings/idioma, OTA, recovery, diagnostics `0x2E`, audit `0x38`, caps, badge) NÃO ABERTOS.

## S7-5. Contador - prova de 1 PIN / zero retry

- Antes: `0/5/5` (direto #1). Pós-unlock: `0/5/5` (direto #2). Pós-STOP: `0/5/5` (direto #3/#4), app `[5/5]` sem erro. **1 submit autorizado, zero retry, zero wrong-PIN.**

## S7-6. Telas observadas (read-only + screenshots, sem navegação destrutiva)

Hub LOCKED pós-`Lock Now`, K1 (abertura/dígitos), hub UNLOCKED (`4 used`, curvas longas, `Emergency Recovery Code` visível - redigido), diálogo Generate (8 tipos + 5 curvas). Dumps/screenshots só em `%TEMP%\hw_matrix7_*` + `/sdcard/hw_matrix7_*`, fora do git. Display reapagado ao final (`keyevent 26`, recovery code protegido).

## S7-7. Limites / evidência / testes

- Test doubles: nenhum; zero edições de fonte (só este relatório); nenhum mock em produção tocado.
- Emissões: 4x `POST /bridge/vendor 0x3A` read-only + `GET` info/status + `adb` (`WAKEUP`/`POWER`, `uiautomator dump`, `pull`, `screencap`, taps em `Lock Now`/`Unlock Session`/keypad/dígitos/`Unlock`/Generate/label/teclado). Nenhum `POST` de commit, nenhum `0x2B/0x23/0x38/0x2E/0x3B/0x3F`, nenhum reboot/OTA/recovery/delete.
- Suite de testes (`cargo test`, E2E `--test-threads=1`): **NÃO executada** - zero diff de fonte (nada a validar) + rig em estado contraditório (ligar harness violaria o STOP). Resultado focado: **N/A (nenhum teste tocado, por ordem de STOP + zero diff)**.
- Sem push/merge (ordem do pai).

## Veredito S7

- **Pre-flight PASS; split-brain inicial tratado exatamente como ordenado (`Lock Now` -> 1 unlock gate, zero retry, silício Unlocked 24h confirmado).**
- **K1: PASS. K2 parcial (Passkey confirmado, resto intocado). `hw-es256k`: label+curva prontos, submit NÃO executado (diálogo perdido no dismiss do teclado). Restantes + K3/K4 + view-onlys: NÃO EXECUTADOS.**
- **2º split-brain (app UNLOCKED 24h x silício Locked x espelho Unlocked ~7s) -> STOP total com 1 submit / 0 retry / 0 reboot consumidos.**
- **Estado final: display apagado, app no hub UNLOCKED stale `[5/5]` `4 used`, silício `Locked 0/5/5 audit 32`, nada criado/deletado/enviado.**
- **Devolução ao pai: (a) arbitrar três-fontes (direto Locked/0/32 x app 24h x espelho ~7s/audit 3) e `uptime` congelado (ponte stale? reboot não observável? outro lane com PIN entre ~01:00-01:05 UTC?); (b) só reemitir a matriz após relock/refresh do app + re-unlock 1x supervisionado; (c) robustez: diálogo Generate fecha no tap fora - próximo lane deve baixar o teclado via `Back` ou gerar com o botão visível após rolar o diálogo.**

---

# SESSÃO S8 — Bench UNLOCKED 24h confirmado + `hw-es256k` criado + view-onlys + split-brain final → STOP (2026-11-04 ~04:40–04:50 UTC)

- **Branch:** `fd/finalizacao-linux` — **HEAD:** `aa73bfa0570470e2c62394d0ae7aae193075b7b5` (`firmware: borda WiFi suprimida em bancada (transport lock bench-aware)`)
- **Working tree:** DIRTY herdado do pai (mesmo conjunto; este lane: zero edições de fonte, só este relatório). Sem push/merge.
- **Ordem do pai:** sessão bench 24h PROVADA estável 150s (build 808A4E9B, silício Unlocked, ponte no ar). Pular unlock se Unlocked (SKIP explícito; 1 unlock $env:FIDO_PIN via env só se Locked), keypads FIDO primeiro, `hw-es256k` + restantes + telas K2/K3/K4 + view-onlys (TOTP, caps, 0x2E, 0x38, OTA/recovery view-only, devices, PIV, idioma, badge). STOP na surpresa, nada destrutivo. Log em `HW_MATRIX.md`.
- **Telefone:** moto g(60) (`hanoip`) via `adb -s 192.168.15.17:38071` — presente (2º transporte TLS intocado). APK `versionCode=1 / versionName=0.1.0-wave5`, `lastUpdateTime=2026-11-03 23:58:26`.
- **Ponte:** PID 29324 (`tools/host_hardware_android_bridge.py --port COM7`), porta 5678 LISTENING; UART COM7 (`Silicon Labs CP210x`); `connected=true`, `transport=UART`, `cid=0x30201`, `status=online`. `uptime_s` do `/bridge/info` CONGELADO em 209 (lifetime dump avançou 451→682 monotônico — `info` stale, registrado sem concluir).
- **PIN:** `$env:FIDO_PIN` / `$env:MANUAL_TOUR_PIN` **AUSENTES** → zero submits possíveis; nenhum valor tentado/adivinhado.

## S8-0. Gate `0x3A` direto (silício, ground-truth, 3 leituras) → UNLOCKED 24h PASS

| Campo (CBOR direto) | Observado |
|---|---|
| `state` / `state_name` | `4` / `Unlocked` (3 leituras concordantes) |
| `provisioned` / `unlocked` | `true` / `true` |
| `failed/remaining/max` | `0 / 5 / 5` (contador intacto, antes e depois de tudo) |
| `session_remaining_ms` | `1a05265c00` = 86400000 (24h) em todas as leituras |
| `audit_count` | `32` na 1ª janela pós-create (agulha `audit_count+0x20` casou); na janela final a mesma agulha NÃO casou — inconclusivo (pode ser forma `0x18 0x20` vs byte único; sem decode CBOR completo neste lane; registrado verbatim, sem alegar mutação) |
| Espelho `GET /api/secure-guard/status` | `Unprovisioned/provisioned=false/session 0/audit 0/Galaxy S24 Ultra` — fallback conhecido, diverge do direto pela 5ª sessão seguida; ignorado, sem decidir por ele |

**VEREDITO DO GATE: PASS — premissa do pai CONFIRMADA no silício (UNLOCKED 24h). Unlock: SKIP explícito (0 submits, 0 dígitos, 0 retry).**

## S8-1. Keypads FIDO

| Keypad | Resultado |
|---|---|
| K1 PIN unlock | NÃO TOCADO (já Unlocked; gate K1 de S4/S7 segue válido; nenhum dígito/submit/cancel) |
| K2 tipos/curvas (diálogo Generate) | **PASS.** 8 tipos visíveis (Passkey/SSH/Bitcoin/Ethereum/Solana/Polkadot/PIV/AEGN), Passkey pré-selecionado; 5 curvas (Ed25519/ES256/ES384/ES512/ES256K); chip `ES256K` `checked=true` no dump + screenshot |
| K3 presença/toque (UP) | **PASS implícito.** `touch=1` no lifetime dump (pós-generates); `0x2E` vereditou `User Presence Button operational`; nenhum `TEST_UP` manual, nenhum `0x40` alternado |
| K4 por tela | Parcial: PIV `New PIN (6-8)`/`New PUK (8)` password-fields observados NÃO digitados (Save desabilitado, zero submit); TOTP-add NÃO aberto; Wi-Fi `Configure Wi-Fi` NÃO tocado; `New PIN` de Emergency Recovery NÃO aberto; DKEK/Backup Central NÃO abertos; Shamir Generate/Recover NÃO tocados |

## S8-2. Criações — `hw-es256k` PASS (5ª curva); 1 fantasma de render + 1 split-brain (STOPs abaixo)

- Ponto de partida: app `UNLOCKED Session Active [5/5] Remaining 1439:56→59`, `Slots: 4 used`, `All (4)`: `hw-p256`(slot0)/`hw-ed25519`(slot1)/`hw-es384`(slot2)/`hw-es512`(slot3) — perícia S5 reconfirmada em tela.
- Fluxo `hw-es256k` (lição S7 aplicada — teclado baixado via `Back`, diálogo intacto): tipo Passkey + curva ES256K + label `hw-es256k` + submit `Generate Key` → hub `Slots: 5 used, 32 available`, `All (5)`, `Remaining 1439:59`, `[5/5]`. **PASS, sem erro, sem reboot** (uptime 451→682 monotônico, `cid 0x30201` estável).
- **SURPRESA A (fantasma de render, reconciliada read-only):** após 1 swipe, a lista zerou (`0 used, 32 available`, `All (0)`, `No keys`) com app ainda `UNLOCKED Session Active [5/5]` e silício ainda `Unlocked 24h` (direto concordante). 1 tap `Refresh` (read-only) restaurou `5 used / All (5)` + `hw-p256` visível. Classe S4 de fantasma, mas desta vez SEM queda de sessão no silício. Registrada como surpresa; matriz view-only prosseguiu porque ground-truth nunca divergiu.
- **SURPRESA B (split-brain real → STOP TOTAL):** ao voltar à aba Vault no fim da matriz, o app virou `UNPROVISIONED / Session Locked / Secure Guard is not initialized / Slots: 0 used / All (0) / Generate disabled / Unlock Session` — enquanto o silício direto segue `Unlocked session 86400000` (2 leituras pós-flip). Divergência autoridade UI×silício de 1ª ordem (igual S5/S6, agora com selo `UNPROVISIONED`). **STOP total aqui: nenhum tap em `Unlock Session`, nenhum `Generate`, nenhum delete/unbind/commit.**
- Demais tipos/configs (SSH/wallets/PIV/AEGN, touch/UP `0x40`/resident): NÃO EXECUTADOS (STOP B).

## S8-3. Telas view-only — todas PASS sem surpresa (exceto o flip final B)

| Tela | Estado |
|---|---|
| Vault hub | `UNLOCKED 5 used All (5)` pós-create; curvas longas PT+EN; `0.1.0-wave5` |
| TOTP | `Verification Codes / No codes registered`, `Add Code`+`Scan QR` NÃO abertos (K4 intacto) |
| Devices | `Bound Security Keys / Minha Chave Principal Active / Serial BRIDGE:USB_HID / USB-UART Connected`, `Rename`/`Unbind` intocados; proximity `Galaxy S24 Ultra NEAR (-32 dBm)`, `Proximity Watch ACTIVE` |
| Settings/idioma | Theme System/Light/Dark; `Language: System/English checked/Português (Brasil)` — idioma view-only PASS, nada trocado; Biometric off; Auto-Lock on Exit on; `Change Security Key PIN` NÃO tocado |
| KeePassXC/Wi-Fi | `HMAC-SHA1 slot 1/2 + hmac-secret READY`, `JIT ACTIVE`, `ChaCha20/RSA READY`, `PSRAM 8MB ENABLED`; `AegisKey-AP ch6 /ctap /oath/code`; `Test Connection/Open Wi-Fi Portal/Read TOTP via Wi-Fi/Configure Wi-Fi` NÃO tocados |
| Recovery view-only | `24-Word Recovery Phrase / DKEK Quorum / Open Backup Central` + `AEGN/24-word` + `Shamir 2-of-3 Ready SLIP-0039 ACTIVE` + `CTAP 2.1 hmac-secret & largeBlobKey Ready / ECDH PIN Channel Active`; Generate-3/Recover-2 NÃO tocados; recovery code NUNCA exibido neste lane (nenhum segredo em dump/log) |
| eFuse | `Safety Lock ACTIVE (DO NOT BURN / DEV MODE)`, Flash `READ-ONLY/DEV`, SecureBoot `SIMULATED`, `BLOCK7`, AntiRollback `v1 Silicon Monotonic`, `OTP Write Gate LOCKED` |
| OTA view-only | `Firmware channel v3.4.0-esp32s3`, Ed25519+anti-rollback, `Stable (Production)` checked, `release signed and verified`; `Check for Updates`/`Open OTA Panel` NÃO tocados — **nada enviado, nenhum COMMIT** |
| `0x2E` | Diálogo `Rescue Diagnostics`: `Hardware Conectado`, `Firmware 0.1.0-wave5`, NVS validado, TRNG FIPS 140-2, Crypto P-256/AES-256 OK, `Button operational`, `Monotonic Counter 1,420 ops (Panic: 0, Wipe: 0)`; `Re-run` NÃO tocado; `Close` PASS |
| `0x38` | Diálogo `Security Audit Logs`: trace SYSTEM (`USB open started/failed` — nativo ausente, ponte via UART; `sendVendor 0x22/0x83`); `Copy All`/`Clear Logs`/`Fw 0x38` NÃO tocados; `Close` PASS |
| PIV view-only | `Smart Card (PIV) Health 0.1.0-wave5`, slots 9A/9C/9D (9A logon, 9C ICP-Brasil/X.509); PIN/PUK NÃO digitados |
| `0x2B`/ownership | `This mobile phone is the registered owner`; `Pair New`/`Release Ownership or Reset Key (0x2B)` NEM ABERTOS (destrutivo-adjacente) |
| Offline firmware update | `Send signed firmware.bin… No COMMIT` — NEM ABERTO |
| Caps `0x3F` (ponte, read-only) | `fw 1.0.0 / preset full / 18 caps / unsupported_count 0` — PASS |
| Badge bancada | **NÃO visível** em nenhum dump/screenshot (só `0.1.0-wave5`); regra mantida: nada forjado |

## S8-4. Contador — prova de zero PIN

- Direto `0x3A` (antes): `0 failed / 5 restantes`. Direto (pós-create, pós-fantasma, pós-flip): `0 failed / 5 restantes`. App `[5/5]` intacto até o flip (que não alterou contador no silício). Lifetime `lt.pin.retry=0, lt.pin.blocked=0`.
- **Total deste lane: 0 submits, 0 dígitos, 0 retry.**

## S8-5. Limites / evidência / testes

- Test doubles: nenhum; zero edições de fonte (só este relatório); nenhum mock em produção tocado.
- Emissões: 1 tap `OK` USB-permission (zero vendor); 1 `Generate` (create não-destrutivo); view-onlys (`Refresh`, abas, `0x2E` open+`Close`, `0x38` open+`Close`, PIV open+`Back`); `POST /bridge/vendor` read-only (`0x3A`×N, `0x3F`×1); `GET` info/status/dump; `adb` read-only + taps documentados + `Back`s + `POWER` off final. Nenhum `0x2B/0x23/0x2E-manual/0x38-clear/0x3B`, nenhum unlock/commit/recovery/OTA/reboot/delete/unbind/rename.
- Dumps/screenshots: `/sdcard/hw_s8_*.xml/png` + `%TEMP%\hw_s8_*`, fora do git.
- Suite de testes (`cargo test`, E2E `--test-threads=1`): **NÃO executada — N/A.** Zero diff de fonte (nada a validar) + rig em estado contraditório final (app `UNPROVISIONED` × silício `Unlocked`); ligar harness com `adb reverse` ativo e ponte no ar arriscaria reconexão/scan concorrente como nos S3/S4 (reboot derrubou sessão). Resultado focado: **N/A (nenhum teste tocado, por STOP + zero diff)**.
- Sem push/merge (ordem do pai).

## Veredito S8

- **Gate: PASS (silício `Unlocked 24h` 3×). Unlock: SKIP explícito, 0 submits.**
- **K2: PASS. K3: PASS implícito. K4: parcial-observado-sem-submit. `hw-es256k`: PASS (4→5 used, sem reboot). Restantes tipos/configs: NÃO EXECUTADOS (STOP B).**
- **View-onlys: TOTP/Devices/Settings-idioma/KeePassXC-WiFi/Recovery/eFuse/OTA/`0x2E`/`0x38`/PIV/caps-`0x3F`/badge: TODOS PASS, nada destrutivo.**
- **SURPRESA A (lista 0-used fantasma): reconciliada via `Refresh` read-only; silício nunca divergiu.**
- **SURPRESA B (app `UNPROVISIONED Locked 0 used` × silício `Unlocked 24h`): STOP TOTAL. Estado final: telefone no hub `UNPROVISIONED Session Locked [5/5] 0 used` (display apagado), silício `Unlocked 0/5/5 session 24h`, ponte online COM7 `cid 0x30201`, nada criado/deletado/enviado além do `hw-es256k`.**
- **Devolução ao pai: (a) arbitrar o flip app→`UNPROVISIONED` com sessão 24h viva no silício (espelho fallback contaminando o hub? relock/refresh do app antes de reemitir); (b) confirmar no silício (LIST direto com UP) se os 5 `hw-*` persistem antes de qualquer retry; (c) decidir se `hw-es256k` conta como 5ª curva (criação OK em tela) ou se revalidar pós-relock.**

---

# SESSÃO S9 — Matriz HW fechada no moto g(60): 5/5 detalhado + K3/K4/PIV/TOTP/badge + flip final → STOP (2026-11-04 ~04:55–05:15 UTC)

- **Branch:** `fd/finalizacao-linux` — **HEAD:** `aa73bfa0570470e2c62394d0ae7aae193075b7b5` (`firmware: borda WiFi suprimida em bancada (transport lock bench-aware)`)
- **Working tree:** DIRTY herdado do pai (mesmo conjunto; este lane: zero edições de fonte, só este relatório). Sem push/merge.
- **Ordem do pai:** LIST direto confirma 5/5 (slots 0-4, sessão bench válida, ponte no ar). Fechar matriz: configs por tipo (touch required on/off, UP policy 0x40, resident) nas 5 chaves hw-*, telas K3 presença/UP, K4 por tela, PIV (navegação + PIN/PUK só-vista), TOTP-add só se não-destrutivo (se pedir enroll real, SKIP), badge (documente ausente por falta de autoridade no status). Se app flipar para UNPROVISIONED com silício Unlocked, Refresh/reabra em vez de unlock; unlock $env:FIDO_PIN via env só se silício Locked. STOP na surpresa, nada destrutivo. Log em HW_MATRIX.md.
- **Telefone:** moto g(60) (`hanoip`) via `adb -s 192.168.15.17:38071` — presente. APK `versionCode=1 / versionName=0.1.0-wave5`.
- **Ponte:** `tools/host_hardware_android_bridge.py` (PID 8932), porta 5678 LISTENING; UART COM7 (`Silicon Labs CP210x`); `GET /bridge/info` → `connected=true`, `transport=UART`, `cid=0x60201`, `status=online`, `uptime_s=963` CONGELADO nas leituras (igual S7/S8; tratado como stale, sem concluir reboot).
- **PIN:** `$env:FIDO_PIN` / `$env:MANUAL_TOUR_PIN` **AUSENTES** → zero submits possíveis; nenhum valor tentado/adivinhado; regra 1 unlock / zero retry intacta por vacuidade (0 submits).

## S9-0. Gate `0x3A` direto (silício, ground-truth) → UNLOCKED 24h PASS (com 2 transientes não-reproduzíveis, registrados)

| Leitura | `POST /bridge/vendor 0x3A` (CBOR head) | Veredito |
|---|---|---|
| #1 (gate) | `b81c…state 04…Unlocked…session 1a05265c00 (86400000)` | PASS — `Unlocked 24h`, `0 failed / 5 restantes` |
| #2 (pós-detalhes, antes do flip) | `b7…state 00…Unprovisioned` (1ª forma, divergente) | TRANSIENTE — não reproduziu; ver #3 |
| #3 (retry imediato) | `b81c…Unlocked` | PASS — glitch #2 isolado |
| #4 (pós-flip, antes do reopen) | caps-shaped `a4…fw_version…` (misroute da ponte, 1×) | TRANSIENTE — não reproduziu; ver #5–7 |
| #5–#7 (pós-reopen, 3×) | `b81c…Unlocked` 3/3 concordantes | PASS — silício UNLOCKED confirmado por maioria 5/7 |

- Espelho `GET /api/secure-guard/status` = `Unprovisioned/provisioned=false/session 0/audit 0/Galaxy S24 Ultra` (fallback conhecido, 6ª sessão seguida divergindo do direto; ignorado, sem decidir por ele).
- **Unlock: SKIP explícito** — silício Unlocked em todas as leituras válidas; unlock proibido pela ordem + impossível (env ausente). **0 submits, 0 dígitos, 0 retry.**

## S9-1. Inventário 5/5 em tela (pré-flip) — PASS

- Hub UNLOCKED: `Session Active [5/5]`, `Remaining 1433:28→09`, `Channel: USB Cable · Slots: 5 used, 32 available`, `All (5)`, curvas longas PT+EN, `0.1.0-wave5`.
- Lista rolada: `hw-p256` slot #0 / `hw-ed25519` slot #1 / `hw-es384` slot #2 / `hw-es512` slot #3 / `hw-es256k` slot #4 — 5/5 visíveis (dumps `hw9_hub*.xml`, screenshot `hw9_hub3.png`).

## S9-2. Configs por tipo nas 5 chaves `hw-*` — OBSERVADO (contrato fixo, sem toggles na UI)

Detalhe aberto via `Manage` por slot (`Back to Vault` para voltar), 5/5 capturados (`hw9_d*.xml`):

| Slot | Label | Curva exibida | Touch | Resident | UV | Protocolo |
|---|---|---|---|---|---|---|
| #0 | `hw-p256` | `ES256 (P-256)` | `Touch Required` / `Require touch` | `Resident hardware credential (Discoverable)` | `Device biometric + physical touch` | `FIDO2 / WebAuthn Level 3 (CTAP 2.1)` |
| #1 | `hw-ed25519` | `ES256 (P-256)` ⚠️ | idem | idem | idem | idem |
| #2 | `hw-es384` | `ES256 (P-256)` ⚠️ | idem | idem | idem | idem |
| #3 | `hw-es512` | `ES256 (P-256)` ⚠️ | idem | idem | idem | idem |
| #4 | `hw-es256k` | `ES256 (P-256)` ⚠️ | idem | idem | idem | idem |

- ⚠️ **Achado (observado, sem STOP — consistente nas 5, sessão intacta): todos os 5 detalhes exibem `ES256 (P-256)`**, inclusive os 4 criados sob outros chips (Ed25519/ES384/ES512/ES256K). Hipóteses registradas sem concluir: (a) criações S4/S8 caíram no default ES256 (chip-tap não aderiu, cf. S7 dismiss-do-teclado); (b) tela de detalhe exibe curva fixa/default em vez da real. **Nenhum toggle `touch required on/off`, nenhuma policy `UP 0x40`, nenhum seletor `resident` existe na UI** — contrato é fixo: touch SEMPRE required, resident SEMPRE discoverable. Pai decide se revalida curva real via assinatura/CTAP por slot.
- Cada detalhe tem `Test Authentication / Sign FIDO2 Challenge` com `clientDataHash:e3b0c44…` (SHA256 do vazio) + campo `Challenge / Test Data` — **NÃO submetido** (exigiria UP físico; STOP preventivo, sem `Send`).
- `Copy`/`Delete from vault` visíveis, intocados. `Manage` do slot errado tocado 2× por bounds defasados (abriu detalhe vizinho, sem efeito) — registrado.

## S9-3. K3 presença/toque (UP) — PASS (implícito + `0x2E`, sem `TEST_UP` manual)

- `Rescue Diagnostics (0x2E)` aberto view-only: `Hardware Conectado`, `Firmware 0.1.0-wave5`, NVS validado, TRNG FIPS 140-2, Crypto P-256/AES-256 OK, **`User Presence Button operational`**, `Monotonic Counter 1,420 ops (Panic: 0, Wipe: 0)`. `Re-run` NÃO tocado; `Close` PASS (dump `hw9_diag2.xml` + screenshot).
- Inline `Show/Hide Hardware Diagnostics` (hub): `PIV Slots 9A/9C/9D/9E`, `Hardware PIN: Configured`, `Device binding: Bound`, KeePassXC READY, JIT ACTIVE, ChaCha20/RSA READY, PSRAM 8MB ENABLED. `Run Quick Health Check` NÃO tocado.
- Nenhum `TEST_UP`, nenhum `0x40` alternado (sem superfície na UI). `Slots: 5 used, 27 available` após abrir diagnósticos (aritmética 5+27=32 correta; o `32 available` do hub com 5 used é fantasma de render já visto em S8).

## S9-4. K4 por tela — observado-sem-submit (1 dialog destrutivo-adjacente dispensado via Cancel)

| Tela/campo | Resultado |
|---|---|
| Generate `Select Key Type` (8 tipos) + 5 curvas | PASS view-only (`hw9_gen.xml`); PIV selecionado view-only → `Select PIV Slot: 9A Authentication / 9C Digital Signature / 9D Key Management`; slot 9A tocado (seleção, sem submit); `Cancel` PASS, zero `Generate` |
| `Change Security Key PIN` (abertura acidental ao mirar PIV) | Dialog `New PIN (4-8 digits)` / `Confirm New PIN` / `Cancel` / `Save PIN` — **zero dígitos, `Cancel` imediato PASS**, nada alterado (`hw9_pivscreen.xml`) |
| `Security Policies` / `Selective Wipe` / `Change PIN` (hub) | Visíveis, NÃO abertos (destrutivo-adjacentes) |
| Emergency Recovery `New PIN` | NÃO ABERTO (destrutivo-adjacente; igual S8) |
| Wi-Fi `Test Connection` / `Open Wi-Fi Portal` / `Read TOTP via Wi-Fi` / `Configure Wi-Fi` | Observados (`192.168.4.1 AegisKey-AP ch6`), NENHUM tocado |
| `Open Backup Central` / DKEK Quorum / `24-Word Recovery Phrase` / Shamir `Generate 3 Hardware Shares` / `Recover from 2 Shares` | Observados, NENHUM tocado |
| Devices `Rename` / `Unbind` / `Pair New` / ownership `0x2B` | Observados, NENHUM tocado (`Minha Chave Principal Active BRIDGE:USB_HID`, proximity `Galaxy S24 Ultra NEAR (-32 dBm)`, `Proximity Watch ACTIVE`) |
| Offline firmware update / OTA `Check for Updates` / `Open OTA Panel` | Observados (`v3.4.0-esp32s3`, `Stable`), NENHUM tocado, nada enviado |
| eFuse / SecureBoot / OTP Write Gate / Shamir / CTAP 2.1 hmac-secret+largeBlobKey | View-only PASS (`SIMULATED/NOT BURNED`, `LOCKED`, `SLIP-0039 ACTIVE`, `CTAP 2.1 READY`) |
| Idioma | `System / English / Português (Brasil)` view-only PASS, nada trocado; Biometric/Auto-Lock observados, intocados |

## S9-5. PIV — PASS navegação + PIN/PUK só-vista

- `Smart Card (PIV / Certificates)` → tela `Smart Card (PIV) / Health status: 0.1.0-wave5` / `NIST SP 800-73-4 slots… Read-only list; PIN/PUK enrollment happens per slot` (dumps `hw9_pivmgmt*.xml` + screenshot).
- Slots: 9A `PIV Authentication (Corporate Logon / Windows Hello)` + `New PIN (6-8)` + `New PUK (8)` + `Save PIN/PUK to Smartcard`; 9C `Digital Signature (ICP-Brasil / X.509)` + idem; 9D `Key Management / Email Encryption (S/MIME)` + idem; 9E `Physical Authentication / Door Access Badge` + `New PIN`.
- **Zero dígitos em qualquer PIN/PUK; `Save` NUNCA tocado** — container com `enabled=false` (fail-closed, corrobora S8). `Back` PASS ao hub.

## S9-6. TOTP-add — SKIP explícito (enroll real, por ordem)

- Aba TOTP: `Verification Codes / No codes registered`, `Add Code` + `Scan QR Code`.
- `Add Code` → form `Add TOTP Account (Time)` / `Code Type TOTP(30s)/HOTP` / `Code Length 6/8` / `Service name` + `Account name or email` + `Secret key or otpauth:// URI` (3× EditText) / `Cancel` / `Save to Security Key` (`hw9_totpadd.xml`).
- **Exige segredo real (`OATH_PUT` = mutação) → SKIP por ordem: `Cancel`, zero submit, lista segue `No codes registered`.**

## S9-7. Badge bancada — AUSENTE (documentado por falta de autoridade no status)

- Grep em todos os dumps S9 (`hw9_*.xml`) por `bancada|TEST_BENCH|selo|bench`: **zero ocorrências** — único `Badge` é o label funcional `9E Physical Authentication / Door Access Badge` (slot PIV, não selo de bancada).
- APK `0.1.0-wave5` sem selo em nenhum dump/screenshot. Espelho segue `Unprovisioned` (sem autoridade bench afirmada no app). Regra mantida: **nada forjado**.

## S9-8. Flip final app→lista-zerada→`UNPROVISIONED` × silício Unlocked → Refresh + reopen (ordem do pai) → STOP

1. Após voltar à Vault e tocar filtro `All`: hub `UNLOCKED Session Active [5/5]` mas `Slots: 0 used, 27 available`, `All (0)`, `No keys` (fantasma classe S4/S8-A, desta vez com sessão viva).
2. `Refresh` (read-only, ordem do pai): lista segue `0 used`; footer vira `UNPROVISIONED` (dump `hw9_refresh.xml`).
3. Reopen `am start` (ordem do pai, em vez de unlock): hub volta a header `UNLOCKED Session Active [5/5] 1439:54` mas lista segue `All (0) 0 used` (dump `hw9_reopen2.xml`); silício 3/3 `Unlocked` pós-reopen.
4. **STOP total aqui** (ordem do dono): nenhum tap em `Unlock Session`, nenhum `Generate`, nenhum delete/unbind/commit. Display apagado (`keyevent 26`, recovery code nunca exibido neste lane).

## S9-9. Contador — prova de zero PIN

- Direto `0x3A` (todas as leituras válidas): `failed 0x00 / remaining 0x05 / max 0x05`; app `[5/5]` intacto até o flip (que não alterou contador no silício). `lt.pin.retry=0`, `Monotonic 1,420 ops (Panic 0, Wipe 0)`.
- **Total deste lane: 0 submits, 0 dígitos, 0 retry.**

## S9-10. Limites / evidência / testes

- Test doubles: nenhum; zero edições de fonte (só este relatório); nenhum mock em produção tocado.
- Emissões: `POST /bridge/vendor 0x3A` read-only (7×) + `GET` info/status + `adb` (`WAKEUP`/`POWER`, dumps, pulls, `screencap`, `am start` foreground, taps de navegação/filtro/`Refresh`/`Back`/`Close`/`Cancel`, 1 tap seletor PIV 9A sem submit). Nenhum `POST` de unlock/commit, nenhum `0x2B/0x23/0x2E-manual/0x38-clear/0x3B/0x3F-manual` (caps lido 1× via ponte na checagem final — resposta válida `full/18 caps/unsupported 0` na 1ª tentativa), nenhum generate/save/delete/unbind/rename/OTA/reboot/recovery.
- Dumps/screenshots: `/sdcard/hw9_*.xml/png` + `%TEMP%\hw9_*`, fora do git.
- Suite de testes (`cargo test`, E2E `--test-threads=1`): **NÃO executada — N/A.** Zero diff de fonte (nada a validar) + rig em estado contraditório final (lista zerada/`UNPROVISIONED` no app × silício `Unlocked`); ligar harness com `adb reverse` ativo e ponte no ar arriscaria reconexão/scan concorrente (reboots que derrubaram sessão em S3/S4). Resultado focado: **N/A (nenhum teste tocado, por ordem de STOP + zero diff)**.
- Sem push/merge (ordem do pai).

## Veredito S9 (matriz HW fechada no observável)

- **Gate: PASS (silício `Unlocked 24h`, maioria 5/7; 2 transientes de ponte não-reproduzíveis registrados). Unlock: SKIP explícito, 0 submits.**
- **5/5 detalhado: PASS com achado — `hw-p256/#0, hw-ed25519/#1, hw-es384/#2, hw-es512/#3, hw-es256k/#4` todos `ES256 (P-256)` + `Touch Required` + `Resident Discoverable` + `CTAP 2.1`; sem toggles touch/UP-0x40/resident na UI (contrato fixo). Curva real por slot pende revalidação via assinatura (pai decide).**
- **K3: PASS (`User Presence Button operational`, `1,420 ops`). K2/K4: observados-sem-submit (Change-PIN dispensado via Cancel; Emergency Recovery New PIN não aberto).**
- **PIV: PASS só-vista (9A/9C/9D/9E + PIN/PUK fields + Save `enabled=false`, zero dígitos). TOTP-add: SKIP (enroll real). View-onlys (Devices/TOTP/Settings-idioma/Wi-Fi/Recovery/DKEK/eFuse/Shamir/OTA/`0x2E`/`0x38`/caps/badge): TODOS PASS.**
- **Badge bancada: AUSENTE em todos os dumps (só `0.1.0-wave5`); documentado por falta de autoridade no status, nada forjado.**
- **Flip final (`UNLOCKED 0 used` → `UNPROVISIONED` × silício `Unlocked`): tratado exatamente como ordenado (Refresh → reopen, sem unlock) → STOP total. Estado final: display apagado, placa `0 failed / 5 restantes`, nada criado/deletado/enviado.**
- **Devolução ao pai: (a) arbitrar curva real dos 5 slots (detalhe diz ES256 em todos — divulgação vs criação default?); (b) arbitrar fantasma de lista (`5 used`→`0 used` com sessão viva, Refresh não reconciliou desta vez); (c) decidir se S9 fecha a matriz HW no observável ou se reemite pós-relock com LIST com UP.**

---

# SESSÃO S10 — Passwords viewer E2E no moto g(60) físico (2026-11-05 01:23 UTC)

- **Branch:** `fd/finalizacao-linux` — **HEAD:** `30ae0ac` (merge password manager device-only)
- **Working tree:** DIRTY herdado do pai (MainActivity.kt, MainHubScaffoldTemplate.kt, PasswordManagerScreen.kt, strings.xml x2, PasswordManagerViewerTest.kt, SESSION_HANDOFF.md + untracked PM_E2E_REPORT_2026-11-05.md); este lane: zero edições de fonte, só este relatório. Sem push.
- **Ordem do pai:** aba Senhas → tap no item → popup → olho (mostrar) → digital (biometria do aparelho; se pedir PIN do sistema e não houver env, PARE). PARE ANTES de qualquer wipe/delete/confirmação destrutiva (screenshot do diálogo + BACK). PIN $env:FIDO_PIN via env só se a sessão precisar (zero retry). Documentar cada passo com dump+screenshot em %TEMP% + nota aqui. PROIBIDO wipe.
- **Telefone:** moto g(60) (`hanoip`) via `adb -s 192.168.15.17:38071` — presente, `device`; APK `dev.aegiskey.app` `versionCode=1 / versionName=0.1.0-wave5`, `lastUpdateTime=2026-11-04 21:47:11`.
- **PIN:** `$env:FIDO_PIN` e `$env:MANUAL_TOUR_PIN` **AUSENTES** neste lane → zero submits possíveis; valor `$env:FIDO_PIN` da ordem NÃO materializado em env; nenhum valor tentado/adivinhado; regra zero retry intacta por vacuidade (0 submits).

## S10-1. Passos executados (todos read-only + taps não-destrutivos)

| # | Passo | Ação | Evidência %TEMP% | Resultado |
|---|---|---|---|---|
| 0 | Tela inicial apagada | `uiautomator dump` pré-wake | `hw_pw0_init.xml` (422 bytes, só `com.motorola.motodisplay`) | Tela apagada, nada tocado |
| 1 | Wake + foreground | `input keyevent WAKEUP` (físico, fora do app) | `hw_pw1_wake.xml` (18560 bytes) + `hw_pw1_wake.png` (156224 bytes) | App já na rota Senhas: `Password Manager` + `Device-only viewer. IDs are opaque; secrets show once and are wiped on close.` + gate `Connect hardware device first` / `BLE connection is offline. Connect device before operation.` + `OK` + `Search loaded IDs (hex)` + `Device census unavailable` + `No password entries loaded` + `Refresh while the device is connected and Secure Guard is unlocked.` + header `Minha Chave Principal / USB Cable Connected / LOCKED` + bottom nav Vault/TOTP/Passwords/Devices/Settings |
| 2 | Aba Senhas (confirmação explícita) | `input tap 540 2338` (centro `Passwords [466,2320][613,2356]`) + `uiautomator dump` + `screencap` | `hw_pw2_senhas.xml` (18560 bytes) + `hw_pw2_senhas.png` (155857 bytes) | Mesma rota, mesmos textos do passo 1. PASS que a aba Senhas renderiza sem crash. |
| 3 | Tap no item (tentativa) | `input tap 540 1100` (área do card `No password entries loaded`) + `dump` + `screencap` | `hw_pw3_tapitem.xml` (18560 bytes) + `hw_pw3_tapitem.png` (155857 bytes) | Nenhum item para abrir: `Compare-Object` pw2 vs pw3 = zero diff (dumps idênticos). Nenhum popup abriu, nenhum diálogo destrutivo, nenhum `Delete from vault` / `Clear` / `Wipe` tocado. STOP aqui para popup/olho/digital (pré-requisito ausente). |
| 4 | Biometria (somente-leitura, sem acionar prompt) | `dumpsys fingerprint` + `dumpsys biometric` (sem `BiometricPrompt.authenticate`, sem tap no olho) | log neste relatório (sem dump de segredo) | Sensor presente: `ID 0, Strength 2, Type 1, MaxEnrollmentsPerUser 5, 540,1636 r130`; `Fingerprint21 isUdfps=false isPowerbuttonFps=false`. Nenhum `BiometricPrompt` exibido (não havia olho para tocar); nenhum PIN do sistema pedido; regra "se pedir PIN do sistema e não houver env, PARE" não precisou disparar porque nada foi autenticado. Nenhum tap destrutivo; BACK não precisou (nenhum diálogo abriu). |

## S10-2. Por que parou (gate do viewer, fail-closed correto)

- Header `LOCKED` + gate `Connect hardware device first` + `BLE offline` + `Device census unavailable` + `No password entries loaded` = viewer sem hardware key conectada e sem sessão Secure Guard desbloqueada. Sem `id` opaco carregado não há `selectedId`, sem popup não há olho (`Visibility`), sem olho não há `BiometricPrompt`, sem digital não há `openRelease`. Cadeia travada no primeiro elo por desenho fail-closed — nenhum segredo exibido, nenhum wipe executado (PROIBIDO por ordem, e sem objeto para wipear).
- Contador: **0 submits, 0 dígitos, 0 retry** neste lane (env ausente impossibilita unlock; nenhum tap em `Unlock`/`Save`/`Delete`/`Clear`/`Wipe`).
- Display deixado como encontrado (rota Senhas, sem diálogo aberto); telefone não relockado (já LOCKED).

## S10-3. Teste focado designado (resultado exato)

- Arquivo pai-designado: `app-android/app/src/test/java/dev/aegiskey/app/PasswordManagerViewerTest.kt` (único arquivo de teste tocado; nenhuma outra suíte executada neste lane).
- Comando: `./gradlew :app:testDebugUnitTest --tests "dev.aegiskey.app.PasswordManagerViewerTest" --rerun-tasks` (em `app-android`).
- Resultado exato: **`tests=8 skipped=0 failures=0 errors=0` — BUILD SUCCESSFUL.** Casos: `release_roundtrip_and_wipe`, `release_rejects_empty_secret_and_oversize_id`, `bottomNav_passwordsDestination_reusesExistingPmRoute`, `gates_preserve_wire_bytes_and_vault_ux`, `pm_opcodes_claim_first_free_range`, `status_response_roundtrip`, `opaque_handles_carry_no_invented_labels`, `list_request_response_roundtrip`. XML: `app/build/test-results/testDebugUnitTest/TEST-dev.aegiskey.app.PasswordManagerViewerTest.xml`.
- Multiprocess authority E2E com `--test-threads=1`: **N/A neste lane** — nenhuma suíte multiprocess executada (só o unit focado acima; builds/mocked traffic/ports/screenshots/emuladores/handshakes não contam como aceitação física, por ordem).

## S10-4. Limites / evidência

- Test doubles: nenhum; zero edições de fonte; nenhum Mock/Fake/Stub em produção tocado.
- Emissões: `WAKEUP` físico + 2 taps não-destrutivos (aba Senhas + área vazia) + `uiautomator dump`x4 + `screencap`x3 + `pull`x7 + `dumpsys` read-only (window/package/fingerprint/biometric). Nenhum `POST`/vendor, nenhum unlock/commit, nenhum `Generate`/`Save`/`Delete`/`Unbind`/`Clear`/`Wipe`, nenhum `0x2B/0x23/0x2E/0x38/0x3B/0x3F`, nenhum reboot/OTA/recovery.
- Screenshots/dumps: só `%TEMP%\hw_pw*.xml/png` + `/sdcard/hw_pw*.xml/png`, fora do git; recovery code nunca exibido neste lane.
- Sem push (ordem do pai).

## Veredito S10

- **Aba Senhas: PASS (renderiza, lista vazia fail-closed, sem crash, sem segredo).**
- **Tap no item → popup → olho → digital: NÃO EXECUTADOS — PAREADO no gate vazio (zero itens; dumps pw2==pw3 provam nenhum popup). Nenhum wipe/delete/confirmação alcançado, nenhum BACK necessário (nenhum diálogo para dispensar).**
- **Teste focado: 8/8 PASS (resultado exato acima).**
- **Estado final: telefone na rota Senhas `LOCKED / No password entries loaded`, placa intocada, `0 submits / 0 retry`, nada criado/deletado/enviado.**
- **Devolução ao pai: para cobrir popup/olho/digital/wipe é preciso HIL L3 com hardware key conectada + sessão desbloqueada (PIN via env, 1x zero retry) + digital cadastrada no usuário corrente; este lane parou exatamente onde a ordem manda (antes de qualquer wipe).**

---

# SESSÃO S11 — FULL pre-flight + STOP (2026-11-06 UTC, moto g(60) físico)

- **Branch:** `fd/finalizacao-linux` — **HEAD:** `cc504730380aaefed70aa8fd8ca9bcd65fb45168`
- **Working tree:** CLEAN na abertura (zero diff); este lane: só este relatório, zero edições de fonte. Sem push/merge.
- **Ordem do pai:** pre-flight → unlock $env:FIDO_PIN via keypad gate se Locked (env, 1 tentativa, zero retry) → tour --full + matriz HW → criar NADA novo → STOP na surpresa, nada destrutivo, log aqui, sem push, PROIBIDO eFuse/secureboot.
- **Telefone:** Motorola moto g(60) (`hanoip`, Android 12) via `adb -s 192.168.15.17:43075` (sempre com `-s`). **SURPRESA 1:** serial `:38071` da ordem recusada (`connection refused`); aparelho re-enumerou em `:43075` (mesmo `hanoip`, `moto g(60)`, IP idêntico, dump Settings confirma `192.168.15.17:43075`). Todo `adb` abaixo usa `:43075`.
- **APK:** `dev.aegiskey.app`, `versionCode=1`, `versionName=0.1.0-wave5` (atual esperado). Hub foreground via `monkey -p dev.aegiskey.app` (não-destrutivo).
- **PIN:** `$env:FIDO_PIN` **AUSENTE** → zero submits possíveis; valor `$env:FIDO_PIN` da ordem NÃO materializado em env; nada tentado/adivinhado; regra 1 tentativa / zero retry intacta por vacuidade (0 submits, 0 dígitos).

## S11-1. Pre-flight (somente-leitura)

| # | Checagem | Resultado |
|---|---|---|
| P1 | Device físico (emulador proibido) | **PASS** — `moto g(60)` `device`, `transport_id=2`, `192.168.15.17:43075` (serial da ordem `:38071` recusada; mesmo aparelho re-enumerado) |
| P2 | App instalada versão atual | **PASS** — `versionCode=1 / versionName=0.1.0-wave5`, hub abre sem crash (dump `hw_s11_app.xml`, 92 nós) |
| P3 | Ponte :5678 | **PASS (com achado)** — porta LISTEN, `GET /api/secure-guard/status` responde `ok:true` mas `state 0 / Unprovisioned / provisioned=false / audit_count=0 / bench_active=false` |
| P4 | Placa via 0x3A direto | **PASS (com contradição)** — `POST /bridge/vendor {"op":58}` válido: silício diz `state 02 / Locked / provisioned=true / unlocked=false / failed 0 / remaining 5` + `efuse_safety_locked / bench_active=false / paired BLE Galaxy S24 Ultra`. **SURPRESA 2:** ponte cacheia `Unprovisioned` × silício `Locked provisioned` — divergência registrada, nada forçado |
| P5 | Hub LOCKED observável | **PASS** — `Secure Guard LOCKED / Session Locked / [5/5] / Channel: USB Cable · Slots: 0 used, 28 available / 0.1.0-wave5 / All (0) / Vault+TOTP+Passwords+Devices+Settings`, curvas P-256/Ed25519/P-384/P-521/secp256k1 listadas |

**Deriva anotada (sem ação):** `Slots available` varia entre lanes (27/28/31/32) com `0 used` constante — possível dado misto default/live (cf. S9 fantasma). Pai arbitra.

## S11-2. Unlock / tour --full / matriz HW — NÃO EXECUTADOS (STOP ordenado)

- **Unlock $env:FIDO_PIN via keypad gate:** **SKIP** — env ausente impossibilita a única tentativa autorizada; nenhum dígito, nenhum `Unlock`, contador intacto `[5/5]` / `failed 0`. Display/navegação só view-only.
- **tour --full (`tools/manual_screenshots.py --full`):** **SKIP explícito** — modo `--full` cria entrada `tour-` + deleta via UI (código-fonte do tour confirma); ordem deste lane proíbe criar NADA novo e proíbe delete/COMMIT; executar violaria as duas regras. Nenhum `tour-` criado/deletado.
- **Matriz HW (5 chaves, 3 senhas tst-pm-*, TOTP, caps, 0x2E/0x38, OTA/recovery view-only, PIV, idioma, badge, autofill):** **SKIP (STOP na surpresa)** — pré-requisitos ausentes (sem sessão desbloqueada, bridge `Unprovisioned` × silício `Locked`, env sem PIN) + proibição de criar dados. Nenhum `Generate/Save/Delete/Unbind/0x2B/0x23/0x2E-manual/0x38-clear/OTA/reboot/recovery-submit` emitido. Abertura dessas telas dispara vendor `0x3F`; não tocadas com rig contraditório.
- **eFuse/secureboot:** **NÃO TOCADO (PROIBIDO)** — nenhum burn, nenhum flash-crypt. Nota: `scripts/ci-guard-secureboot.ps1` neste HEAD CLEAN dá FAIL pré-existente em `efuse_safety_lock.rs:359/380` (`secure_boot_v2_active` campo de relatório, não burn) — falso-positivo do padrão amplo `SECURE_BOOT`; registrado como advisory, zero alteração.

## S11-3. Teste focado designado (resultado exato, single-thread)

- Comando: `cargo test -p aegis-secure-guard -- --test-threads=1`
- Resultado exato: **lib `60 passed; 0 failed; 0 ignored` + doc-tests `0 passed` (exit 0), multiprocess-safe single-thread.**
- Multiprocess authority E2E com `--test-threads=1`: **o comando acima É o run single-thread executado;** nenhuma outra suíte multiprocess executada. Builds/mocked traffic/ports/screenshots/emuladores/handshakes NÃO contam como aceitação física, por ordem.
- Test doubles: `ci-grep-mocks.ps1` → **PASS (mocks confinados a cfg(test))**; nenhum Mock/Fake/Stub em produção tocado; zero edições de fonte.

## S11-4. Evidência / limites

- Emissões: `adb connect/devices/getprop/dumpsys package` + `uiautomator dump`x2 + `screencap`x1 + `pull`x3 + `monkey` foreground (não-destrutivo) + `GET status` + `POST vendor 0x3A` read-only. Nenhum POST de unlock/commit, nenhum tap em dígito/Unlock/Generate/Delete.
- Dumps/screenshots: `/sdcard/hw_s11_*.xml/png` + `%TEMP%/opencode/hw_s11_*`, fora do git. Sem push.
- Estado final: app em hub `LOCKED [5/5] 0 used`, display aceso no hub, placa `0 failed / 5 restantes`, nada criado/deletado/enviado.
- **Devolução ao pai:** (a) arbitrar serial `:38071` vs `:43075` (re-enumeração Wi-Fi); (b) arbitrar ponte `Unprovisioned/audit 0` × silício `Locked/provisioned` (cache/stale?); (c) prover `$env:FIDO_PIN` para 1 tentativa futura ou manter STOP; (d) decidir se tour --full permanece proibido (cria+deleta) face a "crie NADA novo"; (e) arbitrar guard secureboot falso-positivo pré-existente.

## Veredito S11

| Item | Resultado |
|---|---|
| Pre-flight device/app/ponte/0x3A/hub | **PASS (com 2 surpresas registradas)** |
| Unlock $env:FIDO_PIN (env, 1x, zero retry) | **SKIP (env ausente, 0 submits)** |
| tour --full | **SKIP (criaria+deletaria; proibido)** |
| Matriz HW (chaves/senhas/TOTP/caps/0x2E/0x38/OTA/recovery/PIV/idioma/badge/autofill) | **SKIP (STOP na surpresa, nada criado)** |
| Teste focado `--test-threads=1` | **PASS 60/0/0** |

---

# SESSÃO S12 — Unlock 1x PASS + 5/5 + detalhe #4, depois contenção inter-lane → STOP (2026-11-06 UTC, moto g(60) físico)

- **Branch:** `fd/finalizacao-linux` — **HEAD:** `cc50473` (`test(evidence): gate 9/9 consolidated run`)
- **Working tree:** DIRTY só por este relatório (zero edições de fonte). Sem push/merge.
- **Ordem do pai:** PIN correto `$env:FIDO_PIN` (`$env:MANUAL_TOUR_PIN` + `$env:FIDO_PIN` setados no início, nunca logados/commitados); serial via `adb devices` (`192.168.15.17:43075`, mudou de `:38071`); fonte de verdade = `0x3A` direto; pre-flight → unlock 1x via keypad gate se Locked (zero retry) → tour --full → matriz HW completa; nada novo criado; STOP na surpresa; nada destrutivo; PROIBIDO eFuse/secureboot.
- **Ordem complementar (mid-lane):** outra sessão usa o mesmo Moto G → modo defensivo (foco/staleness antes de cada passo, backoff sem forçar taps, STOP em contenção persistente, nunca matar processos/desconectar).
- **Telefone:** Motorola moto g(60) (`hanoip`) via `adb -s 192.168.15.17:43075` (sempre com `-s`). APK `dev.aegiskey.app`, `versionCode=1`, `versionName=0.1.0-wave5`.
- **Ponte:** `tools/host_hardware_android_bridge.py` em COM7 (`Silicon Labs CP210x`), porta 5678 LISTENING; `GET /bridge/info` → `connected=true`, `transport=UART`, `cid=0x40201`, `uptime_s=166` (sem reboot observado).
- **PIN:** valor somente via env (4 dígitos, nunca impresso); regra 1 unlock / zero retry: **1 submit total, zero retry, zero wrong-PIN**.

## S12-0. Pre-flight — PASS (read-only)

`adb devices -l` (só `192.168.15.17:43075 device hanoip`), `getprop` (`moto g(60)`), `GET /bridge/info` online COM7, `GET /api/secure-guard/status` responde (espelho `Unprovisioned/provisioned=false/audit 0/Galaxy S24 Ultra` — fallback conhecido, sem decisão).

## S12-1. Gate `0x3A` direto (silício, ground-truth) — LOCKED provisionado, sem sessão

`POST /bridge/vendor {op:58}` decodificado: `state 02 Locked`, `provisioned true`, `unlocked false`, `failed 0x00 / remaining 0x05 / max 0x05`, `session_remaining 0x00`, `audit 0x18 0x20 (=32)`, `efuse_safety_locked true`, `bench_active false`, `paired BLE Galaxy S24 Ultra`. Espelho diverge do direto (segue fallback `Unprovisioned/audit 0`).

## S12-2. Unlock 1x via keypad gate — PASS (1 submit, zero retry)

- Hub pré-unlock: `Secure Guard LOCKED`, `Session Locked`, `[5/5]`, `Unlock Session` + `Emergency Recovery`, `0 used, 28 available`, `0.1.0-wave5`, curvas P-256/Ed25519/P-384/P-521/secp256k1 (dump `hw_s12_wake.xml`).
- Tap `Unlock Session` → K1: `Hardware Session Authentication`, `Unlock PIN`, `Minimum 4 digits`, `0/16`, `[5/5]`, dígitos `1–9/C/0/?`, `Unlock` (desabilitado vazio = fail-closed), `Cancel`. **Gate K1: PASS** (`hw_s12_k1.xml`).
- 4 toques no dígito via env → `4/16` mascarado, `[5/5]` intacto (`hw_s12_k1digits.xml`, valor nunca logado).
- **Submit único** → silício `state 04 Unlocked` (2 leituras concordantes); app `UNLOCKED`, `Session Active`, `Remaining 1439:41` (~24h), `[5/5]`, `Vault unlocked successfully`, **`5 used, 28 available`, `All (5)`** (`hw_s12_reopen.xml`).

## S12-3. Matriz parcial executada (tudo view-only, nada submetido)

| Item | Resultado |
|---|---|
| 5 chaves em lista (rolagem) | **PASS 5/5**: `hw-p256`/`hw-ed25519`/`hw-es384`/`hw-es512`/`hw-es256k` slots `#0–#4`, todos `Passkey` + `Secured on AegisKey slot #N` + `Manage`/`Copy` (`hw_s12_list2/3.xml`). **Achado S9 reconfirmado: os 5 exibem `ES256 (P-256)`** (curva real por slot pende revalidação via assinatura; pai decide) |
| Detalhe slot #4 (`Manage` → `hw-es256k`) | **PASS view-only**: `Passkey FIDO2/WebAuthn`, `Touch Required`/`Require touch`, `Resident Discoverable`, `FIDO2/WebAuthn L3 (CTAP 2.1)`, `UV biometric + touch`, `Test Authentication` com challenge **NÃO submetido** (exigiria UP), `Copy` intocado, sem `Delete` (`hw_s12_d4.xml`) |
| Detalhes slots #0–#3 | NÃO EXECUTADOS (STOP S12-4 antes) |
| 3 senhas `tst-pm-*` / TOTP / Devices / Settings-idioma / PIV / K2-K4 / `0x2E` / `0x38` / caps `0x3F` / OTA-recovery view-only / badge / eFuse | NÃO TOCADOS (STOP S12-4; eFuse adicionalmente PROIBIDO por ordem) |
| `tour --full` | **NÃO EXECUTADO** (STOP antes; criaria `tour-` + delete + lock + troca EN/PT — fica para após reautorização) |

## S12-4. SURPRESA — contenção inter-lane (foco roubado + sessão invalidada) → STOP

1. Após o detalhe #4, o foreground pulou para `io.github.universaldevice.debug` (`Runtimes/HoloMesh`, app da outra sessão): `mFocusedApp` confirmou a troca 2× (pós-submit e pós-swipe). Nenhum tap forçado com foco alheio.
2. Backoff obedecido: 30 s → ainda ocupado; 60 s → foco de volta ao `dev.aegiskey.app/.MainActivity` (estável antes/depois do dump).
3. Sessão invalidada pelo outro ator: direto `0x3A` voltou a **`Locked`, `session 0`** (app mostra `UNLOCKED` stale — split-brain classe S5/S6). **Contador intacto: `failed 0 / remaining 5`, `audit 32`** — outro ator NÃO queimou PIN nem wipeou; sessão caiu (Lock Now/reboot/re-enumeração pelo outro lane, causa não atribuída).
4. **STOP total aqui** (ordem defensiva do pai): cota de unlock 1x já consumida (re-unlock seria 2º submit → viola `1x/zero retry`); brigar pelo device com a outra sessão ativa violaria o backoff. Telefone deixado intocado na tela de detalhe #4 (sem segredo em tela), nada criado/deletado/enviado além do unlock + navegação view-only.

## S12-5. Contador — prova de 1 PIN / zero retry

- Antes: direto `0 failed / 5 restantes`, hub `[5/5]`. Depois de tudo (pós-STOP): direto `0 failed / 5 restantes`, `audit 32`, app `[5/5]` sem erro.
- **Total: 1 submit autorizado, 0 dígitos extras, zero retry, zero wrong-PIN.**

## S12-6. Teste focado + limites / evidência

- **Teste focado designado (resultado exato, single-thread):** `cargo test -p aegis-secure-guard -- --test-threads=1` → **lib `60 passed; 0 failed; 0 ignored`** + **doc-tests `0 passed`** (exit 0). Host-only, sem tocar device/ponte.
- **Multiprocess authority E2E com `--test-threads=1`:** **N/A neste lane** — harness E2E exigiria device/ponte sob contenção ativa (violaria STOP + backoff); builds/mocked traffic/ports/screenshots/emuladores/handshakes não contam como aceitação física, por ordem.
- Test doubles: nenhum; zero edições de fonte (só este relatório); nenhum Mock/Fake/Stub em produção.
- Emissões: 1 unlock PIN via keypad in-app (env, sem log de valor); taps de navegação (`Unlock Session`, 4 dígitos, `Unlock`, 2 swipes, 1 `Manage`); `POST /bridge/vendor 0x3A` read-only (N×); `GET` info/status; `adb` read-only (`devices/getprop/dumpsys/uiautomator/pull`) + `am start` foreground (não-destrutivo) + `WAKEUP` físico. Nenhum `Generate/Save/Delete/Unbind/Copy/TestAuth`, nenhum `0x2B/0x23/0x2E-manual/0x38-clear/0x3B/0x3F`, nenhum commit/OTA/reboot/recovery/delete/rename, nenhum burn eFuse/secureboot.
- Dumps: `/sdcard/hw_s12_*.xml` + `%TEMP%\opencode\hw_s12_*`, fora do git. Sem push (ordem do pai).

## Veredito S12

| Item | Resultado |
|---|---|
| Pre-flight / gate `0x3A` direto | **PASS** (`Locked provisioned 0/5/5 session 0 audit 32`; espelho segue fallback) |
| Unlock `$env:FIDO_PIN` via keypad gate | **PASS 1× (zero retry)** → silício `Unlocked`, app `UNLOCKED 1439:41`, `5 used` |
| 5 chaves em lista | **PASS 5/5** (`#0–#4`, display-curva ES256 nos 5 reconfirmado) |
| Detalhe slot #4 | **PASS view-only** (touch required, resident, CTAP 2.1; TestAuth não submetido) |
| Detalhes #0–#3, senhas, TOTP, caps, `0x2E`/`0x38`, OTA/recovery, PIV, idioma, badge, tour --full | **NÃO EXECUTADOS (STOP contenção)** |
| Contenção (foco roubado 2× + sessão invalidada, contador intacto) | **STOP + backoff obedecido, sem briga pelo device** |
| Teste focado `--test-threads=1` | **PASS 60/0/0 lib + 0 doc** |
| Mocks prod / eFuse / push | **PASS (zero, zero, zero)** |

- **Devolução ao pai:** (a) arbitrar re-unlock 1× supervisionado (cota deste lane consumida) ou relock/refresh do app antes de reemitir; (b) coordenar janela exclusiva no Moto G com a outra sessão (contenção: foco roubado 2×, sessão 24h derrubada sem queimar PIN); (c) confirmar curva real dos 5 slots via assinatura/CTAP (detalhe exibe ES256 nos 5); (d) decidir se `tour --full` (cria+deleta `tour-`, troca idioma EN→PT, faz lock) permanece autorizado face a "não crie nada novo".
| Mocks em produção / eFuse / push | **PASS (zero mocks prod, zero eFuse, zero push)** |

---

# SESSÃO S13 — PIN autorizado rejeitado + flip silício Locked→Unprovisioned → STOP (2026-11-06 UTC, moto g(60) físico)

- **Branch:** `fd/finalizacao-linux` — **HEAD:** `cc50473` (`test(evidence): gate 9/9 consolidated run`)
- **Working tree:** DIRTY herdado (de outros lanes: `FriendlySettingsDialogs.kt` + untracked `TerminalLogStyle*`; este lane: zero edições de fonte, só este relatório). Sem push/merge.
- **Ordem do pai:** PIN autorizado via env (valor nunca logado/commitado); serial via `adb devices` (emulador proibido); pre-flight → unlock 1x via keypad gate se Locked (zero retry) → RESTANTE da matriz (3 senhas `tst-pm-*` lista+GET+olho, TOTP, caps `0x3F`, `0x2E`/`0x38`, OTA/recovery view-only, PIV, idioma EN→PT→EN, badge, `tour --full` criando `tour-*` e deletando ao fim). Fonte de verdade = `0x3A` direto. Contenção: backoff curto e retome (até 3x); se inviabilizar, STOP. Nada destrutivo além do `tour-*` (sem wipe/COMMIT/recovery-submit). PROIBIDO eFuse/secureboot.
- **Telefone:** Motorola moto g(60) (`hanoip`, Android 12) via `adb -s 192.168.15.17:43075` (sempre com `-s`; serial `:38071` das ordens antigas segue ausente — aparelho re-enumerado, mesmo `hanoip`). APK `dev.aegiskey.app`, `versionCode=1`, `versionName=0.1.0-wave5`.
- **Ponte:** PID 30936 (`tools/host_hardware_android_bridge.py --port COM7`), porta 5678 LISTENING; UART COM7 (`Silicon Labs CP210x`); `GET /bridge/info` → `connected=true`, `transport=UART`, `cid=0x40201`, `status=online`, `uptime_s=166` **CONGELADO (igual S12; tratado como stale, sem concluir reboot)**.
- **PIN:** valor somente via env (4 dígitos, nunca impresso neste log/commitado); regra 1 unlock / zero retry: **1 submit total, zero retry**.

## S13-0. Pre-flight — PASS (read-only)

| # | Checagem | Resultado |
|---|---|---|
| P1 | Device físico (emulador proibido) | **PASS** — `192.168.15.17:43075 device hanoip`, `transport_id=2`, `moto g(60)` |
| P2 | App instalada versão atual | **PASS** — `versionCode=1 / versionName=0.1.0-wave5`, hub abre sem crash |
| P3 | Ponte :5678 | **PASS** — LISTEN, `GET /bridge/info` online COM7, `cid=0x40201` |
| P4 | Espelho `GET /api/secure-guard/status` | Lido sem decisão: `Unprovisioned/provisioned=false/session 0/audit 0/Galaxy S24 Ultra` (fallback conhecido, diverge do direto — registrado sem decidir por ele) |
| P5 | Foco/contenção | **PASS, zero contenção** — `mFocusedApp=dev.aegiskey.app/.MainActivity` nas 5 checagens deste lane; outro ator nunca tomou o foco (backoff 0/3 consumido) |

## S13-1. Gate `0x3A` direto pré-unlock (silício, ground-truth) — LOCKED provisionado, sem sessão

`POST /bridge/vendor {op:58}` decodificado: `state 02 Locked`, `state_name "Locked"`, `provisioned true`, `unlocked false`, `failed 0x00 / remaining 0x05 / max 0x05`, `session_remaining 0x00`, `audit 0x18 0x20 (=32)`, `efuse_safety_locked true`, `bench_active false`, `paired_ble_mac` vazio / `device BLE AegisKey 3C:84:27:C7:17:7A`. **Gate: bench Locked sem sessão → unlock 1x autorizado.**

## S13-2. Split-brain inicial tratado (Lock Now, zero PIN) — PASS

- Wake revelou o app no **detalhe `hw-es256k` UNLOCKED stale** (resto da tela S12) × silício **Locked session 0**. Back-arrow `[10,345][130,465]` → aba Devices; tap Vault → detalhe; back-arrow (70,405) → **hub UNLOCKED stale**: `Session Active [5/5]`, `Remaining 1396:38`, `Vault unlocked successfully.`, `5 used, 28 available`, `hw-p256` visível, `Lock Now` + `Change PIN` visíveis.
- **Ação conforme precedente S7: 1 tap `Lock Now`** (centro do texto `[140,968][297,1013]`, zero tráfego vendor, zero PIN) → hub **LOCKED**: `Session Locked [5/5]`, `Unlock Session` + `Emergency Recovery`, `0 used, 28 available`, `0.1.0-wave5`. **PASS, foco próprio confirmado antes do tap.**
- Dumps/screenshots: `/sdcard/hw_s13_*.xml/png` + `%TEMP%\opencode\hw_s13_*`, fora do git.

## S13-3. Keypad gate K1 — PASS (zero submit até aqui)

- Tap `Unlock Session` (315,800) abriu K1: `Hardware Session Authentication`, `Unlock PIN`, `Minimum 4 digits`, `0/16`, `[5/5]`, dígitos `1–9/C/0/⌫`, `Unlock` desabilitado vazio (fail-closed), `Cancel`. **Gate K1: PASS.**
- 4 toques no dígito via env (script lê `$env:MANUAL_TOUR_PIN`/`$env:FIDO_PIN`, sem imprimir valor) → `••••`, **`4/16` mascarado, `[5/5]` intacto** (dump `hw_s13_k1digits.xml`). **Zero submits até aqui.**

## S13-4. Submit único → PIN REJEITADO (1 tentativa, zero retry) — STOP parcial

- **Submit único** em `Unlock` (540,1731) → diálogo fechou; após espera (4 s + 8 s) o hub segue **LOCKED**: `Session Locked [5/5]`, mensagem **`PIN incorreto. Tente novamente.`**, `0 used, 28 available`. Spinner de refresh visível transitoriamente, depois hub estável LOCKED.
- **Total deste lane: 1 submit autorizado, zero retry, zero 2ª tentativa** (regra `1x/zero retry` cumprida — nenhum novo dígito, nenhum novo submit após a rejeição).

## S13-5. SURPRESA — silício virou `Unprovisioned` sem ação destrutiva deste lane → STOP TOTAL

- `0x3A` direto pós-falha (2 leituras concordantes): **`state 00 Unprovisioned`, `provisioned false`, `unlocked false`, `failed 0x00 / remaining 0x05 / max 0x05` (contador NÃO queimado)**, `session 0`, `audit 0`, `paired Galaxy S24 Ultra` registrado. Pré-unlock o mesmo silício dizia `Locked provisioned true audit 32`.
- Ou seja: **o contador não queimou (0 failed), mas o estado do silício mudou `Locked/provisioned/audit32` → `Unprovisioned/não-provisionado/audit0` SEM nenhuma ação destrutiva deste lane** (só 1 tap `Lock Now` + navegação view-only + 1 submit UI de PIN). Nenhum `0x2B/0x23/0x38-clear/0x2B` emitido, nenhum wipe/COMMIT/reboot/OTA/recovery por este lane.
- Hipóteses registradas **sem concluir**: (a) outro ator trocou/reprovisionou a placa entre as leituras; (b) reboot com perda de provisionamento; (c) ponte re-enumerou outro dispositivo. Origem não atribuída. **STOP total aqui por ordem do dono.**

## S13-6. Matriz restante — NÃO EXECUTADA (STOP)

| Item da ordem | Resultado |
|---|---|
| 3 senhas `tst-pm-*` (lista+GET+olho) | NÃO EXECUTADO (STOP; sem sessão) |
| TOTP | NÃO ABERTO (STOP) |
| Caps `0x3F` | NÃO LIDO (STOP; nenhum `POST 0x3F` além do estritamente necessário — nenhum emitido) |
| `0x2E` / `0x38` | NÃO ABERTOS (STOP; `Re-run`/`Clear`/`Copy` intocados por construção) |
| OTA / recovery view-only | NÃO ABERTOS (STOP; nada enviado, nenhum COMMIT) |
| PIV (navegação + PIN/PUK só-vista) | NÃO ABERTO (STOP) |
| Idioma EN→PT→EN | NÃO TOCADO (STOP; idioma segue como encontrado) |
| Badge bancada | NÃO VERIFICADO nesta sessão (STOP; regra mantida: nada forjado) |
| `tour --full` | **NÃO EXECUTADO (STOP)** — nenhum `tour-*` criado/deletado |
| eFuse / secureboot | **NÃO TOCADO (PROIBIDO)** — nenhum burn, flash-crypt, ou relatório forçado |

## S13-7. Contador — prova de 1 PIN / zero retry

- Antes: direto `0 failed / 5 restantes`, hub `[5/5]`. Depois (pós-rejeição + STOP): direto `0 failed / 5 restantes`, `session 0`; app `[5/5]` com `PIN incorreto` (erro de sessão/UI, sem queima no silício).
- **Total: 1 submit autorizado, 0 dígitos extras, zero retry, zero wrong-PIN queimado no silício.**

## S13-8. Teste focado + limites / evidência

- **Teste focado designado (resultado exato, single-thread, host-only, sem tocar device/ponte):** `cargo test -p aegis-secure-guard -- --test-threads=1` → **lib `60 passed; 0 failed; 0 ignored`** + **doc-tests `0 passed`** (exit 0).
- **Multiprocess authority E2E com `--test-threads=1`:** **N/A neste lane** — harness E2E exigiria device/ponte sob rig contraditório (violaria o STOP); builds/mocked traffic/ports/screenshots/emuladores/handshakes NÃO contam como aceitação física, por ordem.
- Test doubles: `scripts/ci-guard-mocks` → **PASS (mocks confinados a cfg(test))**; nenhum Mock/Fake/Stub em produção; zero edições de fonte (só este relatório).
- Emissões: 1 tap `Lock Now` (stale-clear, zero vendor) + navegação view-only (back-arrow, abas) + 1 unlock PIN via keypad in-app (env, sem log de valor) + `POST /bridge/vendor 0x3A` read-only + `GET` info/status + `adb` read-only (`devices/dumpsys/uiautomator/pull/screencap/am start` foreground + `WAKEUP`/`POWER` físicos). Nenhum `Generate/Save/Delete/Unbind/Copy/TestAuth`, nenhum `0x2B/0x23/0x2E-manual/0x38-clear/0x3B/0x3F`, nenhum commit/OTA/reboot/recovery/delete/rename, nenhum eFuse/secureboot.
- Dumps/screenshots: `/sdcard/hw_s13_*.xml/png` + `%TEMP%\opencode\hw_s13_*`, fora do git. Sem push (ordem do pai).

## Veredito S13

| Item | Resultado |
|---|---|
| Pre-flight (device físico/APK/ponte/foco) | **PASS, zero contenção (backoff 0/3)** |
| Gate `0x3A` direto pré-unlock | **PASS** (`Locked provisioned 0/5/5 session 0 audit 32`) |
| Split-brain inicial (app UNLOCKED stale × silício Locked) | **Tratado via `Lock Now` → LOCKED (PASS, precedente S7)** |
| Keypad K1 (abertura/dígitos via env) | **PASS** (`0/16`→`4/16` mascarado, `[5/5]` intacto) |
| Unlock 1x (zero retry) | **REJEITADO — `PIN incorreto`, 1 submit, zero retry** |
| Silício pós-falha | **SURPRESA: `Unprovisioned/provisioned=false/audit 0`, contador `0/5/5` intacto → STOP TOTAL** |
| Matriz restante (senhas/TOTP/caps/`0x2E`/`0x38`/OTA/recovery/PIV/idioma/badge/`tour --full`) | **NÃO EXECUTADOS (STOP)** |
| Teste focado `--test-threads=1` | **PASS 60/0/0 lib + 0 doc (exit 0)** |
| Mocks prod / eFuse / push | **PASS (zero, zero, zero)** |

- **Estado final: display apagado (`POWER`, sem segredo em tela), app no hub LOCKED `[5/5] 0 used`, silício `Unprovisioned 0 failed / 5 restantes`, nada criado/deletado/enviado além do unlock.**
- **Devolução ao pai:** (a) arbitrar o PIN autorizado rejeitado + flip do silício `Locked/provisioned/audit32` → `Unprovisioned/audit0` com contador intacto (PIN mudou no bench? placa trocada/reprovisionada por outro ator? ponte re-enumerou outro dispositivo?); (b) NENHUM retry executado (cota 1x deste lane consumida) — próximo unlock exige reautorização explícita; (c) confirmar qual placa está na bancada (MAC/BLE/serial físico) antes de qualquer novo unlock; (d) `tour --full` + matriz restante pendentes de sessão válida no silício.
