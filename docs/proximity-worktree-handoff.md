# Handoff Worktree — Trava de Presença RSSI (BLE Proximity Key)

Data: 2026-10-20. Sessão origem: `E:\projetos\fido` (main suja, ver `git status`).
Objetivo da próxima worktree: build/flash/medir + FFI MAC real. Todo resto já está implementado e verde no host.

## 1. O que está pronto

- Firmware `proximity.rs`: `Near/Away/Locked`, lock `< -75 dBm/10s/hist 5dB`, `Locked` só via `confirm_lock`, `unlock(presença+PIN)`, `None`=fraco, clamp 60s, `coex USB>BLE`, `bonding` obrigatório.
- Beacon Wave2: service-data `0xFFFE [VER 0x01|CTR u32LE|TAG 4B]`, `TAG=AES-CCM-128(K_prox, nonce=VER||CTR||fob_id[6B], AAD=VER||CTR)` trunc 4B, `ProximityBeacon tick ~1s` com saturação, `ProximityVerifier` com anti-replay + salto `>1000` reverify, `K_prox` em NVS `prox_k` + `zeroize`, `proximity_adv_allowed`.
- `ble_nimble.rs`: `encode_proximity_adv_payload` 30B≤31B, `should_adv_proximity Idle-only`, `esp_ble_proximity_start`. `GATT 0xFFFD` intacto, rev `0x01`.
- `components/aegis_ble/aegis_ble_nimble.c`: `aegis_ble_proximity_start` fail-closed, reusa coex.
- `main.rs` (+241/-2, tudo `#[cfg(feature="proximity")]`): estado beacon/key/fob, boot `load` ou `rekey` só se `bonded||claimed`, `rekey+ctr=0` nos 2 `Paired`, `delete` em `BIND_RELEASE/RECOVERY_UNLOCK`, tick `~1s` com gate `Idle/bonded/trusted/!usb/key`, `USB` veta (`aegis_usb_is_mounted`, `false` no host), `WiFi` desacelera. Nunca auto-unlock.
- Hosts `tools/host/{win,linux,macos}/proximity_agent.py`: `ProximityDecider` idêntico, `_fob_id_bytes` do MAC bonded, `_ccm_tag` réplica exata do firmware via AES-ECB, `RollingCodeVerifier`, `make_polling_source` exige `0xFFFE` válido, `LockWorkStation/loginctl/CGSession`, lock-only, fail-closed.
- Vetor de interop confirmado: `K=0x42*16, fob=AA:BB:CC:DD:EE:FF, ctr=7, VER=0x01 => TAG=660d4941` (`py-tag == rs-tag`).

## 2. Arquivos tocados

- `crates/aegis-fido-firmware/src/proximity.rs`
- `crates/aegis-fido-firmware/src/ble_nimble.rs`
- `crates/aegis-fido-firmware/src/main.rs`
- `crates/aegis-fido-firmware/components/aegis_ble/aegis_ble_nimble.c`
- `tools/host/{win,linux,macos}/proximity_agent.py` + `test_proximity_agent.py`
- `docs/piv-ble-proximity.md`, READMEs host

Preservar CRLF nos `.rs`/`.py` win e LF no `.c`. Não tocar `CTAP/USB/CBOR`, secure-boot off.

## 3. Verificação (tudo verde na origem)

```powershell
cargo test -p aegis-fido-firmware --features proximity proximity  # 34 passed
cargo clippy -p aegis-fido-firmware --all-targets --features proximity -- -D warnings  # limpo
cargo clippy --all-targets -- -D warnings  # baseline limpo
python tools/host/win/test_proximity_agent.py      # 34 OK
python tools/host/linux/test_proximity_agent.py    # 33 OK
python tools/host/macos/test_proximity_agent.py    # 33 OK
python tools/host/win/proximity_agent.py --self-test  # ok (idem linux/macos)
```

## 4. O que falta (escopo da nova worktree)

1. `fob_id` real: hoje `XOR-fold` do `SERIAL_NUMBER_STRING` (placeholder documentado). Implementar FFI `aegis_ble_own_addr` (`ble_hs_id_copy_addr`/`esp_read_mac`) no `.c` + `extern C` no `ble_nimble.rs`, usar no `main.rs`. Host já usa MAC bonded — alinhar.
2. Provisionamento `K_prox`: hoje `rekey` no `Paired` + `--k-prox-hex`/`FIDO_PROX_KEY_HEX` no host. Falta fluxo fábrica (troca de `K_prox` dentro do link cifrado+bonded, nunca em claro) + doc.
3. Build embarcado: instalar targets `xtensa`/`riscv32imc-esp-espidf` + `idf.py` + `ESP_IDF_VERSION`, `idf.py build` com `--features proximity`, checar `.bss`/flash.
4. Flash + medição aérea: gravar, parear/bond, rodar agente (`--fob-id <MAC> --k-prox-hex <K> --lock-secs 10 --poll-secs 2`), walk-away ≤15s trava, volta não destrava, `USB` ativo silencia BLE, calibrar `-75/5dB` no ambiente.
5. Opcional: `scan-response` p/ nome cheio, `IRK`/privacidade, `Dynamic Lock` como fallback (nunca decisor).

## 5. Como começar na nova worktree

```powershell
git worktree add E:\projetos\fd-worktrees\fido-prox-hw-1 -b feat/prox-hw-1
cd E:\projetos\fd-worktrees\fido-prox-hw-1
cargo test -p aegis-fido-firmware --features proximity proximity
python tools/host/win/proximity_agent.py --self-test
```

Gates: `proximity/ble/wifi/menu` default-off, binário off = baseline; `RSSI` nunca autentica; lock-only; fail-closed sempre.
