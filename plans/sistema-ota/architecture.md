# Architecture: Sistema OTA para Dispositivos AegisKey

## Approach
Servidor Python stdlib (tools/ota_server.py, porta separada de 8888, ex. 8899) detem manifesto assinado + binario + registro de producao; app baixa via HTTPS/API e empurra a chave via USB/CTAPHID em chunks resumiveis de 57/59B; firmware recebe em slot staged, verifica Ed25519 (pubkey provisionada na fabrica) + SHA-256 + versao maior que atual e so entao comita com swap atomico preservando NVS dual-slot (slot_a/slot_b/backup), com rollback automatico. Escolha anti-brick: verify-before-swap + nunca apagar slot ativo + fail-operational identico ao provision.rs (efemero so em host-dev, erro duro em ESP-IDF).

## Components
- tools/ota_server.py (create): GET /api/ota/manifest?serial=&fw= -> versao/sha256/sig_ed25519/url/size; GET /api/ota/firmware/<ver> (binario); POST /api/ota/validate (serial+aaguid+nonce -> allow/deny); ota_registry.json (serial->aaguid+pubkey, gerado por factory_provision).
- crates/aegis-fido-firmware/src/ota.rs (create): parser de manifesto, OtaState (Idle/Staged/Verified/Applying), verify() (sig+sha+versao), stage_chunk() + commit() atomico, rollback; OtaError tipado sem panic.
- crates/aegis-fido-firmware/src/main.rs|lib.rs|persistence.rs (modify minimo): wiring do ota.rs no loop CTAPHID vendor + preservacao NVS no commit.
- tools/factory_provision.py (extend, sem quebrar dry-run): emite tambem ota_pubkey + entrada de registro (so fingerprint/sha, nunca segredo).
- app-android/.../net/OtaApi.kt + usb/OtaTransfer.kt (create): OtaApi.fetchManifest/fetchBinary (HttpURLConnection, timeout 8s, padrao WifiApi.kt) + OtaTransfer.pushViaUsb (reusa UsbCtaphid.frameMessage INIT/CONT).
- tools/ota_simulator_test.py (create): teste ponta-a-ponta (registrado ok / nao-registrado 403 / sig invalida / downgrade / preservacao NVS).

## Data Flow
Producao registra (serial/AAGUID/pubkey) -> ota_registry.json no servidor -> app (com chave USB plugada, CID CTAPHID alocado) chama validate+manifest com serial -> baixa binario -> fragmenta e envia vendor CTAPHID -> firmware monta em staging -> verifica sig+sha+versao -> swap atomico NVS preservada -> reporta version -> servidor registra applied. Offline ou serial ausente -> 403 antes de qualquer byte.

## Alternatives Considered
- So SHA-256 sem assinatura - rejected porque permite firmware forjado se API vazar; Ed25519 ja disponivel no workspace.
- Download direto pelo device via WiFi station - rejected porque aumenta superficie + risco de brick por queda de energia/rede; app como transporte permite resume + validacao online.
- OTA in-place sem staging/dual-slot - rejected porque corrompe chaves em falha de energia; staged+rollback escolhido como mais seguro anti-brick.
- Reusar Aegis Vault para empacotar firmware - reused existing crypto (AES-GCM) mas NAO o formato Vault; Vault e de outro responsavel e nao sera tocado.
