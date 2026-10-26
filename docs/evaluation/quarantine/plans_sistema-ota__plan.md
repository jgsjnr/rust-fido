# Plan: Sistema OTA para Dispositivos AegisKey

## Wave 1 (paralelo)
- [ ] Step 1: Servidor OTA stdlib + registry + endpoints validate/manifest/firmware (traces: R-01, R-02) — files: [tools/ota_server.py, tools/ota_registry.json.example]
- [ ] Step 2: Modulo firmware ota.rs (manifesto, verify Ed25519+SHA256+versao, stage/commit/rollback, OtaError sem panic) (traces: R-04, R-05) — files: [crates/aegis-fido-firmware/src/ota.rs, crates/aegis-fido-firmware/src/lib.rs]
- [ ] Step 3: App transporte OtaApi.fetch + OtaTransfer USB chunked via UsbCtaphid.frameMessage (traces: R-03) — files: [OtaApi.kt, OtaTransfer.kt]

## Wave 2 (sequencial, depende Wave 1)
- [ ] Step 4: Wiring main.rs (vendor CTAPHID opcode 0x30+, gate UP, sem colidir com 0x20-0x2D) + garantia preservacao NVS em persistence.rs (traces: R-04, R-06) — files: [main.rs, persistence.rs]
- [ ] Step 5: factory_provision emite ota_pubkey + registro (dry-run intacto) + simulador ponta-a-ponta + negativos (traces: R-06, R-02) — files: [tools/factory_provision.py, tools/ota_simulator_test.py]
