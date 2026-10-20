# Task: Sistema OTA para Dispositivos AegisKey

**Created:** 2026-10-19T19:30:00Z

## Requirements
- R-01: Servidor Python simples (so stdlib, sem pip) serve metadados + binario de firmware para o app e para o sistema, com validacao online de chave registrada na producao (serial AEGIS-S3-* + AAGUID).
- R-02: Chave precisa estar conectada (USB presente) e registrada para validar no servidor; nao-registrada ou offline e recusada, sem OTA.
- R-03: App Android atua SOMENTE como transporte: baixa da API, empurra a chave via USB/CTAPHID 64B (primario; BLE/WiFi so fallback futuro), nunca ve chaves/segredos.
- R-04: Firmware aplica OTA de forma staged e anti-brick: verifica assinatura Ed25519 + SHA-256 + versao anti-downgrade ANTES de comitar, preserva NVS/dados antigos, rollback automatico em falha, nunca panic no boot.
- R-05: Criptografia obrigatoria fim-a-fim (reuso: AES-256-GCM AEGN + Ed25519 existente); so checksum NAO aceito.
- R-06: Registro de producao (tools/factory_provision.py + eFuse BLOCK7/8 + identity.rs) e fonte de verdade; dispositivo nao provisionado (Unprovisioned) nao recebe OTA.

## Out of Scope
- Atualizacao do proprio app Android/APK (feita por outros canais).
- Cofre seguro apartado / Aegis Vault .aegisvault (outro responsavel - nao tocar).
- TLS prod, HSM/jig de fabrica, burn real eFuse (so dry-run + verify-after-write ja existentes).
- Transporte BLE/WiFi OTA nesta fase (so desenho deixando gancho).

## Acceptance Criteria
- [ ] Servidor sobe com stdlib (python tools/ota_server.py), expoe /api/ota/* e recusa serial nao registrado (401/403) e exige prova de conexao.
- [ ] Fluxo completo: app baixa manifesto+binario da API -> chave conectada valida online -> aplica e reporta versao nova.
- [ ] Chave nao registrada ou offline e recusada (teste negativo verde).
- [ ] Dados antigos (credenciais/OATH/NVS) intactos apos OTA (teste de migracao verde).
- [ ] Falha injetada (assinatura errada / energia no meio / versao menor) faz rollback sem brick e sem corromper chaves.
- [ ] cargo test + suite OTA verdes; sem segredos no repo.

## Constraints
- Reusar primitivas existentes (AES-256-GCM, Ed25519/P-256, eFuse, SecureStorage NVS dual-slot); nao introduzir nova crypto.
- Servidor simples: JSON + binario, registro em arquivo (ex.: ota_registry.json), sem dependencias externas.
- Caminho mais seguro anti-brick escolhido pelo orquestrador (staged verify-before-swap + dual-slot + rollback).
- Note: created WITH codebase research (server.py, provision.rs, identity.rs, UsbCtaphid.kt, WifiApi.kt, factory_provision.py).
- Nao alterar vault/ nem envelope AEGN do cofre.

## Open Questions
- none (transporte=USB primario, crypto=Ed25519+SHA256+AES-GCM, aceite e riscos delegados ao orquestrador por pedido explicito).

## Suppressed Questions
- "Qual transporte usar?" -> answered by: UsbCtaphid.kt (CTAPHID 64B VID 0x303A/PID 0xAE61) ja e o transporte testado; BLE/WiFi viram fallback futuro.
- "So checksum basta?" -> answered by: uniffi-bridge AES-256-GCM + Ed25519 disponivel; auditoria exige assinatura - checksum sozinho rejeitado.
- "Existe OTA parcial?" -> answered by: grep ota|OTA|esp-ota = zero no firmware; nada a reusar, construir novo ota.rs.
