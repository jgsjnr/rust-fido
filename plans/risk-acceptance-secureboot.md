# Aceite formal de risco — sem Secure Boot / Flash Encryption
- Data: 2026-10-19 · Decisão HUMANA explícita e reiterada ("secureboot desabilitado sempre", "não deve ligar o secure boot").
- Escopo: ESP32-S3 e ESP32 classic do projeto AegisKey.
- Risco aceito: com acesso físico+USB, atacante pode regravar firmware e contornar gates (binding/UP/PIN); segredos em NVS cifrada (AES-GCM, master em eFuse) não resistem a firmware malicioso.
- Mitigações vigentes: envelope AES-GCM + eFuse OTP, gates UP/PIN/vínculo, test-mode default-off, guard `ci-guard-secureboot.ps1` (garante que continua desligado — o guard inverte: falha se algo LIGAR).
- Revisão: reavaliar se modelo de ameaça mudar (produção em massa, adversário físico).
