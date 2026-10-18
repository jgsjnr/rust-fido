# Excecoes de Paridade — G0 (o que DEVE mudar vs o que NUNCA muda)

Emenda fd-review CONFIRM-REVIEW 2026-10-18. Regra: rewrite com paridade comprovada;
excecao so entra aqui com justificativa de seguranca.

## DEVEM mudar (W1-W3, com teste dedicado)

- PIN IV zero -> TRNG: `crypto/pin_protocol.rs` (`PinProtocol1::encrypt/decrypt` usam `iv=[0u8;16]`).
- PIN KDF salt zero -> TRNG/salt persistido: `PinProtocol2::kdf` usa `salt=[0u8;32]`.
- Nonce AEAD caller-supplied/fixo -> TRNG monotonico: `persistence.rs :: store(nonce_bytes)`.
- `MockEfuseStorage` (0x5A/0xA5) -> RealEfuse OTP: `firmware/src/efuse.rs`, `main.rs:182,191,193`.
- `MockFlashBackend` volatil -> NVS cifrada em prod; mock so em `#[cfg(test)]`.
- RESC sem gate -> exige UP+PIN: `core/src/otp/rescue.rs`, `core/src/ctap/*`.
- TOTP literal / RP fake / JS mock TOTP / attestation dev key: fixtures de teste, fora de prod (`cfg(test)`).

## NUNCA mudam (golden vectors desta Wave0)

- Bytes de `usb_descriptors` (`snapshots/usb_desc.sha256`): VID `0x303A`, PID `0xAE61`, 4 interfaces, reports 34/63B.
- Dispatch CTAP + status codes (`snapshots/ctap_golden.json`): `0x01/02/04/06/07/08/0A/0C/0D`; vazio->`0x03`, unknown->`0x01`.
- Ordem canonica COSE (`snapshots/coese_order.txt`): EC2 `1,3,-1,-2,-3`; OKP `1,3,-1,-2`.
- AAGUID sem bump; sem `esptool --verify` (v5.6 nao tem); `build/` com backup.
- Features `ble/menu/wifi` default-off: com features off, binario = baseline (G3).

## Verificacao

- `cargo test --workspace` verde antes de qualquer merge.
- `cargo test --test ctap_tests` regressao global; `clippy -D warnings`.
- CI grep: `Mock*` fora de `#[cfg(test)]` = FAIL.