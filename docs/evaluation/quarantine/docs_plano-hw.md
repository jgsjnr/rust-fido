# F7 — Aceleração de hardware (mapa + decisão)

Status: MAPEADO 20/10. Migração só com necessidade medida (benchmark
`--phase bench`); hoje tudo é RustCrypto software e os tempos já são
confortáveis p/ uso interativo.

## O que o S3 tem (conferido no IDF v5.3.1)

| Periférico | Header HAL | Uso hoje | Ganho potencial |
|---|---|---|---|
| RNG HW | `esp_random` (via `OsRng` no ESP-IDF) | **JÁ EM USO** | — |
| AES | `aes_ll.h` (mbedTLS usa sozinho) | software (`aes-gcm`) | médio (envelopes NVS) |
| SHA | `sha_ll.h` (mbedTLS usa sozinho) | software (`sha2`) | baixo (TOTP/HMAC/digests) |
| RSA/MPI | `mpi_ll.h` | n/a (sem RSA no device) | zero |
| HMAC | `hmac_ll.h` | software | baixo |
| DS (Digital Signature) | `ds_ll.h` | n/a (exige eFuse) | bloqueado sem burn |
| ECDSA dedicado | **NÃO EXISTE no S3** | software (`p256/p384`, hot path!) | impossível aqui |

## Conclusão técnica

- O hot path (ECDSA P-256/P-384 em MC/GA/wallet/PIV) **não tem HW no S3**:
  software é a única opção. Baseline atual já responde em ms.
- RNG já é HW (nada a fazer).
- SHA/AES/HMAC via mbedTLS-C dariam economia de bateria/CPU, ao custo
  de trocar o backend cripto auditado (RustCrypto) por bindings C —
  risco de regressão alto, ganho UX baixo (ops já são sub-segundo).
- DS exige chave em eFuse (fora de questão sem decisão de fábrica).

## Regra

Só migrar primitiva com: (a) benchmark mostrando lentidão sentida,
(b) feature flag + A/B contra RustCrypto, (c) release-clean intacto.
Busca: `bench` no e2e registra tempos por op.
