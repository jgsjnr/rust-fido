# Architecture: Carteira cripto — armazenamento

## Approach
Camada fina `wallet/` (no_std + alloc) sobre o `KeyManager` existente: tipa cada slot como ativo cripto (rede, formato de endereço, coin-type) e delega guarda/assinatura/envelope para `KeyManager` + `AegisVault`. Geração/import grava sem OTP e sem lock global; leitura de endereço e assinatura exigem UP; import/delete exigem UP+PIN (gates herdados, não recriados). Persistência usa envelopes AEGN v1 já selados; NVS ganha chaves `wallet_*` formais só documentadas. Web ganha aba assistida que chama os mesmos entry points.

## Components
- `wallet/types.rs`: `CryptoNetwork` (Bitcoin, EthereumEvm, Solana), `WalletRecord` (slot_id, network, address, label) — só metadados, nunca privada.
- `wallet/store.rs`: `WalletStore` — generate/import/get/address/sign/list/delete delegando a `KeyManager` + `AegisVault::seal/open_envelope`.
- `wallet/address.rs`: derivação de endereço (BTC P2WPKH/bech32, ETH keccak-EIP55, SOL base58) a partir da pubkey existente — funções puras, sem I/O.
- `wallet/mod.rs`: re-exports + erros `WalletError` mapeados dos `KeyManagerError`/gates 9.5.
- Docs + web: `docs/carteira-cripto.md`, `docs/nvs_schema.md` (aditivo `wallet_slot_*`), aba web (JS puro, sem OTP).

## Data Flow
generate/import (UP / UP+PIN, sem OTP, sem lock) → privada em `KeyManager`, envelope AEGN via Vault → `WalletRecord` (metadados) → NVS `wallet_slot_*` → address() puro → sign() com UP → teardown zeroize.

## Alternatives Considered
- Novo cofre separado para cripto — rejected because `KeyManager`+Vault já fazem envelope, gates, zeroize e 32 slots; duplicar violaria o ladder (reuse).
- Nova curva/HD-derivation (BIP-32/44) agora — rejected because BIP-39 seed + `from_master_seed` + import de privada já atendem "somente armazenar"; BIP-32 fica para follow-up.
- Gate OTP na gravação — rejected because usuário vetou (sem OTP, sem trava inicial).
