package dev.aegiskey.app.domain.model

enum class AccessKeyType { PASSKEY_FIDO, CRYPTO_WALLET_BTC, CRYPTO_WALLET_ETH, CRYPTO_WALLET_SOL }

data class VaultKeyEntry(
    val slotId: Int,
    val label: String,
    val type: AccessKeyType,
    val publicSummary: String,
    val createdAtEpochMs: Long
)
