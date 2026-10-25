package dev.aegiskey.app.domain.model

enum class AccessKeyType {
    PASSKEY_FIDO,
    VENDOR_SIGNING_KEY,
    CRYPTO_WALLET_BTC,
    CRYPTO_WALLET_ETH,
    CRYPTO_WALLET_SOL,
    CRYPTO_WALLET_DOT,
    PIV_SMARTCARD_SLOT,
    ENCRYPTED_AEGN_ENVELOPE
}

data class VaultKeyEntry(
    val slotId: Int,
    val label: String,
    val type: AccessKeyType,
    val publicSummary: String,
    val createdAtEpochMs: Long,
    val algorithmOrCurve: String = "ES256 (P-256)",
    val usageDescription: String = "Autenticação e Assinatura",
    val derivationPathOrSlotCode: String = "",
    val envelopeHex: String = "",
    val requiresPhysicalTouch: Boolean = true
)

data class HardwareDeviceDiagnostics(
    val firmwareVersion: String,
    val transportChannel: String,
    val totalVaultItems: Int,
    val freeSlotsRemaining: Int,
    val fido2SupportedCurves: List<String>,
    val pivSlotsAvailable: List<String>,
    val healthStatusText: String,
    val isPinConfigured: Boolean,
    val isBoundToThisPhone: Boolean
)
