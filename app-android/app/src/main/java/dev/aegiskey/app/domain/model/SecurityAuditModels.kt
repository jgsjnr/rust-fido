package dev.aegiskey.app.domain.model

/**
 * Modelos de Domínio para Auditoria de Segurança de Hardware:
 * - GAP-01 / GAP-07: Status e Trava de Gravação de eFuse OTP
 * - GAP-02: Canal Criptografado Ponta-a-Ponta ECDH P-256
 * - OPP-05: Backup Shamir Secret Sharing 2-de-3 (SLIP-0039)
 * - OPP-06: Pré-visualização Web3 Clear Signing (OLED 128x64)
 * - OPP-02: Extensão CTAP 2.1 hmac-secret e largeBlobKey
 */

data class EfuseSafetyStatus(
    val flashEncryptionStatus: String = "READ-ONLY / DEV MODE",
    val secureBootStatus: String = "SIMULATED / NOT BURNED",
    val isWriteDisabled: Boolean = true,
    val doNotBurnInDevMode: Boolean = true,
    val permanentOtpLockDisabled: Boolean = true,
    val block7HmacAnchor: String = "DEV DETERMINISTIC FALLBACK",
    val secureVersion: Long = 1L
)

data class ShamirBackupShare(
    val shareIndex: Int,
    val shareLabel: String,
    val mnemonicOrHex: String
)

data class ShamirBackupPlan(
    val totalShares: Int = 3,
    val threshold: Int = 2,
    val shares: List<ShamirBackupShare> = emptyList(),
    val isReady: Boolean = true
)

data class ClearSigningPreviewFrame(
    val network: String,
    val toAddress: String,
    val amount: String,
    val maxFee: String,
    val payloadHash: String,
    val oledBufferLines: List<String>,
    val isCodeOnlyPreview: Boolean = true
)

data class EcdhSessionStatus(
    val isEcdhActive: Boolean = true,
    val curve: String = "P-256 (secp256r1)",
    val clientEphemeralPubHex: String = "",
    val peerPubHex: String = "",
    val kdfAlgorithm: String = "HKDF-SHA256",
    val cipherAlgorithm: String = "AES-256-GCM"
)
