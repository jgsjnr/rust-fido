package dev.aegiskey.app.ota2

import dev.aegiskey.app.ota2.Ota2Constants.OTA_PUBKEY_LEN

/**
 * Offline OTA key source.
 *
 * Authority: firmware OtaKeyProvider (release default all-zeros
 * fail-closed; lab key exists device-side under test-mode builds only).
 * The app never holds private key material, only the 32 B release pubkey.
 *
 * - Production key: injected once via [configureReleaseKey] from a
 *   BuildConfig field (see OTA_HOOK.md; the field itself is other-lane
 *   wiring). Until configured, every verify path denies fail-closed.
 * - [DEV_PUBKEY_HEX]: DEV-ONLY placeholder (all zeros = denied key).
 *   Replace with the lab key hex on dev builds only. NEVER SHIP a nonzero
 *   dev key: production must call [configureReleaseKey], never this const.
 */
object Ota2Keys {
    /** DEV-ONLY placeholder. All zeros = denied key (fail-closed). NEVER SHIP nonzero. */
    const val DEV_PUBKEY_HEX =
        "0000000000000000000000000000000000000000000000000000000000000000"

    /**
     * Lab pubkey slot (test-only, default-off). All zeros = off
     * (fail-closed). A nonzero lab key is honored only in debug builds
     * (see AegisApplication); release builds clear it. Do NOT invent keys:
     * the lab value lives with the key holder; the device-side reference is
     * the firmware test-mode LAB_PUBKEY (crates/aegis-fido-firmware/src/ota.rs).
     */
    const val LAB_PUBKEY_HEX =
        "0000000000000000000000000000000000000000000000000000000000000000"

    @Volatile
    private var releasePubkeyHex: String? = null

    @Volatile
    private var labPubkeyHex: String? = null

    /** Wires the production release pubkey (64 lowercase hex chars). */
    fun configureReleaseKey(hex: String) {
        require(hex.trim().lowercase().matches(Regex("[0-9a-f]{64}"))) { "bad release key" }
        releasePubkeyHex = hex.trim().lowercase()
    }

    /** Test seam: drops the configured release key back to denied. */
    fun clearReleaseKey() {
        releasePubkeyHex = null
    }

    /** Wires the lab pubkey (debug/test builds only; 64 lowercase hex chars). */
    fun configureLabKey(hex: String) {
        require(hex.trim().lowercase().matches(Regex("[0-9a-f]{64}"))) { "bad lab key" }
        labPubkeyHex = hex.trim().lowercase()
    }

    /** Drops the lab key back to off (release builds always call this). */
    fun clearLabKey() {
        labPubkeyHex = null
    }

    /** Active lab pubkey, or null when off/denied (never falls back silently). */
    fun labPubkeyOrNull(): ByteArray? =
        parseKey(labPubkeyHex)?.takeUnless { isDeniedKey(it) }

    /** True when a nonzero lab key is configured (debug/test only). */
    fun isLabConfigured(): Boolean = labPubkeyOrNull() != null

    /** Active pubkey: configured release key, else the denied DEV placeholder. */
    fun activePubkey(): ByteArray =
        parseKey(releasePubkeyHex) ?: ByteArray(OTA_PUBKEY_LEN)

    /** Mirrors firmware OtaKeyProvider::is_denied: all-zeros 32 B denies. */
    fun isDeniedKey(pubkey: ByteArray): Boolean =
        pubkey.size == OTA_PUBKEY_LEN && pubkey.all { it == 0.toByte() }

    private fun parseKey(hex: String?): ByteArray? {
        if (hex == null) return null
        return runCatching {
            ByteArray(OTA_PUBKEY_LEN) { i ->
                hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            }
        }.getOrNull()
    }
}
