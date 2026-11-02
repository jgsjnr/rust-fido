package dev.aegiskey.app.ota2

/**
 * Client-side signature pre-check verdict.
 *
 * The device-side FINISH (Ed25519 verify_strict over the 40 signed bytes)
 * stays the authority; this pre-check only fails fast before any wire
 * byte. UNAVAILABLE means the platform has no Ed25519 provider (older
 * Android): the engine skips the pre-check and lets the device decide,
 * never a faked success.
 */
enum class Ota2VerifyVerdict {
    VERIFIED,
    REJECTED,
    UNAVAILABLE,
}

/** Injected signature seam (host tests drive every branch without JCA). */
fun interface Ota2Verifier {
    fun verify(pubkey: ByteArray, message: ByteArray, signature: ByteArray): Ota2VerifyVerdict
}

/**
 * JCA Ed25519 verifier (firmware verify_ota_signature parity:
 * verify_strict semantics, malformed input denies).
 *
 * Raw 32 B pubkey is wrapped as SubjectPublicKeyInfo (prefix + key);
 * any failure (no provider, bad encoding, bad signature) maps to
 * REJECTED, a missing algorithm maps to UNAVAILABLE. Never throws.
 */
object JcaEd25519Verifier : Ota2Verifier {
    private val SPKI_PREFIX = byteArrayOf(
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
    )

    override fun verify(pubkey: ByteArray, message: ByteArray, signature: ByteArray): Ota2VerifyVerdict {
        if (Ota2Keys.isDeniedKey(pubkey)) return Ota2VerifyVerdict.REJECTED
        if (pubkey.size != Ota2Constants.OTA_PUBKEY_LEN || signature.size != Ota2Constants.MANIFEST_SIG_LEN) {
            return Ota2VerifyVerdict.REJECTED
        }
        return try {
            val kf = java.security.KeyFactory.getInstance("Ed25519")
            val spec = java.security.spec.X509EncodedKeySpec(SPKI_PREFIX + pubkey)
            val publicKey = kf.generatePublic(spec)
            val sig = java.security.Signature.getInstance("Ed25519")
            sig.initVerify(publicKey)
            sig.update(message)
            if (sig.verify(signature)) Ota2VerifyVerdict.VERIFIED else Ota2VerifyVerdict.REJECTED
        } catch (_: java.security.NoSuchAlgorithmException) {
            Ota2VerifyVerdict.UNAVAILABLE
        } catch (_: Exception) {
            Ota2VerifyVerdict.REJECTED
        }
    }
}
