package dev.aegiskey.app.ota2

import dev.aegiskey.app.ota2.Ota2Constants.MANIFEST_SHA_LEN
import dev.aegiskey.app.ota2.Ota2Constants.MANIFEST_SIG_LEN
import dev.aegiskey.app.ota2.Ota2Constants.MANIFEST_SIGNED_LEN
import dev.aegiskey.app.ota2.Ota2Constants.MANIFEST_U32_LEN
import dev.aegiskey.app.ota2.Ota2Constants.MANIFEST_WIRE_LEN
import dev.aegiskey.app.ota2.Ota2Constants.MAX_STAGED_IMAGE_BYTES
import java.security.MessageDigest

/**
 * Staged 104 B manifest (firmware ota.rs wire layout): version u32 BE,
 * size u32 BE, sha256 over the full image, offline release Ed25519
 * signature over [signedBytes] (40 B).
 */
data class Ota2Manifest(
    val version: Long,
    val size: Int,
    val sha256: ByteArray,
    val signature: ByteArray,
)

/**
 * Pure + JVM-testable: parses the fixed 104 B wire manifest and enforces
 * the staged size budget. Throws [Ota2Exception] on length mismatch or
 * zero/over-budget size.
 */
fun parseOta2Manifest(raw: ByteArray): Ota2Manifest {
    if (raw.size != MANIFEST_WIRE_LEN) throw Ota2Exception(Ota2Failure.BadManifest)
    val version = u32Be(raw, 0)
    val size = u32Be(raw, MANIFEST_U32_LEN)
    if (size < 1 || size > MAX_STAGED_IMAGE_BYTES) throw Ota2Exception(Ota2Failure.BadManifest)
    return Ota2Manifest(
        version = version,
        size = size.toInt(),
        sha256 = raw.copyOfRange(8, 8 + MANIFEST_SHA_LEN),
        signature = raw.copyOfRange(8 + MANIFEST_SHA_LEN, MANIFEST_WIRE_LEN),
    )
}

/** Canonical signed bytes: version BE || size BE || sha256 (40 B). */
fun Ota2Manifest.signedBytes(): ByteArray {
    val out = ByteArray(MANIFEST_SIGNED_LEN)
    putU32Be(out, 0, version)
    putU32Be(out, MANIFEST_U32_LEN, size.toLong())
    sha256.copyInto(out, 2 * MANIFEST_U32_LEN)
    return out
}

/**
 * Pure + JVM-testable: rejects version 0 and any version not strictly
 * newer than [currentVersion] (firmware Downgrade fail-closed).
 */
fun checkOta2Version(manifest: Ota2Manifest, currentVersion: Long) {
    if (currentVersion < 0) throw Ota2Exception(Ota2Failure.BadManifest)
    if (manifest.version == 0L || manifest.version <= currentVersion) {
        throw Ota2Exception(Ota2Failure.Downgrade)
    }
}

/** SHA-256 over the full image (streamed by callers for large files). */
fun sha256Of(bytes: ByteArray): ByteArray =
    MessageDigest.getInstance("SHA-256").digest(bytes)

fun ByteArray.toHexLower(): String {
    val hex = "0123456789abcdef"
    val chars = CharArray(size * 2)
    var i = 0
    for (b in this) {
        val v = b.toInt() and 0xFF
        chars[i++] = hex[v shr 4]
        chars[i++] = hex[v and 0x0F]
    }
    return String(chars)
}

internal fun u32Be(raw: ByteArray, off: Int): Long =
    ((raw[off].toInt() and 0xFF).toLong() shl 24) or
        ((raw[off + 1].toInt() and 0xFF).toLong() shl 16) or
        ((raw[off + 2].toInt() and 0xFF).toLong() shl 8) or
        (raw[off + 3].toInt() and 0xFF).toLong()

internal fun putU32Be(out: ByteArray, off: Int, value: Long) {
    out[off] = ((value shr 24) and 0xFF).toByte()
    out[off + 1] = ((value shr 16) and 0xFF).toByte()
    out[off + 2] = ((value shr 8) and 0xFF).toByte()
    out[off + 3] = (value and 0xFF).toByte()
}
