package dev.aegiskey.app.ota2

import dev.aegiskey.app.ota2.Ota2Constants.MAX_STAGED_IMAGE_BYTES
import java.io.InputStream
import java.security.MessageDigest

/** firmware.bin staged in app cache: raw bytes + SHA-256 shown before send. */
data class StagedImage(
    val bytes: ByteArray,
    val sha256: ByteArray,
    val shaHex: String,
)

/**
 * SAF firmware.bin intake (offline-first).
 *
 * Streams [input] (SAF URI via ContentResolver, or any stream) into app
 * cache memory with a running SHA-256 and a hard size cap. Throws
 * [Ota2Exception] on empty (EmptyImage) or over-budget (Oversize) input
 * before any byte reaches the device. Pure JVM-testable: no Context here,
 * the Screen owns the ContentResolver call.
 */
object Ota2FileStore {
    fun stageImage(
        input: InputStream,
        maxBytes: Int = MAX_STAGED_IMAGE_BYTES,
    ): StagedImage {
        require(maxBytes in 1..Ota2Constants.PROTOCOL_MAX_IMAGE_BYTES) { "bad cap" }
        val digest = MessageDigest.getInstance("SHA-256")
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(8192)
        var total = 0
        input.use { ins ->
            while (true) {
                val n = ins.read(buf)
                if (n < 0) break
                total += n
                if (total > maxBytes) throw Ota2Exception(Ota2Failure.Oversize)
                digest.update(buf, 0, n)
                out.write(buf, 0, n)
            }
        }
        if (total == 0) throw Ota2Exception(Ota2Failure.EmptyImage)
        val bytes = out.toByteArray()
        val sha = digest.digest()
        return StagedImage(bytes = bytes, sha256 = sha, shaHex = sha.toHexLower())
    }
}
