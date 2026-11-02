package dev.aegiskey.app.ota2

import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.ota2.Ota2Constants.CHUNK_OFFSET_LEN
import dev.aegiskey.app.ota2.Ota2Constants.DEFAULT_CHUNK_BYTES
import dev.aegiskey.app.ota2.Ota2Constants.MAX_STAGED_IMAGE_BYTES
import dev.aegiskey.app.ota2.Ota2Constants.OP_ABORT
import dev.aegiskey.app.ota2.Ota2Constants.OP_BEGIN
import dev.aegiskey.app.ota2.Ota2Constants.OP_CHUNK
import dev.aegiskey.app.ota2.Ota2Constants.OP_FINISH
import dev.aegiskey.app.ota2.Ota2Constants.STATUS_NEED_UP
import dev.aegiskey.app.ota2.Ota2Constants.STATUS_OK
import dev.aegiskey.app.security.SdkGate

/** Engine outcome: staged+verified, paused for resume, or failed with a code. */
sealed interface Ota2Result {
    /** Device answered OK to FINISH. Commit stays a device-side USB ritual. */
    data class Success(val bytesSent: Int, val version: Long) : Ota2Result

    /** Link lost mid-stream. Re-run with the same session to resume. */
    data class Paused(val offset: Int) : Ota2Result

    /** Terminal. See [Ota2Failure.stringRes] for the user string. */
    data class Failed(val failure: Ota2Failure) : Ota2Result
}

/**
 * Offline firmware.bin OTA engine — single entrypoint ([run]).
 *
 * Order mirrors firmware verify (sig, then digest, then version), all
 * client-side, before any wire byte. Then BEGIN (0x30) + CHUNKs (0x31) +
 * FINISH (0x32) over the device-exposed transport (BLE preferred, USB
 * fallback via [Ota2Transport]). Never sends 0x33 COMMIT: after FINISH
 * the device holds Verified and waits for the physical UP + USB ritual.
 * No telemetry invented: progress reports acked byte counts only.
 */
object Ota2Engine {

    suspend fun run(
        session: Ota2Session,
        currentVersion: Long,
        pubkey: ByteArray,
        transport: Ota2Transport,
        verifier: Ota2Verifier = JcaEd25519Verifier,
        gate: () -> SdkGate.GateOutcome = SdkGate::requireOta,
        chunkBytes: Int = DEFAULT_CHUNK_BYTES,
        onProgress: ((sent: Int, total: Int) -> Unit)? = null,
    ): Ota2Result {
        if (chunkBytes <= 0 || chunkBytes > MAX_STAGED_IMAGE_BYTES) {
            return Ota2Result.Failed(Ota2Failure.BadManifest)
        }
        when (gate()) {
            SdkGate.GateOutcome.Success, SdkGate.GateOutcome.RealVerified -> Unit
            else -> return fail(session, Ota2Failure.GateBlocked, transport, abort = false)
        }

        val manifest = session.manifest
        val image = session.image.bytes

        // Client pre-checks (firmware verify order): sig, digest, version.
        if (Ota2Keys.isDeniedKey(pubkey)) {
            return fail(session, Ota2Failure.BadSignature, transport, abort = false)
        }
        when (verifier.verify(pubkey, manifest.signedBytes(), manifest.signature)) {
            Ota2VerifyVerdict.REJECTED -> {
                return fail(session, Ota2Failure.BadSignature, transport, abort = false)
            }
            Ota2VerifyVerdict.UNAVAILABLE -> {
                DeviceLog.append(DeviceLog.Category.SYSTEM, "OTA precheck unavailable, device decides")
            }
            Ota2VerifyVerdict.VERIFIED -> Unit
        }
        if (!manifest.sha256.contentEquals(sha256Of(image))) {
            return fail(session, Ota2Failure.ShaMismatch, transport, abort = false)
        }
        if (manifest.version == 0L || manifest.version <= currentVersion) {
            return fail(session, Ota2Failure.Downgrade, transport, abort = false)
        }
        if (image.size != manifest.size) {
            return fail(session, Ota2Failure.BadManifest, transport, abort = false)
        }

        // BEGIN (skip on resume: firmware BEGIN discards staging).
        if (!session.beginDone) {
            session.phase = Ota2Phase.STAGING
            val reply = transport.send(OP_BEGIN, session.manifestWire())
                ?: return pause(session)
            when (reply.status) {
                STATUS_OK -> session.beginDone = true
                STATUS_NEED_UP -> return fail(session, Ota2Failure.NeedUp, transport, abort = false)
                else -> return fail(session, Ota2Failure.DeviceRejected, transport, abort = true)
            }
            DeviceLog.append(
                DeviceLog.Category.SYSTEM,
                "OTA begin ok size=" + manifest.size + " ver=" + manifest.version,
            )
        }

        // CHUNKs from the acked cursor.
        while (session.offset < image.size) {
            val end = minOf(session.offset + chunkBytes, image.size)
            val payload = ByteArray(CHUNK_OFFSET_LEN + (end - session.offset))
            putU32Be(payload, 0, session.offset.toLong())
            image.copyInto(payload, CHUNK_OFFSET_LEN, session.offset, end)
            val reply = transport.send(OP_CHUNK, payload) ?: return pause(session)
            when (reply.status) {
                STATUS_OK -> {
                    val received = parseAck(reply.body) ?: return fail(
                        session, Ota2Failure.DeviceRejected, transport, abort = true,
                    )
                    if (received != end) {
                        return fail(session, Ota2Failure.DeviceRejected, transport, abort = true)
                    }
                    session.offset = received
                    onProgress?.invoke(session.offset, image.size)
                }
                STATUS_NEED_UP -> return fail(session, Ota2Failure.NeedUp, transport, abort = false)
                else -> return fail(session, Ota2Failure.DeviceRejected, transport, abort = true)
            }
        }
        session.phase = Ota2Phase.STAGED
        DeviceLog.append(DeviceLog.Category.SYSTEM, "OTA staged ok bytes=" + image.size)

        // FINISH: device is the signature/digest/version authority.
        val finish = transport.send(OP_FINISH, ByteArray(0)) ?: return pause(session)
        when (finish.status) {
            STATUS_OK -> {
                session.phase = Ota2Phase.VERIFIED
                session.phase = Ota2Phase.DONE
                DeviceLog.append(DeviceLog.Category.SYSTEM, "OTA finish ok ver=" + manifest.version)
                return Ota2Result.Success(bytesSent = image.size, version = manifest.version)
            }
            STATUS_NEED_UP -> return fail(session, Ota2Failure.NeedUp, transport, abort = false)
            else -> return fail(session, Ota2Failure.DeviceRejected, transport, abort = true)
        }
    }

    /** Pure + JVM-testable: CHUNK ack is exactly 4 B received-count within budget. */
    fun parseAck(reply: ByteArray): Int? {
        if (reply.size != CHUNK_OFFSET_LEN) return null
        val received = u32Be(reply, 0)
        if (received > MAX_STAGED_IMAGE_BYTES) return null
        return received.toInt()
    }

    private suspend fun pause(session: Ota2Session): Ota2Result {
        DeviceLog.append(DeviceLog.Category.SYSTEM, "OTA paused off=" + session.offset)
        return Ota2Result.Paused(session.offset)
    }

    private suspend fun fail(
        session: Ota2Session,
        failure: Ota2Failure,
        transport: Ota2Transport,
        abort: Boolean,
    ): Ota2Result {
        session.phase = Ota2Phase.FAILED
        if (abort && session.beginDone) {
            runCatching { transport.send(OP_ABORT, ByteArray(0)) }
        }
        DeviceLog.append(DeviceLog.Category.SYSTEM, "OTA failed")
        return Ota2Result.Failed(failure)
    }

    private fun Ota2Session.manifestWire(): ByteArray {
        val out = ByteArray(Ota2Constants.MANIFEST_WIRE_LEN)
        putU32Be(out, 0, manifest.version)
        putU32Be(out, Ota2Constants.MANIFEST_U32_LEN, manifest.size.toLong())
        manifest.sha256.copyInto(out, 8)
        manifest.signature.copyInto(out, 8 + Ota2Constants.MANIFEST_SHA_LEN)
        return out
    }
}
