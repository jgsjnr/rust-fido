package dev.aegiskey.app.ota2

import dev.aegiskey.app.ota2.Ota2Constants.CHUNK_OFFSET_LEN
import dev.aegiskey.app.ota2.Ota2Constants.MANIFEST_WIRE_LEN
import dev.aegiskey.app.ota2.Ota2Constants.OP_ABORT
import dev.aegiskey.app.ota2.Ota2Constants.OP_BEGIN
import dev.aegiskey.app.ota2.Ota2Constants.OP_CHUNK
import dev.aegiskey.app.ota2.Ota2Constants.OP_FINISH
import dev.aegiskey.app.ota2.Ota2Constants.STATUS_FAIL
import dev.aegiskey.app.ota2.Ota2Constants.STATUS_OK
import dev.aegiskey.app.security.SdkGate
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.KeyPairGenerator
import java.security.Signature
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * ota2 engine tests (offline, fake transport, real JCA Ed25519 keys).
 *
 * Authority mirrored: 104 B manifest, in-order chunks, ack = received
 * count, FINISH only on full image. No Android framework beyond R-free
 * pure paths (SdkGate.GateOutcome is a nested type, never initialized).
 */
class Ota2EngineTest {

    private val currentVersion = 7L
    private val nextVersion = 8L

    private data class Fixture(
        val manifest: Ota2Manifest,
        val image: StagedImage,
        val pubkey: ByteArray,
    )

    private fun fixture(version: Long = nextVersion, imageSize: Int = 1024): Fixture {
        val kpg = KeyPairGenerator.getInstance("Ed25519")
        val kp = kpg.generateKeyPair()
        val pubRaw = kp.public.encoded.copyOfRange(12, 44)
        val image = ByteArray(imageSize) { i -> (i % 251).toByte() }
        val sha = sha256Of(image)
        val unsigned = Ota2Manifest(version = version, size = image.size, sha256 = sha, signature = ByteArray(64))
        val sig = Signature.getInstance("Ed25519").apply {
            initSign(kp.private)
            update(unsigned.signedBytes())
        }.sign()
        val manifest = unsigned.copy(signature = sig)
        return Fixture(manifest, StagedImage(image, sha, sha.toHexLower()), pubRaw)
    }

    /** Fake device: enforces order + budget, acks received count, drops on demand. */
    private class FakeOta2Device(var dropAfterChunks: Int = Int.MAX_VALUE) : Ota2Transport {
        val seenOps = mutableListOf<Int>()
        val received = ByteArrayOutputStream()
        var begunSize: Int? = null
        var chunkCount = 0
        var aborted = false

        override suspend fun send(opcode: Int, payload: ByteArray): Ota2Reply? {
            seenOps.add(opcode)
            return when (opcode) {
                OP_BEGIN -> {
                    val m = runCatching { parseOta2Manifest(payload) }.getOrNull()
                        ?: return Ota2Reply(opcode, STATUS_FAIL, ByteArray(0))
                    begunSize = m.size
                    received.reset()
                    chunkCount = 0
                    Ota2Reply(opcode, STATUS_OK, ByteArray(0))
                }
                OP_CHUNK -> {
                    if (chunkCount >= dropAfterChunks) return null
                    if (payload.size < CHUNK_OFFSET_LEN + 1) {
                        return Ota2Reply(opcode, STATUS_FAIL, ByteArray(0))
                    }
                    val off = u32Be(payload, 0).toInt()
                    val data = payload.copyOfRange(CHUNK_OFFSET_LEN, payload.size)
                    val want = begunSize ?: return Ota2Reply(opcode, STATUS_FAIL, ByteArray(0))
                    if (off != received.size() || received.size() + data.size > want) {
                        return Ota2Reply(opcode, STATUS_FAIL, ByteArray(0))
                    }
                    received.write(data)
                    chunkCount++
                    val ack = ByteArray(4)
                    putU32Be(ack, 0, received.size().toLong())
                    Ota2Reply(opcode, STATUS_OK, ack)
                }
                OP_FINISH -> {
                    if (received.size() != begunSize) return Ota2Reply(opcode, STATUS_FAIL, ByteArray(0))
                    Ota2Reply(opcode, STATUS_OK, ByteArray(0))
                }
                OP_ABORT -> {
                    begunSize = null
                    received.reset()
                    aborted = true
                    Ota2Reply(opcode, STATUS_OK, ByteArray(0))
                }
                else -> Ota2Reply(opcode, STATUS_FAIL, ByteArray(0))
            }
        }
    }

    private fun sessionOf(f: Fixture) = Ota2Session(manifest = f.manifest, image = f.image)

    private fun allowGate(gates: IntArray): () -> SdkGate.GateOutcome = {
        gates[0]++
        SdkGate.GateOutcome.Success
    }

    @Test
    fun happyPath_stagesVerifiesInOrder() = runBlocking {
        val f = fixture()
        val device = FakeOta2Device()
        val gates = intArrayOf(0)
        val progress = mutableListOf<Pair<Int, Int>>()
        val result = Ota2Engine.run(
            session = sessionOf(f),
            currentVersion = currentVersion,
            pubkey = f.pubkey,
            transport = device,
            gate = allowGate(gates),
            chunkBytes = 256,
            onProgress = { sent, total -> progress.add(sent to total) },
        )
        assertEquals(Ota2Result.Success(bytesSent = f.image.bytes.size, version = nextVersion), result)
        assertEquals(1, gates[0])
        assertEquals(listOf(OP_BEGIN, OP_CHUNK, OP_CHUNK, OP_CHUNK, OP_CHUNK, OP_FINISH), device.seenOps)
        assertTrue(device.received.toByteArray().contentEquals(f.image.bytes))
        assertEquals(4, progress.size)
        assertEquals(f.image.bytes.size to f.image.bytes.size, progress.last())
        assertTrue(progress.zipWithNext().all { (a, b) -> b.first > a.first })
    }

    @Test
    fun corruptSignature_rejectedBeforeAnyWireByte() = runBlocking {
        val f = fixture()
        val bad = f.manifest.copy(signature = f.manifest.signature.copyOf().also { it[0] = (it[0].toInt() xor 0xFF).toByte() })
        val device = FakeOta2Device()
        val result = Ota2Engine.run(
            session = Ota2Session(manifest = bad, image = f.image),
            currentVersion = currentVersion,
            pubkey = f.pubkey,
            transport = device,
            gate = allowGate(intArrayOf(0)),
            chunkBytes = 256,
        )
        assertEquals(Ota2Result.Failed(Ota2Failure.BadSignature), result)
        assertTrue(device.seenOps.isEmpty())
    }

    @Test
    fun rollback_equalAndOlder_rejected() = runBlocking {
        for (version in listOf(currentVersion, currentVersion - 1)) {
            val f = fixture(version = version)
            val device = FakeOta2Device()
            val result = Ota2Engine.run(
                session = sessionOf(f),
                currentVersion = currentVersion,
                pubkey = f.pubkey,
                transport = device,
                gate = allowGate(intArrayOf(0)),
                chunkBytes = 256,
            )
            assertEquals("version=$version", Ota2Result.Failed(Ota2Failure.Downgrade), result)
            assertTrue(device.seenOps.isEmpty())
        }
    }

    @Test
    fun oversizeFile_rejected() {
        try {
            Ota2FileStore.stageImage(ByteArrayInputStream(ByteArray(200)), maxBytes = 64)
            fail("expected Oversize")
        } catch (e: Ota2Exception) {
            assertEquals(Ota2Failure.Oversize, e.failure)
        }
        val raw = ByteArray(MANIFEST_WIRE_LEN)
        putU32Be(raw, 0, nextVersion)
        putU32Be(raw, 4, (Ota2Constants.MAX_STAGED_IMAGE_BYTES + 1).toLong())
        try {
            parseOta2Manifest(raw)
            fail("expected BadManifest")
        } catch (e: Ota2Exception) {
            assertEquals(Ota2Failure.BadManifest, e.failure)
        }
    }

    @Test
    fun tamperedImage_shaMismatchRejected() = runBlocking {
        val f = fixture()
        val tampered = f.image.bytes.copyOf().also { it[512] = (it[512].toInt() xor 0xFF).toByte() }
        val device = FakeOta2Device()
        val result = Ota2Engine.run(
            session = Ota2Session(f.manifest, f.image.copy(bytes = tampered)),
            currentVersion = currentVersion,
            pubkey = f.pubkey,
            transport = device,
            gate = allowGate(intArrayOf(0)),
            chunkBytes = 256,
        )
        assertEquals(Ota2Result.Failed(Ota2Failure.ShaMismatch), result)
        assertTrue(device.seenOps.isEmpty())
    }

    @Test
    fun resumeFromOffset_completesWithoutDuplication() = runBlocking {
        val f = fixture()
        val session = sessionOf(f)
        val device = FakeOta2Device(dropAfterChunks = 2)
        val gates = intArrayOf(0)
        val first = Ota2Engine.run(
            session = session,
            currentVersion = currentVersion,
            pubkey = f.pubkey,
            transport = device,
            gate = allowGate(gates),
            chunkBytes = 256,
        )
        assertEquals(Ota2Result.Paused(offset = 512), first)

        device.dropAfterChunks = Int.MAX_VALUE
        val progress = mutableListOf<Pair<Int, Int>>()
        val second = Ota2Engine.run(
            session = session,
            currentVersion = currentVersion,
            pubkey = f.pubkey,
            transport = device,
            gate = allowGate(gates),
            chunkBytes = 256,
            onProgress = { sent, total -> progress.add(sent to total) },
        )
        assertEquals(Ota2Result.Success(bytesSent = f.image.bytes.size, version = nextVersion), second)
        // No re-BEGIN (firmware BEGIN discards), no duplicated bytes.
        assertEquals(1, device.seenOps.count { it == OP_BEGIN })
        assertTrue(device.received.toByteArray().contentEquals(f.image.bytes))
        assertEquals(f.image.bytes.size to f.image.bytes.size, progress.last())
    }
}
