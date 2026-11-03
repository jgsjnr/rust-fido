package dev.aegiskey.app

import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.repository.ConnectedKeysRepositoryImpl
import dev.aegiskey.app.data.repository.KeyVaultRepositoryImpl
import dev.aegiskey.app.data.transport.SimulatedRenodeTransport
import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.VaultKeyEntry
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Assinatura via opcode dedicado 0x41 (contrato SIGN da firmware, eeb3e93).
 *
 * - O app NUNCA assina via GEN 0x20 (geração de chaves).
 * - 0x2F é o trigger de pareamento e 0x40 o SET_UP_POLICY: nunca reuse.
 * - Envelope: `0x01 slot + 0x74 msg`; resposta `[0x41, status, sig...]`.
 * - Status 0x04 mapeia para "Falha na operação de assinatura
 *   (operation failed)", sem vazar bytes do wire.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class KeySignOpcodeTest {

    private lateinit var keysStore: EncryptedKeysStore
    private lateinit var connectedKeysRepo: ConnectedKeysRepositoryImpl
    private lateinit var simulatedTransport: SimulatedRenodeTransport

    private val keyId = "sign-test-key"
    private val bindingHex = "A1B2C3D4E5F60718"
    private val slotId = 3

    @Before
    fun setUp() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        keysStore = EncryptedKeysStore(context = null)
        keysStore.clearAll()
        simulatedTransport = SimulatedRenodeTransport()
        connectedKeysRepo = ConnectedKeysRepositoryImpl(
            keysStore = keysStore,
            scope = CoroutineScope(Dispatchers.Unconfined)
        )
        runBlocking {
            connectedKeysRepo.addOrUpdateKey(
                ConnectedKeyDevice(
                    id = keyId,
                    displayName = "Chave Sign Test",
                    hardwareAddressOrId = "usb:303a:ae61",
                    bindingIdHex = bindingHex,
                    transportType = ConnectionTransportType.USB,
                    isCurrentlyConnected = true,
                    firmwareRevision = 1,
                    lastConnectedEpochMs = System.currentTimeMillis()
                )
            )
        }
        keysStore.saveVaultEntries(
            keyId,
            listOf(
                VaultKeyEntry(
                    slotId = slotId,
                    label = "Signer",
                    type = AccessKeyType.VENDOR_SIGNING_KEY,
                    publicSummary = "test",
                    createdAtEpochMs = 0L
                )
            ),
            bindingHex
        )
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private fun repoWithReply(reply: ByteArray?): Pair<KeyVaultRepositoryImpl, Captured> {
        val captured = Captured()
        val repo = KeyVaultRepositoryImpl(
            keysStore = keysStore,
            usbKeyTransport = null,
            bleKeyTransport = null,
            simulatedRenodeTransport = simulatedTransport,
            connectedKeysRepository = connectedKeysRepo,
            scope = CoroutineScope(Dispatchers.Unconfined)
        )
        repo.vendorOverride = { opcode, payload ->
            captured.opcode = opcode
            captured.payload = payload
            reply
        }
        return repo to captured
    }

    private class Captured {
        var opcode: Int = -1
        var payload: ByteArray = ByteArray(0)
    }

    @Test
    fun signRequest_envelopeIsSlotPlusChallenge() {
        val msg = "hello".toByteArray(Charsets.UTF_8)
        val req = VendorOps.signRequest(7, msg)
        val records = VendorOps.parseTlvRecords(req)
        assertArrayEquals(byteArrayOf(7), VendorOps.findTlv(records, VendorOps.TAG_SLOT))
        assertArrayEquals(msg, VendorOps.findTlv(records, VendorOps.TAG_OATH_CHALLENGE))
    }

    @Test
    fun signOp_is0x41_firstFreeAfterUpPolicy() {
        assertEquals(0x41, VendorOps.OP_KEY_SIGN)
    }

    @Test
    fun sign_usesDedicated0x41_neverGen0x20() = runTest {
        val sig = ByteArray(64) { it.toByte() }
        val (repo, captured) = repoWithReply(
            byteArrayOf(VendorOps.OP_KEY_SIGN.toByte(), 0x00.toByte()) + sig
        )

        val result = repo.signChallengeOrTransaction(keyId, slotId, "CHALLENGE_NONCE_ABC123")

        assertEquals(VendorOps.OP_KEY_SIGN, captured.opcode)
        assertEquals(0x41, captured.opcode)
        assertNotEquals(VendorOps.OP_KEY_GEN_ONDEVICE, captured.opcode)
        assertTrue(result.isSuccess)
        assertEquals(sig.joinToString("") { "%02X".format(it) }, result.getOrThrow())
    }

    @Test
    fun sign_envelopeCarriesSlotAndChallenge() = runTest {
        val msg = "CHALLENGE_NONCE_ABC123"
        val (repo, captured) = repoWithReply(
            byteArrayOf(0x41.toByte(), 0x00.toByte()) + ByteArray(64)
        )

        repo.signChallengeOrTransaction(keyId, slotId, msg)

        val records = VendorOps.parseTlvRecords(captured.payload)
        assertArrayEquals(
            byteArrayOf(slotId.toByte()),
            VendorOps.findTlv(records, VendorOps.TAG_SLOT)
        )
        assertArrayEquals(
            msg.toByteArray(Charsets.UTF_8),
            VendorOps.findTlv(records, VendorOps.TAG_OATH_CHALLENGE)
        )
    }

    @Test
    fun sign_maps0x04_toOperationFailed() = runTest {
        val (repo, captured) = repoWithReply(
            byteArrayOf(0x41.toByte(), VendorOps.STATUS_BAD_ENVELOPE.toByte())
        )

        val result = repo.signChallengeOrTransaction(keyId, slotId, "CHALLENGE_NONCE_ABC123")

        assertEquals(0x41, captured.opcode)
        assertTrue(result.isFailure)
        val message = result.exceptionOrNull()?.message.orEmpty()
        assertTrue("esperava 'operation failed', obteve: $message", message.contains("operation failed", ignoreCase = true))
        assertTrue("esperava texto PT, obteve: $message", message.contains("Falha na operação"))
    }
}
