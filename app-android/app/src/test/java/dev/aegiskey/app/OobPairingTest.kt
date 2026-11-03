package dev.aegiskey.app

import dev.aegiskey.app.ble.BindingOps
import dev.aegiskey.app.ble.BleContract
import dev.aegiskey.app.data.transport.KeyTransport
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.usecase.ArmBleOobUseCase
import dev.aegiskey.app.oob.OobPairing
import java.security.SecureRandom
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * OOB-assisted BLE pairing (CAPABILITY_DIET §10, firmware `ble/oob.rs`).
 *
 * - TK: random 16 B via SecureRandom, never all-zero, unique per call.
 * - Arm payload: opcode `0x42` + exactly the 16 TK bytes over USB only.
 * - Gate mapping mirrors the firmware canonical order
 *   (window/binding -> UP -> PIN session): `0x05` bind first, `0x01`
 *   touch, `0x02` unlock, `0x00` armed; anything else fails closed.
 * - `0x42` never travels over BLE GATT (rejected by both allowlists).
 * - Android-side bond stays blocked: no public OS entrypoint consumes
 *   the TK (verified on `android-34`, phone API 31).
 */
class OobPairingTest {

    // --- TK generation ----------------------------------------------------

    @Test
    fun generateTk_isSixteenNonzeroRandomBytes() {
        val a = OobPairing.generateTk()
        val b = OobPairing.generateTk()
        assertEquals(OobPairing.OOB_TK_LEN, a.size)
        assertTrue("TK must carry entropy", OobPairing.isValidTk(a))
        assertFalse("TK must never be all-zero", a.all { it == 0.toByte() })
        assertNotEquals(
            "fresh TKs must differ (2^-128 collision)",
            a.toList(),
            b.toList()
        )
    }

    @Test
    fun generateTk_deterministicRandom_stillValidShape() {
        val tk = OobPairing.generateTk(SecureRandom.getInstance("SHA1PRNG").also { it.setSeed(42L) })
        assertEquals(16, tk.size)
        assertTrue(OobPairing.isValidTk(tk))
    }

    @Test
    fun isValidTk_rejectsGarbageFailClosed() {
        assertFalse(OobPairing.isValidTk(null))
        assertFalse(OobPairing.isValidTk(ByteArray(0)))
        assertFalse(OobPairing.isValidTk(ByteArray(15) { 1 }))
        assertFalse(OobPairing.isValidTk(ByteArray(17) { 1 }))
        assertFalse(OobPairing.isValidTk(ByteArray(32) { 1 }))
        assertFalse(OobPairing.isValidTk(ByteArray(16)))
    }

    @Test
    fun isValidTk_acceptsSingleNonzeroByte() {
        assertTrue(OobPairing.isValidTk(ByteArray(16).also { it[15] = 1 }))
    }

    // --- Arm payload shape --------------------------------------------------

    @Test
    fun armOp_is0x42_firstFreeAfterVendorSign() {
        assertEquals(0x42, OobPairing.OP_BLE_OOB_ARM)
    }

    @Test
    fun armPayload_carriesExactlyTheTkBytes() {
        val tk = ByteArray(16) { (it * 7 + 1).toByte() }
        val payload = OobPairing.armPayload(tk)
        assertArrayEquals(tk, payload)
        assertFalse("payload must be a defensive copy", payload === tk)
    }

    @Test(expected = IllegalArgumentException::class)
    fun armPayload_rejectsWeakTk() {
        OobPairing.armPayload(ByteArray(16))
    }

    // --- Gate mapping (mirrors firmware canonical order) --------------------

    @Test
    fun parseArmResponse_mapsStatusFirstContract() {
        assertTrue(OobPairing.parseArmResponse(byteArrayOf(0x00)) is OobPairing.ArmResult.Armed)
        assertTrue(OobPairing.parseArmResponse(byteArrayOf(0x42.toByte(), 0x00)) is OobPairing.ArmResult.Armed)
        assertTrue(OobPairing.parseArmResponse(byteArrayOf(0x05)) is OobPairing.ArmResult.NeedBinding)
        assertTrue(OobPairing.parseArmResponse(byteArrayOf(0x42.toByte(), 0x05)) is OobPairing.ArmResult.NeedBinding)
        assertTrue(OobPairing.parseArmResponse(byteArrayOf(0x01)) is OobPairing.ArmResult.NeedUp)
        assertTrue(OobPairing.parseArmResponse(byteArrayOf(0x02)) is OobPairing.ArmResult.NeedPin)
    }

    @Test
    fun parseArmResponse_unknownOrAbsent_isFailureNeverSuccess() {
        assertTrue(OobPairing.parseArmResponse(byteArrayOf(0x04)) is OobPairing.ArmResult.BadEnvelope)
        assertTrue(OobPairing.parseArmResponse(byteArrayOf(0x42.toByte(), 0x04)) is OobPairing.ArmResult.BadEnvelope)
        assertTrue(OobPairing.parseArmResponse(byteArrayOf(0x09)) is OobPairing.ArmResult.BadEnvelope)
        assertTrue(OobPairing.parseArmResponse(null) is OobPairing.ArmResult.TransportFailure)
        assertTrue(OobPairing.parseArmResponse(ByteArray(0)) is OobPairing.ArmResult.TransportFailure)
    }

    // --- Transport constraint: serial/USB only --------------------------------

    @Test
    fun oobOp_neverTravelsOverBleGatt() {
        assertFalse(
            "0x42 must stay out of the BLE vendor allowlist (serial/USB only)",
            BleContract.isVendorOp(OobPairing.OP_BLE_OOB_ARM)
        )
        assertFalse(
            "0x42 is not a binding op either",
            BindingOps.isBindingOp(OobPairing.OP_BLE_OOB_ARM)
        )
    }

    // --- Android-side verdict ---------------------------------------------------

    @Test
    fun androidBondVerdict_staysBlockedWithExactGap() {
        assertTrue(
            OobPairing.androidBondVerdict() is OobPairing.AndroidBondVerdict.BlockedNoPublicOobApi
        )
        assertTrue(OobPairing.ANDROID_OOB_GAP.isNotBlank())
    }

    // --- Use case: USB-only arm ---------------------------------------------------

    private class FakeUsbTransport(val reply: ByteArray?, val explode: Boolean = false) : KeyTransport {
        override val transportType: ConnectionTransportType = ConnectionTransportType.USB
        override val isConnected: StateFlow<Boolean> = MutableStateFlow(true)
        var lastOpcode: Int = -1
        var lastPayload: ByteArray = ByteArray(0)
        var calls: Int = 0

        override suspend fun connect(target: String): Result<Unit> = Result.success(Unit)
        override suspend fun disconnect() = Unit
        override suspend fun sendVendor(opcode: Int, payload: ByteArray): ByteArray? {
            calls++
            lastOpcode = opcode
            lastPayload = payload.copyOf()
            if (explode) throw java.io.IOException("usb gone")
            return reply
        }

        override suspend fun sendMsg(payload: ByteArray): ByteArray? = null
        override suspend fun cancel(): Boolean = true
    }

    @Test
    fun armUseCase_sends0x42PlusSixteenTkBytes_overUsbOnly() = runTest {
        val fake = FakeUsbTransport(byteArrayOf(0x42.toByte(), 0x00))
        val useCase = ArmBleOobUseCase(fake)
        val tk = ByteArray(16) { (it + 1).toByte() }

        val result = useCase(tk)

        assertTrue(result is OobPairing.ArmResult.Armed)
        assertEquals(1, fake.calls)
        assertEquals(0x42, fake.lastOpcode)
        assertEquals(16, fake.lastPayload.size)
        assertTrue("TK buffer must be wiped after the one-shot send", tk.all { it == 0.toByte() })
    }

    @Test
    fun armUseCase_mapsAuthorityDenials_withoutThrowing() = runTest {
        val cases = mapOf(
            byteArrayOf(0x05) to OobPairing.ArmResult.NeedBinding::class,
            byteArrayOf(0x01) to OobPairing.ArmResult.NeedUp::class,
            byteArrayOf(0x02) to OobPairing.ArmResult.NeedPin::class,
            byteArrayOf(0x04) to OobPairing.ArmResult.BadEnvelope::class,
            null to OobPairing.ArmResult.TransportFailure::class,
        )
        for ((reply, expected) in cases) {
            val result = ArmBleOobUseCase(FakeUsbTransport(reply))(ByteArray(16) { 3 })
            assertTrue("reply ${reply?.toList()} must map to $expected", expected.isInstance(result))
        }
        val exploded = ArmBleOobUseCase(FakeUsbTransport(null, explode = true))(ByteArray(16) { 3 })
        assertTrue(exploded is OobPairing.ArmResult.TransportFailure)
    }

    @Test
    fun armUseCase_invalidTk_neverReachesWire() = runTest {
        val fake = FakeUsbTransport(byteArrayOf(0x00))
        val result = ArmBleOobUseCase(fake)(ByteArray(16))
        assertTrue(result is OobPairing.ArmResult.BadEnvelope)
        assertEquals("weak TK must not be sent", 0, fake.calls)
    }
}
