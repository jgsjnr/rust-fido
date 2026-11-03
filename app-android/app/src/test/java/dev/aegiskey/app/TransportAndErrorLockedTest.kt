package dev.aegiskey.app

import dev.aegiskey.app.data.cbor.SecureGuardCbor
import dev.aegiskey.app.domain.model.ActiveTransport
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.ErrorLockedRecovery
import dev.aegiskey.app.domain.model.SecureGuardStateEnum
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Regression tests for the two app behavior fixes:
 * Bug 1 — connection status shows the transport carrying the live
 * session (USB HID vs BLE), never a stale stored value; unknown falls
 * back to neutral (null) instead of Bluetooth.
 * Bug 2 — ErrorLocked (0x09 from 0x3A status) routes to recovery
 * instead of a PIN prompt, with frozen counters.
 */
class TransportAndErrorLockedTest {

    // --- Bug 1: active-transport resolution ---

    @Test
    fun resolve_usbPresentWithStoredBle_reportsUsb() {
        assertEquals(
            ConnectionTransportType.USB,
            ActiveTransport.resolve(
                stored = ConnectionTransportType.BLE,
                usbPresent = true,
                bleReady = true
            )
        )
    }

    @Test
    fun resolve_usbPresentWithoutBle_reportsUsb() {
        assertEquals(
            ConnectionTransportType.USB,
            ActiveTransport.resolve(
                stored = ConnectionTransportType.BLE,
                usbPresent = true,
                bleReady = false
            )
        )
    }

    @Test
    fun resolve_bleReadyWithoutUsb_reportsBle() {
        assertEquals(
            ConnectionTransportType.BLE,
            ActiveTransport.resolve(
                stored = ConnectionTransportType.USB,
                usbPresent = false,
                bleReady = true
            )
        )
    }

    @Test
    fun resolve_noLiveLinkWithStoredBle_isNeutralNotBle() {
        assertNull(
            ActiveTransport.resolve(
                stored = ConnectionTransportType.BLE,
                usbPresent = false,
                bleReady = false
            )
        )
    }

    @Test
    fun resolve_noLiveLinkWithStoredUsb_isNeutral() {
        assertNull(
            ActiveTransport.resolve(
                stored = ConnectionTransportType.USB,
                usbPresent = false,
                bleReady = false
            )
        )
    }

    @Test
    fun resolve_noLiveLinkWithoutStored_isNeutral() {
        assertNull(
            ActiveTransport.resolve(stored = null, usbPresent = false, bleReady = false)
        )
    }

    @Test
    fun resolve_noLiveLink_preservesWifiAndSimulator() {
        assertEquals(
            ConnectionTransportType.WIFI,
            ActiveTransport.resolve(
                stored = ConnectionTransportType.WIFI,
                usbPresent = false,
                bleReady = false
            )
        )
        assertEquals(
            ConnectionTransportType.SIMULATOR,
            ActiveTransport.resolve(
                stored = ConnectionTransportType.SIMULATOR,
                usbPresent = false,
                bleReady = false
            )
        )
    }

    @Test
    fun parseStoredOrNull_mapsKnownNamesAndRejectsUnknown() {
        assertEquals(ConnectionTransportType.BLE, ActiveTransport.parseStoredOrNull("BLE"))
        assertEquals(ConnectionTransportType.USB, ActiveTransport.parseStoredOrNull("USB"))
        assertEquals(ConnectionTransportType.WIFI, ActiveTransport.parseStoredOrNull("WIFI"))
        assertEquals(ConnectionTransportType.SIMULATOR, ActiveTransport.parseStoredOrNull("SIMULATOR"))
        assertNull(ActiveTransport.parseStoredOrNull(null))
        assertNull(ActiveTransport.parseStoredOrNull(""))
        assertNull(ActiveTransport.parseStoredOrNull("bluetooth"))
        assertNull(ActiveTransport.parseStoredOrNull("GARBAGE"))
    }

    @Test
    fun inferFromHardwareId_mapsIdentifiers() {
        assertEquals(
            ConnectionTransportType.USB,
            ActiveTransport.inferFromHardwareId("usb:1234:ae61")
        )
        assertEquals(
            ConnectionTransportType.USB,
            ActiveTransport.inferFromHardwareId("BRIDGE:8080")
        )
        assertEquals(
            ConnectionTransportType.WIFI,
            ActiveTransport.inferFromHardwareId("WIFI:http://192.168.4.1")
        )
        assertEquals(
            ConnectionTransportType.BLE,
            ActiveTransport.inferFromHardwareId("AA:BB:CC:DD:EE:FF")
        )
        assertEquals(
            ConnectionTransportType.BLE,
            ActiveTransport.inferFromHardwareId("BLE-BRIDGE")
        )
        assertNull(ActiveTransport.inferFromHardwareId(null))
        assertNull(ActiveTransport.inferFromHardwareId(""))
        assertNull(ActiveTransport.inferFromHardwareId("CONFIGURED-VAULT"))
    }

    // --- Bug 2: ErrorLocked routing ---

    @Test
    fun errorLocked_detectedFromWireCode0x09() {
        assertEquals(SecureGuardStateEnum.ERROR_LOCKED, SecureGuardStateEnum.fromWireCode(0x09))
        assertTrue(ErrorLockedRecovery.isErrorLockedWireCode(0x09))
        assertFalse(ErrorLockedRecovery.isErrorLockedWireCode(0x02))
        assertEquals(
            SecureGuardStateEnum.ERROR_LOCKED,
            SecureGuardStateEnum.fromString("ErrorLocked")
        )
    }

    @Test
    fun errorLocked_detectedFrom0x3aStatusPayload() {
        val payload = SecureGuardCbor.encodeMap(
            linkedMapOf(
                "state" to 9,
                "state_name" to "ErrorLocked",
                "provisioned" to true,
                "unlocked" to false,
                "failed_attempts" to 5,
                "remaining_attempts" to 5,
                "max_attempts" to 5
            )
        )
        val status = SecureGuardCbor.parseStatus(payload)
        assertTrue(status != null)
        assertEquals(SecureGuardStateEnum.ERROR_LOCKED, status!!.state)
        assertTrue(ErrorLockedRecovery.isErrorLocked(status.state))
        assertFalse(ErrorLockedRecovery.shouldPromptPin(status.state))
        assertTrue(ErrorLockedRecovery.isRecoveryRoute(status.state))
    }

    @Test
    fun errorLocked_detectedFromWireCodeOnly() {
        val payload = SecureGuardCbor.encodeMap(
            linkedMapOf(
                "state" to 9,
                "state_name" to "Unrecognized",
                "provisioned" to true,
                "unlocked" to false
            )
        )
        val status = SecureGuardCbor.parseStatus(payload)
        assertTrue(status != null)
        assertEquals(SecureGuardStateEnum.ERROR_LOCKED, status!!.state)
    }

    @Test
    fun errorLocked_neverPromptsForPin() {
        assertFalse(ErrorLockedRecovery.shouldPromptPin(SecureGuardStateEnum.ERROR_LOCKED))
        assertTrue(ErrorLockedRecovery.shouldPromptPin(SecureGuardStateEnum.LOCKED))
        assertTrue(ErrorLockedRecovery.shouldPromptPin(SecureGuardStateEnum.RATE_LIMITED))
        assertFalse(ErrorLockedRecovery.shouldPromptPin(SecureGuardStateEnum.UNLOCKED))
        assertFalse(ErrorLockedRecovery.shouldPromptPin(SecureGuardStateEnum.RECOVERY_REQUIRED))
        assertFalse(ErrorLockedRecovery.shouldPromptPin(SecureGuardStateEnum.UNPROVISIONED))
    }

    @Test
    fun errorLocked_routesToRecovery() {
        assertTrue(ErrorLockedRecovery.isRecoveryRoute(SecureGuardStateEnum.ERROR_LOCKED))
        assertTrue(ErrorLockedRecovery.isRecoveryRoute(SecureGuardStateEnum.RECOVERY_REQUIRED))
        assertFalse(ErrorLockedRecovery.isRecoveryRoute(SecureGuardStateEnum.LOCKED))
        assertFalse(ErrorLockedRecovery.isRecoveryRoute(SecureGuardStateEnum.RATE_LIMITED))
        assertFalse(ErrorLockedRecovery.isRecoveryRoute(SecureGuardStateEnum.UNLOCKED))
    }

    @Test
    fun errorLocked_freezesCountersWithReason_onlyErrorLocked() {
        for (state in SecureGuardStateEnum.entries) {
            if (state == SecureGuardStateEnum.ERROR_LOCKED) {
                assertTrue(state.name, ErrorLockedRecovery.isAttemptsCounterFrozen(state))
            } else {
                assertFalse(state.name, ErrorLockedRecovery.isAttemptsCounterFrozen(state))
            }
        }
    }
}
