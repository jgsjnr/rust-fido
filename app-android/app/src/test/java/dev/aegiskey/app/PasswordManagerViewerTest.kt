package dev.aegiskey.app

import dev.aegiskey.app.pm.PmCbor
import dev.aegiskey.app.ui.VaultGate
import dev.aegiskey.app.ui.navigation.AppRoutes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Host-only viewer tests (F-PM2): codec round-trips, fail-closed gates,
 * opcode audit, and transient-release zeroization. No hardware, no
 * persistence, no secrets in assertions beyond opaque fixtures.
 */
class PasswordManagerViewerTest {

    @Test
    fun pm_opcodes_claim_first_free_range() {
        assertEquals(0x43, PmCbor.OP_PM_PUT)
        assertEquals(0x44, PmCbor.OP_PM_GET)
        assertEquals(0x45, PmCbor.OP_PM_LIST)
        assertEquals(0x46, PmCbor.OP_PM_DELETE)
        assertEquals(0x47, PmCbor.OP_PM_STATUS)
        for (op in PmCbor.PM_OP_MIN..PmCbor.PM_OP_MAX) {
            assertTrue("opcode $op should be PM", PmCbor.isPmOpcode(op))
        }
        for (op in listOf(0x3E, 0x3F, 0x40, 0x41, 0x42, 0x48, 0x81, 0x83)) {
            assertTrue("opcode $op must not be PM", !PmCbor.isPmOpcode(op))
        }
    }

    @Test
    fun list_request_response_roundtrip() {
        val body = PmCbor.encodeListRequest(7L, 10)
        val ids = listOf(ByteArray(16) { 0x01 }, ByteArray(16) { 0x02 })
        val respBody = dev.aegiskey.app.data.cbor.SecureGuardCbor.encodeMap(
            linkedMapOf(
                "ids" to ids,
                "next_cursor" to 9L,
                "has_more" to true,
            )
        )
        assertTrue(body.isNotEmpty())
        val page = PmCbor.decodeListResponse(respBody)
        assertEquals(2, page.ids.size)
        assertEquals(9L, page.nextCursor)
        assertTrue(page.hasMore)
        assertTrue(page.ids[0].contentEquals(ids[0]))
    }

    @Test
    fun release_roundtrip_and_wipe() {
        val id = ByteArray(16) { 0x0A }
        val secret = ByteArray(24) { 0x5A }
        val body = dev.aegiskey.app.data.cbor.SecureGuardCbor.encodeMap(
            linkedMapOf(
                "id" to id,
                "username" to "alice",
                "secret" to secret,
            )
        )
        val rel = PmCbor.decodeReleaseResponse(body)
        assertEquals("alice", rel.username)
        assertTrue(rel.secret.contentEquals(secret))
        rel.wipe()
        assertTrue(rel.secret.all { it == 0.toByte() })
        assertTrue(rel.id.all { it == 0.toByte() })
    }

    @Test
    fun release_rejects_empty_secret_and_oversize_id() {
        val badSecret = dev.aegiskey.app.data.cbor.SecureGuardCbor.encodeMap(
            linkedMapOf(
                "id" to ByteArray(4) { 0x01 },
                "username" to "alice",
                "secret" to ByteArray(0),
            )
        )
        try {
            PmCbor.decodeReleaseResponse(badSecret)
            fail("empty secret must fail closed")
        } catch (_: IllegalArgumentException) {
        }
        val bigId = dev.aegiskey.app.data.cbor.SecureGuardCbor.encodeMap(
            linkedMapOf(
                "id" to ByteArray(PmCbor.PM_ID_MAX_BYTES + 1) { 0x01 },
                "username" to "alice",
                "secret" to ByteArray(8) { 0x01 },
            )
        )
        try {
            PmCbor.decodeReleaseResponse(bigId)
            fail("oversize id must fail closed")
        } catch (_: IllegalArgumentException) {
        }
        try {
            PmCbor.encodeGetRequest(ByteArray(0))
            fail("empty id must fail closed")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun gates_preserve_wire_bytes_and_vault_ux() {
        assertTrue(PmCbor.gateOf(0x00) is PmCbor.PmGate.Ok)
        assertTrue(PmCbor.gateOf(0x05) is PmCbor.PmGate.NeedBinding)
        assertTrue(PmCbor.gateOf(0x01) is PmCbor.PmGate.PresenceRequired)
        assertTrue(PmCbor.gateOf(0x02) is PmCbor.PmGate.PinRequired)
        assertTrue(PmCbor.gateOf(0x04) is PmCbor.PmGate.Denied)
        assertEquals(VaultGate.NEED_BINDING, PmCbor.vaultGateOf(PmCbor.gateOf(0x05)))
        assertEquals(VaultGate.NEED_UP, PmCbor.vaultGateOf(PmCbor.gateOf(0x01)))
        assertEquals(VaultGate.NEED_PIN, PmCbor.vaultGateOf(PmCbor.gateOf(0x02)))
        assertEquals(VaultGate.NO_BLE, PmCbor.vaultGateOf(PmCbor.gateOf(0x00), noTransport = true))
        assertEquals("NeedBinding", PmCbor.statusName(0x05))
        assertEquals("PresenceRequired", PmCbor.statusName(0x01))
        assertEquals("PinRequired", PmCbor.statusName(0x02))
    }

    @Test
    fun opaque_handles_carry_no_invented_labels() {
        val id = byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0x01, 0x02)
        val label = PmCbor.opaqueIdLabel(id)
        assertTrue(label.startsWith("ID "))
        assertTrue(label.contains("abcd"))
        // Short ids render fully; long ids truncate with ellipsis.
        val longId = ByteArray(32) { it.toByte() }
        assertTrue(PmCbor.opaqueIdLabel(longId).contains("…"))
    }

    @Test
    fun status_response_roundtrip() {
        val body = dev.aegiskey.app.data.cbor.SecureGuardCbor.encodeMap(
            linkedMapOf("entry_count" to 3L, "max_entries" to 50L)
        )
        val st = PmCbor.decodeStatusResponse(body)
        assertEquals(3L, st.entryCount)
        assertEquals(50L, st.maxEntries)
    }

    @Test
    fun bottomNav_passwordsDestination_reusesExistingPmRoute() {
        assertEquals(
            AppRoutes.PM,
            dev.aegiskey.app.ui.atomic.templates.HubDestination.PASSWORDS.route,
        )
        assertTrue(
            "NavHost must keep the PM destination registered",
            AppRoutes.ALL.contains(AppRoutes.PM),
        )
    }
}
