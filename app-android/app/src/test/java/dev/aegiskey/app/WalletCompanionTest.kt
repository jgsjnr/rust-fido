package dev.aegiskey.app

import dev.aegiskey.app.approval.ApprovalSignal
import dev.aegiskey.app.approval.WalletApprovalGate
import dev.aegiskey.app.approval.WalletApprovalGate.Decision
import dev.aegiskey.app.approval.WalletCompanion
import dev.aegiskey.app.approval.WalletCompanion.PendingPreview
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Wallet companion vocabulary (F7, app-android only, no board, no push).
 *
 * - Companion opcodes mirror the SDK facade (`0x49` xpub, `0x4A` PSBT,
 *   `0x4B` preview); frozen `0x35`-`0x37` and derivation `0x48` are device
 *   flows, not companion round-trips.
 * - Only PSBT requires app-mediated approval; the preview never does.
 * - Malformed previews deny; approve without biometry sends nothing.
 */
class WalletCompanionTest {

    private val t0 = 1_700_000_000_000L

    private fun idBytes(seed: Int = 7): ByteArray =
        ByteArray(ApprovalSignal.ID_BYTES) { i -> (seed + i * 31).toByte() }

    private fun request(
        kind: ApprovalSignal.Kind = ApprovalSignal.Kind.WALLET_SIGN,
        seed: Int = 7,
    ): ApprovalSignal.Request =
        ApprovalSignal.newRequest(kind, t0, ApprovalSignal.DEFAULT_TTL_MS, idBytes(seed))

    private fun preview() = PendingPreview(
        slot = 3,
        txHashHex = "ab".repeat(32),
        inputs = 1,
        outputs = 2,
    )

    private fun openSnapshot() = ApprovalSignal.GateSnapshot(
        notificationsEnabled = true,
        sessionUnlocked = true,
        appForeground = true,
        biometricOk = true,
        transportAlive = true,
    )

    @Test
    fun companion_opcodes_match_sdk_facade() {
        assertEquals(0x49, WalletCompanion.OP_XPUB)
        assertEquals(0x4A, WalletCompanion.OP_PSBT)
        assertEquals(0x4B, WalletCompanion.OP_PENDING)
        assertArrayEquals(
            intArrayOf(0x49, 0x4A, 0x4B),
            WalletCompanion.COMPANION_OPS,
        )
        for (op in WalletCompanion.COMPANION_OPS) {
            assertTrue(WalletCompanion.isCompanionOpcode(op))
        }
        for (op in intArrayOf(0x00, 0x35, 0x36, 0x37, 0x48, 0x4C)) {
            assertFalse(WalletCompanion.isCompanionOpcode(op))
        }
        assertEquals(32, WalletCompanion.MAX_SLOTS)
        assertEquals(512, WalletCompanion.PSBT_MAX_BYTES)
    }

    @Test
    fun only_psbt_requires_app_mediated_approval() {
        assertTrue(WalletCompanion.requiresAppApproval(WalletCompanion.OP_PSBT))
        assertFalse(WalletCompanion.requiresAppApproval(WalletCompanion.OP_PENDING))
        assertFalse(WalletCompanion.requiresAppApproval(WalletCompanion.OP_XPUB))
    }

    @Test
    fun malformed_previews_are_rejected() {
        assertTrue(WalletCompanion.isWellFormed(preview()))
        assertFalse(WalletCompanion.isWellFormed(null))
        assertFalse(WalletCompanion.isWellFormed(preview().copy(slot = 32)))
        assertFalse(WalletCompanion.isWellFormed(preview().copy(txHashHex = "AB".repeat(32))))
        assertFalse(WalletCompanion.isWellFormed(preview().copy(txHashHex = "ab".repeat(31))))
        assertFalse(WalletCompanion.isWellFormed(preview().copy(inputs = -1)))
    }

    @Test
    fun receipt_flows_through_the_approval_gate() {
        val ok = WalletCompanion.receiptFor(
            preview(), request(), openSnapshot(), Decision.APPROVE, true, t0 + 1_000L,
        )
        assertArrayEquals("approve".toByteArray(), ok)
        assertNull(
            WalletCompanion.receiptFor(
                preview(), request(), openSnapshot(), Decision.APPROVE, false, t0 + 1_000L,
            ),
        )
        assertNull(
            WalletCompanion.receiptFor(
                preview().copy(slot = 32), request(), openSnapshot(),
                Decision.APPROVE, true, t0 + 1_000L,
            ),
        )
        val deny = WalletCompanion.receiptFor(
            preview(), request(), openSnapshot(), Decision.DENY, false, t0 + 1_000L,
        )
        assertArrayEquals("deny".toByteArray(), deny)
        // The companion gate agrees with the underlying approval gate shape.
        assertTrue(WalletApprovalGate.isWellFormed(null).not())
    }
}
