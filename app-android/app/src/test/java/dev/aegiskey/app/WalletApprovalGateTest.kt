package dev.aegiskey.app

import dev.aegiskey.app.approval.ApprovalSignal
import dev.aegiskey.app.approval.WalletApprovalGate
import dev.aegiskey.app.approval.WalletApprovalGate.Decision
import dev.aegiskey.app.approval.WalletApprovalGate.PendingDetails
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Wallet approval gate (F6, app-android only, no board, no push).
 *
 * - The receipt is sent only after an in-app biometric approve: approve
 *   without biometry (or without session/foreground/transport, expired or
 *   tampered handle, malformed details) yields nothing — never a forged
 *   `approve`.
 * - Deny always yields the explicit `deny` receipt (safe to withdraw).
 * - Tamper (mutated handle, wrong details shape) denies.
 */
class WalletApprovalGateTest {

    private val t0 = 1_700_000_000_000L

    private fun idBytes(seed: Int = 7): ByteArray =
        ByteArray(ApprovalSignal.ID_BYTES) { i -> (seed + i * 31).toByte() }

    private fun request(
        kind: ApprovalSignal.Kind = ApprovalSignal.Kind.WALLET_SIGN,
        seed: Int = 7,
    ): ApprovalSignal.Request =
        ApprovalSignal.newRequest(kind, t0, ApprovalSignal.DEFAULT_TTL_MS, idBytes(seed))

    private fun details() = PendingDetails(
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
    fun approve_with_live_biometric_sends_approve_receipt() {
        val receipt = WalletApprovalGate.receiptFor(
            details(), request(), openSnapshot(), Decision.APPROVE, true, t0 + 1_000L,
        )
        assertArrayEquals("approve".toByteArray(), receipt)
    }

    @Test
    fun approve_without_biometry_sends_nothing() {
        assertNull(
            WalletApprovalGate.receiptFor(
                details(), request(), openSnapshot(), Decision.APPROVE, false, t0 + 1_000L,
            ),
        )
    }

    @Test
    fun approve_without_session_or_foreground_sends_nothing() {
        assertNull(
            WalletApprovalGate.receiptFor(
                details(), request(), openSnapshot().copy(sessionUnlocked = false),
                Decision.APPROVE, true, t0 + 1_000L,
            ),
        )
        assertNull(
            WalletApprovalGate.receiptFor(
                details(), request(), openSnapshot().copy(appForeground = false),
                Decision.APPROVE, true, t0 + 1_000L,
            ),
        )
        assertNull(
            WalletApprovalGate.receiptFor(
                details(), request(), openSnapshot().copy(transportAlive = false),
                Decision.APPROVE, true, t0 + 1_000L,
            ),
        )
    }

    @Test
    fun approve_on_expired_or_tampered_handle_sends_nothing() {
        val expired = request()
        assertNull(
            WalletApprovalGate.receiptFor(
                details(), expired, openSnapshot(), Decision.APPROVE, true, t0 + 600_000L,
            ),
        )
        val tampered = request().copy(idHex = "00".repeat(16))
        assertNull(
            WalletApprovalGate.receiptFor(
                details(), tampered, openSnapshot(), Decision.APPROVE, true, t0 + 1_000L,
            ),
        )
        assertNull(
            WalletApprovalGate.receiptFor(
                details(), null, openSnapshot(), Decision.APPROVE, true, t0 + 1_000L,
            ),
        )
    }

    @Test
    fun approve_on_malformed_details_sends_nothing() {
        assertNull(
            WalletApprovalGate.receiptFor(
                null, request(), openSnapshot(), Decision.APPROVE, true, t0 + 1_000L,
            ),
        )
        assertNull(
            WalletApprovalGate.receiptFor(
                details().copy(txHashHex = "NOT-HEX"), request(), openSnapshot(),
                Decision.APPROVE, true, t0 + 1_000L,
            ),
        )
        assertNull(
            WalletApprovalGate.receiptFor(
                details().copy(slot = 32), request(), openSnapshot(),
                Decision.APPROVE, true, t0 + 1_000L,
            ),
        )
        assertTrue(WalletApprovalGate.isWellFormed(details()))
        assertFalse(WalletApprovalGate.isWellFormed(null))
    }

    @Test
    fun deny_always_sends_deny_receipt() {
        assertArrayEquals(
            "deny".toByteArray(),
            WalletApprovalGate.receiptFor(
                details(), request(), openSnapshot(), Decision.DENY, true, t0 + 1_000L,
            ),
        )
        // Even stale/tampered/unknown handles stay safe to withdraw.
        assertArrayEquals(
            "deny".toByteArray(),
            WalletApprovalGate.receiptFor(
                null, null, openSnapshot(), Decision.DENY, false, t0 + 600_000L,
            ),
        )
    }

    @Test
    fun receipts_match_firmware_vocabulary() {
        assertEquals("approve", String(WalletApprovalGate.RECEIPT_APPROVE, Charsets.UTF_8))
        assertEquals("deny", String(WalletApprovalGate.RECEIPT_DENY, Charsets.UTF_8))
    }
}
