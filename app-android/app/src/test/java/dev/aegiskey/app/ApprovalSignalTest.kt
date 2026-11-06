package dev.aegiskey.app

import dev.aegiskey.app.approval.ApprovalSignal
import dev.aegiskey.app.approval.ApprovalSignal.Action
import dev.aegiskey.app.approval.ApprovalSignal.DenyReason
import dev.aegiskey.app.approval.ApprovalSignal.GateSnapshot
import dev.aegiskey.app.approval.ApprovalSignal.Kind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * App-mediated approval signals (app-android only, no board, no push).
 *
 * - Approve demands the full gate: session + transport + foreground +
 *   biometry, fresh and untampered. Anything else denies (fail-closed).
 * - Notification actions route through the same gate; explicit deny is
 *   always safe, even for stale/tampered/unknown handles.
 * - The signal payload carries no values, secrets or details: exact key
 *   whitelist with strict value shapes.
 */
class ApprovalSignalTest {

    private val t0 = 1_700_000_000_000L

    private fun idBytes(seed: Int = 7): ByteArray =
        ByteArray(ApprovalSignal.ID_BYTES) { i -> (seed + i * 31).toByte() }

    private fun request(
        kind: Kind = Kind.WALLET_SIGN,
        nowMs: Long = t0,
        ttlMs: Long = ApprovalSignal.DEFAULT_TTL_MS,
        seed: Int = 7,
    ) = ApprovalSignal.newRequest(kind, nowMs, ttlMs, idBytes(seed))

    private fun openSnapshot() = GateSnapshot(
        notificationsEnabled = true,
        sessionUnlocked = true,
        appForeground = true,
        biometricOk = true,
        transportAlive = true,
    )

    // --- Full gate --------------------------------------------------------

    @Test
    fun approve_allowed_whenFullGate() {
        val req = request()
        val decision = ApprovalSignal.evaluateApprove(req, openSnapshot(), t0 + 1_000L)
        assertTrue(decision.allowed)
        assertEquals(null, decision.reason)
    }

    @Test
    fun approve_denied_withoutSession_failClosed() {
        val req = request()
        val decision = ApprovalSignal.evaluateApprove(
            req,
            openSnapshot().copy(sessionUnlocked = false),
            t0 + 1_000L,
        )
        assertFalse(decision.allowed)
        assertEquals(DenyReason.NO_SESSION, decision.reason)
    }

    @Test
    fun approve_denied_whenBackground() {
        val req = request()
        val decision = ApprovalSignal.evaluateApprove(
            req,
            openSnapshot().copy(appForeground = false),
            t0 + 1_000L,
        )
        assertFalse(decision.allowed)
        assertEquals(DenyReason.APP_BACKGROUND, decision.reason)
    }

    @Test
    fun approve_denied_withoutBiometric() {
        val req = request()
        val decision = ApprovalSignal.evaluateApprove(
            req,
            openSnapshot().copy(biometricOk = false),
            t0 + 1_000L,
        )
        assertFalse(decision.allowed)
        assertEquals(DenyReason.BIOMETRIC, decision.reason)
    }

    @Test
    fun approve_denied_onTransportLoss() {
        val req = request()
        val decision = ApprovalSignal.evaluateApprove(
            req,
            openSnapshot().copy(transportAlive = false),
            t0 + 1_000L,
        )
        assertFalse(decision.allowed)
        assertEquals(DenyReason.TRANSPORT_LOST, decision.reason)
    }

    @Test
    fun approve_denied_whenExpired_timeoutAutoDenies() {
        val req = request(ttlMs = 1_000L)
        assertTrue(ApprovalSignal.isExpired(req, t0 + 1_000L))
        val decision = ApprovalSignal.evaluateApprove(req, openSnapshot(), t0 + 60_000L)
        assertFalse(decision.allowed)
        assertEquals(DenyReason.TIMEOUT, decision.reason)
    }

    @Test
    fun approve_denied_onTamper_mutatedExpiry() {
        val req = request().copy(expiresAtMs = t0 + ApprovalSignal.MAX_TTL_MS)
        assertFalse(ApprovalSignal.verifyBinding(req))
        val decision = ApprovalSignal.evaluateApprove(req, openSnapshot(), t0 + 1_000L)
        assertFalse(decision.allowed)
        assertEquals(DenyReason.TAMPER, decision.reason)
    }

    @Test
    fun approve_denied_onTamper_swappedKind() {
        val req = request(kind = Kind.WALLET_SIGN).copy(kind = Kind.SENSITIVE_RELEASE)
        assertFalse(ApprovalSignal.verifyBinding(req))
        val decision = ApprovalSignal.evaluateApprove(req, openSnapshot(), t0 + 1_000L)
        assertFalse(decision.allowed)
        assertEquals(DenyReason.TAMPER, decision.reason)
    }

    @Test
    fun approve_denied_onTamper_badBinding() {
        val req = request().copy(bindingHex = "0".repeat(64))
        assertFalse(ApprovalSignal.verifyBinding(req))
        val decision = ApprovalSignal.evaluateApprove(req, openSnapshot(), t0 + 1_000L)
        assertFalse(decision.allowed)
        assertEquals(DenyReason.TAMPER, decision.reason)
    }

    @Test
    fun approve_denied_onUnknownRequest() {
        val decision = ApprovalSignal.evaluateApprove(null, openSnapshot(), t0)
        assertFalse(decision.allowed)
        assertEquals(DenyReason.TAMPER, decision.reason)
    }

    // --- Notification actions: same gate ------------------------------------

    @Test
    fun routeAction_approve_matchesFullGate() {
        val req = request()
        val viaRoute = ApprovalSignal.routeAction(Action.APPROVE, req, openSnapshot(), t0 + 1_000L)
        assertTrue(viaRoute.allowed)
        val locked = ApprovalSignal.routeAction(
            Action.APPROVE,
            req,
            openSnapshot().copy(sessionUnlocked = false),
            t0 + 1_000L,
        )
        assertFalse(locked.allowed)
        assertEquals(DenyReason.NO_SESSION, locked.reason)
    }

    @Test
    fun routeAction_approve_deniedWhenToggleOff() {
        val req = request()
        val decision = ApprovalSignal.routeAction(
            Action.APPROVE,
            req,
            openSnapshot().copy(notificationsEnabled = false),
            t0 + 1_000L,
        )
        assertFalse(decision.allowed)
        assertEquals(DenyReason.DISABLED, decision.reason)
    }

    @Test
    fun routeAction_deny_alwaysAllowed_explicitDeny() {
        val expired = request(ttlMs = 1L)
        val tampered = request().copy(bindingHex = "ab".repeat(32))
        val denied = GateSnapshot(false, false, false, false, false)
        assertTrue(ApprovalSignal.routeAction(Action.DENY, expired, denied, t0 + 60_000L).allowed)
        assertTrue(ApprovalSignal.routeAction(Action.DENY, tampered, denied, t0).allowed)
        assertTrue(ApprovalSignal.routeAction(Action.DENY, null, denied, t0).allowed)
    }

    // --- Signal-only payload: no leak ---------------------------------------

    @Test
    fun signalPayload_isSignalOnly_exactKeys() {
        val req = request()
        val payload = ApprovalSignal.signalPayload(req)
        assertEquals(setOf("id", "kind", "expires_at"), payload.keys)
        assertTrue(ApprovalSignal.isSignalOnly(payload))
    }

    @Test
    fun signalPayload_rejectsLeakyExtras() {
        val leaky = ApprovalSignal.signalPayload(request()) + mapOf(
            "amount" to "0.5 ETH",
            "to" to "0x1234567890abcdef1234567890abcdef12345678",
            "label" to "Savings",
        )
        assertFalse(ApprovalSignal.isSignalOnly(leaky))
        assertFalse(ApprovalSignal.isSignalOnly(mapOf("id" to "x")))
        assertFalse(ApprovalSignal.isSignalOnly(emptyMap()))
    }

    @Test
    fun signalPayload_rejectsMalformedValues() {
        val base = ApprovalSignal.signalPayload(request())
        assertFalse(ApprovalSignal.isSignalOnly(base + mapOf("id" to "NOT-HEX!!")))
        assertFalse(ApprovalSignal.isSignalOnly(base + mapOf("kind" to "AMOUNT")))
        assertFalse(ApprovalSignal.isSignalOnly(base + mapOf("expires_at" to "soon")))
    }

    // --- Binding + ttl bounds -------------------------------------------------

    @Test
    fun binding_deterministicAndExpiryBound() {
        val a = request(seed = 7)
        val b = request(seed = 7)
        assertEquals(a.bindingHex, b.bindingHex)
        assertTrue(ApprovalSignal.verifyBinding(a))
        val other = request(seed = 8)
        assertTrue(a.idHex != other.idHex)
        assertTrue(a.bindingHex != other.bindingHex)
    }

    @Test
    fun newRequest_clampsTtl() {
        val huge = request(ttlMs = Long.MAX_VALUE)
        assertEquals(t0 + ApprovalSignal.MAX_TTL_MS, huge.expiresAtMs)
        val zero = request(ttlMs = 0L)
        assertEquals(t0 + 1L, zero.expiresAtMs)
    }
}
