package dev.aegiskey.app.approval

/**
 * Wallet approval gate — app side of the F6 headless-board contract.
 *
 * The firmware exposes the pending preview (opcode `0x4B`: slot, tx hash,
 * input/output counts) and signs only with the explicit approval receipt
 * (`approve` bytes on tag `0x0C`) behind binding → UP → PIN. This object is
 * the single point that turns an owner decision into receipt bytes:
 * - the in-app screen shows [PendingDetails] (display-only, never secret);
 * - a notification signal ([ApprovalNotifications]) only points at the open
 *   app, carrying the opaque handle, never details;
 * - [receiptFor] emits the `approve` receipt ONLY when the full
 *   [ApprovalSignal.evaluateApprove] gate allows AND the in-app biometric
 *   ([dev.aegiskey.app.security.BiometricGate]) succeeded. Anything else —
 *   deny, expired/tampered handle, missing session, background app, failed
 *   biometry — yields the explicit `deny` receipt or nothing, never an
 *   `approve`.
 *
 * Wiring (callers, not this object): on user approve, run
 * `BiometricGate.authenticate(activity, cryptoObject)`; on
 * `BiometricGate.Result.Success` call [receiptFor] with `biometricOk =
 * true` and send the bytes on the sign envelope. On deny (or any failure)
 * send [RECEIPT_DENY] or nothing — both deny device-side. A bare
 * notification tap can never approve ([ApprovalActionReceiver] denies).
 *
 * Pure JVM (no `android.*` imports) so it is unit-testable like
 * [ApprovalSignal]. No core crates are imported: every state is translated
 * from already-observed app state.
 */
object WalletApprovalGate {

    /** Wire receipt sent after an in-app biometric approve. */
    val RECEIPT_APPROVE: ByteArray = "approve".toByteArray(Charsets.UTF_8)

    /** Wire receipt for an explicit deny (also denies device-side). */
    val RECEIPT_DENY: ByteArray = "deny".toByteArray(Charsets.UTF_8)

    /** Owner decision on the displayed pending transaction. */
    enum class Decision {
        APPROVE,
        DENY,
    }

    /**
     * Display-only pending details from the `0x4B` preview. Public
     * metadata (slot, digest commitment, counts) — never secrets, never
     * amounts. Rendered in the open app, never in the notification.
     */
    data class PendingDetails(
        val slot: Int,
        val txHashHex: String,
        val inputs: Int,
        val outputs: Int,
    )

    /** Strict display shape: slot byte (`0..31`), 64-hex digest, counts. */
    fun isWellFormed(details: PendingDetails?): Boolean {
        if (details == null) return false
        if (details.slot !in 0..31) return false
        if (!details.txHashHex.matches(Regex("[0-9a-f]{64}"))) return false
        if (details.inputs < 0 || details.outputs < 0) return false
        return true
    }

    /**
     * Receipt bytes for `decision`, gated on the live approval signal and
     * the in-app biometric.
     *
     * - DENY always yields [RECEIPT_DENY] (safe to withdraw, no session
     *   needed — withdrawing a stale approval is always safe).
     * - APPROVE yields [RECEIPT_APPROVE] only when the details are
     *   well-formed, [ApprovalSignal.evaluateApprove] allows (fresh,
     *   untampered, session + transport + foreground), and `biometricOk`
     *   is true. Otherwise null: the app sends nothing, never a forged
     *   approve.
     */
    fun receiptFor(
        details: PendingDetails?,
        request: ApprovalSignal.Request?,
        snapshot: ApprovalSignal.GateSnapshot,
        decision: Decision,
        biometricOk: Boolean,
        nowMs: Long,
    ): ByteArray? {
        return when (decision) {
            Decision.DENY -> RECEIPT_DENY.copyOf()
            Decision.APPROVE -> {
                if (!isWellFormed(details)) return null
                val allowed = ApprovalSignal.evaluateApprove(request, snapshot, nowMs).allowed
                if (!allowed || !biometricOk) null else RECEIPT_APPROVE.copyOf()
            }
        }
    }
}
