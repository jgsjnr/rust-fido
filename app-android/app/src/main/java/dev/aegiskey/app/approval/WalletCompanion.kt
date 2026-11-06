package dev.aegiskey.app.approval

/**
 * Wallet companion vocabulary — Android side of the F7 facade-first contract.
 *
 * Thin pure-JVM mirror over the `universal-device-sdk` companion surface:
 * the app never frames TLV, never derives keys and never signs. It only
 * validates display shapes, names the companion opcodes, and routes the
 * approve/deny decision through [WalletApprovalGate] (which itself gates on
 * [ApprovalSignal] plus the in-app biometric). TLV framing and transport
 * stay in the Rust SDK + bridge passthrough; every constant below is a
 * documented copy with a parity test in `WalletCompanionTest`.
 *
 * No `android.*` imports, so this object is unit-testable.
 */
object WalletCompanion {

    /** Watch-only xpub export opcode (SDK `WALLET_OP_XPUB`). */
    const val OP_XPUB: Int = 0x49

    /** PSBT signing opcode (SDK `WALLET_OP_PSBT`; needs app-mediated approval). */
    const val OP_PSBT: Int = 0x4A

    /** Pending-preview opcode (SDK `WALLET_OP_PENDING`; display first). */
    const val OP_PENDING: Int = 0x4B

    /** Companion round-trip opcodes (xpub watch-only + PSBT sign + preview). */
    val COMPANION_OPS: IntArray = intArrayOf(OP_XPUB, OP_PSBT, OP_PENDING)

    /** Wallet slots addressable by companions (firmware `WalletStore`). */
    const val MAX_SLOTS: Int = 32

    /** Max PSBT bytes per companion envelope (bridge transport ceiling). */
    const val PSBT_MAX_BYTES: Int = 512

    /**
     * Display-only pending preview (public metadata — never secrets).
     * Rendered in the open app, never in the notification (which carries
     * only the opaque [ApprovalSignal] handle).
     */
    data class PendingPreview(
        val slot: Int,
        val txHashHex: String,
        val inputs: Int,
        val outputs: Int,
    )

    /** True for the F7 companion round-trip surface (xpub/PSBT/preview). */
    fun isCompanionOpcode(op: Int): Boolean =
        op == OP_XPUB || op == OP_PSBT || op == OP_PENDING

    /** True only for PSBT signing (the preview never needs approval). */
    fun requiresAppApproval(op: Int): Boolean = op == OP_PSBT

    /** Strict display shape: slot `0..32`, 64 lowercase hex, counts. */
    fun isWellFormed(preview: PendingPreview?): Boolean {
        if (preview == null) return false
        if (preview.slot !in 0 until MAX_SLOTS) return false
        if (!preview.txHashHex.matches(Regex("[0-9a-f]{64}"))) return false
        if (preview.inputs < 0 || preview.outputs < 0) return false
        return true
    }

    /**
     * Receipt bytes for `decision`, gated on the live approval signal and
     * the in-app biometric (delegates to [WalletApprovalGate.receiptFor]).
     * Approve without biometry/session/foreground/transport yields null —
     * the app sends nothing, never a forged approve.
     */
    fun receiptFor(
        preview: PendingPreview?,
        request: ApprovalSignal.Request?,
        snapshot: ApprovalSignal.GateSnapshot,
        decision: WalletApprovalGate.Decision,
        biometricOk: Boolean,
        nowMs: Long,
    ): ByteArray? {
        val details = preview?.let {
            WalletApprovalGate.PendingDetails(
                slot = it.slot,
                txHashHex = it.txHashHex,
                inputs = it.inputs,
                outputs = it.outputs,
            )
        }
        return WalletApprovalGate.receiptFor(details, request, snapshot, decision, biometricOk, nowMs)
    }
}
