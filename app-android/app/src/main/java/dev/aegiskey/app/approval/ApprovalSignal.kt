package dev.aegiskey.app.approval

import java.security.MessageDigest
import java.security.SecureRandom

/**
 * App-mediated approval signals — single entrypoint of the approval module.
 *
 * Scope (app-android only, no board, no push): local notifications that only
 * *signal* a pending app-mediated confirmation (e.g. wallet signature,
 * sensitive release). The notification never carries values, secrets, labels,
 * amounts, addresses or any sensitive detail — title and body resolve through
 * `strings.xml` (EN + values-pt) with no interpolation.
 *
 * Approval itself never happens here. Approving demands the full in-app gate
 * evaluated by [evaluateApprove]:
 * - app open ([GateSnapshot.appForeground]),
 * - session unlocked ([GateSnapshot.sessionUnlocked], the RAM-only Secure
 *   Guard session PIN — [dev.aegiskey.app.data.repository.SecureGuardRepositoryImpl.isSessionPinValid]),
 * - biometrics ([GateSnapshot.biometricOk], via
 *   [dev.aegiskey.app.security.BiometricGate] in the open app).
 *
 * Fail-closed denials (explicit deny, timeout, lock/transport loss) all
 * converge to [DenyReason]; any divergence (unknown request, bad binding,
 * mutated field) is tamper and denies. Notification actions
 * ([Action.APPROVE]/[Action.DENY]) route through the same gate via
 * [routeAction]: explicit deny is always safe, approve re-checks everything.
 * A bare notification tap can never approve — a [android.content.BroadcastReceiver]
 * observes no foreground activity and runs no biometry, so its approve path
 * always denies and opens the app for the real in-app gate.
 *
 * Tamper evidence: [bindingHex] is SHA-256 over `id|kind|expiresAtMs`. The
 * signal payload carries exactly those three fields ([signalPayload]); any
 * extra key or malformed value fails [isSignalOnly] and any mutation fails
 * [verifyBinding].
 *
 * This object is pure JVM (no `android.*` imports) so it is unit-testable.
 * Android glue lives in [ApprovalNotifications], [ApprovalActionReceiver]
 * and [ApprovalPrefs] inside this same folder. No core crates are imported:
 * every state is translated from already-observed app state.
 */
object ApprovalSignal {

    /** Dedicated channel id (created by [ApprovalNotifications.ensureChannel]). */
    const val CHANNEL_ID = "aegis_approval"

    /** Notification action names (also declared in the manifest receiver). */
    const val ACTION_APPROVE = "dev.aegiskey.app.approval.APPROVE"
    const val ACTION_DENY = "dev.aegiskey.app.approval.DENY"

    /** Intent extras — opaque handle only, never values or secrets. */
    const val EXTRA_REQUEST_ID = "dev.aegiskey.app.approval.REQUEST_ID"
    const val EXTRA_KIND = "dev.aegiskey.app.approval.KIND"
    const val EXTRA_EXPIRES_AT_MS = "dev.aegiskey.app.approval.EXPIRES_AT_MS"
    const val EXTRA_BINDING_HEX = "dev.aegiskey.app.approval.BINDING_HEX"

    /** Default signal lifetime; bounded by [MAX_TTL_MS]. */
    const val DEFAULT_TTL_MS = 120_000L

    /** Upper bound for any signal lifetime (fail-closed, no lingering approvals). */
    const val MAX_TTL_MS = 300_000L

    /** Opaque request handle size (128-bit TRNG, hex-encoded, non-secret). */
    const val ID_BYTES = 16

    /** Generic confirmation families. Labels only — never details. */
    enum class Kind {
        WALLET_SIGN,
        SENSITIVE_RELEASE,
    }

    /** Notification actions, both routed through [routeAction]. */
    enum class Action {
        APPROVE,
        DENY,
    }

    /** Every denial names its cause. No silent paths. */
    enum class DenyReason {
        DISABLED,
        NO_SESSION,
        APP_BACKGROUND,
        BIOMETRIC,
        TIMEOUT,
        TRANSPORT_LOST,
        TAMPER,
    }

    /**
     * Pending approval handle. Carries no values, labels, amounts, addresses
     * or secrets — only the opaque [idHex], the generic [kind] and the expiry.
     */
    data class Request(
        val idHex: String,
        val kind: Kind,
        val createdAtMs: Long,
        val expiresAtMs: Long,
        val bindingHex: String,
    )

    /**
     * Already-observed gate inputs. `null`/unknown upstream always maps to
     * `false` by the caller — unknown never approves.
     */
    data class GateSnapshot(
        val notificationsEnabled: Boolean,
        val sessionUnlocked: Boolean,
        val appForeground: Boolean,
        val biometricOk: Boolean,
        val transportAlive: Boolean,
    )

    /** Structured outcome. Screens/notifications render fixed strings. */
    data class Decision(
        val allowed: Boolean,
        val reason: DenyReason?,
    )

    /** 128-bit TRNG handle bytes (hex-encoded by [newRequest]). */
    fun randomIdBytes(): ByteArray =
        ByteArray(ID_BYTES).also { SecureRandom().nextBytes(it) }

    /**
     * Creates a pending approval handle. [ttlMs] is clamped to
     * `1..[MAX_TTL_MS]`; [idBytes] must be exactly [ID_BYTES].
     */
    fun newRequest(
        kind: Kind,
        nowMs: Long,
        ttlMs: Long = DEFAULT_TTL_MS,
        idBytes: ByteArray = randomIdBytes(),
    ): Request {
        require(idBytes.size == ID_BYTES) { "id fora de 16 B" }
        val ttl = ttlMs.coerceIn(1L, MAX_TTL_MS)
        val idHex = idBytes.toHex()
        val expiresAtMs = nowMs + ttl
        return Request(
            idHex = idHex,
            kind = kind,
            createdAtMs = nowMs,
            expiresAtMs = expiresAtMs,
            bindingHex = bindingFor(idHex, kind, expiresAtMs),
        )
    }

    /** Tamper-evident binding over the full handle (`id|kind|expiresAtMs`). */
    fun bindingFor(idHex: String, kind: Kind, expiresAtMs: Long): String =
        sha256Hex("$idHex|${kind.name}|$expiresAtMs")

    /** Strict handle shape: 32 lowercase hex chars and a forward expiry. */
    fun isWellFormed(request: Request?): Boolean {
        if (request == null) return false
        if (!request.idHex.matches(Regex("[0-9a-f]{32}"))) return false
        if (request.bindingHex.isEmpty() || request.bindingHex.length > 64) return false
        if (!request.bindingHex.matches(Regex("[0-9a-f]{64}"))) return false
        return request.expiresAtMs > request.createdAtMs
    }

    /**
     * Recomputes the binding (constant-time compare). Any divergence —
     * mutated id, kind, expiry or binding — fails. Unknown/malformed fails.
     */
    fun verifyBinding(request: Request?): Boolean {
        if (!isWellFormed(request)) return false
        request as Request
        val expect = bindingFor(request.idHex, request.kind, request.expiresAtMs)
        return MessageDigest.isEqual(
            expect.toByteArray(Charsets.UTF_8),
            request.bindingHex.toByteArray(Charsets.UTF_8),
        )
    }

    /** Expiry check. Expired approvals auto-deny, never approve. */
    fun isExpired(request: Request, nowMs: Long): Boolean =
        nowMs >= request.expiresAtMs

    /**
     * Full in-app approve gate. Check order (first match names the reason):
     * tamper, timeout, session, transport, foreground, biometry. The Settings
     * toggle is NOT consulted here: it gates only the *signal*, never the
     * approval itself.
     */
    fun evaluateApprove(
        request: Request?,
        snapshot: GateSnapshot,
        nowMs: Long,
    ): Decision {
        if (!verifyBinding(request)) return Decision(false, DenyReason.TAMPER)
        request as Request
        if (isExpired(request, nowMs)) return Decision(false, DenyReason.TIMEOUT)
        if (!snapshot.sessionUnlocked) return Decision(false, DenyReason.NO_SESSION)
        if (!snapshot.transportAlive) return Decision(false, DenyReason.TRANSPORT_LOST)
        if (!snapshot.appForeground) return Decision(false, DenyReason.APP_BACKGROUND)
        if (!snapshot.biometricOk) return Decision(false, DenyReason.BIOMETRIC)
        return Decision(true, null)
    }

    /**
     * Routes a notification action through the same gate. Explicit deny is
     * always safe (allowed even for expired/tampered/unknown handles, so a
     * stale notification can always be withdrawn). Approve additionally
     * requires the signal toggle — a disabled channel carries no live
     * actions — then the full [evaluateApprove] gate.
     */
    fun routeAction(
        action: Action,
        request: Request?,
        snapshot: GateSnapshot,
        nowMs: Long,
    ): Decision =
        when (action) {
            Action.DENY -> Decision(true, null)
            Action.APPROVE -> {
                if (!snapshot.notificationsEnabled) Decision(false, DenyReason.DISABLED)
                else evaluateApprove(request, snapshot, nowMs)
            }
        }

    /**
     * Signal-only payload: exactly `id`, `kind`, `expires_at`. By
     * construction there is no field for values, labels, amounts, addresses
     * or secrets — nothing sensitive can ride the notification.
     */
    fun signalPayload(request: Request): Map<String, String> =
        mapOf(
            "id" to request.idHex,
            "kind" to request.kind.name,
            "expires_at" to request.expiresAtMs.toString(),
        )

    /**
     * Leak guard: true only for exactly the three signal keys with strict
     * value shapes (32-hex id, known kind name, digit expiry). Anything else
     * — extra keys, free text, amounts, addresses — fails.
     */
    fun isSignalOnly(payload: Map<String, String>): Boolean {
        if (payload.keys != setOf("id", "kind", "expires_at")) return false
        val id = payload.getValue("id")
        val kind = payload.getValue("kind")
        val expires = payload.getValue("expires_at")
        if (!id.matches(Regex("[0-9a-f]{32}"))) return false
        if (Kind.entries.none { it.name == kind }) return false
        if (!expires.matches(Regex("[0-9]+"))) return false
        return true
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02x".format(it) }

    private fun sha256Hex(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(input.toByteArray(Charsets.UTF_8)).toHex()
    }
}
