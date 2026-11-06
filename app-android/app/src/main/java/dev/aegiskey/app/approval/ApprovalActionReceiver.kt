package dev.aegiskey.app.approval

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import dev.aegiskey.app.MainActivity
import dev.aegiskey.app.data.repository.SecureGuardRepositoryImpl
import dev.aegiskey.app.log.DeviceLog

/**
 * Routes notification actions (Aprovar/Negar) through the same gate.
 *
 * A receiver observes no foreground activity and runs no biometry, so both
 * read as `false` fail-closed here (unknown never approves); the live
 * session is probed via
 * [SecureGuardRepositoryImpl.isSessionPinValid] (any failure = locked).
 * Consequences:
 * - APPROVE from a bare notification tap always denies (at minimum
 *   `APP_BACKGROUND`): the signal is withdrawn and the app is opened so the
 *   user can approve in-app with session + biometry. Nothing is approved
 *   from the background, ever.
 * - DENY (explicit deny) always proceeds: the signal is withdrawn and the
 *   pending approval stays denied. No session is needed to deny.
 *
 * Fixed log lines only — the opaque handle is never logged.
 */
class ApprovalActionReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context?, intent: Intent?) {
        if (context == null || intent == null) return
        val appContext = context.applicationContext ?: context
        val request = parseRequest(intent)
        val snapshot = ApprovalSignal.GateSnapshot(
            notificationsEnabled = runCatching {
                ApprovalPrefs(appContext).isEnabled()
            }.getOrDefault(false),
            sessionUnlocked = runCatching {
                SecureGuardRepositoryImpl.isSessionPinValid()
            }.getOrDefault(false),
            // Receiver context is background by construction: approving
            // demands the open app, so a bare tap always denies here.
            appForeground = false,
            // Biometry runs only in the open app via BiometricGate.
            biometricOk = false,
            // Transport liveness is not observable here; fail-closed.
            transportAlive = false,
        )
        when (intent.action) {
            ApprovalSignal.ACTION_APPROVE -> {
                val decision = ApprovalSignal.routeAction(
                    ApprovalSignal.Action.APPROVE,
                    request,
                    snapshot,
                    System.currentTimeMillis(),
                )
                if (request != null) ApprovalNotifications.cancel(appContext, request)
                DeviceLog.append(
                    DeviceLog.Category.SYSTEM,
                    "approval notification approve denied (${decision.reason?.name ?: "UNKNOWN"})",
                )
                // Open the app so the user can approve through the real
                // in-app gate (session + biometry). Never approves here.
                runCatching {
                    val open = Intent(appContext, MainActivity::class.java)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    if (request != null) {
                        open.putExtra(ApprovalSignal.EXTRA_REQUEST_ID, request.idHex)
                    }
                    appContext.startActivity(open)
                }
            }
            ApprovalSignal.ACTION_DENY -> {
                // Explicit deny: always safe, even for stale/unknown handles.
                if (request != null) ApprovalNotifications.cancel(appContext, request)
                DeviceLog.append(DeviceLog.Category.SYSTEM, "approval notification denied")
            }
            else -> Unit
        }
    }

    /**
     * Rebuilds the handle from extras. Unknown kind or malformed extras
     * yield null — routed as tamper on approve, still cancellable on deny.
     */
    private fun parseRequest(intent: Intent): ApprovalSignal.Request? {
        return try {
            val idHex = intent.getStringExtra(ApprovalSignal.EXTRA_REQUEST_ID)
                ?: return null
            val kindName = intent.getStringExtra(ApprovalSignal.EXTRA_KIND)
                ?: return null
            val kind = runCatching {
                ApprovalSignal.Kind.valueOf(kindName)
            }.getOrNull() ?: return null
            if (!intent.hasExtra(ApprovalSignal.EXTRA_EXPIRES_AT_MS)) return null
            val expiresAtMs = intent.getLongExtra(ApprovalSignal.EXTRA_EXPIRES_AT_MS, -1L)
            val bindingHex = intent.getStringExtra(ApprovalSignal.EXTRA_BINDING_HEX)
                ?: return null
            val request = ApprovalSignal.Request(
                idHex = idHex,
                kind = kind,
                createdAtMs = expiresAtMs - ApprovalSignal.DEFAULT_TTL_MS,
                expiresAtMs = expiresAtMs,
                bindingHex = bindingHex,
            )
            // createdAtMs is not carried (not needed for the gate);
            // reconstructed conservatively. Binding verification uses
            // only id|kind|expiry, so this never validates a mutation.
            if (!ApprovalSignal.isWellFormed(request)) return null
            request
        } catch (_: Throwable) {
            null
        }
    }
}
