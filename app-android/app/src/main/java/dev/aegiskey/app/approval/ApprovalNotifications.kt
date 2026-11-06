package dev.aegiskey.app.approval

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import dev.aegiskey.app.MainActivity
import dev.aegiskey.app.R

/**
 * Android glue for approval signals (channel + signal-only notifications).
 *
 * Signal-only contract: title, body and action labels resolve through
 * `strings.xml` (EN + values-pt) with no interpolation of request data. The
 * opaque handle ([ApprovalSignal.Request.idHex]) travels only inside
 * PendingIntent extras so the app can correlate the tap — it is never
 * rendered, never logged, never placed in notification text.
 *
 * Posting additionally requires the Settings master switch
 * ([ApprovalPrefs], default off) AND the runtime `POST_NOTIFICATIONS`
 * grant on API 33+. Suppressed posts return -1 and change nothing.
 *
 * Auto-deny: [cancel]/[onSessionLost] withdraw the signal (lock, timeout,
 * transport loss); the approval itself stays denied via
 * [ApprovalSignal.evaluateApprove] (no session, no approval).
 */
object ApprovalNotifications {

    /** Stable notification id per request handle. */
    fun notificationId(request: ApprovalSignal.Request): Int =
        request.idHex.hashCode()

    /** Creates the dedicated channel (idempotent). Called at app start. */
    fun ensureChannel(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        runCatching {
            val manager = context.getSystemService(NotificationManager::class.java)
                ?: return
            val channel = NotificationChannel(
                ApprovalSignal.CHANNEL_ID,
                context.getString(R.string.approval_channel_name),
                NotificationManager.IMPORTANCE_HIGH,
            ).apply {
                description = context.getString(R.string.approval_channel_desc)
            }
            manager.createNotificationChannel(channel)
        }
    }

    /** Runtime post permission (API 33+). Any failure reads as not allowed. */
    fun canPost(context: Context): Boolean =
        try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) true
            else ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
        } catch (_: Throwable) {
            false
        }

    /** Signal may post only with the toggle on AND the runtime grant. */
    fun canSignal(context: Context): Boolean =
        try {
            ApprovalPrefs(context.applicationContext).isEnabled() && canPost(context)
        } catch (_: Throwable) {
            false
        }

    /**
     * Posts the signal-only notification. Returns the notification id, or -1
     * when suppressed (toggle off, no grant, tampered/expired handle) or when
     * posting failed. Never throws.
     */
    fun showSignal(
        context: Context,
        request: ApprovalSignal.Request,
        nowMs: Long = System.currentTimeMillis(),
    ): Int {
        if (!canSignal(context)) return -1
        if (!ApprovalSignal.verifyBinding(request)) return -1
        if (ApprovalSignal.isExpired(request, nowMs)) return -1
        return try {
            ensureChannel(context)
            val remainingMs = (request.expiresAtMs - nowMs).coerceAtLeast(1L)
            val contentIntent = PendingIntent.getActivity(
                context,
                notificationId(request),
                Intent(context, MainActivity::class.java)
                    .putExtra(ApprovalSignal.EXTRA_REQUEST_ID, request.idHex),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
            val notification = NotificationCompat.Builder(context, ApprovalSignal.CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentTitle(context.getString(R.string.approval_title))
                .setContentText(context.getString(R.string.approval_body))
                .setContentIntent(contentIntent)
                .setAutoCancel(true)
                .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
                .setTimeoutAfter(remainingMs)
                .addAction(
                    0,
                    context.getString(R.string.approval_approve),
                    actionIntent(context, ApprovalSignal.ACTION_APPROVE, request),
                )
                .addAction(
                    0,
                    context.getString(R.string.approval_deny),
                    actionIntent(context, ApprovalSignal.ACTION_DENY, request),
                )
                .build()
            val id = notificationId(request)
            context.getSystemService(NotificationManager::class.java)?.notify(id, notification)
            id
        } catch (_: Throwable) {
            -1
        }
    }

    /** Withdraws the signal. Never throws. */
    fun cancel(context: Context, request: ApprovalSignal.Request) {
        runCatching {
            context.getSystemService(NotificationManager::class.java)
                ?.cancel(notificationId(request))
        }
    }

    /**
     * Session lock / transport loss hook: withdraws the signal so no stale
     * action can linger. The approval itself is already denied — without a
     * live session [ApprovalSignal.evaluateApprove] never allows.
     */
    fun onSessionLost(context: Context, request: ApprovalSignal.Request) {
        cancel(context, request)
    }

    private fun actionIntent(
        context: Context,
        action: String,
        request: ApprovalSignal.Request,
    ): PendingIntent {
        val intent = Intent(context.applicationContext, ApprovalActionReceiver::class.java)
            .setAction(action)
            .putExtra(ApprovalSignal.EXTRA_REQUEST_ID, request.idHex)
            .putExtra(ApprovalSignal.EXTRA_KIND, request.kind.name)
            .putExtra(ApprovalSignal.EXTRA_EXPIRES_AT_MS, request.expiresAtMs)
            .putExtra(ApprovalSignal.EXTRA_BINDING_HEX, request.bindingHex)
        val code = notificationId(request) * 31 + action.hashCode()
        return PendingIntent.getBroadcast(
            context,
            code,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }
}
