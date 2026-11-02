package dev.aegiskey.app.ota2

import dev.aegiskey.app.R

/**
 * Offline OTA failure taxonomy. Every user-visible string lives in
 * ota_strings.xml (EN + PT, ASD-STE100 short style, no emoji); the
 * engine only returns these codes, never prose.
 */
sealed interface Ota2Failure {
    /** SDK gate denied OTA (compiled off / no native lib). Nothing staged. */
    data object GateBlocked : Ota2Failure

    /** Manifest not 104 B, zero/over-budget size, or bad current version. */
    data object BadManifest : Ota2Failure

    /** Picked file exceeds the staging budget. Nothing staged. */
    data object Oversize : Ota2Failure

    /** Picked file is empty. */
    data object EmptyImage : Ota2Failure

    /** Client pre-check: signature REJECTED. No wire byte was sent. */
    data object BadSignature : Ota2Failure

    /** Anti-rollback: version 0, equal, or older than device. No wire byte sent. */
    data object Downgrade : Ota2Failure

    /** Client pre-check: image digest differs from manifest sha256. */
    data object ShaMismatch : Ota2Failure

    /** Transport gave no reply. Session offset kept for resume. */
    data object TransportLost : Ota2Failure

    /** Device answered FAIL (order/budget/verify). Session aborted. */
    data object DeviceRejected : Ota2Failure

    /** Device needs a physical button tap. Session kept, retry allowed. */
    data object NeedUp : Ota2Failure

    /** User aborted. Session discarded on both ends. */
    data object Aborted : Ota2Failure
}

/** Transport-layer thrower carrying a taxonomy code (file/size problems are IO-shaped). */
class Ota2Exception(val failure: Ota2Failure) : java.io.IOException(failure.name())

private fun Ota2Failure.name(): String = this::class.simpleName ?: "Ota2Failure"

/** Maps a failure code to its user string (authority: ota_strings.xml). */
fun Ota2Failure.stringRes(): Int = when (this) {
    Ota2Failure.GateBlocked -> R.string.ota2_fail_gate
    Ota2Failure.BadManifest -> R.string.ota2_fail_manifest
    Ota2Failure.Oversize -> R.string.ota2_fail_oversize
    Ota2Failure.EmptyImage -> R.string.ota2_fail_empty
    Ota2Failure.BadSignature -> R.string.ota2_fail_sig
    Ota2Failure.Downgrade -> R.string.ota2_fail_downgrade
    Ota2Failure.ShaMismatch -> R.string.ota2_fail_sha
    Ota2Failure.TransportLost -> R.string.ota2_fail_transport
    Ota2Failure.DeviceRejected -> R.string.ota2_fail_rejected
    Ota2Failure.NeedUp -> R.string.ota2_fail_need_up
    Ota2Failure.Aborted -> R.string.ota2_fail_aborted
}
