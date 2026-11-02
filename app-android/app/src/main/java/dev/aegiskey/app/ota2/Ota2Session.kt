package dev.aegiskey.app.ota2

/** ota2 session phases (firmware OtaPhase parity, app-side cursor only). */
enum class Ota2Phase {
    IDLE,
    STAGING,
    STAGED,
    VERIFIED,
    DONE,
    FAILED,
}

/**
 * Progress + resume state machine.
 *
 * Firmware BEGIN discards staging, so resume never re-sends BEGIN:
 * [beginDone] marks a device session already open, and [offset] (last
 * device-acked byte count) is the only resume cursor. A fresh [Ota2Session]
 * per picked file; re-run [Ota2Engine.run] with the same session to resume
 * after [Ota2Result.Paused].
 */
class Ota2Session(
    val manifest: Ota2Manifest,
    val image: StagedImage,
) {
    var phase: Ota2Phase = Ota2Phase.IDLE
        internal set

    /** Bytes acked by the device. Resume cursor. */
    var offset: Int = 0
        internal set

    /** True once the device answered OK to BEGIN (do not re-send). */
    var beginDone: Boolean = false
        internal set
}
