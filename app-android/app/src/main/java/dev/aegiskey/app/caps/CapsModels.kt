package dev.aegiskey.app.caps

/**
 * caps module models (authority data only, never invented).
 *
 * [CapsReport] mirrors the GET_CAPS CBOR map 1:1: every field is
 * device-reported. [CapsResult.Unknown] is the single fail-soft
 * outcome for old firmware (no 0x3F), transport loss, or malformed
 * CBOR — the screen renders "desconhecido", never synthetic data.
 */
data class CapsReport(
    val fwVersion: String,
    val preset: String,
    val caps: List<String>,
    val unsupportedCount: Int,
)

sealed interface CapsResult {
    data class Known(val report: CapsReport) : CapsResult
    data object Unknown : CapsResult
}
