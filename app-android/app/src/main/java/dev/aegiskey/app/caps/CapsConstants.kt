package dev.aegiskey.app.caps

/**
 * GET_CAPS wire constants (caps module).
 *
 * Authority: reports/refactoring/CAPABILITY_DIET.md §7 +
 * scripts/capability-catalog.json#wire_contract.
 * Op 0x3F is the first free byte after the Secure Guard range
 * 0x3A-0x3E. Read-only, no auth, empty request. Response is
 * wire status 0x00 + CBOR map {fw_version, preset, caps[],
 * unsupported_count}.
 */
object CapsConstants {
    /** GET_CAPS capability advertisement (read-only, no auth). */
    const val OP_GET_CAPS = 0x3F

    /** Wire status OK (S9.5 parity, same class as ota2 STATUS_OK). */
    const val STATUS_OK = 0x00

    /** Known presets (displayed as device-reported; see CapsReport). */
    const val PRESET_FULL = "full"
    const val PRESET_FIDO_ONLY = "fido-only"
    const val PRESET_FIDO_TOTP = "fido-totp"

    /** Sanity ceilings for fail-soft parsing (never authority data). */
    const val MAX_TEXT_LEN = 64
    const val MAX_CAPS_ENTRIES = 64
    const val MAX_UNSUPPORTED_COUNT = 1024
}
