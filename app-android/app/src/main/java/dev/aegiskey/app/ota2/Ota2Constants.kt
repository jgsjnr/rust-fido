package dev.aegiskey.app.ota2

/**
 * Offline firmware.bin OTA wire constants (ota2 engine).
 *
 * Authority: crates/aegis-fido-firmware/src/ota.rs + stores/ota_store.rs.
 * The app is transport-only: it stages bytes and reads authority replies,
 * the device owns verify/commit. BLE first (BleContract allowlist
 * 0x30/0x31/0x32/0x34); USB via the same [Ota2Transport] seam.
 */
object Ota2Constants {
    /** BEGIN: open a staged session with the 104 B manifest. */
    const val OP_BEGIN = 0x30

    /** CHUNK: stream one slice (offset u32 BE || data). */
    const val OP_CHUNK = 0x31

    /** FINISH: device verifies staged image (sig, then digest, then version). */
    const val OP_FINISH = 0x32

    /** ABORT: discard staged state back to Idle. */
    const val OP_ABORT = 0x34
    // NOTE: 0x33 COMMIT is intentionally absent. Commit is a USB-only
    // ritual (offline release key + physical UP latch) with no BLE path.
    // This engine never sends 0x33.

    /** Wire length of the staged manifest. */
    const val MANIFEST_WIRE_LEN = 104

    /** Signed prefix: version BE (4) || size BE (4) || sha256 (32). */
    const val MANIFEST_SIGNED_LEN = 40

    /** Manifest sha256 field length. */
    const val MANIFEST_SHA_LEN = 32

    /** Manifest Ed25519 signature field length. */
    const val MANIFEST_SIG_LEN = 64

    /** Manifest version/size field length (u32 BE each). */
    const val MANIFEST_U32_LEN = 4

    /** CHUNK offset prefix length (u32 BE). */
    const val CHUNK_OFFSET_LEN = 4

    /** Offline release/lab pubkey length. */
    const val OTA_PUBKEY_LEN = 32

    /** Protocol ceiling (firmware MAX_OTA_IMAGE_BYTES): never stage above. */
    const val PROTOCOL_MAX_IMAGE_BYTES = 2 * 1024 * 1024

    /** Effective staging budget (firmware OTA_STORAGE_BUDGET_BYTES). */
    const val MAX_STAGED_IMAGE_BYTES = 896 * 1024

    /** Default CHUNK data size: small enough for FFF1 fragments, big enough for pace. */
    const val DEFAULT_CHUNK_BYTES = 1024

    /** Wire status OK (firmware ota_store S9.5 parity). */
    const val STATUS_OK = 0x00

    /** Wire status NEED_UP: tap the key button, session kept. */
    const val STATUS_NEED_UP = 0x01

    /** Wire status FAIL: session rolled back device-side. */
    const val STATUS_FAIL = 0x04
}
