package dev.aegiskey.app.pm

import dev.aegiskey.app.data.cbor.SecureGuardCbor
import dev.aegiskey.app.ui.VaultGate

/**
 * Password-manager blind-transport codec (viewer F-PM2, app side).
 *
 * Mirrors `universal-device-sdk/src/pm.rs` (opcodes `0x43..=0x47`,
 * CBOR bodies, caps) and `crates/uniffi-bridge/src/pm_jni.rs` framing
 * without adding a new SDK: this is a thin transport mapping over the
 * existing [dev.aegiskey.app.data.transport.KeyTransport.sendVendor]
 * path plus [SecureGuardCbor] for CBOR. No crypto here, no persistence,
 * no secret logging — payloads stay opaque except for the punctual
 * release the device discloses (transient, zeroized on close).
 *
 * Authority rule: every surface here renders device-attested bytes
 * only. Ids are opaque device-chosen bytes shown as truncated hex;
 * labels/usernames/secrets never originate on the phone.
 */
object PmCbor {
    const val OP_PM_PUT: Int = 0x43
    const val OP_PM_GET: Int = 0x44
    const val OP_PM_LIST: Int = 0x45
    const val OP_PM_DELETE: Int = 0x46
    const val OP_PM_STATUS: Int = 0x47
    const val PM_OP_MIN: Int = OP_PM_PUT
    const val PM_OP_MAX: Int = OP_PM_STATUS

    const val STATUS_OK: Int = 0x00
    const val STATUS_NEED_UP: Int = 0x01
    const val STATUS_NEED_PIN: Int = 0x02
    const val STATUS_NEED_BINDING: Int = 0x05

    const val PM_ID_MAX_BYTES: Int = 64
    const val PM_LABEL_MAX_BYTES: Int = 128
    const val PM_USERNAME_MAX_BYTES: Int = 256
    const val PM_SECRET_MAX_BYTES: Int = 512
    const val PM_URL_MAX_BYTES: Int = 512
    const val PM_LIST_DEFAULT_LIMIT: Int = 32

    /** Fail-closed gate outcome carried as data (mirrors SDK `PmStatus`). */
    sealed interface PmGate {
        data object Ok : PmGate
        data object NeedBinding : PmGate
        data object PresenceRequired : PmGate
        data object PinRequired : PmGate
        /** Any other device failure rides the raw status byte (never a secret). */
        data class Denied(val status: Int) : PmGate
    }

    data class PmPage(
        val ids: List<ByteArray>,
        val nextCursor: Long,
        val hasMore: Boolean,
    )

    /**
     * Punctual gated release. TRANSIENT ON THE PHONE: display and zeroize,
     * never persist, never log. Call [wipe] when the viewer closes.
     */
    data class PmRelease(
        val id: ByteArray,
        val username: String,
        val secret: ByteArray,
    ) {
        fun wipe() {
            id.fill(0)
            secret.fill(0)
        }
    }

    data class PmStatus(val entryCount: Long, val maxEntries: Long)

    fun isPmOpcode(opcode: Int): Boolean = opcode in PM_OP_MIN..PM_OP_MAX

    fun gateOf(status: Int): PmGate = when (status) {
        STATUS_OK -> PmGate.Ok
        STATUS_NEED_BINDING -> PmGate.NeedBinding
        STATUS_NEED_UP -> PmGate.PresenceRequired
        STATUS_NEED_PIN -> PmGate.PinRequired
        else -> PmGate.Denied(status)
    }

    /** Same UX gates as the vault screens ([VaultGate]). */
    fun vaultGateOf(gate: PmGate, noTransport: Boolean = false): VaultGate = when {
        noTransport -> VaultGate.NO_BLE
        gate is PmGate.NeedBinding -> VaultGate.NEED_BINDING
        gate is PmGate.PresenceRequired -> VaultGate.NEED_UP
        gate is PmGate.PinRequired -> VaultGate.NEED_PIN
        else -> VaultGate.READY
    }

    fun statusName(status: Int): String = when (status) {
        STATUS_OK -> "Ok"
        STATUS_NEED_BINDING -> "NeedBinding"
        STATUS_NEED_UP -> "PresenceRequired"
        STATUS_NEED_PIN -> "PinRequired"
        else -> "Unknown"
    }

    fun encodeListRequest(cursor: Long, limit: Int): ByteArray =
        SecureGuardCbor.encodeMap(
            linkedMapOf(
                "cursor" to cursor.coerceAtLeast(0L),
                "limit" to limit.coerceIn(1, 255),
            )
        )

    /**
     * Punctual create body (transient on the phone: user-typed fields sealed
     * by the device on receipt; the device assigns the opaque record id).
     * Mirrors `universal-device-sdk` `encode_pm_put_request` over `0x43`.
     */
    data class PmPutBody(
        val label: String,
        val username: String,
        val secret: ByteArray,
        val url: String? = null,
    ) {
        fun wipe() {
            secret.fill(0)
        }
    }

    fun encodePutRequest(
        label: String,
        username: String,
        secret: ByteArray,
        url: String? = null,
    ): ByteArray {
        require(label.toByteArray(Charsets.UTF_8).size <= PM_LABEL_MAX_BYTES) { "invalid pm label" }
        require(username.toByteArray(Charsets.UTF_8).size <= PM_USERNAME_MAX_BYTES) { "invalid pm username" }
        require(secret.isNotEmpty() && secret.size <= PM_SECRET_MAX_BYTES) { "invalid pm secret" }
        if (url != null) {
            require(url.toByteArray(Charsets.UTF_8).size <= PM_URL_MAX_BYTES) { "invalid pm url" }
        }
        return SecureGuardCbor.encodeMap(
            linkedMapOf(
                "label" to label,
                "username" to username,
                "secret" to secret.copyOf(),
                "url" to url,
            )
        )
    }

    fun decodePutRequest(body: ByteArray): PmPutBody {
        val decoded = SecureGuardCbor.decode(body) as? Map<*, *>
            ?: throw IllegalStateException("invalid pm put request")
        val label = decoded["label"] as? String
            ?: throw IllegalStateException("invalid pm put request")
        val username = decoded["username"] as? String
            ?: throw IllegalStateException("invalid pm put request")
        val secret = decoded["secret"] as? ByteArray
            ?: throw IllegalStateException("invalid pm put request")
        val url = decoded["url"] as? String
        require(label.toByteArray(Charsets.UTF_8).size <= PM_LABEL_MAX_BYTES) { "invalid pm label" }
        require(username.toByteArray(Charsets.UTF_8).size <= PM_USERNAME_MAX_BYTES) { "invalid pm username" }
        require(secret.isNotEmpty() && secret.size <= PM_SECRET_MAX_BYTES) { "invalid pm secret" }
        if (url != null) {
            require(url.toByteArray(Charsets.UTF_8).size <= PM_URL_MAX_BYTES) { "invalid pm url" }
        }
        return PmPutBody(label, username, secret, url)
    }

    fun encodeDeleteRequest(id: ByteArray): ByteArray {
        require(id.isNotEmpty() && id.size <= PM_ID_MAX_BYTES) { "invalid pm id" }
        return SecureGuardCbor.encodeMap(linkedMapOf("id" to id.copyOf()))
    }

    fun encodeGetRequest(id: ByteArray): ByteArray {
        require(id.isNotEmpty() && id.size <= PM_ID_MAX_BYTES) { "invalid pm id" }
        return SecureGuardCbor.encodeMap(linkedMapOf("id" to id))
    }

    fun encodeStatusRequest(): ByteArray = SecureGuardCbor.encodeStatusRequest()

    fun decodeListResponse(body: ByteArray): PmPage {
        val decoded = SecureGuardCbor.decode(body) as? Map<*, *>
            ?: throw IllegalStateException("invalid pm list response")
        val rawIds = decoded["ids"] as? List<*>
            ?: throw IllegalStateException("invalid pm list response")
        val ids = rawIds.map { item ->
            val bytes = item as? ByteArray
                ?: throw IllegalStateException("invalid pm list response")
            require(bytes.isNotEmpty() && bytes.size <= PM_ID_MAX_BYTES) { "invalid pm id" }
            bytes
        }
        val nextCursor = (decoded["next_cursor"] as? Number)?.toLong() ?: 0L
        val hasMore = decoded["has_more"] as? Boolean ?: false
        return PmPage(ids, nextCursor, hasMore)
    }

    fun decodeReleaseResponse(body: ByteArray): PmRelease {
        val decoded = SecureGuardCbor.decode(body) as? Map<*, *>
            ?: throw IllegalStateException("invalid pm release response")
        val id = decoded["id"] as? ByteArray
            ?: throw IllegalStateException("invalid pm release response")
        val username = decoded["username"] as? String
            ?: throw IllegalStateException("invalid pm release response")
        val secret = decoded["secret"] as? ByteArray
            ?: throw IllegalStateException("invalid pm release response")
        require(id.isNotEmpty() && id.size <= PM_ID_MAX_BYTES) { "invalid pm id" }
        require(username.length <= PM_USERNAME_MAX_BYTES) { "invalid pm release" }
        require(secret.isNotEmpty() && secret.size <= PM_SECRET_MAX_BYTES) { "invalid pm release" }
        return PmRelease(id, username, secret)
    }

    fun decodeStatusResponse(body: ByteArray): PmStatus {
        val decoded = SecureGuardCbor.decode(body) as? Map<*, *>
            ?: throw IllegalStateException("invalid pm status response")
        val entryCount = (decoded["entry_count"] as? Number)?.toLong() ?: 0L
        val maxEntries = (decoded["max_entries"] as? Number)?.toLong() ?: 0L
        return PmStatus(entryCount, maxEntries)
    }

    /**
     * Display handle for an opaque record id. The id is device-chosen and
     * carries no label; truncated hex is a handle, never an invented name.
     */
    fun opaqueIdLabel(id: ByteArray): String {
        val hex = id.joinToString("") { "%02x".format(it) }
        return if (hex.length <= 12) "ID $hex" else "ID ${hex.take(8)}…${hex.takeLast(4)}"
    }

    fun opaqueIdHex(id: ByteArray): String =
        id.joinToString("") { "%02x".format(it) }
}
