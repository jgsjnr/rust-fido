package dev.aegiskey.app.oob

import java.security.SecureRandom

/**
 * OOB-assisted BLE pairing — single entrypoint of the oob module.
 *
 * Wire contract (firmware `CAPABILITY_DIET.md` §10, executor
 * `ble/oob.rs`): the phone generates a random 16 B Temporary Key,
 * sends it as `CMD_MSG [0x42, tk0..tk15]` over serial/USB only
 * (`UsbKeyTransport.sendVendor`, which already falls back to the host
 * bridge), and the firmware arms its SM OOB latch one-shot. Gates are
 * enforced by the device in canonical order (pairing-window, binding,
 * UP, PIN session); the app only translates the authority answer and
 * never invents state.
 *
 * Transport constraint: the BLE GATT path never carries `0x42` (the
 * firmware reassembler rejects it fail-closed, and
 * `AegisBleClient.sendVendor` allowlists only
 * `BleContract.isVendorOp/isBindingOp`, which exclude `0x42`).
 *
 * Android-side verdict: there is no public Android SDK API (verified on
 * `android-34`, the app's `targetSdk`; the test phone reports API 31)
 * that accepts a BLE SMP OOB Temporary Key. `BluetoothDevice` exposes
 * only `createBond()/setPin()/setPairingConfirmation()` for pairing,
 * `android.bluetooth.OobData` does not exist in the public SDK, and
 * `AssociationRequest.Builder` takes no OOB material. Hidden `@hide`
 * methods exist but require reflection, which is forbidden. The
 * firmware keeps MITM required, so a plain `createBond()` fails closed
 * on the key. This module therefore reports the Android bond step as
 * blocked with the exact gap instead of hacking around it.
 *
 * This module invents no telemetry: every outcome translates a
 * structured device response. No core crates are imported.
 */
object OobPairing {
    /** `CMD_MSG` opcode of the OOB arm op (first free byte after `VENDOR_SIGN 0x41`). */
    const val OP_BLE_OOB_ARM: Int = 0x42

    /** Length of the OOB Temporary Key (peer random, 128 bits). */
    const val OOB_TK_LEN: Int = 16

    /** Bounded retries while sampling; an all-zero TK is never returned. */
    const val MAX_TK_GEN_ATTEMPTS: Int = 8

    /**
     * Samples a fresh 16 B Temporary Key. Never returns an all-zero TK
     * (fail-closed: TK=0 is the weakest key and never legitimate);
     * throws after [MAX_TK_GEN_ATTEMPTS] zero draws.
     */
    fun generateTk(random: SecureRandom = SecureRandom()): ByteArray {
        repeat(MAX_TK_GEN_ATTEMPTS) {
            val tk = ByteArray(OOB_TK_LEN)
            random.nextBytes(tk)
            if (isValidTk(tk)) return tk
        }
        throw IllegalStateException("OOB TK sampler drew all-zero too many times")
    }

    /** True for exactly 16 B with at least one nonzero byte. */
    fun isValidTk(tk: ByteArray?): Boolean =
        tk != null && tk.size == OOB_TK_LEN && tk.any { it != 0.toByte() }

    /**
     * Defensive copy handed to the USB transport as the `sendVendor`
     * payload (the transport frames `[0x42, tk...]` on the wire).
     * Requires a valid TK; never ships a weak or short key.
     */
    fun armPayload(tk: ByteArray): ByteArray {
        require(isValidTk(tk)) { "OOB TK must be 16 nonzero-tracked bytes" }
        return tk.copyOf()
    }

    /** Status byte of an arm response. Prefers `[op, status]` echo framing, else status-first. */
    fun statusOf(raw: ByteArray?): Int? {
        if (raw == null || raw.isEmpty()) return null
        if (raw.size >= 2 && (raw[0].toInt() and 0xFF) == OP_BLE_OOB_ARM) {
            return raw[1].toInt() and 0xFF
        }
        return raw[0].toInt() and 0xFF
    }

    /** Structured outcome of a `0x42` arm attempt. Unknown bytes are failures, never success. */
    sealed interface ArmResult {
        data object Armed : ArmResult
        data object NeedBinding : ArmResult
        data object NeedUp : ArmResult
        data object NeedPin : ArmResult
        data class BadEnvelope(val status: Int) : ArmResult
        data object TransportFailure : ArmResult
    }

    /**
     * Maps the authority answer fail-closed: `0x00` armed; `0x05`
     * pair/bind first; `0x01` touch the key; `0x02` unlock the session;
     * anything else (including `0x04` shape/radio denials and absent
     * answers) is a failure that changes no local state.
     */
    fun parseArmResponse(raw: ByteArray?): ArmResult {
        return when (val status = statusOf(raw)) {
            0x00 -> ArmResult.Armed
            0x05 -> ArmResult.NeedBinding
            0x01 -> ArmResult.NeedUp
            0x02 -> ArmResult.NeedPin
            null -> ArmResult.TransportFailure
            else -> ArmResult.BadEnvelope(status)
        }
    }

    /**
     * Android-side BLE bond step verdict. Always blocked: the OS offers
     * no public entrypoint to consume the TK (see class KDoc for the
     * verified API gap). Callers surface [ANDROID_OOB_GAP] through
     * `strings.xml`, never as invented prose.
     */
    sealed interface AndroidBondVerdict {
        data object BlockedNoPublicOobApi : AndroidBondVerdict
    }

    fun androidBondVerdict(): AndroidBondVerdict =
        AndroidBondVerdict.BlockedNoPublicOobApi

    /** Exact public-API gap behind the blocked Android bond step (log/diagnostics only). */
    const val ANDROID_OOB_GAP: String =
        "No public Android SDK API (target 34; phone API 31) accepts a BLE SMP OOB Temporary Key: " +
            "BluetoothDevice exposes only createBond/setPin/setPairingConfirmation, " +
            "android.bluetooth.OobData is absent from the public SDK, and " +
            "AssociationRequest.Builder takes no OOB material. Hidden methods require reflection (forbidden)."
}
