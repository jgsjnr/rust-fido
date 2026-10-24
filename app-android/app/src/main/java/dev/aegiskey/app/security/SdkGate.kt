package dev.aegiskey.app.security

import dev.aegiskey.app.ble.BindingOps
import dev.aegiskey.app.ble.BleContract
import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.ui.VaultGate
import uniffi.aegis_bridge.BridgeException

/**
 * A1 SDK gate: the only path from UI surfaces to SDK domains (facade-first, R3).
 *
 * - One `require*()` per domain (fido/backup/oath/ota/otp/piv/policy/
 *   proximity/rescue/wallet/audit). Every check reads
 *   [FeatureFlags.capabilityBits] (which mirrors the SDK `capabilities()`
 *   build set) — never a per-domain literal. Feature off reads
 *   [GateOutcome.NotCompiled] honestly: never a crash, never `todo()`.
 * - [mapBridgeError] translates the UniFFI BridgeException surface into R4
 *   (Success/Unsupported/Unavailable/PermissionDenied/NotCompiled/
 *   ExternalBlocked/RealVerified). Only [GateOutcome.Success] and
 *   [GateOutcome.RealVerified] count as usable; everything else is fail-closed.
 * - [mapWireStatus] translates the frozen S9.5 wire bytes (0x00-0x05) into R4.
 * - [gateBannerState] adapts R4 to the existing [VaultGate]/GateBanner pair.
 *   Outcomes with no honest GateBanner text map to null (no banner): callers
 *   must render their own R4 notice instead of borrowing a misleading one.
 *
 * No secrets cross this object: log lines carry fixed tokens only
 * (domain/outcome names), via [DeviceLog]. Call [require] from event handlers
 * or effects, not from composition (each call appends one log line).
 */
object SdkGate {

    /** SDK domain (gate mapping mirrors `SdkRequest::check_compiled`). */
    enum class SdkDomain(val capabilityBit: Int) {
        FIDO(FeatureFlags.CAP_FIDO),
        BACKUP(FeatureFlags.CAP_BACKUP),
        OATH(FeatureFlags.CAP_OATH),
        OTA(FeatureFlags.CAP_OTA),
        OTP(FeatureFlags.CAP_OTP),
        PIV(FeatureFlags.CAP_PIV),
        POLICY(FeatureFlags.CAP_POLICY),
        PROXIMITY(FeatureFlags.CAP_PROXIMITY),
        /** Rescue rides the otp gate (0x2E transport; see `check_compiled`). */
        RESCUE(FeatureFlags.CAP_OTP),
        /** Wallet + WalletSign ride hardwallet (see `check_compiled`). */
        WALLET(FeatureFlags.CAP_HARDWALLET),
        AUDIT(FeatureFlags.CAP_AUDIT),
    }

    /** R4 facade outcome (no synthetic success, no mock paths). */
    sealed interface GateOutcome {
        data object Success : GateOutcome
        data object Unsupported : GateOutcome
        data object Unavailable : GateOutcome
        data object PermissionDenied : GateOutcome
        data class NotCompiled(val domain: SdkDomain) : GateOutcome
        data class ExternalBlocked(val reason: BlockReason) : GateOutcome
        data object RealVerified : GateOutcome
    }

    /** Fixed, non-secret block tokens (never payloads, never values). */
    enum class BlockReason {
        NO_NATIVE_LIB,
        NO_TRANSPORT,
        NO_PEER,
        LAB_MOCKS_OFF,
    }

    /** Core gate: native reachability first (ExternalBlocked), then the capability bit. */
    fun require(domain: SdkDomain): GateOutcome {
        val outcome = when {
            !AegisBridge.nativeLoaded -> GateOutcome.ExternalBlocked(BlockReason.NO_NATIVE_LIB)
            (FeatureFlags.capabilityBits() and domain.capabilityBit) == domain.capabilityBit ->
                GateOutcome.Success
            else -> GateOutcome.NotCompiled(domain)
        }
        DeviceLog.append(
            DeviceLog.Category.SYSTEM,
            "sdk-gate " + domain.name.lowercase() + " " + outcomeToken(outcome),
        )
        return outcome
    }

    fun requireFido(): GateOutcome = require(SdkDomain.FIDO)
    fun requireBackup(): GateOutcome = require(SdkDomain.BACKUP)
    fun requireOath(): GateOutcome = require(SdkDomain.OATH)
    fun requireOta(): GateOutcome = require(SdkDomain.OTA)
    fun requireOtp(): GateOutcome = require(SdkDomain.OTP)
    fun requirePiv(): GateOutcome = require(SdkDomain.PIV)
    fun requirePolicy(): GateOutcome = require(SdkDomain.POLICY)
    fun requireProximity(): GateOutcome = require(SdkDomain.PROXIMITY)
    fun requireRescue(): GateOutcome = require(SdkDomain.RESCUE)
    fun requireWallet(): GateOutcome = require(SdkDomain.WALLET)
    fun requireAudit(): GateOutcome = require(SdkDomain.AUDIT)

    /** Snapshot of every domain (diagnostics/A9; fixed tokens only). */
    fun allDomainStates(): Map<SdkDomain, GateOutcome> =
        SdkDomain.entries.associateWith(::require)

    /**
     * UniFFI errors to R4 (fail-closed; deterministic faults never retry):
     * - Opcode/fragment/envelope/cose/oath/address faults -> Unsupported
     *   (contract misuse or wire 0x04 class; retry cannot help).
     * - Overflow (over a transport/envelope ceiling) -> Unsupported.
     * - Crypto failure (auth/decrypt/KDF reject) -> PermissionDenied
     *   (caller must re-prove; never silent-retry).
     * - Missing native lib -> ExternalBlocked(NO_NATIVE_LIB).
     * - Anything else unexpected -> Unavailable (may retry).
     */
    fun mapBridgeError(e: Throwable): GateOutcome {
        val outcome = when (e) {
            is BridgeException.InvalidOpcode,
            is BridgeException.InvalidFragment,
            is BridgeException.InvalidEnvelope,
            is BridgeException.InvalidCose,
            is BridgeException.InvalidOath,
            is BridgeException.InvalidAddress,
            is BridgeException.Overflow -> GateOutcome.Unsupported
            is BridgeException.CryptoException -> GateOutcome.PermissionDenied
            is UnsatisfiedLinkError -> GateOutcome.ExternalBlocked(BlockReason.NO_NATIVE_LIB)
            else -> GateOutcome.Unavailable
        }
        DeviceLog.append(DeviceLog.Category.SYSTEM, "sdk-bridge " + outcomeToken(outcome))
        return outcome
    }

    /**
     * S9.5 wire byte to R4 (frozen set 0x00-0x05; constants from
     * BleContract/BindingOps, no literals here):
     * 0x00 OK -> Success; 0x01/0x02/0x05 (UP/PIN/binding) -> PermissionDenied
     * (fail-closed; the binding -> UP -> PIN order lives device-side);
     * 0x03 NO_SLOT / 0x04 BAD_ENVELOPE / unknown -> Unsupported.
     */
    fun mapWireStatus(status: Int): GateOutcome = when (status) {
        BleContract.VENDOR_OK -> GateOutcome.Success
        BleContract.VENDOR_NEED_UP,
        BleContract.VENDOR_NEED_PIN,
        BindingOps.STATUS_NEED_BINDING -> GateOutcome.PermissionDenied
        BleContract.VENDOR_NO_SLOT,
        BleContract.VENDOR_BAD_ENVELOPE -> GateOutcome.Unsupported
        else -> GateOutcome.Unsupported
    }

    /**
     * R4 to VaultGate for the existing GateBanner. Null means "no banner":
     * - Success/RealVerified -> null (nothing to show).
     * - PermissionDenied -> NEED_UP (device-side user proof outstanding;
     *   the banner body already covers button + PIN).
     * - NotCompiled/ExternalBlocked/Unsupported/Unavailable -> null. There is
     *   no honest GateBanner text for a compiled-off feature or a blocked
     *   dependency (borrowing NEED_BINDING would lie about the cause), so
     *   callers render their own R4 notice (A2-A8) instead.
     */
    fun gateBannerState(outcome: GateOutcome): VaultGate? = when (outcome) {
        GateOutcome.Success, GateOutcome.RealVerified -> null
        GateOutcome.PermissionDenied -> VaultGate.NEED_UP
        else -> null
    }

    private fun outcomeToken(outcome: GateOutcome): String = when (outcome) {
        GateOutcome.Success -> "ok"
        GateOutcome.Unsupported -> "unsupported"
        GateOutcome.Unavailable -> "unavailable"
        GateOutcome.PermissionDenied -> "denied"
        is GateOutcome.NotCompiled -> "not-compiled"
        is GateOutcome.ExternalBlocked -> "blocked-" + outcome.reason.name.lowercase()
        GateOutcome.RealVerified -> "real-verified"
    }
}
