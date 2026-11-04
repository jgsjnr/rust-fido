package dev.aegiskey.app.benchmode

import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.SecureGuardStatus

/**
 * Bench/test session badge decision — single entrypoint of the benchmode module.
 *
 * Shows the `MODO BANCADA/TESTE` badge only when the live session is a bench
 * session, derived exclusively from already-observed authority data:
 *
 * - Firmware authority (`SecureGuardStatus`, translated from the
 *   universal-device-sdk/Core CBOR `0x3A` status via
 *   `SecureGuardRepository`/`SecureGuardCbor` — never invented here):
 *   `policy.testModeNonDestructiveWipe == true` (firmware lab/test build),
 *   `lastWipeSimulated == true` (a simulated/non-destructive wipe ran, which
 *   only happens in test mode), or the new `benchActive == true` contract
 *   (`bench_active: bool` in the `0x3A` map; absent reads as false).
 * - Bridge authority (virtual bench path): `transport == SIMULATOR`
 *   (in-memory deterministic simulator or TCP Renode/bridge bench; the host
 *   `HostUsbUartBridgeClient` is documented as the dev/bench host bridge).
 *   The deterministic simulator always reports both firmware flags above as
 *   true, so the status-only overload already covers it; the transport
 *   overload keeps the bridge path explicit when the caller knows it.
 *
 * Pure read-only translation: no telemetry is invented, no state is mutated,
 * no lock/unlock/wipe/policy effect is produced. Production lock flow
 * (`transportlock` + `SecureGuardRepository.onTransportLost` +
 * `SecureGuardViewModel.onTransportLost`) is never touched here; callers
 * render the existing `guard_bench_badge` string when this returns true and
 * render nothing otherwise. `null` transport means unknown and never marks
 * bench by itself. No core crates are imported.
 */
object BenchSession {

    /**
     * Returns true when [status] alone proves a bench/test session
     * (firmware test-mode policy, a simulated wipe on record, or the live
     * `bench_active` contract from `0x3A`).
     */
    fun isBench(status: SecureGuardStatus): Boolean =
        isBench(status, null)

    /**
     * Returns true when the bench session is proven by firmware authority
     * ([status] `benchActive`, test-mode policy, or simulated wipe) or by
     * the virtual bench carrier ([transport] `SIMULATOR`). Any other
     * transport (BLE/USB/Wi-Fi/unknown) never marks bench by itself;
     * production statuses stay false.
     */
    fun isBench(
        status: SecureGuardStatus,
        transport: ConnectionTransportType?,
    ): Boolean {
        if (status.benchActive) return true
        if (status.policy.testModeNonDestructiveWipe) return true
        if (status.lastWipeSimulated) return true
        if (transport == ConnectionTransportType.SIMULATOR) return true
        return false
    }
}
