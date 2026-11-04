package dev.aegiskey.app.transportlock

import dev.aegiskey.app.domain.model.ConnectionTransportType

/**
 * Transport-loss session lock — single entrypoint of the transportlock module.
 *
 * Decides, from already-observed link signals, whether losing the transport
 * must lock the session immediately (state LOCKED, session memory cleared,
 * UI shows Disconnected via `R.string.status_disconnected` /
 * `vault_disconnected_*`, polling cancelled by the observers).
 *
 * Covered carriers (app-android only, no firmware/board):
 * - BT: BLE link not READY while the session rides BLE ([TransportLossCause.BLE_DISCONNECTED]).
 * - Wi-Fi: AP unreachable while the session rides Wi-Fi ([TransportLossCause.WIFI_LOST]).
 * - Cabo: USB/UART link gone while the session rides USB ([TransportLossCause.USB_CABLE_DOWN]);
 *   cable sessions carried by the host bridge also die with it
 *   ([TransportLossCause.BRIDGE_OFFLINE]).
 * - Bridge offline: no authority reachable through the host bridge while the
 *   session depends on it ([TransportLossCause.BRIDGE_OFFLINE]).
 *
 * This module invents no telemetry: every signal is an observed boolean and
 * `null` means unknown (never probed) — unknown signals never lock and never
 * clear a cause. Callers translate the returned [TransportLockDecision] into
 * effects ([dev.aegiskey.app.domain.repository.SecureGuardRepository.onTransportLost]);
 * no core crates are imported.
 */
enum class TransportLossCause {
    BRIDGE_OFFLINE,
    BLE_DISCONNECTED,
    WIFI_LOST,
    USB_CABLE_DOWN,
}

/**
 * Observed link liveness. Each field is an already-probed signal; `null`
 * means unknown (not probed) and must never trigger a lock by itself.
 *
 * `bridgeReachable` is authority reachability (the bridge answers for the
 * session), not a bare TCP ping: a live daemon with no device attached is
 * not reachable.
 */
data class TransportSnapshot(
    val bridgeReachable: Boolean? = null,
    val bleReady: Boolean? = null,
    val usbPresent: Boolean? = null,
    val wifiReachable: Boolean? = null,
)

/**
 * Structured outcome of [TransportSessionLock.evaluate]. Screens render the
 * existing disconnected strings when [shouldLock] (aliased as
 * [isDisconnected]) — no new prose is invented here.
 */
data class TransportLockDecision(
    val shouldLock: Boolean,
    val causes: Set<TransportLossCause>,
) {
    val isDisconnected: Boolean get() = shouldLock
}

object TransportSessionLock {

    /**
     * Maps a dead link to its lock causes. The link monitor
     * ([dev.aegiskey.app.data.repository.ConnectedKeysRepositoryImpl]) reports
     * the transport whose `isCurrentlyConnected` flipped to false; this maps
     * it without inventing extra signals. SIMULATOR has no physical link to
     * lose, so it never locks.
     */
    fun causesForLinkLoss(transport: ConnectionTransportType): Set<TransportLossCause> =
        when (transport) {
            ConnectionTransportType.BLE -> setOf(TransportLossCause.BLE_DISCONNECTED)
            ConnectionTransportType.WIFI -> setOf(TransportLossCause.WIFI_LOST)
            ConnectionTransportType.USB -> setOf(TransportLossCause.USB_CABLE_DOWN)
            ConnectionTransportType.SIMULATOR -> emptySet()
        }

    /**
     * Returns whether the session on [activeTransport] must lock given
     * [snapshot]. The session stays alive while any carrier that can serve it
     * is up (BLE: its own link; Wi-Fi: its AP; USB/cabo: direct OTG presence
     * or the host bridge; unknown carrier: any live path). Otherwise it locks
     * as soon as at least one loss is known — pure unknowns never lock.
     */
    fun evaluate(
        activeTransport: ConnectionTransportType?,
        snapshot: TransportSnapshot,
    ): TransportLockDecision {
        val causes = buildSet {
            if (snapshot.bleReady == false) add(TransportLossCause.BLE_DISCONNECTED)
            if (snapshot.wifiReachable == false) add(TransportLossCause.WIFI_LOST)
            if (snapshot.usbPresent == false) add(TransportLossCause.USB_CABLE_DOWN)
            if (snapshot.bridgeReachable == false) add(TransportLossCause.BRIDGE_OFFLINE)
        }

        val carrierAlive = when (activeTransport) {
            ConnectionTransportType.BLE -> snapshot.bleReady == true
            ConnectionTransportType.WIFI -> snapshot.wifiReachable == true
            ConnectionTransportType.USB ->
                snapshot.usbPresent == true || snapshot.bridgeReachable == true
            ConnectionTransportType.SIMULATOR -> true
            null ->
                snapshot.bleReady == true ||
                    snapshot.wifiReachable == true ||
                    snapshot.usbPresent == true ||
                    snapshot.bridgeReachable == true
        }

        return TransportLockDecision(
            shouldLock = !carrierAlive && causes.isNotEmpty(),
            causes = if (!carrierAlive && causes.isNotEmpty()) causes else emptySet(),
        )
    }
}
