package dev.aegiskey.app.domain.model

enum class ConnectionTransportType { BLE, USB, SIMULATOR }

data class SecurityToggles(
    val lockOnWalkAway: Boolean = true,
    val requireBiometricsOnOpen: Boolean = false,
    val requireTouchForEveryCode: Boolean = true
)

data class ConnectedKeyDevice(
    val id: String,
    val displayName: String,
    val hardwareAddressOrId: String,
    val bindingIdHex: String,
    val transportType: ConnectionTransportType,
    val isCurrentlyConnected: Boolean,
    val firmwareRevision: Int = 1,
    val lastConnectedEpochMs: Long = System.currentTimeMillis(),
    val toggles: SecurityToggles = SecurityToggles()
)
