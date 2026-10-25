package dev.aegiskey.app.domain.model

enum class OnboardingStep(val stepNumber: Int, val totalSteps: Int = 5) {
    WELCOME_TRANSPORT(1),
    HOLD_PHYSICAL_BUTTON(2),
    DISCOVER_AND_CONNECT(3),
    TOUCH_AND_BIOMETRIC_BIND(4),
    NAME_AND_FINISH(5)
}

data class DiscoveredKeyCandidate(
    val id: String,
    val name: String,
    val signalRssi: Int,
    val transportType: ConnectionTransportType
)
