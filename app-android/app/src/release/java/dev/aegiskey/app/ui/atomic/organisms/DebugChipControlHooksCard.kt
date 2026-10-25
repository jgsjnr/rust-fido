package dev.aegiskey.app.ui.atomic.organisms

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier

/**
 * Release source set implementation of DebugChipControlHooksCard.
 * In release builds, this composable emits zero UI and performs no operation.
 */
@Composable
fun DebugChipControlHooksCard(
    modifier: Modifier = Modifier,
    onSimulateHold5s: () -> Unit = {},
    onSimulateTouch: () -> Unit = {},
    onInjectSampleData: () -> Unit = {},
    onSimulatePing: () -> Unit = {},
    onToggleConnection: () -> Unit = {},
    onResetAllKeys: () -> Unit = {},
) {
    // Pure no-op in release builds: zero UI emitted, zero debug hooks
}
