package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * Wave7 device-press sheet (behind FeatureFlags.ENABLE_DEVICE_PRESS).
 * Shown while the device reports up-needed: the user confirms on the
 * authenticator BOOT button (up to 25s, like the firmware UP wait);
 * Cancel sends CANCEL (0xBE) through [onCancel].
 */
@Composable
fun PressDeviceSheet(statusLabel: String, onCancel: () -> Unit) {
    Card {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Press the device button", style = MaterialTheme.typography.titleMedium)
            Text("Device status: $statusLabel")
            Text("Confirm on the authenticator (BOOT, up to 25s), or cancel below.")
            Button(onClick = onCancel) { Text("Cancel (0xBE)") }
        }
    }
}
