package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

/**
 * Gate banner for fail-closed hardware security state.
 * Standardized to ASD-STE100 technical documentation.
 */
enum class VaultGate {
    NO_BLE,
    NEED_BINDING,
    NEED_UP,
    NEED_PIN,
    READY,
}

@Composable
fun GateBanner(
    gate: VaultGate,
    onConnect: () -> Unit = {},
    onBind: () -> Unit = {},
    modifier: Modifier = Modifier,
) {
    if (gate == VaultGate.READY) return
    val (title, body, action) = when (gate) {
        VaultGate.NO_BLE -> Triple(
            "Connect hardware device first",
            "BLE connection is offline. Connect device before operation.",
            "OK",
        )
        VaultGate.NEED_BINDING -> Triple(
            "Bind hardware device first",
            "Hardware device has no owner. Complete initial pairing setup.",
            "Bind device",
        )
        VaultGate.NEED_UP -> Triple(
            "Press physical button",
            "Hardware device requires User Presence (UP) verification.",
            "OK",
        )
        VaultGate.NEED_PIN -> Triple(
            "PIN authentication required",
            "Hardware device requires PIN authentication.",
            "OK",
        )
        VaultGate.READY -> Triple("", "", "")
    }
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
    ) {
        Column(Modifier.padding(12.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = body,
                style = MaterialTheme.typography.bodySmall,
                maxLines = 3,
                overflow = TextOverflow.Ellipsis,
            )
            if (gate == VaultGate.NO_BLE || gate == VaultGate.NEED_BINDING) {
                Button(onClick = { if (gate == VaultGate.NO_BLE) onConnect() else onBind() }) {
                    Text(action, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
        }
    }
}
