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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.R

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
            stringResource(R.string.gate_noble_title),
            stringResource(R.string.gate_noble_body),
            stringResource(R.string.gate_ok),
        )
        VaultGate.NEED_BINDING -> Triple(
            stringResource(R.string.gate_bind_title),
            stringResource(R.string.gate_bind_body),
            stringResource(R.string.gate_bind_action),
        )
        VaultGate.NEED_UP -> Triple(
            stringResource(R.string.gate_up_title),
            stringResource(R.string.gate_up_body),
            stringResource(R.string.gate_ok),
        )
        VaultGate.NEED_PIN -> Triple(
            stringResource(R.string.gate_pin_title),
            stringResource(R.string.gate_pin_body),
            stringResource(R.string.gate_ok),
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
