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
 * Sheet de toque no dispositivo (NEED_UP via FFF2):
 * mostra quando o aparelho pede confirmacao no botao fisico (ate 25s,
 * como a espera UP do firmware); Cancelar envia CANCEL (0xBE) via [onCancel].
 * Textos PT simples; sempre tem saida (Cancelar/Fechar via [onDismiss]).
 */
@Composable
fun PressDeviceSheet(statusLabel: String, onCancel: () -> Unit, onDismiss: (() -> Unit)? = null) {
    Card {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Toque no botão do dispositivo", style = MaterialTheme.typography.titleMedium)
            Text("Situação: $statusLabel")
            Text("Confirme no botão do aparelho (até 25s) ou cancele abaixo.")
            Button(onClick = onCancel) { Text("Cancelar (0xBE)") }
            if (onDismiss != null) {
                androidx.compose.material3.OutlinedButton(onClick = onDismiss) { Text("Fechar") }
            }
        }
    }
}
