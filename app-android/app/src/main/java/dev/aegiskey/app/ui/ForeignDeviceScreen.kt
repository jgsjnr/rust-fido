package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

/**
 * Dispositivo alheio: ja tem dono em outro celular. Este app nao gerencia
 * nada (sem claim, sem listas, sem codigos) — so uso FIDO2 via cabo USB.
 * Textos simples, sem Log com PII (so UI).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ForeignDeviceScreen(onUseUsb: () -> Unit, onBack: () -> Unit) {
    Scaffold(topBar = { TopAppBar(title = { Text("Dispositivo de outra pessoa", maxLines = 1, overflow = TextOverflow.Ellipsis) }) }) { inner ->
        AegisScreenColumn(inner = inner) {
            SectionTitle("Este dispositivo ja tem dono")
            Card {
                Column(Modifier.padding(12.dp)) {
                    FriendlyText(
                        text = "Ele pertence a outro celular. Voce nao pode ver nem gerenciar as contas dele.",
                        maxLines = 3,
                    )
                    FriendlyText(
                        text = "Para ter o seu, use um dispositivo novo e faca a primeira configuracao.",
                        style = MaterialTheme.typography.bodySmall,
                        maxLines = 3,
                    )
                }
            }
            SectionTitle("Usar como chave de seguranca")
            FriendlyText(
                text = "Voce ainda pode usar ele como chave de seguranca (FIDO2) com cabo USB, igual a uma chave comum.",
                maxLines = 3,
            )
            Button(onClick = onUseUsb, modifier = Modifier.fillMaxWidth()) {
                Text("Usar via USB", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
                Text("Voltar", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}
