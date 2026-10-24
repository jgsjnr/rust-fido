package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
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
 * Caminho USB: posse do cabo = vinculo. Passos numerados + fail-closed.
 * Stub honesto opcional: quando [usbPresent] e nulo o preview mostra
 * o card "conecte o dispositivo" sem fingir comportamento.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SetupDeviceUsbScreen(
    onDone: () -> Unit = {},
    onBack: () -> Unit = {},
    gate: VaultGate = VaultGate.NEED_BINDING,
    usbPresent: Boolean? = null,
) {
    Scaffold(topBar = { TopAppBar(title = { Text("Configurar via USB", maxLines = 1, overflow = TextOverflow.Ellipsis) }) }) { inner ->
        AegisScreenColumn(inner = inner) {
            GateBanner(gate = gate, onBind = onDone)
            SectionTitle("Passo a passo")
            NumberedStep(1, "Ligue o AegisKey no celular com o cabo (use adaptador OTG se preciso).")
            NumberedStep(2, "Confira se o aparelho aparece: VID 0x303A / PID 0xAE61.")
            NumberedStep(3, "Confirme a permissao USB na janelinha do sistema.")
            NumberedStep(4, "Faca o vinculo (virar dono) e toque no botao do aparelho para confirmar.")
            if (usbPresent == false) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
                ) {
                    Column(Modifier.padding(12.dp)) {
                        FriendlyText(text = "Conecte o dispositivo", maxLines = 1)
                        FriendlyText(
                            text = "Sem aparelho plugado nada continua. Ligue o cabo e tente de novo.",
                            style = MaterialTheme.typography.bodySmall,
                            maxLines = 3,
                        )
                    }
                }
            }
            FriendlyText(
                text = "Dica: quem esta com o cabo na mao e o dono. Guarde bem o aparelho.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 3,
            )
            Button(onClick = onDone, modifier = Modifier.fillMaxWidth()) {
                Text("Concluir: abrir meu cofre", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
                Text("Voltar", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

@Composable
private fun NumberedStep(n: Int, text: String) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Text("$n. $text", style = MaterialTheme.typography.bodyMedium, maxLines = 4, overflow = TextOverflow.Ellipsis)
        }
    }
}
