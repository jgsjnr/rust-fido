package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
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
import dev.aegiskey.app.ble.AegisBleClient

/**
 * Tela inicial: o que e o AegisKey + 2 caminhos (USB ou Bluetooth).
 * Copy simples, fail-closed: sem vinculo o cofre segue bloqueado.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WelcomeScreen(
    onUsb: () -> Unit = {},
    onBle: () -> Unit = {},
    onOpenVault: () -> Unit = {},
    gate: VaultGate = VaultGate.NEED_BINDING,
    client: AegisBleClient? = null,
) {
    Scaffold(topBar = { TopAppBar(title = { Text("Bem-vindo", maxLines = 1, overflow = TextOverflow.Ellipsis) }) }) { inner ->
        AegisScreenColumn(inner = inner) {
            GateBanner(gate = gate, onConnect = onBle, onBind = onUsb)
            if (client != null) TestModeBanner(client)

            SectionTitle("O que e o AegisKey")
            FriendlyText(
                text = "Sua chave fica guardada no aparelhinho, fora do celular.",
                maxLines = 3,
            )
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp)) {
                    Bullet("Voce e o unico dono: so este app manda nele.")
                    Bullet("O segredo nunca sai do aparelho: so o codigo de 6 numeros viaja.")
                    Bullet("O toque no botao confirma: nada acontece sem voce apertar.")
                }
            }

            SectionTitle("Escolha como configurar")
            Button(onClick = onUsb, modifier = Modifier.fillMaxWidth()) {
                Text("Configurar via USB", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            FriendlyText(
                text = "Com o cabo na mao: ligue no celular (OTG) e confira VID 0x303A / PID 0xAE61.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 3,
            )
            OutlinedButton(onClick = onBle, modifier = Modifier.fillMaxWidth()) {
                Text("Configurar via Bluetooth", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            FriendlyText(
                text = "Sem fio: procure o aparelho, pareie (GATT 0xFFFD) e confirme o vinculo (0x28).",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 3,
            )

            OutlinedButton(onClick = onOpenVault, modifier = Modifier.fillMaxWidth()) {
                Text("Ja configurei: abrir meu cofre", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

@Composable
private fun Bullet(text: String) {
    FriendlyText(text = "\u2022 " + text, maxLines = 3)
}
