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
import dev.aegiskey.app.ble.AegisBleClient

/**
 * Caminho Bluetooth: scan -> GATT 0xFFFD -> parear -> claim 0x28.
 * Fail-closed: sem permissao BLE ou sem aparelho, nada continua.
 * [blePermissionGranted]=false mostra como habilitar; [deviceFound]=false
 * mostra o card "conecte o dispositivo". Nulo = estado desconhecido
 * (stub honesto de preview, marcado como teste).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SetupDeviceBleScreen(
    onDone: () -> Unit = {},
    onBack: () -> Unit = {},
    onOpenScan: () -> Unit = {},
    gate: VaultGate = VaultGate.NEED_BINDING,
    blePermissionGranted: Boolean? = null,
    deviceFound: Boolean? = null,
    client: AegisBleClient? = null,
) {
    Scaffold(topBar = { TopAppBar(title = { Text("Configurar via Bluetooth", maxLines = 1, overflow = TextOverflow.Ellipsis) }) }) { inner ->
        AegisScreenColumn(inner = inner) {
            GateBanner(gate = gate, onConnect = onOpenScan, onBind = onOpenScan)
            if (client != null) TestModeBanner(client)
            SectionTitle("Passo a passo")
            BleStep(1, "Segure o botao do AegisKey por 5 segundos ate piscar rapido.")
            BleStep(2, "Toque em Procurar e escolha seu AegisKey na lista.")
            BleStep(3, "Confira o servico GATT 0xFFFD e pareie com o codigo de 6 numeros.")
            BleStep(4, "Faca o vinculo (claim 0x28) e confirme no botao do aparelho.")
            if (blePermissionGranted == false) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
                ) {
                    Column(Modifier.padding(12.dp)) {
                        FriendlyText(text = "Permissao do Bluetooth desligada", maxLines = 1)
                        FriendlyText(
                            text = "Abra Ajustes > Apps > AegisKey > Permissoes e ligue Localizacao e Dispositivos proximos. Depois volte e toque em Procurar.",
                            style = MaterialTheme.typography.bodySmall,
                            maxLines = 4,
                        )
                    }
                }
            }
            if (deviceFound == false) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
                ) {
                    Column(Modifier.padding(12.dp)) {
                        FriendlyText(text = "Conecte o dispositivo", maxLines = 1)
                        FriendlyText(
                            text = "Nenhum AegisKey por perto. Aproxime o aparelho, segure o botao 5s e procure de novo.",
                            style = MaterialTheme.typography.bodySmall,
                            maxLines = 4,
                        )
                    }
                }
            }
            if (blePermissionGranted == null && deviceFound == null && client == null) {
                FriendlyText(
                    text = "Previa de teste: estados de permissao e busca aparecem aqui no app de verdade.",
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 3,
                )
            }
            Button(onClick = onOpenScan, modifier = Modifier.fillMaxWidth()) {
                Text("Procurar AegisKey", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
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
private fun BleStep(n: Int, text: String) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Text("$n. $text", style = MaterialTheme.typography.bodyMedium, maxLines = 4, overflow = TextOverflow.Ellipsis)
        }
    }
}
