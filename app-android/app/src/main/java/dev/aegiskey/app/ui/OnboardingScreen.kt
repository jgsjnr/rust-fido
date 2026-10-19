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
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.ble.AegisBleClient

/**
 * Inicio simples em PT-BR para usuario nao-tecnico.
 * Rota "onboarding" mantida (bottom bar + NavHost inalterados).
 * Jornada tecnica (journey mirror) fica colapsada em "Detalhes tecnicos".
 * Sem Log com PII.
 */
private data class JourneyStep(val title: String, val body: String)

private val STEPS = listOf(
    JourneyStep("Boot", "Splash + version. LED rainbow. Lands on Home when init is ok."),
    JourneyStep("Home", "Device active, breathing cyan. Hold the button 5s to arm pairing."),
    JourneyStep("Pairing BLE / AP", "6-digit code on LCD, breathing blue. 60s window, then Locked."),
    JourneyStep("Vault", "Label + TOTP code + 30s bar. Auto-clears in 15s back to Home."),
    JourneyStep("Locked", "Red flash. Hold 5s again to re-arm."),
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun OnboardingScreen(
    onStart: () -> Unit,
    onOpenKeys: () -> Unit = {},
    onOpenVault: () -> Unit = {},
    onOpenLog: () -> Unit = {},
    client: AegisBleClient? = null,
) {
    Scaffold(topBar = { TopAppBar(title = { Text("Início") }) }) { inner ->
        AegisScreenColumn(inner = inner) {
            SectionTitle("Status")
            StatusCard(client)
            SectionTitle("O que você quer fazer?")
            HomeActions(
                onStart = onStart,
                onOpenKeys = onOpenKeys,
                onOpenVault = onOpenVault,
                onOpenLog = onOpenLog,
            )
            HelpCard()
            TechnicalDetailsCard()
        }
    }
}

@Composable
private fun StatusCard(client: AegisBleClient?) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            if (client == null) {
                Text(
                    "Nenhum dispositivo conectado",
                    style = MaterialTheme.typography.titleMedium,
                )
                FriendlyText(
                    text = "Toque em Conectar para procurar seu AegisKey.",
                    maxLines = 3,
                )
            } else {
                val state by client.state.collectAsState()
                val label = when (state.connection) {
                    AegisBleClient.Connection.READY ->
                        "Conectado"
                    AegisBleClient.Connection.SCANNING -> "Procurando dispositivo…"
                    AegisBleClient.Connection.CONNECTING -> "Conectando…"
                    else -> "Nenhum dispositivo conectado"
                }
                Text(label, style = MaterialTheme.typography.titleMedium)
                FriendlyText(
                    text = if (state.connection == AegisBleClient.Connection.READY) {
                        "Tudo pronto. Você pode gerar chaves ou ver códigos."
                    } else {
                        "Toque em Conectar para procurar seu AegisKey."
                    },
                    maxLines = 3,
                )
            }
        }
    }
}

@Composable
private fun HomeActions(
    onStart: () -> Unit,
    onOpenKeys: () -> Unit,
    onOpenVault: () -> Unit,
    onOpenLog: () -> Unit,
) {
    Button(onClick = onStart, modifier = Modifier.fillMaxWidth()) {
        Text("Conectar")
    }
    OutlinedButton(onClick = onOpenKeys, modifier = Modifier.fillMaxWidth()) {
        Text("Gerar chave no dispositivo")
    }
    OutlinedButton(onClick = onOpenVault, modifier = Modifier.fillMaxWidth()) {
        Text("Ver código")
    }
    OutlinedButton(onClick = onOpenLog, modifier = Modifier.fillMaxWidth()) {
        Text("Ver registros")
    }
}

@Composable
private fun HelpCard() {
    var expanded by remember { mutableStateOf(false) }
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Text("Precisa de ajuda?", style = MaterialTheme.typography.titleMedium)
            FriendlyText(
                text = "Segure o botão do dispositivo por 5 segundos até piscar rápido.",
                maxLines = 3,
            )
            TextButton(onClick = { expanded = !expanded }) {
                Text(if (expanded) "Ocultar ajuda" else "Como parear")
            }
            if (expanded) {
                FriendlyText(
                    text = "1. Segure o botão 5s. 2. Confirme o código de 6 números na tela Conectar. " +
                        "3. O botão do dispositivo sempre confirma — o app nunca decide sozinho.",
                    maxLines = 6,
                )
            }
        }
    }
}

@Composable
private fun TechnicalDetailsCard() {
    var expanded by remember { mutableStateOf(false) }
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Text("Detalhes técnicos", style = MaterialTheme.typography.titleMedium)
            FriendlyText(
                text = "Só para quem entende do dispositivo. Pode ignorar.",
                maxLines = 2,
            )
            TextButton(onClick = { expanded = !expanded }) {
                Text(if (expanded) "Ocultar" else "Mostrar")
            }
            if (expanded) {
                for (step in STEPS) {
                    Text(step.title, style = MaterialTheme.typography.titleSmall)
                    FriendlyText(text = step.body, maxLines = 5)
                }
                FriendlyText(
                    text = "As chaves nunca saem do dispositivo. Só códigos viajam.",
                    maxLines = 3,
                )
            }
        }
    }
}
