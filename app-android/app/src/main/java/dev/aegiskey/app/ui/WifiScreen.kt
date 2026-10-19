package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import dev.aegiskey.app.net.WifiApi
import dev.aegiskey.app.net.WifiDiscovery
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * WiFi: mDNS (`aegiskey-*.local` via NsdManager) + IP manual
 * + redes salvas do device (GET /wifi/nets) + teste de conexao.
 * Sem permissao nova (so INTERNET, ja declarada). IP manual e o
 * caminho primario; mDNS e conveniencia. Sem PII no log (so contagens).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WifiScreen() {
    val context = LocalContext.current
    val discovery = remember { WifiDiscovery(context) }
    val found by discovery.found.collectAsState()
    val scanning by discovery.scanning.collectAsState()
    val scope = rememberCoroutineScope()

    var baseUrl by remember { mutableStateOf("http://192.168.4.1") }
    var nets by remember { mutableStateOf(listOf<String>()) }
    var busy by remember { mutableStateOf(false) }
    var msg by remember { mutableStateOf("Digite o IP ou descubra via mDNS.") }

    DisposableEffect(discovery) {
        onDispose { discovery.stop() }
    }

    fun loadNets() {
        scope.launch {
            busy = true
            try {
                val list = withContext(Dispatchers.IO) { WifiApi.getWifiNets(baseUrl.trim()) }
                nets = list
                msg = if (list.isEmpty()) "Nenhuma rede salva (ou device sem essa tela ainda)." else list.size.toString() + " rede(s) no dispositivo."
            } catch (e: Exception) {
                msg = (e.message ?: "falha ao carregar").take(64)
            } finally {
                busy = false
            }
        }
    }

    fun test() {
        scope.launch {
            busy = true
            try {
                val ok = withContext(Dispatchers.IO) { WifiApi.testConnection(baseUrl.trim()) }
                msg = if (ok) "Dispositivo alcancavel em " + baseUrl.trim() else "Sem resposta — confira IP e AP."
            } finally {
                busy = false
            }
        }
    }

    Scaffold(topBar = { TopAppBar(title = { Text("WiFi", maxLines = 1, overflow = TextOverflow.Ellipsis) }) }) { inner ->
        AegisScreenColumn(inner = inner) {
            SectionTitle("Endereco do dispositivo")
            OutlinedTextField(
                value = baseUrl,
                onValueChange = { baseUrl = it },
                label = { Text("IP manual (ex.: http://192.168.4.1)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(onClick = ::test, enabled = !busy && baseUrl.isNotBlank(), modifier = Modifier.fillMaxWidth()) {
                Text("Testar conexao", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }

            SectionTitle("Descoberta (mDNS)")
            FriendlyText(
                text = "Procura aegiskey-*.local na rede. Se nao achar, use o IP manual.",
                maxLines = 2,
            )
            OutlinedButton(
                onClick = { if (scanning) discovery.stop() else discovery.start() },
                modifier = Modifier.fillMaxWidth(),
            ) { Text(if (scanning) "Parar descoberta" else "Descobrir via mDNS", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            if (found.isEmpty()) {
                FriendlyEmpty(message = if (scanning) "Procurando… aproxime-se do AP do dispositivo." else "Nada aqui ainda. Toque em Descobrir ou digite o IP.")
            } else {
                for (entry in found) {
                    ListItem(
                        headlineContent = { Text(entry.name, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                        supportingContent = { Text(entry.host + ":" + entry.port, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                        trailingContent = {
                            OutlinedButton(onClick = { baseUrl = "http://" + entry.host + ":" + entry.port }) {
                                Text("Usar", maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }
                        },
                    )
                }
            }

            SectionTitle("Redes salvas no dispositivo")
            OutlinedButton(onClick = ::loadNets, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                Text("Carregar redes (GET /wifi/nets)", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            if (busy) CircularProgressIndicator()
            if (nets.isEmpty()) {
                FriendlyText(text = msg, maxLines = 2)
            } else {
                for (ssid in nets) {
                    ListItem(
                        headlineContent = { Text(ssid, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                    )
                }
                FriendlyText(text = msg, maxLines = 1, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}
