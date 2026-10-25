package dev.aegiskey.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.net.WifiApi
import dev.aegiskey.app.net.WifiDiscovery
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * WiFi: mDNS (`aegiskey-*.local` via NsdManager) + IP manual com fallback transparente
 * + teste de conexão + leitura de TOTP (/oath/code) + configuração completa do AP (SSID/WPA2/Canal).
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
    var msg by remember { mutableStateOf("Digite o IP ou descubra via mDNS (fallback automático 10.0.2.2 ativo).") }

    // Estados de leitura de TOTP
    var totpAccount by remember { mutableStateOf("AegisKey:admin") }
    var totpResult by remember { mutableStateOf<String?>(null) }
    var totpBusy by remember { mutableStateOf(false) }

    // Estados de configuração da rede Wi-Fi
    var cfgSsid by remember { mutableStateOf("AegisKey-AP") }
    var cfgPassword by remember { mutableStateOf("12345678") }
    var cfgChannel by remember { mutableIntStateOf(6) }
    var cfgPowerSave by remember { mutableStateOf(false) }
    var cfgBusy by remember { mutableStateOf(false) }
    var cfgResult by remember { mutableStateOf<String?>(null) }

    DisposableEffect(discovery) {
        onDispose { discovery.stop() }
    }

    fun loadNets() {
        scope.launch {
            busy = true
            try {
                val list = withContext(Dispatchers.IO) { WifiApi.getWifiNets(baseUrl.trim()) }
                nets = list
                msg = if (list.isEmpty()) "Nenhuma rede salva no momento." else "${list.size} rede(s) no dispositivo."
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
                msg = if (ok) "Dispositivo acessível em $baseUrl (ou fallback 10.0.2.2:5678)." else "Sem resposta — confira o AP ou ponte USB/UART."
            } finally {
                busy = false
            }
        }
    }

    fun fetchTotp() {
        scope.launch {
            totpBusy = true
            totpResult = "Consultando hardware via GET /oath/code..."
            try {
                val res = withContext(Dispatchers.IO) { WifiApi.fetchOathCode(baseUrl.trim(), totpAccount.trim()) }
                totpResult = res.fold(
                    onSuccess = { entry -> "Código OTP: ${entry.code} · Restam ${entry.remainingSeconds}s" },
                    onFailure = { err -> "Falha: ${err.message ?: "Erro ao ler OTP"}" }
                )
            } finally {
                totpBusy = false
            }
        }
    }

    fun saveWifiConfig() {
        scope.launch {
            cfgBusy = true
            cfgResult = "Gravando parâmetros Wi-Fi no hardware..."
            try {
                val res = withContext(Dispatchers.IO) {
                    WifiApi.configureWifi(
                        baseUrl = baseUrl.trim(),
                        ssid = cfgSsid.trim(),
                        password = cfgPassword,
                        channel = cfgChannel,
                        powerSave = cfgPowerSave
                    )
                }
                cfgResult = res.getOrElse { "Erro: ${it.localizedMessage}" }
            } finally {
                cfgBusy = false
            }
        }
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Wi-Fi & SoftAP", maxLines = 1, overflow = TextOverflow.Ellipsis) }) }) { inner ->
        AegisScreenColumn(inner = inner) {
            SectionTitle("Endereço do dispositivo")
            OutlinedTextField(
                value = baseUrl,
                onValueChange = { baseUrl = it },
                label = { Text("IP manual (ex.: http://192.168.4.1)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(onClick = ::test, enabled = !busy && baseUrl.isNotBlank(), modifier = Modifier.fillMaxWidth()) {
                if (busy) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                    Spacer(modifier = Modifier.width(8.dp))
                }
                Text("Testar conexão", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            FriendlyText(text = msg, maxLines = 2)

            Spacer(modifier = Modifier.height(8.dp))

            // --- Seção: Leitura de TOTP via Wi-Fi ---
            SectionTitle("Leitura de TOTP via Wi-Fi (/oath/code)")
            Card(
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = totpAccount,
                        onValueChange = { totpAccount = it },
                        label = { Text("Conta TOTP (ex.: AegisKey:admin ou GitHub:user)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Button(
                        onClick = ::fetchTotp,
                        enabled = !totpBusy && totpAccount.isNotBlank(),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        if (totpBusy) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                            Spacer(modifier = Modifier.width(8.dp))
                        }
                        Text("Ler TOTP do Hardware (/oath/code)", maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    totpResult?.let { result ->
                        Text(
                            text = result,
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace,
                            color = if (result.contains("Código")) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            // --- Seção: Configuração da Rede Wi-Fi ---
            SectionTitle("Configurar Rede Wi-Fi da Chave")
            Card(
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = cfgSsid,
                        onValueChange = { cfgSsid = it },
                        label = { Text("Nome da Rede (SSID)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = cfgPassword,
                        onValueChange = { cfgPassword = it },
                        label = { Text("Senha WPA2 (mínimo 8 caracteres)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )

                    Text("Canal Wi-Fi (2.4 GHz)", style = MaterialTheme.typography.labelMedium)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceEvenly
                    ) {
                        listOf(1, 6, 11).forEach { ch ->
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.clickable { cfgChannel = ch }
                            ) {
                                RadioButton(selected = cfgChannel == ch, onClick = { cfgChannel = ch })
                                Text("Canal $ch", style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text("Modo Economia de Energia", style = MaterialTheme.typography.bodySmall)
                        Switch(checked = cfgPowerSave, onCheckedChange = { cfgPowerSave = it })
                    }

                    Button(
                        onClick = ::saveWifiConfig,
                        enabled = !cfgBusy && cfgSsid.isNotBlank() && cfgPassword.length >= 8,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        if (cfgBusy) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                            Spacer(modifier = Modifier.width(8.dp))
                        }
                        Text("Gravar Configuração no Hardware", maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }

                    cfgResult?.let { result ->
                        Text(
                            text = result,
                            style = MaterialTheme.typography.bodySmall,
                            color = if (result.contains("sucesso", ignoreCase = true)) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            SectionTitle("Descoberta (mDNS)")
            FriendlyText(
                text = "Procura aegiskey-*.local na rede. Se não achar, use o IP manual ou a ponte host.",
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
            if (nets.isNotEmpty()) {
                for (ssid in nets) {
                    ListItem(
                        headlineContent = { Text(ssid, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                    )
                }
            }
        }
    }
}
