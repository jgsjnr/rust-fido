package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import dev.aegiskey.app.usb.UsbCtaphid
import kotlinx.coroutines.launch

/**
 * Conectar-USB (host): acha VID 0x303A / PID 0xAE61, pede permissao,
 * abre, reivindica a interface CTAPHID e testa com PING 64B interrupt
 * (mesmo framing do firmware). Status conectado + fallback "use BLE".
 * Sem Log com PII: so status/tamanhos (ver UsbCtaphid/DeviceLog).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun UsbScreen(onUseBle: () -> Unit = {}) {
    val context = LocalContext.current
    val usb = remember { UsbCtaphid(context) }
    val ui by usb.ui.collectAsState()
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var detail by remember { mutableStateOf("Toque em Procurar com o dispositivo plugado.") }

    DisposableEffect(usb) {
        onDispose { usb.release() }
    }

    val searching = busy || ui.state == UsbCtaphid.State.SEARCHING
    val waitingPermission = ui.state == UsbCtaphid.State.PERMISSION_NEEDED
    val connected = ui.state == UsbCtaphid.State.CONNECTED

    Scaffold(topBar = { TopAppBar(title = { Text("Conectar USB", maxLines = 1, overflow = TextOverflow.Ellipsis) }) }) { inner ->
        AegisScreenColumn(inner = inner) {
            SectionTitle("Chave via cabo (USB host)")
            FriendlyText(text = "Estado: " + ui.label, maxLines = 2)
            ui.error?.let {
                Text("Erro: " + it, color = MaterialTheme.colorScheme.error, maxLines = 3, overflow = TextOverflow.Ellipsis)
            }
            if (searching) CircularProgressIndicator()

            Button(
                onClick = {
                    scope.launch {
                        busy = true
                        detail = "Procurando..."
                        try {
                            usb.markSearching()
                            val device = usb.findDevice()
                            if (device == null) {
                                usb.noteNotFound()
                                detail = "AegisKey nao achada. Confira o cabo OTG. Tente de novo ou use BLE."
                            } else {
                                usb.requestPermission(device)
                                detail = "Confirme a permissao no dialogo do sistema."
                            }
                        } finally {
                            busy = false
                        }
                    }
                },
                enabled = !busy && !connected && !waitingPermission && ui.state != UsbCtaphid.State.SEARCHING,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Procurar AegisKey USB", maxLines = 1, overflow = TextOverflow.Ellipsis) }

            OutlinedButton(
                onClick = {
                    scope.launch {
                        busy = true
                        try {
                            val ok = usb.pingTest()
                            detail = if (ok) "Teste PING ok — canal 64B funcionando." else "Teste falhou — tente de novo ou use BLE."
                        } finally {
                            busy = false
                        }
                    }
                },
                enabled = !busy && connected,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Testar conexao (PING)", maxLines = 1, overflow = TextOverflow.Ellipsis) }

            OutlinedButton(
                onClick = {
                    usb.close()
                    detail = "Desconectado. Toque em Procurar para tentar de novo."
                },
                enabled = ui.state != UsbCtaphid.State.IDLE,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Desconectar USB", maxLines = 1, overflow = TextOverflow.Ellipsis) }

            FriendlyText(text = detail, maxLines = 4)
            FriendlyText(
                text = "Sem cabo ou sem resposta? Use BLE (sem fio).",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 2,
            )
            OutlinedButton(onClick = onUseBle, modifier = Modifier.fillMaxWidth()) {
                Text("Usar BLE em vez disso", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}
