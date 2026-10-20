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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.ble.BleContract
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.security.SanitizedLog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val CONTROL_POLL_MS = 2000L

/**
 * Controle pos-pareamento (menus por operacao):
 * - Reage a cada status (livre / processando / toque no botao / erro / sem conexao).
 * - NEED_UP sempre com sheet PT + Cancelar (0xBE); a tela nunca trava sem saida
 *   (Voltar + Desconectar + Tentar de novo sempre visiveis).
 * - Polling leve FFF3 a cada 2s quando READY + Re-assinar FFF2 manual.
 * - Menus por operacao: Chaves / Auth / Cofre / Log (rotas existentes, sem inventar).
 * - Textos PT simples, Material3, sem Log com PII.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeviceControlScreen(
    client: AegisBleClient,
    onOpenKeys: () -> Unit = {},
    onOpenAuth: () -> Unit = {},
    onOpenVault: () -> Unit = {},
    onOpenWallet: () -> Unit = {},
    onOpenPiv: () -> Unit = {},
    onOpenLog: () -> Unit = {},
    onBack: () -> Unit = {},
) {
    val state by client.state.collectAsState()
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var lastPoll by remember { mutableStateOf("—") }
    var upHidden by remember { mutableStateOf(false) }

    val needsUp = state.status == BleContract.STATUS_UP_NEEDED
    val isReady = state.connection == AegisBleClient.Connection.READY
    val isError = state.connection == AegisBleClient.Connection.ERROR
    val isIdle = state.connection == AegisBleClient.Connection.IDLE

    if (!needsUp) upHidden = false

    // Polling NEED_UP consciente: so quando READY, intervalo fixo, sem travar.
    LaunchedEffect(isReady) {
        while (isReady) {
            delay(CONTROL_POLL_MS)
            runCatching {
                val pending = withContext(Dispatchers.IO) { client.pollPendingOnce() }
                lastPoll = if (pending < 0) "sem conexão" else "livre ($pending pendentes)"
            }
        }
    }

    fun doResubscribe() {
        scope.launch {
            busy = true
            try {
                withContext(Dispatchers.IO) { client.ensureSubscribed() }
                DeviceLog.append(DeviceLog.Category.BLE, "re-assinar ok")
            } catch (e: Exception) {
                DeviceLog.append(DeviceLog.Category.BLE, "re-assinar falhou")
            } finally {
                busy = false
            }
        }
    }

    fun doCancel() {
        scope.launch(Dispatchers.IO) {
            client.cancel()
            SanitizedLog.record(SanitizedLog.Event.DEVICE_PRESS_CANCELLED)
            DeviceLog.append(DeviceLog.Category.BLE, "cancel 0xBE enviado")
        }
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Controle do dispositivo", maxLines = 1, overflow = TextOverflow.Ellipsis) }) }) { inner ->
        AegisScreenColumn(inner = inner) {
            SectionTitle("Situação")
            FriendlyText(
                text = "Link: " + connectionLabel(state.connection) + " · " + BleContract.statusLabel(state.status),
                maxLines = 2,
            )
            state.revision?.let { FriendlyText(text = "Revisão: 0x%02X (esperado 0x01)".format(it), maxLines = 1) }
            if (state.bonded) FriendlyText(text = "Pareado (botão + código confirmados)", maxLines = 1)
            FriendlyText(text = "Última checagem: $lastPoll", maxLines = 1)
            if (busy) CircularProgressIndicator()

            if (needsUp && !upHidden) {
                PressDeviceSheet(
                    statusLabel = BleContract.statusLabel(state.status),
                    onCancel = ::doCancel,
                    onDismiss = { upHidden = true },
                )
            }

            state.error?.let {
                FriendlyText(text = "Erro: $it", maxLines = 3)
                OutlinedButton(onClick = ::doResubscribe, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                    Text("Tentar de novo (re-assinar)", maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }

            if (isError) {
                FriendlyText(
                    text = "Não conectou. Volte, confira o botão do aparelho e tente de novo.",
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 2,
                )
            }
            if (isIdle) {
                FriendlyText(
                    text = "Sem conexão. Volte para procurar e parear.",
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 2,
                )
            }

            SectionTitle("Ligação")
            OutlinedButton(onClick = ::doResubscribe, enabled = !busy && !isIdle, modifier = Modifier.fillMaxWidth()) {
                Text("Re-assinar avisos (FFF2)", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            OutlinedButton(
                onClick = {
                    scope.launch {
                        busy = true
                        try {
                            withContext(Dispatchers.IO) { client.pollPendingOnce() }
                            lastPoll = "atualizado agora"
                        } finally {
                            busy = false
                        }
                    }
                },
                enabled = !busy && isReady,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Atualizar agora", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            OutlinedButton(onClick = ::doCancel, enabled = !busy && isReady, modifier = Modifier.fillMaxWidth()) {
                Text("Cancelar operação (0xBE)", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            OutlinedButton(onClick = {
                client.disconnect()
                DeviceLog.append(DeviceLog.Category.BLE, "desconectado (app)")
            }, modifier = Modifier.fillMaxWidth()) {
                Text("Desconectar", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }

            SectionTitle("Operações")
            FriendlyText(
                text = "Escolha o que fazer. Cada uma abre sua tela e sempre dá para voltar.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 2,
            )
            Button(onClick = onOpenKeys, modifier = Modifier.fillMaxWidth()) {
                Text("Chaves: criar e ver", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Button(onClick = onOpenAuth, modifier = Modifier.fillMaxWidth()) {
                Text("Entrar: provar identidade", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Button(onClick = onOpenVault, modifier = Modifier.fillMaxWidth()) {
                Text("Cofre: ver códigos", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Button(onClick = onOpenWallet, modifier = Modifier.fillMaxWidth()) {
                Text("Carteira: Bitcoin e redes", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Button(onClick = onOpenPiv, modifier = Modifier.fillMaxWidth()) {
                Text("PIV: PIN do smartcard", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            OutlinedButton(onClick = onOpenLog, modifier = Modifier.fillMaxWidth()) {
                Text("Ver log do dispositivo", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }

            SectionTitle("Sair")
            OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
                Text("Voltar", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

private fun connectionLabel(connection: AegisBleClient.Connection): String = when (connection) {
    AegisBleClient.Connection.IDLE -> "desligado"
    AegisBleClient.Connection.SCANNING -> "procurando"
    AegisBleClient.Connection.CONNECTING -> "ligando"
    AegisBleClient.Connection.READY -> "ligado"
    AegisBleClient.Connection.ERROR -> "erro"
}
