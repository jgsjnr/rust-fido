package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.log.DeviceLog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Resgate (diagnostico): PING + DIAGNOSTICS via Rescue `0x2E`.
 *
 * O frame RESC viaja como **payload de `OP_MSG (0x83)`**
 * (`[0x2E, MAGIC, VER, CMD, LEN_BE, ...]` via [AegisBleClient.sendMsg]),
 * nunca como opcode de fragmento (`gatt_core.rs` rejeita `0x2E` no
 * reassembler; o dispatch BLE so desvia `0x2E` dentro do ramo `OP_MSG`).
 * Resposta: `[0x83, status RESC, corpo...]` ([RescueOps.parseResponse]).
 *
 * So operacoes somente-leitura (UP fisico): ping prova vida do canal e
 * diagnostico mostra flags por subsistema — tudo vindo do device
 * (nada inventado: campos ausentes/malformados viram "resposta ilegivel").
 * Destrutivos (wipe/killswitch/reboot, `0x03/0x05/0x06`) exigem sessao
 * PIN viva + UP e nao tem botao aqui (fail-closed, sem um toque).
 * Sem Log com PII (so cmd/status/tamanhos).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RescueScreen(client: AegisBleClient, onBack: () -> Unit) {
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("—") }
    var ping by remember { mutableStateOf<RescueOps.PingInfo?>(null) }
    var diag by remember { mutableStateOf<RescueOps.Diagnostics?>(null) }

    fun send(cmd: Int, onOk: (ByteArray) -> Unit) {
        scope.launch {
            busy = true
            message = "aperte o botao do dispositivo e aguarde..."
            var payload = ByteArray(0)
            try {
                payload = RescueOps.opMsgPayload(cmd)
                val raw = withContext(Dispatchers.IO) { client.sendMsg(payload) }
                val resp = RescueOps.parseResponse(raw)
                when {
                    resp == null -> {
                        message = "resposta ilegivel — tente de novo"
                        DeviceLog.append(DeviceLog.Category.BLE, "rescue 0x2E sem eco OP_MSG")
                    }
                    resp.status != RescueOps.STATUS_OK -> {
                        message = RescueOps.statusLabel(resp.status)
                        DeviceLog.append(
                            DeviceLog.Category.BLE,
                            "rescue 0x2E " + RescueOps.cmdName(cmd) +
                                " status=" + resp.status,
                        )
                    }
                    else -> {
                        onOk(resp.body)
                        DeviceLog.append(
                            DeviceLog.Category.BLE,
                            "rescue 0x2E " + RescueOps.cmdName(cmd) +
                                " ok bytes=" + resp.body.size,
                        )
                        message = "resposta do dispositivo abaixo"
                    }
                }
            } catch (e: Exception) {
                message = (e.message ?: "falha no resgate").take(64)
            } finally {
                AegisBridge.wipe(payload)
                busy = false
            }
        }
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Resgate (diagnostico)", maxLines = 1, overflow = TextOverflow.Ellipsis) }) }) { inner ->
        AegisScreenColumn(inner = inner) {
            SectionTitle("Prova de vida do dispositivo")
            Card {
                Column(Modifier.padding(12.dp)) {
                    FriendlyText(
                        text = "Pergunta direto ao dispositivo (sem conta, sem nuvem). Aperte o botao dele antes de cada tentativa.",
                        maxLines = 3,
                    )
                    FriendlyText(
                        text = "So leitura: ping e diagnostico nao mudam nada no dispositivo.",
                        style = MaterialTheme.typography.bodySmall,
                        maxLines = 2,
                    )
                }
            }
            PingCard(
                ping = ping,
                busy = busy,
                onPing = {
                    send(RescueOps.CMD_PING) { body ->
                        val info = RescueOps.parsePing(body)
                        if (info == null) {
                            message = "resposta ilegivel — tente de novo"
                        } else {
                            ping = info
                        }
                    }
                },
            )
            DiagnosticsCard(
                diag = diag,
                busy = busy,
                onCheck = {
                    send(RescueOps.CMD_DIAGNOSTICS) { body ->
                        val info = RescueOps.parseDiagnostics(body)
                        if (info == null) {
                            message = "resposta ilegivel — tente de novo"
                        } else {
                            diag = info
                        }
                    }
                },
            )
            if (busy) CircularProgressIndicator()
            FriendlyText(text = "Resultado: " + message, maxLines = 3)
            DestructiveNoteCard()
            OutlinedButton(onClick = onBack, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                Text("Voltar", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

/** Secao ping: botao + contadores reais do device (ou nada). */
@Composable
private fun PingCard(ping: RescueOps.PingInfo?, busy: Boolean, onPing: () -> Unit) {
    Card {
        Column(Modifier.padding(12.dp)) {
            FriendlyText(text = "Ping (prova de vida)", maxLines = 1)
            FriendlyText(
                text = "O dispositivo responde versao + contadores internos.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 2,
            )
            Button(
                onClick = onPing,
                enabled = !busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Ping (aperte o botao)", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            ping?.let {
                FriendlyText(
                    text = "versao " + it.version +
                        " · panics " + it.panicCount +
                        " · wipes " + it.wipeCount +
                        " · modo-recuperacao " + (if (it.recoveryMode) "sim" else "nao"),
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 3,
                )
            }
        }
    }
}

/** Secao diagnostico: botao + flags reais por subsistema (ou nada). */
@Composable
private fun DiagnosticsCard(diag: RescueOps.Diagnostics?, busy: Boolean, onCheck: () -> Unit) {
    Card {
        Column(Modifier.padding(12.dp)) {
            FriendlyText(text = "Diagnostico (subsistemas)", maxLines = 1)
            FriendlyText(
                text = "O dispositivo informa cada parte: cripto, memoria, sorteio e botao.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 2,
            )
            Button(
                onClick = onCheck,
                enabled = !busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Verificar (aperte o botao)", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            diag?.let {
                FriendlyText(
                    text = "cripto " + okWord(it.cryptoOk) +
                        " · memoria " + okWord(it.flashOk) +
                        " · sorteio " + okWord(it.rngOk) +
                        " · botao " + okWord(it.buttonOk),
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 3,
                )
            }
        }
    }
}

private fun okWord(ok: Boolean): String = if (ok) "ok" else "falha"

/** Aviso fail-closed: destrutivos sem botao (exigem sessao PIN + UP). */
@Composable
private fun DestructiveNoteCard() {
    Card {
        Column(Modifier.padding(12.dp)) {
            FriendlyText(text = "Apagar de emergencia (sem botao aqui)", maxLines = 1)
            FriendlyText(
                text = "Apagar tudo, reiniciar ou killswitch pedem a senha do dispositivo + o botao juntos. Por seguranca, isso nao e um toque na tela.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 4,
            )
        }
    }
}
