package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.log.DeviceLog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private fun formatTs(ts: Long): String {
    val total = ts % 86_400_000
    val hh = total / 3_600_000
    val mm = (total % 3_600_000) / 60_000
    val ss = (total % 60_000) / 1000
    val ms = total % 1000
    return String.format("%02d:%02d:%02d.%03d", hh, mm, ss, ms)
}

/**
 * Log do dispositivo (debug), duas fontes:
 * (a) tráfego observado pelo app — notifies FFF2, requests/responses FFF1
 *     (opcodes + status, sem payload sensivel), HTTP WiFi e eventos de
 *     pairing/lock locais, ao vivo abaixo;
 * (b) LOG REAL DA FIRMWARE (op 0x38) — anel de eventos do device (boot,
 *     janela, bond, ops + status), puxado sob demanda na seção própria.
 * Sem PII em tela ou copy. FLAG_SECURE ja vale app-wide (MainActivity);
 * ltrace completo via serial (live_monitor.py).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LogScreen(client: AegisBleClient) {
    val live by DeviceLog.entries.collectAsState()
    var filter by remember { mutableStateOf<DeviceLog.Category?>(null) }
    var paused by remember { mutableStateOf(false) }
    var autoScroll by remember { mutableStateOf(true) }
    var frozen by remember { mutableStateOf<List<DeviceLog.Entry>>(emptyList()) }
    val clipboard = LocalClipboardManager.current
    val listState = rememberLazyListState()

    LaunchedEffect(live, paused) { if (!paused) frozen = live }
    val source = if (paused) frozen else live
    val displayed = remember(source, filter) {
        (if (filter == null) source else source.filter { it.category == filter }).takeLast(300)
    }
    LaunchedEffect(displayed.size, autoScroll, paused) {
        if (autoScroll && !paused && displayed.isNotEmpty()) {
            runCatching { listState.scrollToItem(displayed.size - 1) }
        }
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Log do dispositivo") }) }) { inner ->
        Column(
            Modifier.padding(inner).fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                "Fonte (a): trafego observado pelo app (BLE FFF1/FFF2 + HTTP WiFi). " +
                    "Opcodes, status e tamanhos apenas — sem payload sensivel. " +
                    "Fonte (b): log real da firmware, seção abaixo.",
                style = MaterialTheme.typography.bodySmall
            )
            FwLogSection(client)
            LogControls(
                paused = paused,
                autoScroll = autoScroll,
                onPause = { paused = !paused },
                onAutoScroll = { autoScroll = it },
                onClear = { DeviceLog.clear() },
                onCopy = { clipboard.setText(AnnotatedString(DeviceLog.snapshotText())) }
            )
            LogFilterRow(filter = filter, onFilter = { filter = it })
            Text(
                displayed.size.toString() + " linhas" + if (paused) " (pausado)" else "",
                style = MaterialTheme.typography.bodySmall
            )
            LazyColumn(
                modifier = Modifier.weight(1f).fillMaxWidth(),
                state = listState,
                verticalArrangement = Arrangement.spacedBy(2.dp)
            ) {
                items(displayed, key = { it.id }) { entry ->
                    Text(
                        formatTs(entry.ts) + " [" + entry.category + "] " + entry.line,
                        style = MaterialTheme.typography.bodySmall,
                        maxLines = 3,
                        overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }
        }
    }
}

/**
 * Fonte (b): LOG REAL DA FIRMWARE via op 0x38 (anel em RAM: boot, janela,
 * bond, ops + status — sem PII). Exige link READY + vínculo no BLE;
 * firmware antiga sem a op responde com falha amigável.
 */
@Composable
private fun FwLogSection(client: AegisBleClient) {
    val scope = rememberCoroutineScope()
    val state by client.state.collectAsState()
    var fwText by remember { mutableStateOf<String?>(null) }
    var fwStatus by remember { mutableStateOf("nunca puxado") }
    var busy by remember { mutableStateOf(false) }
    val ready = state.connection == AegisBleClient.Connection.READY

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Log da firmware (0x38)", style = MaterialTheme.typography.titleSmall)
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Button(
                enabled = ready && !busy,
                onClick = {
                    scope.launch {
                        busy = true
                        fwStatus = "puxando..."
                        try {
                            val text = withContext(Dispatchers.IO) {
                                client.fetchFwLog().getOrThrow()
                            }
                            fwText = text
                            val n = text.lines().size
                            fwStatus = "ok · " + n + " linhas"
                            DeviceLog.append(DeviceLog.Category.BLE, "fw-log puxado: " + n + " linhas")
                        } catch (e: Exception) {
                            val msg = (e.message ?: "falha").take(80)
                            fwStatus = msg
                            DeviceLog.append(DeviceLog.Category.BLE, "fw-log falhou: " + msg)
                        } finally {
                            busy = false
                        }
                    }
                }
            ) { Text("Puxar log da firmware") }
            if (busy) CircularProgressIndicator()
        }
        Text(
            if (ready) fwStatus else "conecte primeiro (Conectar → BLE)",
            style = MaterialTheme.typography.bodySmall
        )
        fwText?.let { text ->
            Text(
                text,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                maxLines = 40,
                overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun LogControls(    paused: Boolean,
    autoScroll: Boolean,
    onPause: () -> Unit,
    onAutoScroll: (Boolean) -> Unit,
    onClear: () -> Unit,
    onCopy: () -> Unit,
) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        OutlinedButton(onClick = onPause) { Text(if (paused) "Retomar" else "Pausar") }
        OutlinedButton(onClick = onClear) { Text("Limpar") }
        OutlinedButton(onClick = onCopy) { Text("Copiar") }
    }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
        Switch(checked = autoScroll, onCheckedChange = onAutoScroll)
        Text("Autoscroll", style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun LogFilterRow(
    filter: DeviceLog.Category?,
    onFilter: (DeviceLog.Category?) -> Unit,
) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        FilterChip(selected = filter == null, onClick = { onFilter(null) }, label = { Text("Todas") })
        for (category in DeviceLog.Category.values()) {
            FilterChip(
                selected = filter == category,
                onClick = { onFilter(if (filter == category) null else category) },
                label = { Text(category.name) }
            )
        }
    }
}

