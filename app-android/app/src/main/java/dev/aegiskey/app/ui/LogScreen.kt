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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.log.DeviceLog

private fun formatTs(ts: Long): String {
    val total = ts % 86_400_000
    val hh = total / 3_600_000
    val mm = (total % 3_600_000) / 60_000
    val ss = (total % 60_000) / 1000
    val ms = total % 1000
    return String.format("%02d:%02d:%02d.%03d", hh, mm, ss, ms)
}

/**
 * Log do dispositivo (debug): texto ao vivo de tudo que o app ve do device
 * conectado — notifies FFF2, requests/responses FFF1 (opcodes + status, sem
 * payload sensivel), keepalive, HTTP WiFi (metodo + path + status) e eventos
 * de pairing/lock locais. Cada linha tem timestamp. Sem PII em tela ou copy.
 * FLAG_SECURE ja vale app-wide (MainActivity); ltrace completo via serial
 * (live_monitor.py).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LogScreen() {
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
                "Fonte: trafego observado pelo app (BLE FFF1/FFF2 + HTTP WiFi). " +
                    "Opcodes, status e tamanhos apenas — sem payload sensivel. " +
                    "ltrace completo via serial (live_monitor.py).",
                style = MaterialTheme.typography.bodySmall
            )
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

@Composable
private fun LogControls(
    paused: Boolean,
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

