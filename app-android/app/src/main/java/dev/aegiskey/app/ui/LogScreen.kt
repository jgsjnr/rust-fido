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
import androidx.compose.runtime.mutableIntStateOf
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
import dev.aegiskey.app.security.SdkGate
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
 *
 * A8: a leitura passa por `SdkGate.requireAudit()` (deny/NotCompiled vira
 * aviso próprio, nunca banner enganoso); a tela mostra contadores por
 * evento (EV) + filtro por opcode (ARG das linhas EV=9/10) e só metadados.
 */
@Composable
private fun FwLogSection(client: AegisBleClient) {
    val scope = rememberCoroutineScope()
    val state by client.state.collectAsState()
    var fwEvents by remember { mutableStateOf<List<FwEvent>>(emptyList()) }
    var fwDropped by remember { mutableIntStateOf(0) }
    var fwOpFilter by remember { mutableStateOf<Int?>(null) }
    var fwStatus by remember { mutableStateOf("nunca puxado") }
    var auditGate by remember { mutableStateOf<SdkGate.GateOutcome?>(null) }
    var auditNotice by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val ready = state.connection == AegisBleClient.Connection.READY

    val counts = remember(fwEvents) {
        fwEvents.groupingBy { it.ev }.eachCount().toSortedMap()
    }
    val opcodes = remember(fwEvents) {
        fwEvents.filter { it.ev == FW_EV_OP_RX || it.ev == FW_EV_OP_RESP }
            .map { it.arg }.distinct().sorted()
    }
    val displayed = remember(fwEvents, fwOpFilter) {
        if (fwOpFilter == null) fwEvents
        else fwEvents.filter {
            (it.ev == FW_EV_OP_RX || it.ev == FW_EV_OP_RESP) && it.arg == fwOpFilter
        }
    }

    fun pullFw() {
        val warning = fwAuditNotice(SdkGate.requireAudit().also { auditGate = it })
        auditNotice = warning
        if (warning != null) {
            fwStatus = warning
            DeviceLog.append(DeviceLog.Category.BLE, "fw-log gate denied")
            return
        }
        if (!ready) {
            fwStatus = "conecte primeiro (Conectar -> BLE)"
            return
        }
        scope.launch {
            busy = true
            fwStatus = "puxando..."
            try {
                val text = withContext(Dispatchers.IO) {
                    client.fetchFwLog().getOrThrow()
                }
                val (events, dropped) = parseFwLogEvents(text)
                fwEvents = events
                fwDropped = dropped
                fwOpFilter = null
                val n = text.lines().size
                fwStatus = "ok - " + n + " linhas - " + events.size + " eventos"
                DeviceLog.append(
                    DeviceLog.Category.BLE,
                    "fw-log puxado: " + n + " linhas " + events.size + " eventos " + dropped + " ilegiveis",
                )
            } catch (e: Exception) {
                val msg = (e.message ?: "falha").take(80)
                fwStatus = msg
                DeviceLog.append(DeviceLog.Category.BLE, "fw-log falhou: " + msg)
            } finally {
                busy = false
            }
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Log da firmware (0x38)", style = MaterialTheme.typography.titleSmall)
        val banner = auditGate?.let { SdkGate.gateBannerState(it) }
        if (banner != null) {
            GateBanner(gate = banner)
        }
        auditNotice?.let {
            Text(it, style = MaterialTheme.typography.bodySmall)
        }
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Button(
                enabled = ready && !busy,
                onClick = ::pullFw
            ) { Text("Puxar log da firmware") }
            if (busy) CircularProgressIndicator()
        }
        Text(
            if (ready) fwStatus else "conecte primeiro (Conectar → BLE)",
            style = MaterialTheme.typography.bodySmall
        )
        if (fwEvents.isNotEmpty()) {
            Text(
                fwEvents.size.toString() + " eventos - " + counts.size + " tipos" +
                    if (fwDropped > 0) " - " + fwDropped + " ilegiveis descartadas" else "",
                style = MaterialTheme.typography.bodySmall
            )
            Text(
                counts.entries.joinToString(" - ") { (ev, n) ->
                    "EV=" + ev + " " + fwEventName(ev) + " x" + n
                },
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                maxLines = 8,
                overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
            )
            if (opcodes.isNotEmpty()) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        selected = fwOpFilter == null,
                        onClick = { fwOpFilter = null },
                        label = { Text("Todas") }
                    )
                    for (op in opcodes) {
                        FilterChip(
                            selected = fwOpFilter == op,
                            onClick = { fwOpFilter = if (fwOpFilter == op) null else op },
                            label = { Text("0x" + String.format("%02X", op)) }
                        )
                    }
                }
            }
            Text(
                displayed.size.toString() + " linhas" +
                    (fwOpFilter?.let { " (op 0x" + String.format("%02X", it) + ")" } ?: ""),
                style = MaterialTheme.typography.bodySmall
            )
            Text(
                displayed.take(200).joinToString("\n") {
                    it.seq.toString() + " EV=" + it.ev + " ARG=" + it.arg + " T=" + it.t
                },
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                maxLines = 40,
                overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
            )
        }
    }
}

/** Uma linha do fw-log 0x38: so metadados (seq, evento, arg/opcode, tempo). */
private data class FwEvent(val seq: Int, val ev: Int, val arg: Int, val t: Long)

/** Eventos de op: o ARG carrega o opcode (filtro por opcode da A8). */
private const val FW_EV_OP_RX = 9
private const val FW_EV_OP_RESP = 10

private val FW_LINE = Regex("""^(\d{1,5}) EV=(\d{1,3}) ARG=(\d{1,3}) T=(\d{1,10})$""")

/**
 * Parseia o ASCII do fw-log (`SEQ EV=cc ARG=aa T=mmmm`, ver fw_log.rs).
 * Devolve (eventos, ilegiveis): linha fora do formato eh contada e
 * descartada, nunca exibida (regra "so opcode+status+contagem").
 */
private fun parseFwLogEvents(text: String): Pair<List<FwEvent>, Int> {
    var dropped = 0
    val events = ArrayList<FwEvent>()
    for (raw in text.split('\n')) {
        val line = raw.trim()
        if (line.isEmpty()) continue
        val m = FW_LINE.matchEntire(line)
        if (m == null) {
            dropped += 1
            continue
        }
        val (seq, ev, arg, t) = m.destructured
        events.add(FwEvent(seq.toInt(), ev.toInt(), arg.toInt(), t.toLong()))
    }
    return events to dropped
}

/** Nome curto PT de cada codigo de evento (fw_log.rs; sem PII, sem payload). */
private fun fwEventName(ev: Int): String = when (ev) {
    1 -> "boot"
    2 -> "anuncio ligado"
    3 -> "anuncio desligado"
    4 -> "janela aberta"
    5 -> "janela fechada"
    6 -> "pareamento ok"
    9 -> "op recebida"
    10 -> "resposta enviada"
    11 -> "UP pedido"
    12 -> "UP confirmado"
    13 -> "carteira"
    14 -> "resgate"
    15 -> "OTA"
    16 -> "erro"
    17 -> "anuncio sem memoria"
    else -> "evento $ev"
}

/**
 * Aviso proprio p/ outcomes sem texto honesto no GateBanner (R4):
 * gateBannerState() retorna null p/ NotCompiled/ExternalBlocked, e a
 * tela renderiza este texto em vez de banner enganoso. Null = liberado.
 */
private fun fwAuditNotice(outcome: SdkGate.GateOutcome): String? = when (outcome) {
    is SdkGate.GateOutcome.Success, SdkGate.GateOutcome.RealVerified -> null
    is SdkGate.GateOutcome.NotCompiled ->
        "Auditoria fora da compilacao deste app (fala com o dono do SDK; sem crash, sem fingir)."
    is SdkGate.GateOutcome.ExternalBlocked ->
        "Auditoria bloqueada aqui: sem transporte nativo - conecte o device e tente de novo."
    SdkGate.GateOutcome.PermissionDenied -> "toque no botao do dispositivo (UP+PIN)"
    SdkGate.GateOutcome.Unsupported -> "device recusou a leitura (firmware antiga?)"
    SdkGate.GateOutcome.Unavailable -> "device sem resposta - toque e tente de novo"
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

