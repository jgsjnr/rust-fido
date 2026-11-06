package dev.aegiskey.app.testterminal

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState

import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import dev.aegiskey.app.R
import dev.aegiskey.app.data.transport.HostUsbUartBridgeClient
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.log.TerminalLogStyle
import kotlinx.coroutines.launch

/**
 * Diálogo do Terminal de Testes (lab, test-mode only).
 *
 * Menu com o catálogo [TestTerminal.CATALOG] (cada item: descrição +
 * botão enviar) e console de saída estilo terminal — mesmo visual do
 * [TerminalLogStyle] maker usado pelo AuditLogsModalDialog (fundo
 * terminal, mono, dots, auto-scroll lifecycle-aware).
 *
 * Envia via `POST /bridge/text_line {line}`; endpoint ausente mostra
 * "ponte sem suporte" (fail-closed). O chamador só monta este diálogo
 * quando [TestTerminal.isVisible] é true (em release some).
 */
@Composable
fun TestTerminalDialog(
    onDismiss: () -> Unit,
    bridgeClient: HostUsbUartBridgeClient,
) {
    val console = remember { mutableStateListOf<String>() }
    var sendingLine by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val listState = rememberLazyListState()
    val menuScroll = rememberScrollState()
    val lifecycleOwner = LocalLifecycleOwner.current
    var isForeground by remember { mutableStateOf(true) }
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_START, Lifecycle.Event.ON_RESUME -> isForeground = true
                Lifecycle.Event.ON_PAUSE, Lifecycle.Event.ON_STOP -> isForeground = false
                else -> Unit
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }
    val terminalBg = Color(TerminalLogStyle.BACKGROUND_ARGB.toULong())
    val terminalText = Color(TerminalLogStyle.TEXT_ARGB.toULong())
    val terminalDim = Color(TerminalLogStyle.DIM_ARGB.toULong())
    val terminalPrompt = Color(TerminalLogStyle.PROMPT_ARGB.toULong())

    // Auto-scroll acompanha o fim somente com o terminal visível
    // (foreground); ao voltar do background, salta para o estado atual.
    LaunchedEffect(console.size, isForeground) {
        if (isForeground && console.isNotEmpty()) listState.scrollToItem(console.size - 1)
    }

    fun send(line: String) {
        if (sendingLine != null) return
        sendingLine = line
        scope.launch {
            try {
                console.add(TestTerminal.txLine(line))
                DeviceLog.append(DeviceLog.Category.SYSTEM, "TEST_TX $line")
                when (val res = bridgeClient.postTextLine(line)) {
                    is HostUsbUartBridgeClient.TextLineResult.Ok -> {
                        when (val ack = TestTerminal.classifyAck(line, res.body)) {
                            is TestTerminal.Ack.Ok -> console.add(TestTerminal.rxLine(ack.body))
                            TestTerminal.Ack.IgnoredRelease -> console.add(TestTerminal.ignoredLine())
                            TestTerminal.Ack.Unrecognized -> console.add(TestTerminal.rxLine(res.body))
                        }
                        DeviceLog.append(DeviceLog.Category.SYSTEM, "TEST_RX $line <- ${res.body.trim().take(120)}")
                    }
                    HostUsbUartBridgeClient.TextLineResult.BridgeUnsupported ->
                        console.add(TestTerminal.unsupportedLine())
                    HostUsbUartBridgeClient.TextLineResult.TransportError ->
                        console.add(TestTerminal.transportErrorLine())
                }
            } finally {
                sendingLine = null
            }
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(14.dp),
        containerColor = terminalBg,
        titleContentColor = terminalText,
        textContentColor = terminalText,
        title = {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Window dots (decorative, read-only terminal header)
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Box(modifier = Modifier.size(11.dp).clip(CircleShape).background(Color(0xFFFF5F57)))
                    Box(modifier = Modifier.size(11.dp).clip(CircleShape).background(Color(0xFFFEBC2E)))
                    Box(modifier = Modifier.size(11.dp).clip(CircleShape).background(Color(0xFF28C840)))
                }
                Spacer(modifier = Modifier.width(10.dp))
                Text(
                    text = stringResource(R.string.test_terminal_title) + " -- test-mode",
                    style = MaterialTheme.typography.labelLarge,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    color = terminalText,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
                TextButton(onClick = { console.clear() }) {
                    Text(
                        stringResource(R.string.action_clear_logs),
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = FontFamily.Monospace,
                        color = terminalPrompt
                    )
                }
            }
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(440.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Text(
                    text = "$ " + stringResource(R.string.test_terminal_desc),
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace,
                    color = terminalDim,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
                if (!isForeground) {
                    Text(
                        text = "$ [pausado em background -- retomando ao voltar]",
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = FontFamily.Monospace,
                        color = terminalPrompt,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                // Menu: catálogo TEST_* com descrição + botão enviar.
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f)
                        .verticalScroll(menuScroll),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    TestTerminal.CATALOG.forEach { hook ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = hook.line,
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    color = terminalText,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    text = hook.description,
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = terminalDim,
                                    maxLines = 2,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                            Spacer(modifier = Modifier.width(8.dp))
                            OutlinedButton(
                                onClick = { send(hook.line) },
                                enabled = sendingLine == null,
                                shape = RoundedCornerShape(8.dp)
                            ) {
                                Text(
                                    if (sendingLine == hook.line) "$ ..." else "$ " + stringResource(R.string.test_terminal_send),
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                        }
                    }
                }
                // Console de saída estilo terminal (auto-scroll).
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f)
                        .clip(RoundedCornerShape(8.dp))
                        .background(Color(TerminalLogStyle.SURFACE_ARGB.toULong()))
                        .padding(horizontal = 8.dp, vertical = 6.dp)
                ) {
                    if (console.isEmpty()) {
                        Box(
                            modifier = Modifier.fillMaxSize(),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = "$ " + stringResource(R.string.test_terminal_empty),
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                color = terminalDim
                            )
                        }
                    } else {
                        SelectionContainer {
                            LazyColumn(
                                state = listState,
                                modifier = Modifier.fillMaxSize(),
                                verticalArrangement = Arrangement.spacedBy(3.dp)
                            ) {
                                items(console.size) { idx ->
                                    val line = console[idx]
                                    val isTx = line.startsWith("> ")
                                    Text(
                                        text = buildAnnotatedString {
                                            withStyle(
                                                SpanStyle(
                                                    color = terminalPrompt,
                                                    fontWeight = FontWeight.Bold
                                                )
                                            ) {
                                                append(if (isTx) "> " else "< ")
                                            }
                                            withStyle(SpanStyle(color = if (isTx) terminalText else terminalDim)) {
                                                append(line.drop(2))
                                            }
                                        },
                                        style = MaterialTheme.typography.labelSmall,
                                        fontFamily = FontFamily.Monospace
                                    )
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text(
                    stringResource(R.string.guard_btn_close),
                    fontFamily = FontFamily.Monospace,
                    color = terminalPrompt
                )
            }
        }
    )
}
