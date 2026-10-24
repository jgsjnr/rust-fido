package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.net.OtaApi
import dev.aegiskey.app.net.OtaManifest
import dev.aegiskey.app.net.OtaOp
import dev.aegiskey.app.security.SdkGate
import dev.aegiskey.app.usb.UsbCtaphid
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Atualizacao OTA end-to-end (transporte-only, fechada).
 *
 * - HTTP: manifesto + binario via [OtaApi] (fetchManifest/fetchBinary ja
 *   existentes: sha/size checados, erros sanitizados). O app nunca ve
 *   chaves; a assinatura e verificada no device.
 * - USB: binario baixado e empurrado via [UsbCtaphid.pushOtaImage]
 *   (fatia 0x30 em pacotes CTAPHID 64B por OtaTransfer, aborta no primeiro
 *   write-fail). Exige USB CONNECTED.
 * - BLE estagiado: BEGIN (0x30) + CHUNKs (0x31) + FINISH (0x32) + ABORT
 *   (0x34) via builders de [OtaApi] (gate SdkGate.requireOta + manifest
 *   104 B validado antes de qualquer stage) transportados por
 *   AegisBleClient.sendVendor. Opcodes/status vindos de OtaApi/VendorOps
 *   (sem literais novos aqui); respostas via VendorOps.parseResponse +
 *   OtaApi.mapStatus/parseChunkAck (dados de autoridade, sem PII no log).
 *
 * 0x33 (COMMIT) nao tem botao, builder, parametro nem flag NESTA TELA por
 * desenho (ver OtaApi): commit e ritual USB-only offline (release key +
 * latch UP fisico) do bootloader/rollback; sem caminho BLE/serial em
 * codigo. Se o GATT nao despachar 0x30-0x34 neste build, o sendVendor
 * rejeita e a tela mostra o motivo honesto (fail-closed, sem envio).
 */
private const val OTA_BLE_CHUNK_BYTES = 128

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun OtaScreen(
    client: AegisBleClient,
    onBack: () -> Unit = {},
) {
    val context = LocalContext.current
    val usb = remember { UsbCtaphid(context) }
    val usbUi by usb.ui.collectAsState()
    val bleUi by client.state.collectAsState()
    val scope = rememberCoroutineScope()

    var gate by remember { mutableStateOf<SdkGate.GateOutcome?>(null) }
    var baseUrl by remember { mutableStateOf("http://192.168.4.1") }
    var serial by remember { mutableStateOf("") }
    var currentFw by remember { mutableStateOf("") }
    var manifest by remember { mutableStateOf<OtaManifest?>(null) }
    var image by remember { mutableStateOf<ByteArray?>(null) }
    var manifestHex by remember { mutableStateOf("") }
    var currentVersion by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var sent by remember { mutableStateOf(0) }
    var total by remember { mutableStateOf(0) }
    var received by remember { mutableStateOf<Int?>(null) }
    var msg by remember { mutableStateOf("Busque o manifesto, baixe a imagem e escolha USB ou BLE.") }

    DisposableEffect(usb) {
        onDispose { usb.release() }
    }
    LaunchedEffect(Unit) {
        gate = withContext(Dispatchers.IO) { OtaApi.otaGate() }
    }

    val gateOk = gate == SdkGate.GateOutcome.Success ||
        gate == SdkGate.GateOutcome.RealVerified
    val usbReady = usbUi.state == UsbCtaphid.State.CONNECTED
    val bleReady = client.isReady()

    fun fail(e: Throwable, prefix: String) {
        msg = prefix + (e.message?.take(80) ?: "falha")
    }

    fun doFetchManifest() {
        scope.launch {
            busy = true
            try {
                val got = withContext(Dispatchers.IO) {
                    OtaApi.fetchManifest(baseUrl.trim(), serial.trim(), currentFw.trim())
                }
                manifest = got
                msg = "Manifesto: v" + got.version.take(24) + " bytes=" + got.size
            } catch (e: Exception) {
                fail(e, "Manifesto falhou: ")
            } finally {
                busy = false
            }
        }
    }

    fun doFetchBinary() {
        val m = manifest ?: run {
            msg = "Busque o manifesto primeiro."
            return
        }
        scope.launch {
            busy = true
            try {
                val bin = withContext(Dispatchers.IO) {
                    OtaApi.fetchBinary(m.url, m.sha256Hex)
                }
                image = bin
                received = null
                msg = "Imagem ok bytes=" + bin.size + " sha conferido."
            } catch (e: Exception) {
                fail(e, "Imagem falhou: ")
            } finally {
                busy = false
            }
        }
    }

    fun doUsbPush() {
        val bin = image ?: run {
            msg = "Baixe a imagem primeiro."
            return
        }
        if (!gateOk) {
            msg = "OTA bloqueado: " + gateToken(gate)
            return
        }
        if (!usbReady) {
            msg = "USB nao conectado — procure e permita primeiro."
            return
        }
        scope.launch {
            busy = true
            sent = 0
            total = 0
            try {
                val ok = usb.pushOtaImage(bin) { s, t ->
                    sent = s
                    total = t
                }
                msg = if (ok) "USB ok pacotes=" + total + " bytes=" + bin.size
                else "USB abortou no pacote " + sent + "/" + total
            } catch (e: Exception) {
                fail(e, "USB falhou: ")
            } finally {
                busy = false
            }
        }
    }

    suspend fun bleSend(opcode: Int, payload: ByteArray): VendorOps.VendorResponse? {
        val raw = try {
            withContext(Dispatchers.IO) { client.sendVendor(opcode, payload) }
        } catch (e: IllegalArgumentException) {
            throw IllegalStateException("fora do contrato BLE deste build (sem despacho 0x30-0x34); use USB")
        }
        return VendorOps.parseResponse(raw)
            ?: throw IllegalStateException("resposta ilegivel")
    }

    fun doBleBegin() {
        if (!gateOk) {
            msg = "OTA bloqueado: " + gateToken(gate)
            return
        }
        if (!bleReady) {
            msg = "BLE nao pronto — pareie e conecte primeiro."
            return
        }
        scope.launch {
            busy = true
            try {
                val raw = parseHexBytes(manifestHex)
                val cur = currentVersion.trim().toLongOrNull()
                    ?: throw IllegalArgumentException("versao atual invalida (u32)")
                val op = OtaApi.beginOp(raw, cur)
                when (op) {
                    is OtaOp.Blocked -> msg = "BEGIN bloqueado: " + gateToken(op.outcome)
                    is OtaOp.Ready -> {
                        val resp = bleSend(op.opcode, op.payload)
                            ?: throw IllegalStateException("sem resposta — toque no botao e tente de novo")
                        val mapped = OtaApi.mapStatus(resp.status)
                        msg = "BEGIN 0x30 status=" + VendorOps.statusLabel(resp.status) +
                            " (" + gateToken(mapped) + ")"
                    }
                }
            } catch (e: Exception) {
                fail(e, "BEGIN falhou: ")
            } finally {
                busy = false
            }
        }
    }

    fun doBleChunks() {
        val bin = image ?: run {
            msg = "Baixe a imagem primeiro."
            return
        }
        if (!gateOk) {
            msg = "OTA bloqueado: " + gateToken(gate)
            return
        }
        if (!bleReady) {
            msg = "BLE nao pronto — pareie e conecte primeiro."
            return
        }
        scope.launch {
            busy = true
            try {
                var off = 0
                while (off < bin.size) {
                    val end = minOf(off + OTA_BLE_CHUNK_BYTES, bin.size)
                    val op = OtaApi.chunkOp(off, bin.copyOfRange(off, end), bin.size)
                    when (op) {
                        is OtaOp.Blocked -> throw IllegalStateException("CHUNK bloqueado: " + gateToken(op.outcome))
                        is OtaOp.Ready -> {
                            val resp = bleSend(op.opcode, op.payload)
                                ?: throw IllegalStateException("sem resposta no off=" + off)
                            if (resp.op != OtaApi.OP_CHUNK || resp.status != 0) {
                                throw IllegalStateException(
                                    "CHUNK 0x31 off=" + off + " status=" + VendorOps.statusLabel(resp.status),
                                )
                            }
                            off = OtaApi.parseChunkAck(resp.tlv)
                            received = off
                        }
                    }
                }
                msg = "CHUNKs 0x31 ok recebido=" + off + "/" + bin.size
            } catch (e: Exception) {
                fail(e, "CHUNK falhou: ")
            } finally {
                busy = false
            }
        }
    }

    fun doBleFinish() {
        if (!gateOk) {
            msg = "OTA bloqueado: " + gateToken(gate)
            return
        }
        if (!bleReady) {
            msg = "BLE nao pronto — pareie e conecte primeiro."
            return
        }
        scope.launch {
            busy = true
            try {
                val op = OtaApi.finishOp()
                when (op) {
                    is OtaOp.Blocked -> msg = "FINISH bloqueado: " + gateToken(op.outcome)
                    is OtaOp.Ready -> {
                        val resp = bleSend(op.opcode, op.payload)
                            ?: throw IllegalStateException("sem resposta — toque no botao e tente de novo")
                        val mapped = OtaApi.mapStatus(resp.status)
                        msg = "FINISH 0x32 status=" + VendorOps.statusLabel(resp.status) +
                            " (" + gateToken(mapped) + ")"
                    }
                }
            } catch (e: Exception) {
                fail(e, "FINISH falhou: ")
            } finally {
                busy = false
            }
        }
    }

    fun doBleAbort() {
        if (!bleReady) {
            msg = "BLE nao pronto — pareie e conecte primeiro."
            return
        }
        scope.launch {
            busy = true
            try {
                val op = OtaApi.abortOp()
                when (op) {
                    is OtaOp.Blocked -> msg = "ABORT bloqueado: " + gateToken(op.outcome)
                    is OtaOp.Ready -> {
                        val resp = bleSend(op.opcode, op.payload)
                            ?: throw IllegalStateException("sem resposta")
                        received = null
                        msg = "ABORT 0x34 status=" + VendorOps.statusLabel(resp.status)
                    }
                }
            } catch (e: Exception) {
                fail(e, "ABORT falhou: ")
            } finally {
                busy = false
            }
        }
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Atualizar (OTA)", maxLines = 1, overflow = TextOverflow.Ellipsis) }) }) { inner ->
        AegisScreenColumn(inner = inner) {
            SectionTitle("Permissao OTA")
            FriendlyText(
                text = "Portao: " + gateToken(gate) + " · BLE: " + bleLabel(bleUi.connection) + " · USB: " + usbUi.label,
                maxLines = 2,
            )
            FriendlyText(
                text = "COMMIT (0x33) nao existe aqui por desenho: e ritual USB-only offline com botao fisico.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 2,
            )

            SectionTitle("1 · Manifesto (HTTP)")
            OutlinedTextField(
                value = baseUrl,
                onValueChange = { baseUrl = it },
                label = { Text("Servidor (ex.: http://192.168.4.1)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = serial,
                onValueChange = { serial = it },
                label = { Text("Serial do dispositivo") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = currentFw,
                onValueChange = { currentFw = it },
                label = { Text("Firmware atual (ex.: 1.0.0)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(onClick = ::doFetchManifest, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                Text("Buscar manifesto", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            OutlinedButton(
                onClick = ::doFetchBinary,
                enabled = !busy && manifest != null,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Baixar imagem (sha conferido)", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }

            SectionTitle("2 · Enviar via USB (0x30, 64B)")
            FriendlyText(
                text = if (image != null) "Imagem pronta bytes=" + (image?.size ?: 0) else "Sem imagem — complete o passo 1.",
                maxLines = 1,
            )
            OutlinedButton(
                onClick = {
                    scope.launch {
                        busy = true
                        try {
                            usb.markSearching()
                            val device = usb.findDevice()
                            if (device == null) usb.noteNotFound()
                            else usb.requestPermission(device)
                        } finally {
                            busy = false
                        }
                    }
                },
                enabled = !busy && !usbReady,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Procurar USB", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Button(onClick = ::doUsbPush, enabled = !busy && usbReady && image != null, modifier = Modifier.fillMaxWidth()) {
                Text("Enviar via USB", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            if (total > 0) {
                LinearProgressIndicator(progress = { sent.toFloat() / total.toFloat() }, modifier = Modifier.fillMaxWidth())
                FriendlyText(text = "USB pacote " + sent + "/" + total, maxLines = 1)
            }

            SectionTitle("3 · Estagiar via BLE (0x30-0x32, 0x34)")
            OutlinedTextField(
                value = manifestHex,
                onValueChange = { manifestHex = it },
                label = { Text("Manifesto 104 B (hex da ferramenta release)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = currentVersion,
                onValueChange = { currentVersion = it },
                label = { Text("Versao atual no device (u32)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            FriendlyText(
                text = received?.let { "Recebido no device: " + it + " bytes" } ?: "Nada estagiado ainda.",
                maxLines = 1,
            )
            OutlinedButton(onClick = ::doBleBegin, enabled = !busy && bleReady, modifier = Modifier.fillMaxWidth()) {
                Text("BEGIN (0x30)", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            OutlinedButton(onClick = ::doBleChunks, enabled = !busy && bleReady && image != null, modifier = Modifier.fillMaxWidth()) {
                Text("Enviar CHUNKs (0x31)", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            OutlinedButton(onClick = ::doBleFinish, enabled = !busy && bleReady, modifier = Modifier.fillMaxWidth()) {
                Text("FINISH verificar (0x32)", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            OutlinedButton(onClick = ::doBleAbort, enabled = !busy && bleReady, modifier = Modifier.fillMaxWidth()) {
                Text("ABORT descartar (0x34)", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }

            if (busy) CircularProgressIndicator()
            FriendlyText(text = msg, maxLines = 4)
            stateError(bleUi.error)?.let {
                FriendlyText(text = "BLE: " + it, maxLines = 2)
            }
            usbUi.error?.let {
                Text("USB: " + it, color = MaterialTheme.colorScheme.error, maxLines = 3, overflow = TextOverflow.Ellipsis)
            }

            SectionTitle("Sair")
            OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
                Text("Voltar", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

private fun gateToken(outcome: SdkGate.GateOutcome?): String = when (outcome) {
    null -> "checando..."
    SdkGate.GateOutcome.Success -> "permitido"
    SdkGate.GateOutcome.RealVerified -> "verificado"
    SdkGate.GateOutcome.Unsupported -> "nao suportado neste build (sem envio)"
    SdkGate.GateOutcome.Unavailable -> "indisponivel — tente de novo (sem envio)"
    SdkGate.GateOutcome.PermissionDenied -> "negado (botao/PIN/vinculo pendente)"
    is SdkGate.GateOutcome.NotCompiled -> "OTA fora do build (sem envio)"
    is SdkGate.GateOutcome.ExternalBlocked -> "bloqueado (" + outcome.reason.name.lowercase() + ", sem envio)"
}

private fun bleLabel(connection: AegisBleClient.Connection): String = when (connection) {
    AegisBleClient.Connection.IDLE -> "desligado"
    AegisBleClient.Connection.SCANNING -> "procurando"
    AegisBleClient.Connection.CONNECTING -> "ligando"
    AegisBleClient.Connection.READY -> "ligado"
    AegisBleClient.Connection.ERROR -> "erro"
}

private fun stateError(error: String?): String? = error?.take(80)

private fun parseHexBytes(hex: String): ByteArray {
    val clean = hex.filter { !it.isWhitespace() }.lowercase()
    require(clean.isNotEmpty() && clean.length % 2 == 0) { "hex vazio ou impar" }
    require(clean.all { it in '0'..'9' || it in 'a'..'f' }) { "hex invalido (0-9 a-f)" }
    require(clean.length / 2 <= OtaApi.MAX_IMAGE_BYTES) { "hex grande demais" }
    val out = ByteArray(clean.length / 2)
    var i = 0
    while (i < out.size) {
        val hi = clean[i * 2].digitToInt(16)
        val lo = clean[i * 2 + 1].digitToInt(16)
        out[i] = ((hi shl 4) or lo).toByte()
        i += 1
    }
    return out
}
