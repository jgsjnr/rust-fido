package dev.aegiskey.app.ui

import android.app.Activity
import android.util.Base64
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.ble.BindingOps
import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.security.BindingKey
import dev.aegiskey.app.security.RecoveryBackup
import dev.aegiskey.app.security.SdkGate
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Transferir posse (espelha `release_signed` em `binding.rs`).
 *
 * - O app dono pede um desafio 32B ao device, assina
 *   `challenge || 0x52 || sha256(binding_id)` com a digital
 *   ([AuthorizeSignSheet] + [BindingKey.authenticateAndSign]) e envia.
 * - No OK o device apaga o dono (wipe); este app apaga o vinculo local.
 *   O celular novo vira dono fazendo a primeira configuracao (claim novo).
 * - Confirmacao destrutiva antes de assinar. Sem Log com PII (so tamanhos).
 *
 * A5 backup/restore (envelope AEGN): secoes abaixo, todas via
 * SdkGate.requireBackup() (NotCompiled/ExternalBlocked/deny viram aviso
 * proprio da tela, nunca banner enganoso). Export gera envelope via
 * bridge (respeita maxPlaintextBytes do SDK), mostra destino/arquivo;
 * import valida formato + versao antes de enviar; frase 24 exibe
 * entropia + checksum p/ anotacao (sem salvar); DKEK n-de-m registra
 * shares sem reconstruir fora do device.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TransferOwnershipScreen(client: AegisBleClient, onDone: () -> Unit) {
    val context = LocalContext.current
    val activity = context as? Activity
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("—") }
    var confirmRelease by remember { mutableStateOf(false) }
    var showAuthSheet by remember { mutableStateOf(false) }
    var pendingChallenge by remember { mutableStateOf<ByteArray?>(null) }
    var backupNotice by remember { mutableStateOf<String?>(null) }

    val bindingId = remember { BindingKey.loadBindingId(context) }

    /** Toda acao A5 passa primeiro pelo SdkGate (facade-first, R4). */
    fun backupAllowed(): Boolean {
        val g = SdkGate.requireBackup()
        backupNotice = backupGateNotice(g)
        return g is SdkGate.GateOutcome.Success || g is SdkGate.GateOutcome.RealVerified
    }

    fun requestChallenge() {
        if (bindingId == null) {
            message = "este app nao e o dono — nada p/ transferir"
            return
        }
        scope.launch {
            busy = true
            try {
                val raw = withContext(Dispatchers.IO) {
                    client.sendVendor(BindingOps.OP_BINDING_CHALLENGE, BindingWire.challengePayload())
                }
                val resp = VendorOps.parseResponse(raw)
                val challenge = resp?.let { BindingWire.parseChallenge(it.tlv) }
                if (resp == null || challenge == null) {
                    message = resp?.let { BindingOps.statusLabel(it.status) }
                        ?: "sem resposta — toque no dispositivo e tente de novo"
                } else {
                    DeviceLog.append(DeviceLog.Category.PAIRING, "binding challenge bytes=" + challenge.size)
                    pendingChallenge = challenge
                    confirmRelease = true
                }
            } catch (e: Exception) {
                message = (e.message ?: "falha ao pedir").take(64)
            } finally {
                busy = false
            }
        }
    }

    fun signAndRelease() {
        val challenge = pendingChallenge ?: return
        val id = bindingId ?: return
        val act = activity ?: run {
            message = "tela indisponivel — tente de novo"
            return
        }
        val idHash = BindingKey.sha256(id)
        val covered = BindingKey.coveredMessage(challenge, BindingOps.BIND_OP_RELEASE, idHash)
        BindingKey.authenticateAndSign(
            activity = act,
            title = "Autorize com a digital",
            subtitle = "Liberar a posse do dispositivo",
            message = covered,
        ) { result ->
            AegisBridge.wipe(covered)
            when (result) {
                is BindingKey.SignResult.Signed -> {
                    val rawSig = BindingKey.derToRawRS(result.signatureDer)
                    if (rawSig == null) {
                        message = "assinatura invalida — tente de novo"
                        return@authenticateAndSign
                    }
                    scope.launch {
                        busy = true
                        try {
                            val req = BindingWire.releasePayload(challenge, idHash, rawSig)
                            val raw = withContext(Dispatchers.IO) {
                                client.sendVendor(BindingOps.OP_BINDING_RELEASE, req)
                            }
                            AegisBridge.wipe(rawSig)
                            val resp = VendorOps.parseResponse(raw)
                            if (resp != null && resp.status == VendorOps.STATUS_OK) {
                                BindingKey.clearBinding(context)
                                DeviceLog.append(DeviceLog.Category.PAIRING, "binding released ok")
                                message = "posse liberada — o celular novo pode fazer a primeira configuracao"
                                showAuthSheet = false
                            } else {
                                message = resp?.let { BindingOps.statusLabel(it.status) }
                                    ?: "sem resposta — tente de novo"
                            }
                        } catch (e: Exception) {
                            message = (e.message ?: "falha ao transferir").take(64)
                        } finally {
                            busy = false
                        }
                    }
                }
                BindingKey.SignResult.Unavailable ->
                    message = "digital indisponivel — ative a biometria e tente de novo"
                is BindingKey.SignResult.Failed ->
                    message = if (result.code == "cancelled") "voce cancelou — nada mudou"
                    else "nao autorizado — tente de novo"
            }
        }
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Transferir posse", maxLines = 1, overflow = TextOverflow.Ellipsis) }) }) { inner ->
        AegisScreenColumn(inner = inner) {
            SectionTitle("Liberar p/ um novo dono")
            Card {
                Column(Modifier.padding(12.dp)) {
                    FriendlyText(
                        text = "Voce assina a liberacao com a digital. Depois disso, este app deixa de ser o dono.",
                        maxLines = 3,
                    )
                    FriendlyText(
                        text = "O celular novo vira dono fazendo a primeira configuracao (segurar 5s + vinculo).",
                        style = MaterialTheme.typography.bodySmall,
                        maxLines = 3,
                    )
                }
            }
            if (bindingId == null) {
                FriendlyText(text = "Este app nao e o dono — nada p/ transferir.", maxLines = 2)
            } else {
                if (busy) CircularProgressIndicator()
                if (showAuthSheet) {
                    AuthorizeSignSheet(
                        opTitle = "Liberar a posse do dispositivo",
                        opHelp = "Sera assinado so o desafio + a prova de dono. Toque na digital p/ confirmar.",
                        onAuthorize = ::signAndRelease,
                        onCancel = { showAuthSheet = false },
                    )
                } else {
                    Button(
                        onClick = ::requestChallenge,
                        enabled = !busy,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Assinar liberacao", maxLines = 1, overflow = TextOverflow.Ellipsis) }
                }
            }
            FriendlyText(text = "Resultado: " + message, maxLines = 3)
            SectionTitle("Backup e restauracao (envelope)")
            backupNotice?.let { FriendlyText(text = it, maxLines = 3) }
            BackupExportCard(onGate = { backupAllowed() })
            BackupImportCard(onGate = { backupAllowed() })
            RecoveryPhraseCard(onGate = { backupAllowed() })
            DkekQuorumCard(onGate = { backupAllowed() })
            OutlinedButton(onClick = onDone, modifier = Modifier.fillMaxWidth()) {
                Text("Voltar", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            if (confirmRelease) {
                ConfirmActionDialog(
                    title = "Liberar a posse?",
                    body = "Este app deixara de ser o dono na hora. So continue se o celular novo ja esta com voce.",
                    confirmLabel = "CONTINUAR",
                    onConfirm = { confirmRelease = false; showAuthSheet = true },
                    onDismiss = { confirmRelease = false },
                )
            }
        }
    }
}

/**
 * Aviso proprio p/ outcomes sem texto honesto no GateBanner (R4):
 * gateBannerState() retorna null p/ NotCompiled/ExternalBlocked/deny, e a
 * tela renderiza este texto em vez de banner enganoso. Null = liberado.
 * Reusado p/ gate (requireBackup) e p/ erros do bridge (mapBridgeError).
 */
private fun backupGateNotice(outcome: SdkGate.GateOutcome): String? = when (outcome) {
    is SdkGate.GateOutcome.Success, SdkGate.GateOutcome.RealVerified -> null
    is SdkGate.GateOutcome.NotCompiled ->
        "Backup fora da compilacao deste app (fala com o dono do SDK; sem crash, sem fingir)."
    is SdkGate.GateOutcome.ExternalBlocked ->
        "Backup bloqueado aqui: " + when (outcome.reason) {
            SdkGate.BlockReason.NO_NATIVE_LIB -> "libs nativas ausentes (rode com o .so do bridge)"
            SdkGate.BlockReason.NO_TRANSPORT -> "sem transporte"
            SdkGate.BlockReason.NO_PEER -> "sem par pareado"
            SdkGate.BlockReason.LAB_MOCKS_OFF -> "mocks de lab desligados"
        }
    SdkGate.GateOutcome.PermissionDenied -> "chave ou envelope nao conferem - revise os dados"
    SdkGate.GateOutcome.Unsupported -> "envelope recusado (formato, versao ou tamanho)"
    SdkGate.GateOutcome.Unavailable -> "bridge indisponivel - toque e tente de novo"
}

/** Export: sela via bridge (teto do SDK), salva blob, mostra destino + frase 1x. */
@Composable
private fun BackupExportCard(onGate: () -> Boolean) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var payload by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("—") }
    var blobInfo by remember { mutableStateOf<String?>(null) }
    var blobHead by remember { mutableStateOf<String?>(null) }
    var phraseSlots by remember { mutableStateOf<List<String>?>(null) }
    var entropyHex by remember { mutableStateOf("") }
    var checksumHex by remember { mutableStateOf("") }
    var liveKey by remember { mutableStateOf<ByteArray?>(null) }

    fun discardKey(note: String) {
        liveKey?.let { AegisBridge.wipe(it) }
        liveKey = null
        phraseSlots = null
        entropyHex = ""
        checksumHex = ""
        message = note
    }

    fun export() {
        if (!onGate()) return
        val text = payload
        if (text.isBlank()) {
            message = "digite o conteudo p/ selar"
            return
        }
        scope.launch {
            busy = true
            message = "selando..."
            var pt = ByteArray(0)
            try {
                discardKey("selando...")
                pt = text.toByteArray(Charsets.UTF_8)
                val ceiling = AegisBridge.maxPlaintextBytes().getOrElse {
                    throw IllegalStateException("teto do SDK ilegivel")
                }
                if (pt.size > ceiling) {
                    message = "conteudo com " + pt.size + " B acima do teto do SDK (" + ceiling + " B)"
                    return@launch
                }
                val sealed = RecoveryBackup.sealForExport(pt).getOrThrow()
                val bytes = sealed.envelope.size
                val head = Base64.encodeToString(sealed.envelope, Base64.NO_WRAP).take(96)
                val id = "bkp-" + System.currentTimeMillis()
                withContext(Dispatchers.IO) {
                    RecoveryBackup.saveEnvelopeBlob(context, id, sealed.envelope).getOrThrow()
                }
                val indices = RecoveryBackup.phraseIndices(sealed.key)
                phraseSlots = RecoveryBackup.wordsOrIndices(indices, null)
                entropyHex = RecoveryBackup.toHex(sealed.key)
                checksumHex = RecoveryBackup.toHex(byteArrayOf(RecoveryBackup.phraseChecksumByte(sealed.key)))
                liveKey = sealed.key
                blobInfo = "destino: arquivo " + id + " (" + bytes + " B)"
                blobHead = head
                payload = ""
                message = "selado e salvo - anote a frase no papel e descarte a chave"
            } catch (e: Exception) {
                message = backupGateNotice(SdkGate.mapBridgeError(e)) ?: "falha ao selar"
            } finally {
                AegisBridge.wipe(pt)
                busy = false
            }
        }
    }

    Card {
        Column(Modifier.padding(12.dp)) {
            FriendlyText(text = "Exportar (selar envelope)", maxLines = 1)
            FriendlyText(
                text = "O app gera a chave e sela aqui; o device guarda so o blob cifrado. A chave aparece 1x abaixo e nunca e salva.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 3,
            )
            OutlinedTextField(
                value = payload,
                onValueChange = { payload = it.take(2048) },
                label = { Text("Conteudo p/ selar") },
                singleLine = false,
                enabled = !busy,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                onClick = ::export,
                enabled = !busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Gerar chave + selar", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            blobInfo?.let { FriendlyText(text = it, maxLines = 2) }
            blobHead?.let { FriendlyText(text = "base64 (p/ QR/arquivo): " + it + "...", maxLines = 2) }
            phraseSlots?.let { slots ->
                slots.chunked(4).forEach { row ->
                    FriendlyText(text = row.joinToString("  "), maxLines = 1)
                }
                FriendlyText(text = "entropia: " + entropyHex, maxLines = 3)
                FriendlyText(text = "checksum: " + checksumHex, maxLines = 1)
                OutlinedButton(
                    onClick = { discardKey("chave apagada da memoria - sem ela o blob nao abre") },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Descartar chave da memoria", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            }
            FriendlyText(text = "Resultado: " + message, maxLines = 3)
        }
    }
}

/** Import: valida formato + versao antes de enviar; erro vira R4 honesto. */
@Composable
private fun BackupImportCard(onGate: () -> Boolean) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var blobId by remember { mutableStateOf("") }
    var envelopeB64 by remember { mutableStateOf("") }
    var keyHex by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("—") }
    var openedInfo by remember { mutableStateOf<String?>(null) }
    var savedIds by remember { mutableStateOf(RecoveryBackup.listEnvelopeIds(context)) }
    var confirmDelete by remember { mutableStateOf(false) }

    fun refresh() {
        savedIds = RecoveryBackup.listEnvelopeIds(context)
    }

    fun import() {
        if (!onGate()) return
        val key = RecoveryBackup.fromHex(keyHex)
        if (key == null || key.size != RecoveryBackup.ENVELOPE_KEY_BYTES) {
            message = "chave em hexa invalida (64 digitos, 32 B)"
            return
        }
        scope.launch {
            busy = true
            openedInfo = null
            var pt = ByteArray(0)
            try {
                val envelope = if (blobId.isNotBlank()) {
                    withContext(Dispatchers.IO) {
                        RecoveryBackup.loadEnvelopeBlob(context, blobId.trim()).getOrThrow()
                    }
                } else if (envelopeB64.isNotBlank()) {
                    try {
                        Base64.decode(envelopeB64.trim(), Base64.NO_WRAP)
                    } catch (_: IllegalArgumentException) {
                        message = "base64 invalido"
                        return@launch
                    }
                } else {
                    message = "informe o id do blob ou cole o envelope"
                    return@launch
                }
                when (val pre = RecoveryBackup.preValidateEnvelope(envelope)) {
                    is RecoveryBackup.EnvelopeCheck.Ok -> Unit
                    else -> {
                        message = RecoveryBackup.envelopeProblem(pre) ?: "envelope invalido"
                        AegisBridge.wipe(envelope)
                        return@launch
                    }
                }
                pt = RecoveryBackup.openForImport(key, envelope).getOrThrow()
                AegisBridge.wipe(envelope)
                openedInfo = "aberto (" + pt.size + " B): " + pt.toString(Charsets.UTF_8).take(512)
                message = "restaurado - confira o conteudo acima"
                keyHex = ""
            } catch (e: Exception) {
                message = backupGateNotice(SdkGate.mapBridgeError(e)) ?: "falha ao abrir"
            } finally {
                AegisBridge.wipe(key)
                AegisBridge.wipe(pt)
                busy = false
            }
        }
    }

    Card {
        Column(Modifier.padding(12.dp)) {
            FriendlyText(text = "Restaurar (abrir envelope)", maxLines = 1)
            FriendlyText(
                text = "O formato e a versao sao validados antes de qualquer envio. Erro vira aviso honesto, sem crash.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 3,
            )
            FriendlyText(
                text = "blobs salvos: " + (savedIds.joinToString(" ").take(120).ifBlank { "nenhum" }),
                style = MaterialTheme.typography.bodySmall,
                maxLines = 2,
            )
            OutlinedTextField(
                value = blobId,
                onValueChange = { blobId = it.trim().take(32) },
                label = { Text("Id do blob (ou vazio p/ colar)") },
                singleLine = true,
                enabled = !busy,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = envelopeB64,
                onValueChange = { envelopeB64 = it.trim().take(8192) },
                label = { Text("Envelope em base64 (ou vazio p/ id)") },
                singleLine = false,
                enabled = !busy,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = keyHex,
                onValueChange = { keyHex = it.trim().take(64) },
                label = { Text("Chave em hexa (64 digitos)") },
                singleLine = true,
                enabled = !busy,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                onClick = ::import,
                enabled = !busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Validar e abrir", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            openedInfo?.let { FriendlyText(text = it, maxLines = 4) }
            Row(modifier = Modifier.fillMaxWidth()) {
                OutlinedButton(
                    onClick = ::refresh,
                    enabled = !busy,
                    modifier = Modifier.weight(1f),
                ) { Text("Atualizar lista", maxLines = 1, overflow = TextOverflow.Ellipsis) }
                OutlinedButton(
                    onClick = {
                        if (!onGate()) return@OutlinedButton
                        if (blobId.isBlank()) {
                            message = "informe o id do blob p/ apagar"
                            return@OutlinedButton
                        }
                        confirmDelete = true
                    },
                    enabled = !busy,
                    modifier = Modifier.weight(1f),
                ) { Text("Apagar blob", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            }
            FriendlyText(text = "Resultado: " + message, maxLines = 3)
            if (confirmDelete) {
                ConfirmActionDialog(
                    title = "Apagar blob?",
                    body = "O arquivo cifrado sai deste celular. O dispositivo nao muda.",
                    confirmLabel = "APAGAR",
                    onConfirm = {
                        confirmDelete = false
                        if (RecoveryBackup.deleteEnvelopeBlob(context, blobId.trim())) {
                            message = "blob apagado"
                            blobId = ""
                            refresh()
                        } else {
                            message = "blob nao encontrado"
                        }
                    },
                    onDismiss = { confirmDelete = false },
                )
            }
        }
    }
}

/** Frase 24: entropia + checksum exibidos p/ anotacao, sem salvar. */
@Composable
private fun RecoveryPhraseCard(onGate: () -> Boolean) {
    var slots by remember { mutableStateOf<List<String>?>(null) }
    var entropyHex by remember { mutableStateOf("") }
    var checksumHex by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("—") }
    var live by remember { mutableStateOf<ByteArray?>(null) }

    fun discard(note: String) {
        live?.let { AegisBridge.wipe(it) }
        live = null
        slots = null
        entropyHex = ""
        checksumHex = ""
        message = note
    }

    fun generate() {
        if (!onGate()) return
        discard("gerando...")
        val entropy = RecoveryBackup.generatePhraseEntropy()
        slots = RecoveryBackup.wordsOrIndices(RecoveryBackup.phraseIndices(entropy), null)
        entropyHex = RecoveryBackup.toHex(entropy)
        checksumHex = RecoveryBackup.toHex(byteArrayOf(RecoveryBackup.phraseChecksumByte(entropy)))
        live = entropy
        message = "anote no papel (24 itens + entropia + checksum) e descarte"
    }

    Card {
        Column(Modifier.padding(12.dp)) {
            FriendlyText(text = "Frase 24 (anotar no papel)", maxLines = 1)
            FriendlyText(
                text = "Entropia + checksum p/ anotacao. O app nunca salva: so existe na memoria ate descartar.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 3,
            )
            slots?.let { list ->
                list.chunked(4).forEach { row ->
                    FriendlyText(text = row.joinToString("  "), maxLines = 1)
                }
                FriendlyText(text = "entropia: " + entropyHex, maxLines = 3)
                FriendlyText(text = "checksum: " + checksumHex, maxLines = 1)
                OutlinedButton(
                    onClick = { discard("frase apagada da memoria") },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Descartar da memoria", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            } ?: Button(
                onClick = ::generate,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Gerar frase", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            FriendlyText(text = "Resultado: " + message, maxLines = 3)
        }
    }
}

/** DKEK n-de-m: registra shares (x + tamanho) sem reconstruir fora do device. */
@Composable
private fun DkekQuorumCard(onGate: () -> Boolean) {
    var nStr by remember { mutableStateOf("3") }
    var mStr by remember { mutableStateOf("2") }
    var quorum by remember { mutableStateOf<RecoveryBackup.DkekQuorum?>(null) }
    var seen by remember { mutableStateOf(0) }
    var xStr by remember { mutableStateOf("") }
    var lenStr by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("—") }

    fun setup() {
        if (!onGate()) return
        val n = nStr.toIntOrNull()
        val m = mStr.toIntOrNull()
        if (n == null || m == null) {
            message = "n e m precisam ser numeros"
            return
        }
        val err = RecoveryBackup.validateDkekParams(n, m)
        if (err != null) {
            message = err
            return
        }
        quorum = RecoveryBackup.DkekQuorum(n, m)
        seen = 0
        message = "quorum " + m + "-de-" + n + " pronto - registre os shares"
    }

    fun add() {
        if (!onGate()) return
        val q = quorum ?: run {
            message = "defina o quorum primeiro"
            return
        }
        val x = xStr.toIntOrNull()
        val len = lenStr.toIntOrNull()
        if (x == null || len == null) {
            message = "x e tamanho precisam ser numeros"
            return
        }
        when (val r = q.addShare(x, len)) {
            is RecoveryBackup.DkekQuorum.AddResult.Added -> {
                xStr = ""
                lenStr = ""
                seen = q.received()
                message = if (q.quorumMet()) {
                    "quorum atingido - a recuperacao executa no dispositivo (este app nunca junta shares)"
                } else {
                    "share x=" + x + " registrado (" + q.received() + " de " + q.total +
                        "; faltam " + q.remaining() + ")"
                }
            }
            is RecoveryBackup.DkekQuorum.AddResult.Rejected -> message = "share recusado: " + r.why
        }
    }

    Card {
        Column(Modifier.padding(12.dp)) {
            FriendlyText(text = "DKEK n-de-m (quorum)", maxLines = 1)
            FriendlyText(
                text = "Split/recover rodam no device. Aqui entra so x + tamanho de cada share (nunca o conteudo), p/ acompanhar o quorum.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 4,
            )
            Row(modifier = Modifier.fillMaxWidth()) {
                OutlinedTextField(
                    value = nStr,
                    onValueChange = { nStr = it.filter { ch -> ch.isDigit() }.take(2) },
                    label = { Text("n (total)") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                )
                OutlinedTextField(
                    value = mStr,
                    onValueChange = { mStr = it.filter { ch -> ch.isDigit() }.take(2) },
                    label = { Text("m (limiar)") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                )
            }
            OutlinedButton(
                onClick = ::setup,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Definir quorum (2 <= m <= n <= 32)", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            quorum?.let { q ->
                FriendlyText(
                    text = "shares: " + (q.slots().entries.joinToString(" ") { "x=" + it.key + ":" + it.value + "B" }.ifBlank { "nenhum" }),
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 3,
                )
                FriendlyText(
                    text = "recebidos " + seen + " (limiar " + q.threshold + ")",
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 1,
                )
                Row(modifier = Modifier.fillMaxWidth()) {
                    OutlinedTextField(
                        value = xStr,
                        onValueChange = { xStr = it.filter { ch -> ch.isDigit() }.take(2) },
                        label = { Text("x") },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                    )
                    OutlinedTextField(
                        value = lenStr,
                        onValueChange = { lenStr = it.filter { ch -> ch.isDigit() }.take(2) },
                        label = { Text("tam. bytes") },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                    )
                }
                Button(
                    onClick = ::add,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Registrar share (so x + tamanho)", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            }
            FriendlyText(text = "Resultado: " + message, maxLines = 3)
        }
    }
}