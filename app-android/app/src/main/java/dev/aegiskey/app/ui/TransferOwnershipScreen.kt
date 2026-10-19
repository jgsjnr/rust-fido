package dev.aegiskey.app.ui

import android.app.Activity
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.ble.BindingOps
import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.security.BindingKey
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

    val bindingId = remember { BindingKey.loadBindingId(context) }

    fun requestChallenge() {
        val id = bindingId ?: run {
            message = "este app nao e o dono — nada p/ transferir"
            return
        }
        scope.launch {
            busy = true
            try {
                val raw = withContext(Dispatchers.IO) {
                    client.sendVendor(BindingOps.OP_BINDING_CHALLENGE, BindingOps.challengeRequest(id))
                }
                val resp = VendorOps.parseResponse(raw)
                val challenge = resp?.let { BindingOps.parseChallenge(it.tlv) }
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
                            val req = BindingOps.releaseRequest(id, rawSig)
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
