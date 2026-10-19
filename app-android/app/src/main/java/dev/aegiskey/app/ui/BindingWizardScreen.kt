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
import androidx.compose.runtime.collectAsState
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
import dev.aegiskey.app.ble.BleContract
import dev.aegiskey.app.ble.BindingOps
import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.security.BindingKey
import dev.aegiskey.app.security.SanitizedLog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Wizard "Primeira configuracao": este app vira o unico dono.
 *
 * Passos: explica posse exclusiva -> cria chave P-256 no celular ->
 * guia hold-5s -> envia claim (pubkey SEC1 + binding_id 16B) com UP ->
 * "Voce e o dono". O claim nao pede assinatura (pareamento + UP bastam,
 * per `binding.rs`); desafios assinados com a digital entram nas
 * operacoes sensiveis seguintes (ex.: transferir posse).
 * Se o device ja tem dono (claim responde 0x04): sai para [onForeignDevice].
 * Textos simples p/ usuario nao-tecnico. Sem Log com PII (so tamanhos).
 */
private enum class WizardStep { EXPLAIN, KEY, HOLD, CLAIM, RECOVERY, DONE }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BindingWizardScreen(
    client: AegisBleClient,
    onDone: () -> Unit,
    onForeignDevice: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val bleState by client.state.collectAsState()
    var step by remember { mutableStateOf(WizardStep.EXPLAIN) }
    var keyInfo by remember { mutableStateOf<BindingKey.KeyInfo?>(null) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }

    fun sendClaim() {
        scope.launch {
            busy = true
            message = null
            val pubkey = BindingKey.publicKeyUncompressed()
            val bindingId = BindingKey.generateBindingId()
            try {
                if (pubkey == null) {
                    message = "sem chave — volte e crie a chave"
                    return@launch
                }
                val req = BindingOps.claimRequest(pubkey, bindingId)
                val raw = withContext(Dispatchers.IO) {
                    client.sendVendor(BindingOps.OP_BINDING_CLAIM, req)
                }
                val resp = VendorOps.parseResponse(raw)
                if (resp == null) {
                    message = "sem resposta — toque no dispositivo e tente de novo"
                    return@launch
                }
                DeviceLog.append(DeviceLog.Category.PAIRING, "binding claim status=" + resp.status)
                when {
                    resp.status == VendorOps.STATUS_OK && BindingOps.echoMatches(resp.tlv, bindingId) -> {
                        BindingKey.saveBindingId(context, bindingId)
                        SanitizedLog.record(SanitizedLog.Event.BINDING_CLAIMED)
                        step = WizardStep.RECOVERY
                    }
                    resp.status == VendorOps.STATUS_OK -> {
                        message = "resposta incompleta — tente de novo"
                    }
                    BindingOps.claimMeansAlreadyOwned(resp.status) -> onForeignDevice()
                    else -> message = BindingOps.statusLabel(resp.status)
                }
            } catch (e: Exception) {
                message = (e.message ?: "falha no vinculo").take(64)
            } finally {
                if (pubkey != null) AegisBridge.wipe(pubkey)
                AegisBridge.wipe(bindingId)
                busy = false
            }
        }
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Primeira configuracao", maxLines = 1, overflow = TextOverflow.Ellipsis) }) }) { inner ->
        AegisScreenColumn(inner = inner) {
            FriendlyText(
                text = stateLine(bleState.connection, bleState.status),
                style = MaterialTheme.typography.bodySmall,
                maxLines = 2,
            )
            when (step) {
                WizardStep.EXPLAIN -> {
                    SectionTitle("So este app vai mandar")
                    Card {
                        Column(Modifier.padding(12.dp)) {
                            FriendlyText(
                                text = "Este celular sera o unico dono do dispositivo. So ele podera criar chaves e ver codigos.",
                                maxLines = 3,
                            )
                            FriendlyText(
                                text = "A chave do vinculo fica guardada no chip de seguranca do celular e nunca sai dele.",
                                style = MaterialTheme.typography.bodySmall,
                                maxLines = 3,
                            )
                            FriendlyText(
                                text = "Outro celular que achar este dispositivo vera so \u201cdispositivo de outra pessoa\u201d.",
                                style = MaterialTheme.typography.bodySmall,
                                maxLines = 3,
                            )
                        }
                    }
                    Button(
                        onClick = { step = WizardStep.KEY },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Entendi — continuar", maxLines = 1, overflow = TextOverflow.Ellipsis) }
                }
                WizardStep.KEY -> {
                    SectionTitle("Criar a chave no celular")
                    FriendlyText(
                        text = "A chave nasce dentro do chip de seguranca. Ela nunca sai do celular, nem p/ nos.",
                        maxLines = 3,
                    )
                    Button(
                        onClick = {
                            scope.launch {
                                busy = true
                                try {
                                    keyInfo = withContext(Dispatchers.IO) { BindingKey.ensureKey() }
                                    message = null
                                } catch (e: Exception) {
                                    message = (e.message ?: "falha ao criar").take(64)
                                } finally {
                                    busy = false
                                }
                            }
                        },
                        enabled = !busy && keyInfo == null,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Criar chave neste celular", maxLines = 1, overflow = TextOverflow.Ellipsis) }
                    keyInfo?.let {
                        FriendlyText(
                            text = if (it.strongBox) "Chave criada no chip dedicado. Ela nunca sai do celular."
                            else "Chave criada no cofre do sistema. Ela nunca sai do celular.",
                            maxLines = 2,
                        )
                        Button(
                            onClick = { step = WizardStep.HOLD },
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text("Continuar", maxLines = 1, overflow = TextOverflow.Ellipsis) }
                    }
                }
                WizardStep.HOLD -> {
                    SectionTitle("Segure o botao do dispositivo")
                    Card {
                        Column(Modifier.padding(12.dp)) {
                            FriendlyText(
                                text = "Segure o botao do dispositivo por 5 segundos, ate piscar rapido.",
                                maxLines = 2,
                            )
                            FriendlyText(
                                text = "Isso libera o pareamento. So vale por 60 segundos.",
                                style = MaterialTheme.typography.bodySmall,
                                maxLines = 2,
                            )
                        }
                    }
                    FriendlyText(
                        text = "Dispositivo: " + BleContract.statusLabel(bleState.status),
                        style = MaterialTheme.typography.bodySmall,
                        maxLines = 2,
                    )
                    Button(
                        onClick = { step = WizardStep.CLAIM },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Ja segurei — continuar", maxLines = 1, overflow = TextOverflow.Ellipsis) }
                }
                WizardStep.CLAIM -> {
                    SectionTitle("Enviar o vinculo")
                    FriendlyText(
                        text = "O app manda so a parte publica da chave. Toque no botao do dispositivo se ele pedir.",
                        maxLines = 3,
                    )
                    if (busy) CircularProgressIndicator()
                    Button(
                        onClick = ::sendClaim,
                        enabled = !busy,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Enviar vinculo", maxLines = 1, overflow = TextOverflow.Ellipsis) }
                }
                WizardStep.RECOVERY -> {
                    SectionTitle("Protecao e recuperacao")
                    FriendlyText(
                        text = "Escolha pelo menos uma rede de seguranca. Vale fazer as duas.",
                        maxLines = 2,
                    )
                    ProtectionRecoverySection(client)
                    Button(
                        onClick = { step = WizardStep.DONE },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Continuar", maxLines = 1, overflow = TextOverflow.Ellipsis) }
                }
                WizardStep.DONE -> {
                    SectionTitle("Voce e o dono")
                    Card {
                        Column(Modifier.padding(12.dp)) {
                            FriendlyText(
                                text = "Pronto! Este celular agora e o unico dono do dispositivo.",
                                maxLines = 2,
                            )
                            FriendlyText(
                                text = "Operacoes importantes vao pedir sua digital na hora. A chave continua presa ao celular.",
                                style = MaterialTheme.typography.bodySmall,
                                maxLines = 3,
                            )
                        }
                    }
                    Button(onClick = onDone, modifier = Modifier.fillMaxWidth()) {
                        Text("Comecar a usar", maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                }
            }
            message?.let {
                Text("Aviso: " + it, color = MaterialTheme.colorScheme.error, maxLines = 3, overflow = TextOverflow.Ellipsis)
            }
            if (step != WizardStep.EXPLAIN && step != WizardStep.DONE) {
                OutlinedButton(
                    onClick = onDone,
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Sair do assistente", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            }
        }
    }
}

private fun stateLine(connection: AegisBleClient.Connection, status: Int): String =
    "Conexao: " + connection + " · dispositivo: " + BleContract.statusLabel(status)
