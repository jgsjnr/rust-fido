package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.ble.BleContract
import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.security.AppLock
import dev.aegiskey.app.security.FeatureFlags
import dev.aegiskey.app.security.SanitizedLog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.SecureRandom

private fun hexToBytes(hex: String): ByteArray {
    val clean = hex.filterNot { it.isWhitespace() }
    require(clean.length % 2 == 0 && clean.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
        "bad hex"
    }
    return clean.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

/**
 * Chaves (contrato S2 + Fase6 S9): GetInfo/MakeCredential (0x83 MSG) +
 * Keys no device (0x20-0x23 vendor, mesmo framing S3 via sendVendor).
 *
 * - Origem: no dispositivo (Rust TRNG, recomendado) ou gerada no app
 *   (envelope AEGN na hora via bridge, zerada da memoria, 0x21 UP+PIN).
 * - Algoritmo: dropdown explicado (5 curvas, curves.rs) + uso
 *   Assinar/Autenticar (hint 0x06, ignorado per S9.6).
 * - Lista via KEY_LIST (0x22) com EXCLUIR (confirma + 0x23 UP+PIN) e
 *   REGENERAR (apaga a antiga + cria nova no mesmo slot).
 * - Importar envelope manual (0x21) mantido. Sem Log com PII.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AccountsScreen(client: AegisBleClient) {
    val state by client.state.collectAsState()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val appLock = remember { AppLock(context) }
    var unlocked by remember { mutableStateOf(!FeatureFlags.ENABLE_APP_LOCK) }
    if (FeatureFlags.ENABLE_APP_LOCK && !unlocked) {
        LockScreen(appLock = appLock, onUnlocked = { unlocked = true })
        return
    }
    var busy by remember { mutableStateOf(false) }
    var mcHex by remember { mutableStateOf("") }
    var result by remember { mutableStateOf("—") }

    val curveDropdownOptions = remember {
        VendorOps.CURVES.map { c -> ExplainedOption(c, c.friendly, curveSimple(c)) }
    }
    var curveOption by remember { mutableStateOf(curveDropdownOptions[0]) }
    var useHardwareOrigin by remember { mutableStateOf(true) }
    var useSign by remember { mutableStateOf(true) }
    var useAuth by remember { mutableStateOf(true) }
    var confirmDelete by remember { mutableStateOf(false) }
    var confirmRegen by remember { mutableStateOf(false) }
    var label by remember { mutableStateOf("") }
    var slotText by remember { mutableStateOf("0") }
    var genMsg by remember { mutableStateOf("—") }

    var keysExpanded by remember { mutableStateOf(false) }
    var keys by remember { mutableStateOf(listOf<VendorOps.KeyEntry>()) }
    var selectedKey by remember { mutableStateOf<VendorOps.KeyEntry?>(null) }
    var listMsg by remember { mutableStateOf<String?>(null) }
    var importHex by remember { mutableStateOf("") }
    var importMsg by remember { mutableStateOf("—") }

    fun send(cmd: Int, cborHex: String) {
        scope.launch {
            busy = true
            try {
                val cbor = hexToBytes(cborHex)
                val response = withContext(Dispatchers.IO) {
                    client.sendMsg(byteArrayOf(cmd.toByte()) + cbor)
                }
                result = if (response == null) "sem resposta (UP? timeout?)" else "OK · " + response.size + " bytes"
            } catch (e: Exception) {
                result = "falhou: " + ((e.message ?: "erro").take(48))
            } finally {
                busy = false
            }
        }
    }

    fun refreshKeys() {
        scope.launch {
            busy = true
            listMsg = null
            try {
                val raw = withContext(Dispatchers.IO) {
                    client.sendVendor(VendorOps.OP_KEY_LIST, ByteArray(0))
                }
                val resp = VendorOps.parseResponse(raw)
                if (resp == null) {
                    listMsg = "sem resposta — toque no dispositivo e tente de novo"
                } else if (resp.status != VendorOps.STATUS_OK) {
                    listMsg = VendorOps.statusLabel(resp.status)
                } else {
                    keys = VendorOps.parseKeyList(resp.tlv)
                    if (selectedKey != null && keys.none { it.slot == selectedKey!!.slot }) {
                        selectedKey = null
                    }
                    listMsg = null
                }
            } catch (e: Exception) {
                listMsg = (e.message ?: "falha ao listar").take(64)
            } finally {
                busy = false
            }
        }
    }

    fun usageMaskOrNull(): Int? {
        val mask = (if (useSign) VendorOps.USAGE_SIGN else 0) or
            (if (useAuth) VendorOps.USAGE_AUTH else 0)
        return if (mask == 0) null else mask
    }

    fun generateOnDevice() {
        scope.launch {
            busy = true
            genMsg = "gerando no dispositivo… toque no botao dele"
            try {
                val slot = slotText.trim().toIntOrNull()
                require(slot != null && slot in 0..255) { "slot 0..255" }
                val req = VendorOps.genRequest(slot, label.trim(), curveOption.value.coseAlg, usageMaskOrNull())
                val raw = withContext(Dispatchers.IO) {
                    client.sendVendor(VendorOps.OP_KEY_GEN_ONDEVICE, req)
                }
                val resp = VendorOps.parseResponse(raw)
                genMsg = when {
                    resp == null -> "sem resposta — toque no dispositivo e tente de novo"
                    resp.status != VendorOps.STATUS_OK -> VendorOps.statusLabel(resp.status)
                    else -> {
                        refreshKeys()
                        "chave criada no slot " + slot + " (" + curveOption.title + ")"
                    }
                }
            } catch (e: Exception) {
                genMsg = (e.message ?: "falha ao gerar").take(64)
            } finally {
                busy = false
            }
        }
    }

    /**
     * Gera 32B no app, sela em envelope AEGN na hora, importa (0x21, UP+PIN)
     * e ZERA tudo da memoria (nunca persiste no celular; so NVS do device).
     */
    suspend fun sealAndImport(slot: Int, labelText: String): String {
        require(slot in 0..255) { "slot 0..255" }
        val labelBytes = labelText.trim().toByteArray(Charsets.UTF_8)
        require(labelBytes.size in 1..32) { "nome 1..32 letras" }
        var keyMat = ByteArray(0)
        var sealKey = ByteArray(0)
        var nonce = ByteArray(0)
        var envelope = ByteArray(0)
        var req = ByteArray(0)
        try {
            val rng = SecureRandom()
            keyMat = ByteArray(32).also { rng.nextBytes(it) }
            sealKey = ByteArray(32).also { rng.nextBytes(it) }
            nonce = ByteArray(12).also { rng.nextBytes(it) }
            envelope = withContext(Dispatchers.Default) {
                AegisBridge.envelopeSeal(sealKey, keyMat, ByteArray(0), nonce).getOrThrow()
            }
            req = VendorOps.writeTlv(VendorOps.TAG_SLOT, byteArrayOf(slot.toByte())) +
                VendorOps.writeTlv(VendorOps.TAG_ENVELOPE, envelope)
            val raw = withContext(Dispatchers.IO) {
                client.sendVendor(VendorOps.OP_KEY_IMPORT_ENVELOPE, req)
            }
            val resp = VendorOps.parseResponse(raw)
            when {
                resp == null -> throw IllegalStateException("sem resposta — toque no dispositivo e tente de novo")
                resp.status != VendorOps.STATUS_OK -> throw IllegalStateException(
                    VendorOps.statusLabel(resp.status) + " (enviar exige UP+PIN)",
                )
            }
            return "envelope salvo no slot " + slot + " (sumiu do celular)"
        } finally {
            AegisBridge.wipe(keyMat, sealKey, nonce, envelope, req)
        }
    }

    fun generateLocalAndImport() {
        scope.launch {
            busy = true
            genMsg = "criando envelope no app…"
            try {
                val slot = slotText.trim().toIntOrNull()
                require(slot != null && slot in 0..255) { "slot 0..255" }
                require(label.trim().isNotEmpty()) { "de um nome para a chave" }
                genMsg = sealAndImport(slot, label.trim())
                refreshKeys()
            } catch (e: Exception) {
                genMsg = (e.message ?: "falha ao gerar").take(64)
            } finally {
                busy = false
            }
        }
    }

    /** Rotacao: apaga a antiga e cria uma nova no mesmo slot (a antiga morre). */
    fun rotateSelected() {
        val target = selectedKey ?: return
        scope.launch {
            busy = true
            try {
                val delReq = VendorOps.writeTlv(VendorOps.TAG_SLOT, byteArrayOf(target.slot.toByte()))
                val delRaw = withContext(Dispatchers.IO) {
                    client.sendVendor(VendorOps.OP_KEY_DELETE, delReq)
                }
                val delResp = VendorOps.parseResponse(delRaw)
                if (delResp == null || delResp.status != VendorOps.STATUS_OK) {
                    throw IllegalStateException(
                        (delResp?.let { VendorOps.statusLabel(it.status) } ?: "sem resposta") +
                            " (rotacao cancelada, antiga mantida)",
                    )
                }
                genMsg = if (useHardwareOrigin) {
                    val req = VendorOps.genRequest(
                        target.slot, target.label, curveOption.value.coseAlg, usageMaskOrNull(),
                    )
                    val raw = withContext(Dispatchers.IO) {
                        client.sendVendor(VendorOps.OP_KEY_GEN_ONDEVICE, req)
                    }
                    val resp = VendorOps.parseResponse(raw)
                    if (resp == null || resp.status != VendorOps.STATUS_OK) {
                        "antiga apagada; nova falhou: " +
                            (resp?.let { VendorOps.statusLabel(it.status) } ?: "sem resposta")
                    } else {
                        "girada no slot " + target.slot + " (antiga parou de funcionar)"
                    }
                } else {
                    sealAndImport(target.slot, target.label)
                }
                refreshKeys()
            } catch (e: Exception) {
                genMsg = (e.message ?: "falha ao girar").take(96)
            } finally {
                busy = false
            }
        }
    }

    fun deleteSelected() {
        val target = selectedKey ?: return
        scope.launch {
            busy = true
            try {
                val req = VendorOps.writeTlv(VendorOps.TAG_SLOT, byteArrayOf(target.slot.toByte()))
                val raw = withContext(Dispatchers.IO) {
                    client.sendVendor(VendorOps.OP_KEY_DELETE, req)
                }
                val resp = VendorOps.parseResponse(raw)
                genMsg = when {
                    resp == null -> "sem resposta — toque no dispositivo e tente de novo"
                    resp.status != VendorOps.STATUS_OK -> VendorOps.statusLabel(resp.status) + " (apagar exige UP+PIN)"
                    else -> {
                        selectedKey = null
                        refreshKeys()
                        "apagada do dispositivo (slot " + target.slot + ")"
                    }
                }
            } catch (e: Exception) {
                genMsg = (e.message ?: "falha ao apagar").take(64)
            } finally {
                busy = false
            }
        }
    }

    fun importEnvelope() {
        scope.launch {
            busy = true
            try {
                val slot = slotText.trim().toIntOrNull()
                require(slot != null && slot in 0..255) { "slot 0..255" }
                val env = hexToBytes(importHex)
                val req = VendorOps.writeTlv(VendorOps.TAG_SLOT, byteArrayOf(slot.toByte())) +
                    VendorOps.writeTlv(VendorOps.TAG_ENVELOPE, env)
                val raw = withContext(Dispatchers.IO) {
                    client.sendVendor(VendorOps.OP_KEY_IMPORT_ENVELOPE, req)
                }
                val resp = VendorOps.parseResponse(raw)
                importMsg = when {
                    resp == null -> "sem resposta — toque no dispositivo e tente de novo"
                    resp.status != VendorOps.STATUS_OK -> VendorOps.statusLabel(resp.status) + " (importar exige UP+PIN)"
                    else -> {
                        refreshKeys()
                        "envelope importado no slot " + slot
                    }
                }
            } catch (e: Exception) {
                importMsg = (e.message ?: "envelope invalido").take(64)
            } finally {
                busy = false
            }
        }
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Chaves", maxLines = 1, overflow = TextOverflow.Ellipsis) }) }) { inner ->
        AegisScreenColumn(inner = inner) {
            FriendlyText(
                text = "Link: " + state.connection + " · " + BleContract.statusLabel(state.status),
                maxLines = 2,
            )
            if (FeatureFlags.ENABLE_DEVICE_PRESS && state.status == BleContract.STATUS_UP_NEEDED) {
                PressDeviceSheet(
                    statusLabel = BleContract.statusLabel(state.status),
                    onCancel = {
                        scope.launch(Dispatchers.IO) {
                            client.cancel()
                            SanitizedLog.record(SanitizedLog.Event.DEVICE_PRESS_CANCELLED)
                        }
                    }
                )
            }
            if (busy) CircularProgressIndicator()

            SectionTitle("Nova chave — onde criar?")
            FriendlyText(
                text = "Onde fica salvo: só no dispositivo. O celular nunca guarda a chave.",
                maxLines = 2,
            )
            LabeledRadio(
                selected = useHardwareOrigin,
                title = "No dispositivo (recomendado)",
                explanation = "A chave nasce dentro do aparelho e nunca sai de lá.",
                onClick = { useHardwareOrigin = true },
                enabled = !busy,
            )
            LabeledRadio(
                selected = !useHardwareOrigin,
                title = "Gerar no app e enviar selado",
                explanation = "O app cria agora, manda um envelope na hora e apaga do celular.",
                onClick = { useHardwareOrigin = false },
                enabled = !busy,
            )
            ExplainedDropdown(
                label = "Algoritmo",
                options = curveDropdownOptions,
                selected = curveOption,
                onSelected = { curveOption = it },
                enabled = !busy,
            )
            OutlinedTextField(
                value = label,
                onValueChange = { label = it.take(32) },
                label = { Text("Nome (1..32 letras)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = slotText,
                onValueChange = { slotText = it.filter { ch -> ch.isDigit() }.take(3) },
                label = { Text("Slot (0..255)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            SectionTitle("Para que ela serve?")
            LabeledCheckbox(
                checked = useSign,
                title = "Assinar",
                explanation = "Provar que foi você (entrar em sites, aprovar).",
                onCheckedChange = { useSign = it },
                enabled = !busy,
            )
            LabeledCheckbox(
                checked = useAuth,
                title = "Autenticar",
                explanation = "Destravar acesso (desbloquear apps e contas).",
                onCheckedChange = { useAuth = it },
                enabled = !busy,
            )
            Button(
                onClick = { if (useHardwareOrigin) generateOnDevice() else generateLocalAndImport() },
                enabled = !busy && label.trim().isNotEmpty() && (useSign || useAuth),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("GERAR E SALVAR NO DISPOSITIVO", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            FriendlyText(text = "Resultado: " + genMsg, maxLines = 3)

            SectionTitle("Chaves no dispositivo")
            OutlinedButton(onClick = ::refreshKeys, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                Text("Atualizar lista (toque no dispositivo)", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            if (keys.isEmpty()) {
                FriendlyEmpty(message = listMsg ?: "Nada aqui ainda. Toque no dispositivo para carregar.")
            } else {
                ExposedDropdownMenuBox(
                    expanded = keysExpanded,
                    onExpandedChange = { keysExpanded = !keysExpanded },
                ) {
                    OutlinedTextField(
                        value = selectedKey?.let { "slot " + it.slot + " · " + it.label } ?: "Escolha uma chave",
                        onValueChange = {},
                        readOnly = true,
                        label = { Text("Chaves (KEY_LIST)") },
                        trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = keysExpanded) },
                        modifier = Modifier.menuAnchor().fillMaxWidth(),
                    )
                    ExposedDropdownMenu(
                        expanded = keysExpanded,
                        onDismissRequest = { keysExpanded = false },
                    ) {
                        for (entry in keys) {
                            DropdownMenuItem(
                                text = { Text("slot " + entry.slot + " · " + entry.label, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                                onClick = {
                                    selectedKey = entry
                                    keysExpanded = false
                                },
                            )
                        }
                    }
                }
                OutlinedButton(
                    onClick = { confirmDelete = true },
                    enabled = !busy && selectedKey != null,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("EXCLUIR selecionada (UP+PIN)", maxLines = 1, overflow = TextOverflow.Ellipsis) }
                OutlinedButton(
                    onClick = { confirmRegen = true },
                    enabled = !busy && selectedKey != null,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("REGENERAR (troca por uma nova)", maxLines = 1, overflow = TextOverflow.Ellipsis) }
                FriendlyText(
                    text = "Regenerar apaga a antiga e cria uma nova no mesmo lugar. A antiga para de funcionar.",
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 2,
                )
            }
            listMsg?.let {
                if (keys.isNotEmpty()) FriendlyText(text = it, maxLines = 2)
            }

            SectionTitle("Importar envelope (AEGN)")
            OutlinedTextField(
                value = importHex,
                onValueChange = { importHex = it },
                label = { Text("Envelope (hex)") },
                supportingText = { Text("Opaco: o device so valida e guarda.") },
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedButton(
                onClick = ::importEnvelope,
                enabled = !busy && importHex.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Importar no slot acima (UP+PIN)", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            FriendlyText(text = "Envelope: " + importMsg, maxLines = 2)

            SectionTitle("Avancado (CTAP direto)")
            OutlinedButton(
                onClick = { send(BleContract.CTAP_CMD_GET_INFO, "") },
                enabled = !busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("GetInfo (0x04)", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            OutlinedTextField(
                value = mcHex,
                onValueChange = { mcHex = it },
                label = { Text("MakeCredential CBOR (hex)") },
                supportingText = { Text("Tecnico: enviado como [0x01 + CBOR].") },
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                onClick = { send(BleContract.CTAP_CMD_MAKE_CREDENTIAL, mcHex) },
                enabled = !busy && mcHex.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("MakeCredential (0x01)", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            FriendlyText(text = "Resultado: " + result, maxLines = 2)
            FriendlyText(
                text = "A privada nunca sai do dispositivo.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 2,
            )
            if (confirmDelete && selectedKey != null) {
                ConfirmActionDialog(
                    title = "Excluir chave?",
                    body = "Apagar \u0022" + selectedKey!!.label + "\u0022 (slot " + selectedKey!!.slot +
                        ") do dispositivo? Ela para de funcionar. Precisa tocar no botão do aparelho (UP+PIN).",
                    confirmLabel = "EXCLUIR",
                    onConfirm = { confirmDelete = false; deleteSelected() },
                    onDismiss = { confirmDelete = false },
                )
            }
            if (confirmRegen && selectedKey != null) {
                ConfirmActionDialog(
                    title = "Regenerar chave?",
                    body = "Trocar \u0022" + selectedKey!!.label + "\u0022 por uma nova no mesmo lugar? A antiga para de funcionar.",
                    confirmLabel = "REGENERAR",
                    onConfirm = { confirmRegen = false; rotateSelected() },
                    onDismiss = { confirmRegen = false },
                )
            }
        }
    }
}

/** Texto simples do que cada curva significa (usuario nao-tecnico). */
private fun curveSimple(curve: VendorOps.CurveOption): String = when (curve.coseAlg) {
    -7 -> "Padrão da internet, rápido e compatível com quase tudo."
    -8 -> "Moderna e rápida (ótima escolha também)."
    -35 -> "Segurança extra, um pouco mais lenta."
    -36 -> "Segurança máxima, mais lenta."
    -47 -> "A curva do Bitcoin (casos especiais)."
    else -> curve.detail
}
