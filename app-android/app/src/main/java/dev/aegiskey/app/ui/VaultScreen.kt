package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.net.WifiApi
import dev.aegiskey.app.security.AppLock
import dev.aegiskey.app.security.FeatureFlags
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import java.io.File

/**
 * Cofre OATH: codigos gerados NO dispositivo, exibidos com countdown 30s.
 * - Adicionar: nome + TOTP/HOTP explicado + digitos + segredo colado
 *   (QR sem camera: cole o segredo) ou gerado aqui; PUT (0x24, UP+PIN)
 *   com buffer zerado apos o envio (nunca persiste no celular).
 * - Contas via OATH_LIST (0x25): ver-codigo (0x26), EXCLUIR
 *   (confirma + 0x27 UP+PIN) e REGENERAR (segredo novo via PUT).
 * - WiFi GET /oath/code (fallback) + import/export AEGN mantidos.
 * - Segredos nunca sao exibidos, logados ou guardados. Sem Log com PII.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultScreen(client: AegisBleClient? = null) {
    val context = LocalContext.current
    val appLock = remember { AppLock(context) }
    var unlocked by remember { mutableStateOf(!FeatureFlags.ENABLE_APP_LOCK) }
    if (FeatureFlags.ENABLE_APP_LOCK && !unlocked) {
        LockScreen(appLock = appLock, onUnlocked = { unlocked = true })
        return
    }
    val clipboard = LocalClipboardManager.current
    val scope = rememberCoroutineScope()
    var baseUrl by remember { mutableStateOf("http://192.168.4.1") }
    var account by remember { mutableStateOf("") }
    var accountsExpanded by remember { mutableStateOf(false) }
    var deviceAccounts by remember { mutableStateOf(listOf<VendorOps.OathEntry>()) }
    var listMsg by remember { mutableStateOf<String?>(null) }
    var entries by remember { mutableStateOf(listOf<AegisBridge.OathEntry>()) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var envHex by remember { mutableStateOf("") }
    var envInfo by remember { mutableStateOf("—") }
    var savedCount by remember { mutableStateOf(0) }
    var nowSec by remember { mutableStateOf(System.currentTimeMillis() / 1000) }
    var addName by remember { mutableStateOf("") }
    var isTotp by remember { mutableStateOf(true) }
    var digitsOption by remember { mutableStateOf(DIGIT_OPTIONS[0]) }
    var addSecret by remember { mutableStateOf("") }
    var counterText by remember { mutableStateOf("0") }
    var addMsg by remember { mutableStateOf("—") }
    var confirmOathDelete by remember { mutableStateOf(false) }
    var confirmOathRegen by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        while (true) {
            delay(1000)
            nowSec = System.currentTimeMillis() / 1000
        }
    }

    fun refreshAccounts() {
        val ble = client ?: run {
            listMsg = "conecte via BLE primeiro (tela Conectar)"
            return
        }
        scope.launch {
            busy = true
            listMsg = null
            try {
                val raw = withContext(Dispatchers.IO) {
                    ble.sendVendor(VendorOps.OP_OATH_LIST, ByteArray(0))
                }
                val resp = VendorOps.parseResponse(raw)
                if (resp == null) {
                    listMsg = "sem resposta — toque no dispositivo e tente de novo"
                } else if (resp.status != VendorOps.STATUS_OK) {
                    listMsg = VendorOps.statusLabel(resp.status)
                } else {
                    deviceAccounts = VendorOps.parseOathList(resp.tlv)
                    listMsg = null
                }
            } catch (e: Exception) {
                listMsg = (e.message ?: "falha ao listar").take(64)
            } finally {
                busy = false
            }
        }
    }

    fun fetchBleCode(name: String) {
        val ble = client ?: return
        scope.launch {
            busy = true
            error = null
            try {
                val nameBytes = name.toByteArray(Charsets.UTF_8)
                val req = VendorOps.writeTlv(VendorOps.TAG_OATH_NAME, nameBytes)
                val raw = withContext(Dispatchers.IO) {
                    ble.sendVendor(VendorOps.OP_OATH_CODE, req)
                }
                val resp = VendorOps.parseResponse(raw)
                if (resp == null) {
                    error = "sem resposta — toque no dispositivo"
                } else if (resp.status != VendorOps.STATUS_OK) {
                    error = VendorOps.statusLabel(resp.status)
                } else {
                    val records = VendorOps.parseTlvRecords(resp.tlv)
                    val codeBytes = VendorOps.findTlv(records, VendorOps.TAG_OATH_RESPONSE)
                        ?: VendorOps.findTlv(records, VendorOps.TAG_OATH_TRUNCATED)
                    val code = codeBytes?.let { runCatching { it.toString(Charsets.UTF_8) }.getOrNull() }?.take(8)
                    if (code.isNullOrBlank()) {
                        error = "codigo vazio do dispositivo"
                    } else {
                        val entry = AegisBridge.OathEntry(name, code, AegisBridge.remainingSeconds(nowSec))
                        entries = (entries.filterNot { it.account == entry.account } + entry).take(32)
                        DeviceLog.append(DeviceLog.Category.BLE, "OATH code ok bytes=" + code.length)
                    }
                }
            } catch (e: Exception) {
                error = (e.message ?: "falha ao buscar").take(64)
            } finally {
                busy = false
            }
        }
    }

    fun fetchWifi() {
        scope.launch {
            busy = true
            error = null
            try {
                val entry = withContext(Dispatchers.IO) { WifiApi.getOathCode(baseUrl, account.trim()) }
                entries = (entries.filterNot { it.account == entry.account } + entry).take(32)
            } catch (e: Exception) {
                error = (e.message ?: "falha ao buscar").take(64)
            } finally {
                busy = false
            }
        }
    }

    /** PUT (0x24, UP+PIN): monta TLV, envia e ZERA segredo+req (nunca persiste). */
    fun putOathAccount(secret: ByteArray) {
        val ble = client ?: run {
            addMsg = "conecte via BLE primeiro (tela Conectar)"
            AegisBridge.wipe(secret)
            return
        }
        scope.launch {
            busy = true
            var req = ByteArray(0)
            try {
                val typeAlgo = (if (isTotp) VendorOps.OATH_TYPE_TOTP else VendorOps.OATH_TYPE_HOTP) or
                    VendorOps.OATH_ALGO_SHA1
                val counter = if (isTotp) {
                    null
                } else {
                    val c = counterText.trim().toLongOrNull()
                    require(c != null && c in 0..0xFFFFFFFFL) { "contador 0..4294967295" }
                    c
                }
                req = VendorOps.oathPutRequest(addName, typeAlgo, digitsOption.value, secret, counter)
                val raw = withContext(Dispatchers.IO) {
                    ble.sendVendor(VendorOps.OP_OATH_PUT, req)
                }
                val resp = VendorOps.parseResponse(raw)
                addMsg = when {
                    resp == null -> "sem resposta — toque no dispositivo e tente de novo"
                    resp.status != VendorOps.STATUS_OK -> VendorOps.statusLabel(resp.status) + " (salvar exige UP+PIN)"
                    else -> {
                        addSecret = ""
                        refreshAccounts()
                        "conta salva no dispositivo (segredo sumiu do celular)"
                    }
                }
            } catch (e: Exception) {
                addMsg = (e.message ?: "falha ao salvar").take(64)
            } finally {
                AegisBridge.wipe(secret, req)
                busy = false
            }
        }
    }

    fun saveManualSecret() {
        if (addName.trim().isEmpty()) {
            addMsg = "de um nome para a conta (ex.: GitHub:alice)"
            return
        }
        try {
            putOathAccount(base32ToBytes(addSecret))
        } catch (e: Exception) {
            addMsg = (e.message ?: "segredo invalido").take(64)
        }
    }

    fun generateAndSaveSecret() {
        if (addName.trim().isEmpty()) {
            addMsg = "de um nome para a conta (ex.: GitHub:alice)"
            return
        }
        val rng = SecureRandom()
        putOathAccount(ByteArray(20).also { rng.nextBytes(it) })
    }

    fun deleteOathAccount() {
        val target = account.ifBlank { null } ?: return
        val ble = client ?: run {
            listMsg = "conecte via BLE primeiro (tela Conectar)"
            return
        }
        scope.launch {
            busy = true
            try {
                val req = VendorOps.writeTlv(VendorOps.TAG_OATH_NAME, target.toByteArray(Charsets.UTF_8))
                val raw = withContext(Dispatchers.IO) {
                    ble.sendVendor(VendorOps.OP_OATH_DELETE, req)
                }
                val resp = VendorOps.parseResponse(raw)
                if (resp == null || resp.status != VendorOps.STATUS_OK) {
                    listMsg = (resp?.let { VendorOps.statusLabel(it.status) } ?: "sem resposta") +
                        " (apagar exige UP+PIN)"
                } else {
                    account = ""
                    listMsg = null
                    refreshAccounts()
                }
            } catch (e: Exception) {
                listMsg = (e.message ?: "falha ao apagar").take(64)
            } finally {
                busy = false
            }
        }
    }

    /** Rotacao OATH: segredo novo gerado aqui faz PUT por cima do mesmo nome. */
    fun regenOathSecret() {
        val target = account.ifBlank { null } ?: return
        if (client == null) {
            listMsg = "conecte via BLE primeiro (tela Conectar)"
            return
        }
        addName = target
        val rng = SecureRandom()
        putOathAccount(ByteArray(20).also { rng.nextBytes(it) })
    }

    fun importEnvelope() {
        scope.launch(Dispatchers.Default) {
            try {
                val clean = envHex.filterNot { it.isWhitespace() }
                require(clean.length % 2 == 0) { "hex invalido" }
                val bytes = clean.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                val ctLen = AegisBridge.envelopeValidate(bytes).getOrThrow()
                envInfo = "envelope AEGN valido · " + ctLen + " bytes"
                val key = MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
                val file = File(context.filesDir, "envelope_" + System.currentTimeMillis() + ".aegn")
                val enc = EncryptedFile.Builder(
                    context, file, key,
                    EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
                ).build()
                withContext(Dispatchers.IO) { enc.openFileOutput().use { it.write(bytes) } }
                savedCount += 1
            } catch (e: Exception) {
                envInfo = "invalido: " + ((e.message ?: "erro").take(48))
            }
        }
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Cofre (OATH)", maxLines = 1, overflow = TextOverflow.Ellipsis) }) }) { inner ->
        AegisScreenColumn(inner = inner) {
            SectionTitle("Adicionar conta")
            FriendlyText(
                text = "Onde fica salvo: só no dispositivo. O app nunca guarda o segredo.",
                maxLines = 2,
            )
            OutlinedTextField(
                value = addName,
                onValueChange = { addName = it.take(64) },
                label = { Text("Conta (ex.: GitHub:alice)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            LabeledToggle(
                checked = isTotp,
                title = if (isTotp) "TOTP — muda com o tempo" else "HOTP — muda a cada uso",
                explanation = if (isTotp) {
                    "O código troca sozinho a cada 30 segundos. É o mais comum."
                } else {
                    "O código troca a cada uso, com contador. Só para casos especiais."
                },
                onCheckedChange = { isTotp = it },
                enabled = !busy,
            )
            ExplainedDropdown(
                label = "Dígitos do código",
                options = DIGIT_OPTIONS,
                selected = digitsOption,
                onSelected = { digitsOption = it },
                enabled = !busy,
            )
            OutlinedTextField(
                value = addSecret,
                onValueChange = { addSecret = it },
                label = { Text("Segredo (cole do site ou do QR)") },
                supportingText = { Text("Sem câmera: abra o QR em outro app e cole o segredo aqui.") },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            if (!isTotp) {
                OutlinedTextField(
                    value = counterText,
                    onValueChange = { counterText = it.filter { ch -> ch.isDigit() }.take(10) },
                    label = { Text("Contador inicial") },
                    supportingText = { Text("Começa em 0; tem que igualar o do site.") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            Button(
                onClick = ::saveManualSecret,
                enabled = !busy && addName.isNotBlank() && addSecret.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Salvar no dispositivo (UP+PIN)", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            OutlinedButton(
                onClick = ::generateAndSaveSecret,
                enabled = !busy && addName.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Gerar segredo aqui e salvar", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            FriendlyText(text = "Resultado: " + addMsg, maxLines = 3)

            SectionTitle("Contas no dispositivo")
            OutlinedButton(onClick = ::refreshAccounts, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                Text("Atualizar contas (toque no dispositivo)", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            if (deviceAccounts.isEmpty()) {
                FriendlyEmpty(message = listMsg ?: "Nada aqui ainda. Toque no dispositivo para carregar.")
            } else {
                ExposedDropdownMenuBox(
                    expanded = accountsExpanded,
                    onExpandedChange = { accountsExpanded = !accountsExpanded },
                ) {
                    OutlinedTextField(
                        value = account.ifBlank { "Escolha uma conta" },
                        onValueChange = {},
                        readOnly = true,
                        label = { Text("Contas (OATH_LIST)") },
                        trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = accountsExpanded) },
                        modifier = Modifier.menuAnchor().fillMaxWidth(),
                    )
                    ExposedDropdownMenu(
                        expanded = accountsExpanded,
                        onDismissRequest = { accountsExpanded = false },
                    ) {
                        for (entry in deviceAccounts) {
                            DropdownMenuItem(
                                text = { Text(entry.name, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                                onClick = {
                                    account = entry.name
                                    accountsExpanded = false
                                    fetchBleCode(entry.name)
                                },
                            )
                        }
                    }
                }
            }
            listMsg?.let {
                if (deviceAccounts.isNotEmpty()) FriendlyText(text = it, maxLines = 2)
            }

            if (account.isNotBlank()) {
                OutlinedButton(
                    onClick = { fetchBleCode(account) },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Ver código da selecionada", maxLines = 1, overflow = TextOverflow.Ellipsis) }
                OutlinedButton(
                    onClick = { confirmOathDelete = true },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("EXCLUIR selecionada (UP+PIN)", maxLines = 1, overflow = TextOverflow.Ellipsis) }
                OutlinedButton(
                    onClick = { confirmOathRegen = true },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("REGENERAR segredo", maxLines = 1, overflow = TextOverflow.Ellipsis) }
                FriendlyText(
                    text = "Regenerar cria um segredo novo na hora (usa tipo e dígitos acima). O código antigo para de funcionar.",
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 3,
                )
            }

            SectionTitle("Buscar por WiFi (alternativo)")
            OutlinedTextField(
                value = baseUrl,
                onValueChange = { baseUrl = it },
                label = { Text("Endereco do dispositivo") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = account,
                onValueChange = { account = it },
                label = { Text("Conta (ex.: GitHub:alice)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                onClick = ::fetchWifi,
                enabled = !busy && account.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Buscar codigo (WiFi)", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            if (busy) CircularProgressIndicator()
            error?.let { Text("Erro: " + it, color = MaterialTheme.colorScheme.error, maxLines = 2, overflow = TextOverflow.Ellipsis) }
            for (entry in entries) {
                val remaining = AegisBridge.remainingSeconds(nowSec)
                Card {
                    androidx.compose.foundation.layout.Column(
                        Modifier.padding(12.dp),
                        verticalArrangement = androidx.compose.foundation.layout.Arrangement.spacedBy(4.dp),
                    ) {
                        Text(entry.account, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(entry.code, style = MaterialTheme.typography.displaySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        LinearProgressIndicator(progress = { remaining / 30f })
                        FriendlyText(text = remaining.toString() + " s restantes (janela 30s)", maxLines = 1)
                        OutlinedButton(onClick = { clipboard.setText(AnnotatedString(entry.code)) }) {
                            Text("Copiar codigo", maxLines = 1, overflow = TextOverflow.Ellipsis)
                        }
                    }
                }
            }
            SectionTitle("Importar / exportar envelope")
            OutlinedTextField(
                value = envHex,
                onValueChange = { envHex = it },
                label = { Text("Envelope (hex)") },
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                onClick = ::importEnvelope,
                enabled = envHex.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Validar + salvar criptografado", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            FriendlyText(text = "Envelope: " + envInfo + " · salvos: " + savedCount, maxLines = 2)
            FriendlyText(
                text = "So codigos e nomes saem do dispositivo. Segredos ficam nele.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 2,
            )
            if (confirmOathDelete) {
                ConfirmActionDialog(
                    title = "Excluir conta?",
                    body = "Apagar \u0022" + account + "\u0022 do dispositivo? Os códigos param de funcionar. Precisa tocar no botão do aparelho (UP+PIN).",
                    confirmLabel = "EXCLUIR",
                    onConfirm = { confirmOathDelete = false; deleteOathAccount() },
                    onDismiss = { confirmOathDelete = false },
                )
            }
            if (confirmOathRegen) {
                ConfirmActionDialog(
                    title = "Regenerar segredo?",
                    body = "Criar um segredo novo para \u0022" + account + "\u0022? O código antigo para de funcionar na hora.",
                    confirmLabel = "REGENERAR",
                    onConfirm = { confirmOathRegen = false; regenOathSecret() },
                    onDismiss = { confirmOathRegen = false },
                )
            }
        }
    }
}

private val DIGIT_OPTIONS = listOf(
    ExplainedOption(6, "6 dígitos", "O mais comum — funciona quase sempre."),
    ExplainedOption(7, "7 dígitos", "Alguns bancos e empresas pedem."),
    ExplainedOption(8, "8 dígitos", "Mais longo; use se o site pedir."),
)

/** Decodifica segredo base32 (RFC4648, sem padding obrigatório). */
private fun base32ToBytes(input: String): ByteArray {
    val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    val clean = input.trim().uppercase().filter { !it.isWhitespace() && it != '-' }.trimEnd('=')
    require(clean.isNotEmpty() && clean.all { it in alphabet }) { "segredo base32 invalido" }
    var bits = 0
    var value = 0
    val out = mutableListOf<Byte>()
    for (c in clean) {
        value = (value shl 5) or alphabet.indexOf(c)
        bits += 5
        if (bits >= 8) {
            out.add(((value shr (bits - 8)) and 0xFF).toByte())
            bits -= 8
        }
    }
    require(out.size in 10..64) { "segredo 10..64 bytes" }
    return out.toByteArray()
}
