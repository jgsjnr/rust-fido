package dev.aegiskey.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
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
import java.io.File
import java.security.SecureRandom

/**
 * Cofre OATH — 3 blocos (Jornadas 1-4):
 * 1. Estado de vinculo fail-closed no topo (GateBanner + TestModeBanner).
 * 2. Lista de contas com codigo mono XXX XXX + barra countdown + Copiar.
 * 3. Secoes colapsadas: Adicionar / WiFi / Envelope.
 *
 * Origens: OATH_LIST 0x25 / OATH_CODE 0x26 via BLE (so codigos, nunca
 * segredo; wipe em finally preservado) e GET /oath/code via WiFi.
 * Gates: vinculo -> UP (PressDeviceSheet) -> PIN. Tick 1s so texto+progresso;
 * animacao (fade 200ms) so na troca do codigo (CodeCard).
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
    var selected by remember { mutableStateOf("") }
    var deviceAccounts by remember { mutableStateOf(listOf<VendorOps.OathEntry>()) }
    var listMsg by remember { mutableStateOf<String?>(null) }
    var entries by remember { mutableStateOf(listOf<AegisBridge.OathEntry>()) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var lastStatus by remember { mutableStateOf<Int?>(null) }
    var showPressSheet by remember { mutableStateOf(false) }
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

    val gate = when {
        client == null -> VaultGate.NO_BLE
        // Fail-closed: antes da primeira resposta do dispositivo, assume sem
        // vinculo (banner NEED_BINDING visivel onde os codigos deveriam estar).
        lastStatus == null -> VaultGate.NEED_BINDING
        lastStatus == VendorOps.STATUS_NEED_BINDING -> VaultGate.NEED_BINDING
        lastStatus == VendorOps.STATUS_NEED_UP || showPressSheet -> VaultGate.NEED_UP
        lastStatus == VendorOps.STATUS_NEED_PIN -> VaultGate.NEED_PIN
        else -> VaultGate.READY
    }

    LaunchedEffect(Unit) {
        while (true) {
            delay(1000)
            nowSec = System.currentTimeMillis() / 1000
        }
    }

    fun noteStatus(status: Int) {
        lastStatus = status
        showPressSheet = status == VendorOps.STATUS_NEED_UP
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
                    noteStatus(resp.status)
                    listMsg = VendorOps.statusLabel(resp.status)
                } else {
                    lastStatus = VendorOps.STATUS_OK
                    showPressSheet = false
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
                // TOTP precisa do contador (device sem RTC): 8B big-endian.
                // HOTP ignora o challenge (usa o contador interno).
                val counter = nowSec / 30
                val chalBytes = ByteArray(8) { i -> ((counter shr (56 - 8 * i)) and 0xFFL).toByte() }
                val req = VendorOps.writeTlv(VendorOps.TAG_OATH_NAME, nameBytes) +
                    VendorOps.writeTlv(VendorOps.TAG_OATH_CHALLENGE, chalBytes)
                val raw = withContext(Dispatchers.IO) {
                    ble.sendVendor(VendorOps.OP_OATH_CODE, req)
                }
                val resp = VendorOps.parseResponse(raw)
                if (resp == null) {
                    error = "sem resposta — toque no dispositivo"
                } else if (resp.status != VendorOps.STATUS_OK) {
                    noteStatus(resp.status)
                    error = VendorOps.statusLabel(resp.status)
                } else {
                    lastStatus = VendorOps.STATUS_OK
                    showPressSheet = false
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

    /** Ponto de extensao: despacha por [VaultAccount.kind]; wallet/PIV entram sem refazer a lista. */
    fun fetchVaultCode(account: VaultAccount) {
        when (account.kind) {
            VaultKind.OATH_TOTP, VaultKind.OATH_HOTP -> fetchBleCode(account.name)
            VaultKind.WALLET -> error = "carteira sai em outra tela (extensao pronta)"
            VaultKind.PIV -> error = "PIV sai em outra tela (extensao pronta)"
        }
    }

    fun fetchWifi() {
        scope.launch {
            busy = true
            error = null
            try {
                val entry = withContext(Dispatchers.IO) { WifiApi.getOathCode(baseUrl, selected.trim()) }
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
                    resp.status != VendorOps.STATUS_OK -> {
                        noteStatus(resp.status)
                        VendorOps.statusLabel(resp.status) + " (salvar exige UP+PIN)"
                    }
                    else -> {
                        lastStatus = VendorOps.STATUS_OK
                        showPressSheet = false
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
        val target = selected.ifBlank { null } ?: return
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
                    if (resp != null) noteStatus(resp.status)
                    listMsg = (resp?.let { VendorOps.statusLabel(it.status) } ?: "sem resposta") +
                        " (apagar exige UP+PIN)"
                } else {
                    lastStatus = VendorOps.STATUS_OK
                    showPressSheet = false
                    selected = ""
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
        val target = selected.ifBlank { null } ?: return
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
                    EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB,
                ).build()
                withContext(Dispatchers.IO) { enc.openFileOutput().use { it.write(bytes) } }
                savedCount += 1
            } catch (e: Exception) {
                envInfo = "invalido: " + ((e.message ?: "erro").take(48))
            }
        }
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Cofre", maxLines = 1, overflow = TextOverflow.Ellipsis) }) }) { inner ->
        AegisScreenColumn(inner = inner) {
            // Bloco 1 — vinculo fail-closed no topo.
            GateBanner(gate = gate)
            if (client != null) {
                TestModeBanner(client = client)
            } else {
                FriendlyText(
                    text = "Sem conexao: o cofre mostra este aviso em vez de codigos.",
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 2,
                )
            }
            if (showPressSheet && client != null) {
                PressDeviceSheet(
                    statusLabel = "toque no dispositivo (UP)",
                    onCancel = {
                        scope.launch(Dispatchers.IO) {
                            runCatching { client.cancel() }
                            showPressSheet = false
                        }
                    },
                    onDismiss = { showPressSheet = false },
                )
            }
            if (busy) CircularProgressIndicator()
            error?.let { Text("Erro: " + it, color = MaterialTheme.colorScheme.error, maxLines = 2, overflow = TextOverflow.Ellipsis) }

            // Bloco 2 — codigos (Jornada 2).
            SectionTitle("Codigos")
            FriendlyText(
                text = "Jornada 2: escolha a conta e veja o codigo atual. So codigos e nomes saem do dispositivo — segredos ficam nele.",
                maxLines = 3,
            )
            OutlinedButton(onClick = ::refreshAccounts, enabled = !busy && client != null, modifier = Modifier.fillMaxWidth()) {
                Text("Atualizar contas (toque no dispositivo)", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            if (deviceAccounts.isEmpty()) {
                FriendlyEmpty(message = listMsg ?: "Nada aqui ainda. Toque no dispositivo para carregar.")
            } else {
                listMsg?.let { FriendlyText(text = it, maxLines = 2) }
                for (dev in deviceAccounts) {
                    val kind = if (isTotp) VaultKind.OATH_TOTP else VaultKind.OATH_HOTP
                    val vault = VaultAccount(dev.name, kind)
                    val cached = entries.firstOrNull { it.account == dev.name }
                    CodeCard(
                        account = vault,
                        code = cached?.code,
                        remaining = AegisBridge.remainingSeconds(nowSec),
                        busy = busy,
                        onCopy = { clipboard.setText(AnnotatedString(it)) },
                        onRefresh = { fetchVaultCode(it) },
                    )
                }
            }
            // Codigos via WiFi tambem aparecem aqui (mesmo cartao).
            for (entry in entries.filter { e -> deviceAccounts.none { it.name == e.account } }) {
                CodeCard(
                    account = VaultAccount(entry.account),
                    code = entry.code,
                    remaining = AegisBridge.remainingSeconds(nowSec),
                    busy = busy,
                    onCopy = { clipboard.setText(AnnotatedString(it)) },
                    onRefresh = { fetchVaultCode(it) },
                )
            }
            if (selected.isNotBlank()) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                    OutlinedButton(onClick = { confirmOathDelete = true }, enabled = !busy, modifier = Modifier.weight(1f)) {
                        Text("EXCLUIR (UP+PIN)", maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    OutlinedButton(onClick = { confirmOathRegen = true }, enabled = !busy, modifier = Modifier.weight(1f)) {
                        Text("REGENERAR", maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                }
            }

            // Bloco 3 — secoes colapsadas (Jornadas 3-4).
            SectionTitle("Mais opcoes")
            CollapsedSection(title = "Adicionar conta (Jornada 3)") {
                FriendlyText(
                    text = "Onde fica salvo: so no dispositivo. O app nunca guarda o segredo.",
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
                        "O codigo troca sozinho a cada 30 segundos. E o mais comum."
                    } else {
                        "O codigo troca a cada uso, com contador. So para casos especiais."
                    },
                    onCheckedChange = { isTotp = it },
                    enabled = !busy,
                )
                ExplainedDropdown(
                    label = "Digitos do codigo",
                    options = DIGIT_OPTIONS,
                    selected = digitsOption,
                    onSelected = { digitsOption = it },
                    enabled = !busy,
                )
                OutlinedTextField(
                    value = addSecret,
                    onValueChange = { addSecret = it },
                    label = { Text("Segredo (cole do site ou do QR)") },
                    supportingText = { Text("Sem camera: abra o QR em outro app e cole o segredo aqui.") },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                if (!isTotp) {
                    OutlinedTextField(
                        value = counterText,
                        onValueChange = { counterText = it.filter { ch: Char -> ch.isDigit() }.take(10) },
                        label = { Text("Contador inicial") },
                        supportingText = { Text("Comeca em 0; tem que igualar o do site.") },
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
                FriendlyText(
                    text = "Regenerar cria um segredo novo na hora. O codigo antigo para de funcionar.",
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 3,
                )
            }
            CollapsedSection(title = "Buscar por WiFi (alternativo, Jornada 4)") {
                OutlinedTextField(
                    value = baseUrl,
                    onValueChange = { baseUrl = it },
                    label = { Text("Endereco do dispositivo") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = selected,
                    onValueChange = { selected = it },
                    label = { Text("Conta (ex.: GitHub:alice)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(
                    onClick = ::fetchWifi,
                    enabled = !busy && selected.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Buscar codigo (WiFi)", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            }
            CollapsedSection(title = "Importar envelope") {
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
            }
            if (confirmOathDelete) {
                ConfirmActionDialog(
                    title = "Excluir conta?",
                    body = "Apagar \u0022" + selected + "\u0022 do dispositivo? Os codigos param de funcionar. Precisa tocar no botao do aparelho (UP+PIN).",
                    confirmLabel = "EXCLUIR",
                    onConfirm = { confirmOathDelete = false; deleteOathAccount() },
                    onDismiss = { confirmOathDelete = false },
                )
            }
            if (confirmOathRegen) {
                ConfirmActionDialog(
                    title = "Regenerar segredo?",
                    body = "Criar um segredo novo para \u0022" + selected + "\u0022? O codigo antigo para de funcionar na hora.",
                    confirmLabel = "REGENERAR",
                    onConfirm = { confirmOathRegen = false; regenOathSecret() },
                    onDismiss = { confirmOathRegen = false },
                )
            }
        }
    }
}

@Composable
private fun CollapsedSection(title: String, content: @Composable ColumnScope.() -> Unit) {
    var open by remember { mutableStateOf(false) }
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth().clickable { open = !open },
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(title, style = MaterialTheme.typography.titleSmall, maxLines = 2, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                Text(if (open) "Recolher" else "Abrir", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
            }
            if (open) Column(verticalArrangement = Arrangement.spacedBy(8.dp), content = content)
        }
    }
}

private val DIGIT_OPTIONS = listOf(
    ExplainedOption(6, "6 digitos", "O mais comum — funciona quase sempre."),
    ExplainedOption(7, "7 digitos", "Alguns bancos e empresas pedem."),
    ExplainedOption(8, "8 digitos", "Mais longo; use se o site pedir."),
)

/** Decodifica segredo base32 (RFC4648, sem padding obrigatorio). */
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
