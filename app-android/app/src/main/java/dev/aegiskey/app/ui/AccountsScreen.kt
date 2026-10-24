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
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.security.AppLock
import dev.aegiskey.app.security.FeatureFlags
import dev.aegiskey.app.security.SanitizedLog
import dev.aegiskey.app.security.SdkGate
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.PasswordVisualTransformation
import kotlinx.coroutines.delay
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
    val clipboard = LocalClipboardManager.current
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
    // OATH (A2, 0x24-0x27): nomes+codigos p/ exibir; segredo nunca persiste
    // (wipe em finally) e nunca entra em argumento de navegacao.
    var oathGate by remember { mutableStateOf<SdkGate.GateOutcome?>(null) }
    var oathNotice by remember { mutableStateOf<String?>(null) }
    var oathAccounts by remember { mutableStateOf(listOf<VendorOps.OathEntry>()) }
    var oathCodes by remember { mutableStateOf(mapOf<String, String>()) }
    var oathSelected by remember { mutableStateOf("") }
    var oathExpanded by remember { mutableStateOf(false) }
    var oathHotpNames by remember { mutableStateOf(setOf<String>()) }
    var oathListMsg by remember { mutableStateOf<String?>(null) }
    var oathName by remember { mutableStateOf("") }
    var oathIsTotp by remember { mutableStateOf(true) }
    var oathDigits by remember { mutableStateOf(OATH_DIGIT_OPTIONS[0]) }
    var oathSecret by remember { mutableStateOf("") }
    var oathCounterText by remember { mutableStateOf("0") }
    var oathMsg by remember { mutableStateOf("-") }
    var confirmOathDelete by remember { mutableStateOf(false) }
    var nowSec by remember { mutableStateOf(System.currentTimeMillis() / 1000) }
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
                DeviceLog.append(DeviceLog.Category.BLE, "key list: " + keys.size + " chaves")
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
                DeviceLog.append(DeviceLog.Category.BLE, "key gen slot=" + slot + " -> " + genMsg.take(40))
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

    /**
     * Aviso proprio p/ outcomes sem texto honesto no GateBanner (R4):
     * gateBannerState() retorna null p/ NotCompiled/ExternalBlocked, e a
     * tela renderiza este texto em vez de banner enganoso. Null = liberado.
     */
    fun oathGateNotice(outcome: SdkGate.GateOutcome): String? = when (outcome) {
        is SdkGate.GateOutcome.Success, SdkGate.GateOutcome.RealVerified -> null
        is SdkGate.GateOutcome.NotCompiled ->
            "OATH fora da compilacao deste app (fala com o dono do SDK; sem crash, sem fingir)."
        is SdkGate.GateOutcome.ExternalBlocked ->
            "OATH bloqueado aqui: " + when (outcome.reason) {
                SdkGate.BlockReason.NO_NATIVE_LIB -> "libs nativas ausentes (rode com o .so do bridge)"
                SdkGate.BlockReason.NO_TRANSPORT -> "sem transporte BLE"
                SdkGate.BlockReason.NO_PEER -> "sem par pareado"
                SdkGate.BlockReason.LAB_MOCKS_OFF -> "mocks de lab desligados"
            }
        SdkGate.GateOutcome.PermissionDenied -> "toque no botao do dispositivo (UP+PIN)"
        SdkGate.GateOutcome.Unsupported -> "device recusou (dado invalido ou conta inexistente)"
        SdkGate.GateOutcome.Unavailable -> "device sem resposta - toque e tente de novo"
    }

    /** Toda acao OATH passa primeiro pelo SdkGate (facade-first, R4). */
    fun oathAllowed(): Boolean {
        val g = SdkGate.requireOath()
        oathGate = g
        oathNotice = oathGateNotice(g)
        return g is SdkGate.GateOutcome.Success || g is SdkGate.GateOutcome.RealVerified
    }

    fun refreshOath() {
        if (!oathAllowed()) return
        scope.launch {
            busy = true
            oathListMsg = null
            try {
                val raw = withContext(Dispatchers.IO) {
                    client.sendVendor(VendorOps.OP_OATH_LIST, ByteArray(0))
                }
                val resp = VendorOps.parseResponse(raw)
                if (resp == null) {
                    oathListMsg = "sem resposta - toque no dispositivo e tente de novo"
                } else if (resp.status != VendorOps.STATUS_OK) {
                    SdkGate.mapWireStatus(resp.status)
                    oathListMsg = if (resp.status == VendorOps.STATUS_NEED_PIN) {
                        "PIN necessario"
                    } else {
                        VendorOps.statusLabel(resp.status)
                    }
                } else {
                    oathAccounts = VendorOps.parseOathList(resp.tlv)
                    if (oathSelected.isNotBlank() && oathAccounts.none { it.name == oathSelected }) {
                        oathSelected = ""
                    }
                    oathListMsg = null
                }
                DeviceLog.append(DeviceLog.Category.BLE, "oath list: " + oathAccounts.size + " contas")
            } catch (e: Exception) {
                oathListMsg = (e.message ?: "falha ao listar").take(64)
            } finally {
                busy = false
            }
        }
    }

    /**
     * CODE (0x26) com tolerancia +-1 periodo: desafio = contador atual
     * (TOTP precisa do contador; device sem RTC). Resposta vazia na borda
     * da janela tenta o periodo vizinho uma vez. HOTP nao manda challenge:
     * o contador e persistente no device (nenhum cache local que divirja).
     */
    fun fetchOathCode(name: String, hotp: Boolean) {
        if (!oathAllowed()) return
        scope.launch {
            busy = true
            try {
                val cur = nowSec / 30
                val counters: List<Long?> = if (hotp) listOf(null) else listOf(cur, cur - 1, cur + 1).distinct()
                var code: String? = null
                var lastStatus: Int? = null
                var noResponse = false
                for (c in counters) {
                    val nameBytes = name.toByteArray(Charsets.UTF_8)
                    val chal = if (c == null) {
                        ByteArray(0)
                    } else {
                        ByteArray(8) { i -> ((c shr (56 - 8 * i)) and 0xFFL).toByte() }
                    }
                    val req = VendorOps.writeTlv(VendorOps.TAG_OATH_NAME, nameBytes) +
                        (if (chal.isEmpty()) ByteArray(0) else VendorOps.writeTlv(VendorOps.TAG_OATH_CHALLENGE, chal))
                    val raw = withContext(Dispatchers.IO) {
                        client.sendVendor(VendorOps.OP_OATH_CODE, req)
                    }
                    val resp = VendorOps.parseResponse(raw)
                    if (resp == null) {
                        noResponse = true
                        break
                    }
                    if (resp.status != VendorOps.STATUS_OK) {
                        lastStatus = resp.status
                        SdkGate.mapWireStatus(resp.status)
                        break
                    }
                    val records = VendorOps.parseTlvRecords(resp.tlv)
                    val got = (VendorOps.findTlv(records, VendorOps.TAG_OATH_RESPONSE)
                        ?: VendorOps.findTlv(records, VendorOps.TAG_OATH_TRUNCATED))
                        ?.let { runCatching { it.toString(Charsets.UTF_8) }.getOrNull() }
                        ?.take(8)?.takeIf { it.isNotBlank() && it.all(Char::isDigit) }
                    if (got != null) {
                        code = got
                        break
                    }
                    val edge = AegisBridge.remainingSeconds(nowSec) <= 2 ||
                        AegisBridge.remainingSeconds(nowSec) >= 28
                    if (hotp || !edge) break
                }
                if (code != null) {
                    oathCodes = (oathCodes + (name to code)).toList().takeLast(32).toMap()
                    DeviceLog.append(DeviceLog.Category.BLE, "oath code ok bytes=" + code.length)
                } else if (noResponse) {
                    oathListMsg = "sem resposta - toque no dispositivo e tente de novo"
                } else if (lastStatus != null) {
                    oathListMsg = if (lastStatus == VendorOps.STATUS_NEED_PIN) {
                        "PIN necessario"
                    } else {
                        VendorOps.statusLabel(lastStatus)
                    }
                } else {
                    oathListMsg = "codigo vazio - toque e tente de novo"
                }
            } catch (e: Exception) {
                oathListMsg = (e.message ?: "falha ao buscar").take(64)
            } finally {
                busy = false
            }
        }
    }

    /** PUT (0x24, UP+PIN): monta TLV, envia e ZERA segredo+req (nunca persiste). */
    fun putOathAccount(secret: ByteArray) {
        if (!oathAllowed()) {
            AegisBridge.wipe(secret)
            oathMsg = oathNotice ?: "bloqueado pelo gate"
            return
        }
        scope.launch {
            busy = true
            var req = ByteArray(0)
            try {
                val typeAlgo = (if (oathIsTotp) VendorOps.OATH_TYPE_TOTP else VendorOps.OATH_TYPE_HOTP) or
                    VendorOps.OATH_ALGO_SHA1
                val counter = if (oathIsTotp) {
                    null
                } else {
                    val c = oathCounterText.trim().toLongOrNull()
                    require(c != null && c in 0..0xFFFFFFFFL) { "contador 0..4294967295" }
                    c
                }
                req = VendorOps.oathPutRequest(oathName, typeAlgo, oathDigits.value, secret, counter)
                val raw = withContext(Dispatchers.IO) {
                    client.sendVendor(VendorOps.OP_OATH_PUT, req)
                }
                val resp = VendorOps.parseResponse(raw)
                oathMsg = when {
                    resp == null -> "sem resposta - toque no dispositivo e tente de novo"
                    resp.status != VendorOps.STATUS_OK -> {
                        SdkGate.mapWireStatus(resp.status)
                        if (resp.status == VendorOps.STATUS_NEED_PIN) {
                            "PIN necessario (salvar exige UP+PIN)"
                        } else {
                            VendorOps.statusLabel(resp.status) + " (salvar exige UP+PIN)"
                        }
                    }
                    else -> {
                        if (!oathIsTotp) oathHotpNames = oathHotpNames + oathName.trim()
                        oathSecret = ""
                        refreshOath()
                        "conta salva no dispositivo (segredo sumiu do celular)"
                    }
                }
            } catch (e: Exception) {
                oathMsg = (e.message ?: "falha ao salvar").take(64)
            } finally {
                AegisBridge.wipe(secret, req)
                busy = false
            }
        }
    }

    fun saveOathManual() {
        if (oathName.trim().isEmpty()) {
            oathMsg = "de um nome para a conta (ex.: GitHub:alice)"
            return
        }
        try {
            putOathAccount(oathBase32ToBytes(oathSecret))
        } catch (e: Exception) {
            oathMsg = (e.message ?: "segredo invalido").take(64)
        }
    }

    fun generateOathSecret() {
        if (oathName.trim().isEmpty()) {
            oathMsg = "de um nome para a conta (ex.: GitHub:alice)"
            return
        }
        val rng = SecureRandom()
        putOathAccount(ByteArray(20).also { rng.nextBytes(it) })
    }

    /** DELETE (0x27, UP+PIN): so via dialogo de confirmacao; sem PIN vira 0x02. */
    fun deleteOathAccount() {
        val target = oathSelected.ifBlank { null } ?: return
        if (!oathAllowed()) return
        scope.launch {
            busy = true
            try {
                val req = VendorOps.writeTlv(VendorOps.TAG_OATH_NAME, target.toByteArray(Charsets.UTF_8))
                val raw = withContext(Dispatchers.IO) {
                    client.sendVendor(VendorOps.OP_OATH_DELETE, req)
                }
                val resp = VendorOps.parseResponse(raw)
                if (resp == null || resp.status != VendorOps.STATUS_OK) {
                    val st = resp?.status
                    if (st != null) SdkGate.mapWireStatus(st)
                    oathListMsg = (st?.let { if (it == VendorOps.STATUS_NEED_PIN) "PIN necessario" else VendorOps.statusLabel(it) } ?: "sem resposta") +
                        " (apagar exige UP+PIN)"
                } else {
                    oathSelected = ""
                    oathCodes = oathCodes - target
                    oathHotpNames = oathHotpNames - target
                    oathListMsg = null
                    refreshOath()
                }
            } catch (e: Exception) {
                oathListMsg = (e.message ?: "falha ao apagar").take(64)
            } finally {
                busy = false
            }
        }
    }

    // A2: sonda do gate uma vez (efeito, nao composicao) + tick de 1s p/ o countdown.
    LaunchedEffect(Unit) {
        val g = SdkGate.requireOath()
        oathGate = g
        oathNotice = oathGateNotice(g)
        while (true) {
            delay(1000)
            nowSec = System.currentTimeMillis() / 1000
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

            SectionTitle("Contas OATH no dispositivo")
            // Gate honesto (R4): banner so p/ UP/PIN; NotCompiled/ExternalBlocked
            // viram aviso proprio da tela, nunca banner enganoso.
            val oathBanner = oathGate?.let { SdkGate.gateBannerState(it) }
            if (oathBanner != null) {
                GateBanner(gate = oathBanner)
            }
            oathNotice?.let {
                FriendlyText(text = it, maxLines = 3)
            }
            FriendlyText(
                text = "So nomes e codigos saem do aparelho. O segredo nunca sai dele.",
                maxLines = 2,
            )
            OutlinedButton(onClick = ::refreshOath, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                Text("Atualizar contas OATH (toque no dispositivo)", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            if (oathAccounts.isEmpty()) {
                FriendlyEmpty(message = oathListMsg ?: "Nada aqui ainda. Toque no dispositivo para carregar.")
            } else {
                oathListMsg?.let { FriendlyText(text = it, maxLines = 2) }
                for (entry in oathAccounts) {
                    val hotp = oathHotpNames.contains(entry.name)
                    val vault = VaultAccount(entry.name, if (hotp) VaultKind.OATH_HOTP else VaultKind.OATH_TOTP)
                    CodeCard(
                        account = vault,
                        code = oathCodes[entry.name],
                        remaining = AegisBridge.remainingSeconds(nowSec),
                        busy = busy,
                        onCopy = { clipboard.setText(AnnotatedString(it)) },
                        onRefresh = { fetchOathCode(it.name, it.kind == VaultKind.OATH_HOTP) },
                    )
                }
                ExposedDropdownMenuBox(
                    expanded = oathExpanded,
                    onExpandedChange = { oathExpanded = !oathExpanded },
                ) {
                    OutlinedTextField(
                        value = oathSelected.ifBlank { "Escolha uma conta" },
                        onValueChange = {},
                        readOnly = true,
                        label = { Text("Contas (OATH_LIST)") },
                        trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = oathExpanded) },
                        modifier = Modifier.menuAnchor().fillMaxWidth(),
                    )
                    ExposedDropdownMenu(
                        expanded = oathExpanded,
                        onDismissRequest = { oathExpanded = false },
                    ) {
                        for (entry in oathAccounts) {
                            DropdownMenuItem(
                                text = { Text(entry.name, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                                onClick = {
                                    oathSelected = entry.name
                                    oathExpanded = false
                                },
                            )
                        }
                    }
                }
                OutlinedButton(
                    onClick = { confirmOathDelete = true },
                    enabled = !busy && oathSelected.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("EXCLUIR conta selecionada (UP+PIN)", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            }

            SectionTitle("Adicionar conta OATH")
            FriendlyText(
                text = "Onde fica salvo: so no dispositivo. O app nunca guarda o segredo.",
                maxLines = 2,
            )
            OutlinedTextField(
                value = oathName,
                onValueChange = { oathName = it.take(64) },
                label = { Text("Conta (ex.: GitHub:alice)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            LabeledToggle(
                checked = oathIsTotp,
                title = if (oathIsTotp) "TOTP - muda com o tempo" else "HOTP - muda a cada uso",
                explanation = if (oathIsTotp) {
                    "O codigo troca sozinho a cada 30 segundos. E o mais comum."
                } else {
                    "O codigo troca a cada uso; o contador mora no dispositivo, nunca no celular."
                },
                onCheckedChange = { oathIsTotp = it },
                enabled = !busy,
            )
            ExplainedDropdown(
                label = "Digitos do codigo",
                options = OATH_DIGIT_OPTIONS,
                selected = oathDigits,
                onSelected = { oathDigits = it },
                enabled = !busy,
            )
            OutlinedTextField(
                value = oathSecret,
                onValueChange = { oathSecret = it },
                label = { Text("Segredo (cole do site ou do QR)") },
                supportingText = { Text("Sem camera: abra o QR em outro app e cole o segredo aqui.") },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            if (!oathIsTotp) {
                OutlinedTextField(
                    value = oathCounterText,
                    onValueChange = { oathCounterText = it.filter { ch: Char -> ch.isDigit() }.take(10) },
                    label = { Text("Contador inicial") },
                    supportingText = { Text("Comeca em 0; tem que igualar o do site. Depois o device guarda sozinho.") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            Button(
                onClick = ::saveOathManual,
                enabled = !busy && oathName.isNotBlank() && oathSecret.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Salvar no dispositivo (UP+PIN)", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            OutlinedButton(
                onClick = ::generateOathSecret,
                enabled = !busy && oathName.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Gerar segredo aqui e salvar", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            FriendlyText(text = "Resultado: " + oathMsg, maxLines = 3)
            if (confirmOathDelete && oathSelected.isNotBlank()) {
                ConfirmActionDialog(
                    title = "Excluir conta?",
                    body = "Apagar \"" + oathSelected + "\" do dispositivo? Os codigos param de funcionar. Precisa tocar no botao do aparelho (UP+PIN).",
                    confirmLabel = "EXCLUIR",
                    onConfirm = { confirmOathDelete = false; deleteOathAccount() },
                    onDismiss = { confirmOathDelete = false },
                )
            }

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

/** Opcoes de digitos OATH (6-8, mesmo padrao do cofre). */
private val OATH_DIGIT_OPTIONS = listOf(
    ExplainedOption(6, "6 digitos", "O mais comum - funciona quase sempre."),
    ExplainedOption(7, "7 digitos", "Alguns bancos e empresas pedem."),
    ExplainedOption(8, "8 digitos", "Mais longo; use se o site pedir."),
)

/**
 * Decodifica segredo base32 (RFC4648, sem padding obrigatorio).
 * Copia local p/ nao cruzar telas; o retorno e zerado pelo chamador
 * (wipe em finally) apos o PUT.
 */
private fun oathBase32ToBytes(input: String): ByteArray {
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
