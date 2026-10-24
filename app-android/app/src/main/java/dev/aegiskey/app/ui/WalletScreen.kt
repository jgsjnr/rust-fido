package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
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
import dev.aegiskey.app.security.SdkGate
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Carteira (Bitcoin primeiro) no fio 0x35-0x37 (binding -> UP).
 *
 * - GEN 0x35: [slot 0x01, label 0x02, rede 0x08] -> [slot, label, endereco 0x07].
 *   A chave nasce e fica no aparelho; aqui so viajam metadados publicos.
 * - LIST 0x36: [] -> repeticao de [slot, label, endereco].
 * - ADDR 0x37: [slot] -> [endereco 0x07].
 * - Conferir: pubkey HEX publica -> endereco via bridge Rust local
 *   (bech32 / EIP-55 / base58). Nada secreto passa por aqui.
 *
 * Gates: toda acao passa por SdkGate.requireWallet(); NotCompiled /
 * ExternalBlocked / negacao viram aviso proprio da tela (nunca crash,
 * nunca GateBanner emprestado). Rede/slot/nome sao validados no app
 * antes do fio: rede invalida responde o 0x04 honesto sem enviar nada.
 * Caminho HD (BIP32/SLIP-0010) so e exibido quando o firmware devolve;
 * o app nunca deriva nada (SLIP-0010 roda no aparelho). RAM-only: as
 * chaves vivem na sessao e somem no reboot (NVS e follow-up). Textos
 * PT simples, sem Log com segredo/endereco (so rede/slot/opcode/tamanhos).
 */
data class WalletNetwork(
    val id: String,
    val title: String,
    val explanation: String,
    val netTag: Int,
    val pubkeyBytes: Int,
)

private const val TAG_WALLET_SLOT = 0x01
private const val TAG_WALLET_LABEL = 0x02
private const val TAG_WALLET_ADDRESS = 0x07
private const val TAG_WALLET_NETWORK = 0x08
private const val MAX_WALLET_SLOT = 31
private const val MAX_USER_LABEL_BYTES = 25

/** Entrada de carteira no aparelho (so metadados publicos; nunca segredo). */
private data class WalletDeviceEntry(
    val slot: Int,
    val label: String,
    val address: String,
    val hdPath: String?,
)

private val WALLET_NETWORKS = listOf(
    WalletNetwork(
        "bitcoin",
        "Bitcoin (P2WPKH bech32)",
        "Endereco bc1q… da pubkey secp256k1 comprimida (33 letras hex). Rede 0x01 no fio.",
        0x01,
        33,
    ),
    WalletNetwork(
        "ethereum",
        "Ethereum (EIP-55)",
        "Endereco 0x… da pubkey x||y sem prefixo (64 letras hex). Rede 0x02 no fio.",
        0x02,
        64,
    ),
    WalletNetwork(
        "solana",
        "Solana (base58)",
        "Endereco da pubkey Ed25519 (32 letras hex). Rede 0x03 no fio.",
        0x03,
        32,
    ),
)

/** Aviso proprio da tela para cada R4 sem GateBanner honesto (nunca crash). */
private fun walletGateNotice(outcome: SdkGate.GateOutcome): String? = when (outcome) {
    SdkGate.GateOutcome.Success, SdkGate.GateOutcome.RealVerified -> null
    is SdkGate.GateOutcome.NotCompiled ->
        "Carteira fora deste build (SDK sem hardwallet): nada foi enviado ao dispositivo."
    is SdkGate.GateOutcome.ExternalBlocked ->
        when (outcome.reason) {
            SdkGate.BlockReason.NO_NATIVE_LIB -> "Biblioteca nativa ausente: esta acao precisa do bridge. Nada foi enviado."
            SdkGate.BlockReason.NO_TRANSPORT -> "Sem transporte para a carteira. Nada foi enviado."
            SdkGate.BlockReason.NO_PEER -> "Sem par pareado para a carteira. Nada foi enviado."
            SdkGate.BlockReason.LAB_MOCKS_OFF -> "Mocks de laboratorio desligados: sem caminho real. Nada foi enviado."
        }
    SdkGate.GateOutcome.PermissionDenied ->
        "Falta prova no dispositivo (vinculo -> botao -> PIN). Toque no aparelho e tente de novo."
    SdkGate.GateOutcome.Unsupported -> "Operacao nao suportada pelo SDK/firmware. Nada foi inventado."
    SdkGate.GateOutcome.Unavailable -> "Carteira indisponivel agora. Tente de novo."
}

/**
 * Validacao local antes do fio: qualquer violacao vira o 0x04 honesto
 * ("dados invalidos") sem enviar nada. Rede desconhecida, slot fora de
 * 0..31 e nome fora de 1..25 letras nunca chegam ao aparelho.
 */
private fun validateWalletGenLocal(netTag: Int, slot: Int?, label: String): String? {
    if (netTag !in 0x01..0x03) {
        return VendorOps.statusLabel(VendorOps.STATUS_BAD_ENVELOPE) + " (rede invalida; nada foi enviado)"
    }
    if (slot == null || slot !in 0..MAX_WALLET_SLOT) {
        return VendorOps.statusLabel(VendorOps.STATUS_BAD_ENVELOPE) + " (slot 0..31; nada foi enviado)"
    }
    val bytes = label.trim().toByteArray(Charsets.UTF_8)
    if (bytes.isEmpty() || bytes.size > MAX_USER_LABEL_BYTES) {
        return VendorOps.statusLabel(VendorOps.STATUS_BAD_ENVELOPE) + " (nome 1..25 letras; nada foi enviado)"
    }
    return null
}

/**
 * Caminho HD (ex.: m/44'/0'/0'/0/0) so quando o firmware devolve num TLV
 * de texto. O app nunca deriva: SLIP-0010/BIP32 rodam no aparelho.
 */
private fun extractWalletHdPath(values: List<ByteArray>): String? {
    for (v in values) {
        val text = runCatching { v.toString(Charsets.UTF_8) }.getOrNull() ?: continue
        if (text.startsWith("m/") && text.length <= 64 && text.all { c -> c in "m/0123456789'Hh" }) {
            return text
        }
    }
    return null
}

/** Agrupa TLVs 0x01/0x02/0x07 por slot; ignora tags desconhecidas (S9.6). */
private fun parseWalletEntries(tlv: ByteArray): List<WalletDeviceEntry> {
    val chunks = mutableListOf<MutableList<VendorOps.Tlv>>()
    for (r in VendorOps.parseTlvRecords(tlv)) {
        if (r.tag == TAG_WALLET_SLOT) chunks.add(mutableListOf())
        if (chunks.isEmpty()) chunks.add(mutableListOf())
        chunks.last().add(r)
    }
    return chunks.mapNotNull { chunk ->
        val slotBytes = VendorOps.findTlv(chunk, TAG_WALLET_SLOT)
        val slot = if (slotBytes != null && slotBytes.size == 1) slotBytes[0].toInt() and 0xFF else null
        if (slot == null) return@mapNotNull null
        val label = VendorOps.findTlv(chunk, TAG_WALLET_LABEL)?.let {
            runCatching { it.toString(Charsets.UTF_8).take(32) }.getOrDefault("slot $slot")
        } ?: "slot $slot"
        val address = VendorOps.findTlv(chunk, TAG_WALLET_ADDRESS)?.let {
            runCatching { it.toString(Charsets.UTF_8).take(128) }.getOrNull()
        } ?: ""
        WalletDeviceEntry(slot, label, address, extractWalletHdPath(chunk.map { it.value }))
    }.take(64)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WalletScreen(client: AegisBleClient) {
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
    var gateNotice by remember { mutableStateOf<String?>(null) }
    val networkOptions = remember {
        WALLET_NETWORKS.map { n -> ExplainedOption(n, n.title, n.explanation) }
    }
    var networkOption by remember { mutableStateOf(networkOptions[0]) }
    var label by remember { mutableStateOf("") }
    var slotText by remember { mutableStateOf("0") }
    var genMsg by remember { mutableStateOf("—") }
    var pubkeyHex by remember { mutableStateOf("") }
    var addressPreview by remember { mutableStateOf("—") }
    var walletKeys by remember { mutableStateOf(listOf<WalletDeviceEntry>()) }
    var listMsg by remember { mutableStateOf<String?>(null) }
    var addrMsg by remember { mutableStateOf<String?>(null) }

    fun checkWalletGate(): Boolean {
        gateNotice = walletGateNotice(SdkGate.requireWallet())
        return gateNotice == null
    }

    fun refreshWalletKeys() {
        if (!checkWalletGate()) return
        scope.launch {
            busy = true
            listMsg = null
            try {
                val raw = withContext(Dispatchers.IO) {
                    client.sendVendor(BleContract.OP_WALLET_LIST, ByteArray(0))
                }
                val resp = VendorOps.parseResponse(raw)
                if (resp == null) {
                    listMsg = "sem resposta — toque no dispositivo e tente de novo"
                } else if (resp.status != VendorOps.STATUS_OK) {
                    gateNotice = walletGateNotice(SdkGate.mapWireStatus(resp.status))
                    listMsg = VendorOps.statusLabel(resp.status)
                } else {
                    gateNotice = null
                    walletKeys = parseWalletEntries(resp.tlv)
                    if (walletKeys.isEmpty()) listMsg = "nenhuma carteira salva ainda"
                    DeviceLog.append(
                        DeviceLog.Category.BLE,
                        "wallet list ok n=" + walletKeys.size,
                    )
                }
            } catch (e: Exception) {
                listMsg = (e.message ?: "falha ao listar").take(64)
            } finally {
                busy = false
            }
        }
    }

    fun generateOnDevice() {
        if (!checkWalletGate()) return
        scope.launch {
            busy = true
            genMsg = "gerando no dispositivo… toque no botão dele"
            try {
                val net = networkOption.value
                val slot = slotText.trim().toIntOrNull()
                val localError = validateWalletGenLocal(net.netTag, slot, label)
                if (localError != null) {
                    genMsg = localError
                    return@launch
                }
                val validSlot = slot!!
                val labelBytes = label.trim().toByteArray(Charsets.UTF_8)
                val req = VendorOps.writeTlv(TAG_WALLET_SLOT, byteArrayOf(validSlot.toByte())) +
                    VendorOps.writeTlv(TAG_WALLET_LABEL, labelBytes) +
                    VendorOps.writeTlv(TAG_WALLET_NETWORK, byteArrayOf(net.netTag.toByte()))
                val raw = withContext(Dispatchers.IO) {
                    client.sendVendor(BleContract.OP_WALLET_GEN, req)
                }
                val resp = VendorOps.parseResponse(raw)
                genMsg = when {
                    resp == null -> "sem resposta — toque no dispositivo e tente de novo"
                    resp.status != VendorOps.STATUS_OK -> {
                        gateNotice = walletGateNotice(SdkGate.mapWireStatus(resp.status))
                        VendorOps.statusLabel(resp.status)
                    }
                    else -> {
                        gateNotice = null
                        DeviceLog.append(
                            DeviceLog.Category.BLE,
                            "wallet gen rede=" + net.id + " slot=" + validSlot,
                        )
                        val entry = parseWalletEntries(resp.tlv).firstOrNull()
                        refreshWalletKeys()
                        if (entry != null && entry.address.isNotEmpty()) {
                            "carteira " + net.title + " salva no slot " + validSlot + " · endereco " + entry.address
                        } else {
                            "carteira " + net.title + " salva no slot " + validSlot
                        }
                    }
                }
            } catch (e: Exception) {
                genMsg = (e.message ?: "falha ao gerar").take(64)
            } finally {
                busy = false
            }
        }
    }

    fun fetchWalletAddr(slot: Int) {
        if (!checkWalletGate()) return
        scope.launch {
            busy = true
            addrMsg = null
            try {
                val req = VendorOps.writeTlv(TAG_WALLET_SLOT, byteArrayOf(slot.toByte()))
                val raw = withContext(Dispatchers.IO) {
                    client.sendVendor(BleContract.OP_WALLET_ADDR, req)
                }
                val resp = VendorOps.parseResponse(raw)
                if (resp == null) {
                    addrMsg = "sem resposta — toque no dispositivo"
                } else if (resp.status != VendorOps.STATUS_OK) {
                    gateNotice = walletGateNotice(SdkGate.mapWireStatus(resp.status))
                    addrMsg = VendorOps.statusLabel(resp.status)
                } else {
                    gateNotice = null
                    val addr = VendorOps.findTlv(VendorOps.parseTlvRecords(resp.tlv), TAG_WALLET_ADDRESS)?.let {
                        runCatching { it.toString(Charsets.UTF_8).take(128) }.getOrNull()
                    } ?: ""
                    if (addr.isBlank()) {
                        addrMsg = "endereco vazio do dispositivo"
                    } else {
                        walletKeys = walletKeys.map { k -> if (k.slot == slot) k.copy(address = addr) else k }
                        addrMsg = "endereco do slot " + slot + " atualizado"
                        DeviceLog.append(DeviceLog.Category.BLE, "wallet addr slot=" + slot)
                    }
                }
            } catch (e: Exception) {
                addrMsg = (e.message ?: "falha ao buscar").take(64)
            } finally {
                busy = false
            }
        }
    }

    fun previewAddress() {
        if (!checkWalletGate()) {
            addressPreview = "—"
            return
        }
        scope.launch {
            busy = true
            addressPreview = "calculando…"
            try {
                val net = networkOption.value
                val hex = pubkeyHex.filterNot { it.isWhitespace() }
                val bytes = withContext(Dispatchers.Default) {
                    AegisBridge.walletAddress(net.id, hex).getOrThrow()
                }
                addressPreview = bytes
                DeviceLog.append(
                    DeviceLog.Category.BLE,
                    "wallet preview rede=" + net.id + " hex=" + hex.length + " letras",
                )
            } catch (e: Exception) {
                gateNotice = walletGateNotice(SdkGate.mapBridgeError(e))
                addressPreview = (e.message ?: "pubkey inválida").take(64)
            } finally {
                busy = false
            }
        }
    }

    Scaffold(
        topBar = { TopAppBar(title = { Text("Carteira", maxLines = 1, overflow = TextOverflow.Ellipsis) }) },
    ) { inner ->
        AegisScreenColumn(inner = inner) {
            TestModeBanner(client)
            if (busy) CircularProgressIndicator()
            FriendlyText(
                text = "BLE: " + state.connection + " · " + BleContract.statusLabel(state.status),
                maxLines = 2,
            )
            FriendlyText(
                text = "Aviso: chaves em RAM nesta sessao — somem se o aparelho reiniciar (NVS e follow-up).",
                maxLines = 3,
            )
            if (gateNotice != null) FriendlyText(text = gateNotice!!, maxLines = 3)

            SectionTitle("Salvar no dispositivo")
            ExplainedDropdown(
                label = "Rede",
                options = networkOptions,
                selected = networkOption,
                onSelected = { networkOption = it },
                enabled = !busy,
            )
            OutlinedTextField(
                value = label,
                onValueChange = { label = it.take(25) },
                label = { Text("Nome (1..25 letras)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = slotText,
                onValueChange = { slotText = it.filter { ch -> ch.isDigit() }.take(2) },
                label = { Text("Slot (0..31)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                onClick = ::generateOnDevice,
                enabled = !busy && label.trim().isNotEmpty(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("GERAR E SALVAR NO DISPOSITIVO", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            FriendlyText(text = "Resultado: " + genMsg, maxLines = 3)

            SectionTitle("Conferir endereço (só pubkey pública)")
            FriendlyText(
                text = "Cole a pubkey em hex (" + networkOption.value.pubkeyBytes + " letras esperadas). Calculado no celular, sem tocar no dispositivo.",
                maxLines = 3,
            )
            OutlinedTextField(
                value = pubkeyHex,
                onValueChange = { pubkeyHex = it.filter { ch -> ch.isLetterOrDigit() }.take(128) },
                label = { Text("Pubkey em hex") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedButton(
                onClick = ::previewAddress,
                enabled = !busy && pubkeyHex.trim().isNotEmpty(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("CALCULAR ENDEREÇO", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            FriendlyText(text = "Endereço: " + addressPreview, maxLines = 3)

            SectionTitle("Carteiras no dispositivo")
            OutlinedButton(onClick = ::refreshWalletKeys, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                Text("Atualizar lista (toque no dispositivo)", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            if (listMsg != null) FriendlyText(text = listMsg!!, maxLines = 2)
            for (k in walletKeys) {
                FriendlyText(text = "slot " + k.slot + " · " + k.label, maxLines = 2)
                if (k.address.isNotEmpty()) FriendlyText(text = "endereco: " + k.address, maxLines = 2)
                if (k.hdPath != null) FriendlyText(text = "caminho HD: " + k.hdPath + " (so exibido; deriva no aparelho)", maxLines = 2)
                OutlinedButton(onClick = { fetchWalletAddr(k.slot) }, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                    Text("Conferir endereco do slot " + k.slot + " (0x37)", maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
            if (addrMsg != null) FriendlyText(text = addrMsg!!, maxLines = 2)
        }
    }
}