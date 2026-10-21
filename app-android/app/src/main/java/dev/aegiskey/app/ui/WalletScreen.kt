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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Carteira (Bitcoin primeiro): salvar chaves de rede no dispositivo +
 * conferir endereço de pubkey pública localmente.
 *
 * - Salvar: GEN 0x20 no device (curva da rede como hint, UP físico).
 *   A chave nasce e fica no aparelho; aqui só viajam metadados.
 * - Conferir: pubkey HEX pública → endereço via bridge Rust local
 *   (bech32 / EIP-55 / base58). Nada secreto passa por aqui.
 * - Listar: KEY_LIST 0x22 filtrada pelo prefixo "wallet:".
 * Textos PT simples, sem Log com PII (só rede/opcode/tamanhos).
 */
data class WalletNetwork(
    val id: String,
    val title: String,
    val explanation: String,
    val coseAlg: Int,
    val pubkeyBytes: Int,
)

private val WALLET_NETWORKS = listOf(
    WalletNetwork(
        "bitcoin",
        "Bitcoin (P2WPKH bech32)",
        "Endereço bc1q… da pubkey secp256k1 comprimida (33 letras hex).",
        -47,
        33,
    ),
    WalletNetwork(
        "ethereum",
        "Ethereum (EIP-55)",
        "Endereço 0x… da pubkey x||y sem prefixo (64 letras hex).",
        -47,
        64,
    ),
    WalletNetwork(
        "solana",
        "Solana (base58)",
        "Endereço da pubkey Ed25519 (32 letras hex).",
        -8,
        32,
    ),
)

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
    val networkOptions = remember {
        WALLET_NETWORKS.map { n -> ExplainedOption(n, n.title, n.explanation) }
    }
    var networkOption by remember { mutableStateOf(networkOptions[0]) }
    var label by remember { mutableStateOf("") }
    var slotText by remember { mutableStateOf("0") }
    var genMsg by remember { mutableStateOf("—") }
    var pubkeyHex by remember { mutableStateOf("") }
    var addressPreview by remember { mutableStateOf("—") }
    var walletKeys by remember { mutableStateOf(listOf<VendorOps.KeyEntry>()) }
    var listMsg by remember { mutableStateOf<String?>(null) }

    fun refreshWalletKeys() {
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
                    walletKeys = VendorOps.parseKeyList(resp.tlv)
                        .filter { it.label.startsWith("wallet:") }
                    if (walletKeys.isEmpty()) listMsg = "nenhuma carteira salva ainda"
                }
            } catch (e: Exception) {
                listMsg = (e.message ?: "falha ao listar").take(64)
            } finally {
                busy = false
            }
        }
    }

    fun generateOnDevice() {
        scope.launch {
            busy = true
            genMsg = "gerando no dispositivo… toque no botão dele"
            try {
                val net = networkOption.value
                val slot = slotText.trim().toIntOrNull()
                require(slot != null && slot in 0..255) { "slot 0..255" }
                require(label.trim().isNotEmpty()) { "dê um nome para a carteira" }
                val req = VendorOps.genRequest(slot, label.trim(), net.coseAlg, VendorOps.USAGE_SIGN)
                val raw = withContext(Dispatchers.IO) {
                    client.sendVendor(VendorOps.OP_KEY_GEN_ONDEVICE, req)
                }
                val resp = VendorOps.parseResponse(raw)
                genMsg = when {
                    resp == null -> "sem resposta — toque no dispositivo e tente de novo"
                    resp.status != VendorOps.STATUS_OK -> VendorOps.statusLabel(resp.status)
                    else -> {
                        DeviceLog.append(
                            DeviceLog.Category.BLE,
                            "wallet gen rede=" + net.id + " slot=" + slot,
                        )
                        refreshWalletKeys()
                        "carteira " + net.title + " salva no slot " + slot
                    }
                }
            } catch (e: Exception) {
                genMsg = (e.message ?: "falha ao gerar").take(64)
            } finally {
                busy = false
            }
        }
    }

    fun previewAddress() {
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
            }
            if (!AegisBridge.nativeLoaded) {
                FriendlyText(
                    text = "Aviso: biblioteca nativa ausente — o cálculo de endereço precisa dela.",
                    maxLines = 3,
                )
            }
        }
    }
}
