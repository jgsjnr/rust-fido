package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.foundation.text.KeyboardOptions
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.ble.BleContract
import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.log.DeviceLog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * PIV / smartcard: define o PIN (6-8 dígitos) + PUK (8 dígitos) no
 * dispositivo via enrollment vendor 0x39 (pareamento + UP físico).
 *
 * - Validação local de geometria (só dígitos, tamanhos) antes de enviar.
 * - Fio: `sendVendor(0x39, [pin_len:1, pin, puk])`; resposta status-first
 *   (`0x00` ok). `0x04` é falha genérica OU já provisionado — o app diz
 *   isso honestamente, sem oráculo.
 * - PIN/PUK nunca entram no Log (só opcode/tamanhos) e os buffers são
 *   zerados com wipe após o envio; campos limpos no sucesso.
 * Textos PT simples, Material3, mesmo padrão das telas existentes.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PivScreen(client: AegisBleClient, onOpenPairing: () -> Unit = {}) {
    val state by client.state.collectAsState()
    val scope = rememberCoroutineScope()
    var pin by remember { mutableStateOf("") }
    var pinConfirm by remember { mutableStateOf("") }
    var puk by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf("—") }
    var upHidden by remember { mutableStateOf(false) }

    val needsUp = state.status == BleContract.STATUS_UP_NEEDED
    if (!needsUp) upHidden = false

    fun digitsOnly(s: String): String = s.filter { it.isDigit() }

    /** Geometria local; null = ok, senão a mensagem para o usuário. */
    fun localError(): String? = when {
        pin.any { !it.isDigit() } || puk.any { !it.isDigit() } -> "só números, sem letras nem espaços"
        pin.length !in 6..8 -> "PIN com 6 a 8 números"
        pin != pinConfirm -> "os dois PINs estão diferentes"
        puk.length != 8 -> "PUK com 8 números"
        else -> null
    }

    fun enroll() {
        val err = localError()
        if (err != null) {
            result = err
            return
        }
        scope.launch {
            busy = true
            result = "enviando… toque no botão do dispositivo"
            var pinBytes = ByteArray(0)
            var pukBytes = ByteArray(0)
            var req = ByteArray(0)
            try {
                pinBytes = pin.toByteArray(Charsets.US_ASCII)
                pukBytes = puk.toByteArray(Charsets.US_ASCII)
                req = VendorOps.pivEnrollRequest(pinBytes, pukBytes)
                val raw = withContext(Dispatchers.IO) {
                    client.sendVendor(VendorOps.OP_PIV_ENROLL, req)
                }
                val resp = VendorOps.parseResponse(raw)
                result = when {
                    resp == null -> "sem resposta — toque no dispositivo e tente de novo"
                    resp.status == VendorOps.STATUS_OK -> {
                        DeviceLog.append(DeviceLog.Category.BLE, "piv enroll ok")
                        pin = ""
                        pinConfirm = ""
                        puk = ""
                        "PIV pronto no dispositivo"
                    }
                    resp.status == VendorOps.STATUS_NEED_UP ->
                        "toque no botão do dispositivo e tente de novo"
                    resp.status == VendorOps.STATUS_NEED_BINDING ->
                        "vincule o dispositivo primeiro (tela de pareamento)"
                    resp.status == VendorOps.STATUS_BAD_ENVELOPE ->
                        "não gravou: falhou ou já provisionado — sem como saber qual"
                    else -> VendorOps.statusLabel(resp.status)
                }
            } catch (e: Exception) {
                result = (e.message ?: "falha ao gravar").take(64)
            } finally {
                AegisBridge.wipe(pinBytes, pukBytes, req)
                busy = false
            }
        }
    }

    Scaffold(
        topBar = { TopAppBar(title = { Text("PIV / Smartcard", maxLines = 1, overflow = TextOverflow.Ellipsis) }) },
    ) { inner ->
        AegisScreenColumn(inner = inner) {
            TestModeBanner(client)
            if (busy) CircularProgressIndicator()
            FriendlyText(
                text = "BLE: " + state.connection + " · " + BleContract.statusLabel(state.status),
                maxLines = 2,
            )

            if (needsUp && !upHidden) {
                PressDeviceSheet(
                    statusLabel = BleContract.statusLabel(state.status),
                    onCancel = { scope.launch(Dispatchers.IO) { client.cancel() } },
                    onDismiss = { upHidden = true },
                )
            }

            SectionTitle("Criar PIN do cartão")
            FriendlyText(
                text = "O PIN e o PUK ficam só no dispositivo. O app não guarda nem mostra depois.",
                maxLines = 3,
            )
            OutlinedTextField(
                value = pin,
                onValueChange = { pin = digitsOnly(it).take(8) },
                label = { Text("PIN (6 a 8 números)") },
                supportingText = { Text("Só números. É o que você digita no dia a dia.") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = pinConfirm,
                onValueChange = { pinConfirm = digitsOnly(it).take(8) },
                label = { Text("Repita o PIN") },
                supportingText = { Text("Tem que ser igual ao de cima.") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = puk,
                onValueChange = { puk = digitsOnly(it).take(8) },
                label = { Text("PUK (8 números)") },
                supportingText = { Text("Só serve para desbloquear se o PIN travar. Guarde em papel.") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                onClick = ::enroll,
                enabled = !busy && pin.isNotEmpty() && pinConfirm.isNotEmpty() && puk.isNotEmpty(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("GRAVAR NO DISPOSITIVO", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            FriendlyText(text = "Resultado: " + result, maxLines = 3)

            if (result.startsWith("vincule")) {
                OutlinedButton(onClick = onOpenPairing, modifier = Modifier.fillMaxWidth()) {
                    Text("Abrir pareamento", maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }

            FriendlyText(
                text = "Se der erro 0x04, pode ser que o cartão já tenha PIN — o dispositivo não conta o motivo.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 3,
            )
        }
    }
}
