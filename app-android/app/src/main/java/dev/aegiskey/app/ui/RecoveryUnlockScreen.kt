package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.Column
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.ble.BindingOps
import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.security.SanitizedLog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Fluxo "Perdi meu app" (decisao 2): nova instalacao -> digita a senha
 * de 4-6 numeros + aperta o botao do dispositivo -> 0x2D destrava no
 * device (apaga o vinculo antigo) -> o app abre a primeira configuracao
 * (re-claim, sem precisar do celular perdido). Tentativas contam no
 * dispositivo (8 no total; zerou, so o reset fisico recupera).
 * Sem Log com PII (a senha nunca e logada nem guardada).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RecoveryUnlockScreen(client: AegisBleClient, onReclaim: () -> Unit, onBack: () -> Unit) {
    val scope = rememberCoroutineScope()
    var pin by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var unlocked by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("—") }

    fun unlock() {
        if (!BindingOps.isValidRecoveryPin(pin)) {
            message = "digite os 4 a 6 numeros da senha"
            return
        }
        scope.launch {
            busy = true
            message = "aperte o botao do dispositivo e aguarde..."
            var payload = ByteArray(0)
            try {
                payload = BindingOps.recoveryPinRequest(pin)
                val raw = withContext(Dispatchers.IO) {
                    client.sendVendor(BindingOps.OP_RECOVERY_UNLOCK, payload)
                }
                val resp = VendorOps.parseResponse(raw)
                when {
                    resp == null -> message = "sem resposta - aperte o botao e tente de novo"
                    resp.status == VendorOps.STATUS_OK -> {
                        unlocked = true
                        pin = ""
                        SanitizedLog.record(SanitizedLog.Event.RECOVERY_UNLOCKED)
                        DeviceLog.append(DeviceLog.Category.PAIRING, "recovery unlock ok (re-claim free)")
                        message = "vinculo antigo apagado - continue p/ refazer a primeira configuracao"
                    }
                    else -> message = BindingOps.recoveryStatusLabel(resp.status)
                }
            } catch (e: Exception) {
                message = (e.message ?: "falha ao recuperar").take(64)
            } finally {
                AegisBridge.wipe(payload)
                busy = false
            }
        }
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Recuperar com senha", maxLines = 1, overflow = TextOverflow.Ellipsis) }) }) { inner ->
        AegisScreenColumn(inner = inner) {
            SectionTitle("Perdi meu app")
            Card {
                Column(Modifier.padding(12.dp)) {
                    FriendlyText(
                        text = "Instalou de novo? Digite a senha de 4 a 6 numeros e aperte o botao do dispositivo.",
                        maxLines = 3,
                    )
                    FriendlyText(
                        text = "Se a senha estiver certa, o vinculo antigo e apagado e voce vira o dono de novo.",
                        style = MaterialTheme.typography.bodySmall,
                        maxLines = 3,
                    )
                    FriendlyText(
                        text = "Errou muito (8 vezes)? So o reset fisico no dispositivo recupera.",
                        style = MaterialTheme.typography.bodySmall,
                        maxLines = 2,
                    )
                }
            }
            if (!unlocked) {
                OutlinedTextField(
                    value = pin,
                    onValueChange = { pin = it.filter { ch -> ch.isDigit() }.take(6) },
                    label = { Text("Senha (4 a 6 numeros)") },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    singleLine = true,
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth(),
                )
                if (busy) CircularProgressIndicator()
                Button(
                    onClick = ::unlock,
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Recuperar (aperte o botao)", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            } else {
                Button(
                    onClick = onReclaim,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Continuar p/ primeira configuracao", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            }
            FriendlyText(text = "Resultado: " + message, maxLines = 3)
            OutlinedButton(onClick = onBack, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                Text("Voltar", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}
