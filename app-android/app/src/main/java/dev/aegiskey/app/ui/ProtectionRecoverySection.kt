package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.ble.BindingOps
import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.security.RecoveryBackup
import dev.aegiskey.app.security.SanitizedLog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Secao "Protecao e recuperacao" (decisao 1): duas redes de seguranca,
 * escolha uma ou as duas. Reusada no wizard (primeira configuracao) e
 * em Settings. Textos simples p/ usuario nao-tecnico. Sem Log com PII
 * (so status/tamanho; a senha nunca e logada nem guardada no celular).
 */
@Composable
fun ProtectionRecoverySection(client: AegisBleClient?) {
    SectionTitle("Protecao e recuperacao")
    FriendlyText(
        text = "Escolha pelo menos uma. Vale fazer as duas: se uma falhar, a outra salva.",
        maxLines = 2,
    )
    BackupKeyOption()
    RecoveryPinOption(client)
}

/** Opcao A: chave-reserva cifrada neste celular (so abre junto do dispositivo). */
@Composable
private fun BackupKeyOption() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var guardada by remember { mutableStateOf(RecoveryBackup.hasBackup(context)) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }

    Card {
        Column(Modifier.padding(12.dp)) {
            FriendlyText(text = "Opcao A - chave-reserva neste celular", maxLines = 1)
            FriendlyText(
                text = "Uma chave extra, cifrada e guardada so neste app. Sozinha ela nao abre nada: so funciona junto do seu dispositivo.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 3,
            )
            FriendlyText(
                text = if (guardada) "Situacao: guardada neste celular." else "Situacao: nenhuma guardada ainda.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 1,
            )
            Button(
                onClick = {
                    scope.launch {
                        busy = true
                        message = null
                        val fresh = RecoveryBackup.generate()
                        try {
                            withContext(Dispatchers.IO) { RecoveryBackup.save(context, fresh) }
                            guardada = true
                        } catch (e: Exception) {
                            message = (e.message ?: "falha ao guardar").take(64)
                        } finally {
                            AegisBridge.wipe(fresh)
                            busy = false
                        }
                    }
                },
                enabled = !busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Guardar chave-reserva", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            if (guardada) {
                OutlinedButton(
                    onClick = {
                        RecoveryBackup.clear(context)
                        guardada = false
                    },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Apagar chave-reserva", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            }
            message?.let {
                Text(it, color = MaterialTheme.colorScheme.error, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

/** Opcao B: senha de 4-6 numeros guardada (hash) NO dispositivo, via 0x2C com UP. */
@Composable
private fun RecoveryPinOption(client: AegisBleClient?) {
    val scope = rememberCoroutineScope()
    var pin by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("—") }

    fun send() {
        val ble = client ?: run {
            message = "conecte via BLE primeiro (tela Conectar)"
            return
        }
        if (pin != confirm) {
            message = "as duas senhas estao diferentes - digite igual"
            return
        }
        if (!BindingOps.isValidRecoveryPin(pin)) {
            message = "a senha precisa ter 4 a 6 numeros"
            return
        }
        scope.launch {
            busy = true
            message = "aperte o botao do dispositivo e aguarde..."
            var payload = ByteArray(0)
            try {
                payload = BindingOps.recoveryPinRequest(pin)
                val raw = withContext(Dispatchers.IO) {
                    ble.sendVendor(BindingOps.OP_RECOVERY_SET, payload)
                }
                val resp = VendorOps.parseResponse(raw)
                message = when {
                    resp == null -> "sem resposta - aperte o botao e tente de novo"
                    resp.status == VendorOps.STATUS_OK -> {
                        pin = ""
                        confirm = ""
                        SanitizedLog.record(SanitizedLog.Event.RECOVERY_PIN_SET)
                        DeviceLog.append(DeviceLog.Category.PAIRING, "recovery set ok")
                        "senha salva no dispositivo"
                    }
                    else -> BindingOps.recoveryStatusLabel(resp.status)
                }
            } catch (e: Exception) {
                message = (e.message ?: "falha ao salvar").take(64)
            } finally {
                AegisBridge.wipe(payload)
                busy = false
            }
        }
    }

    Card {
        Column(Modifier.padding(12.dp)) {
            FriendlyText(text = "Opcao B - senha de 4 a 6 numeros", maxLines = 1)
            FriendlyText(
                text = "Fica guardada dentro do dispositivo, nao no celular. Se perder o celular, essa senha + o botao recuperam tudo.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 3,
            )
            RecoveryPinFields(pin, confirm, { pin = it }, { confirm = it }, !busy)
            Button(
                onClick = ::send,
                enabled = !busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Salvar senha no dispositivo", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            FriendlyText(text = "Resultado: " + message, maxLines = 3)
        }
    }
}

/** Os dois campos de senha (so numeros, escondidos). */
@Composable
private fun RecoveryPinFields(
    pin: String,
    confirm: String,
    onPin: (String) -> Unit,
    onConfirm: (String) -> Unit,
    enabled: Boolean,
) {
    OutlinedTextField(
        value = pin,
        onValueChange = { onPin(it.filter { ch -> ch.isDigit() }.take(6)) },
        label = { Text("Senha (4 a 6 numeros)") },
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
        singleLine = true,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(
        value = confirm,
        onValueChange = { onConfirm(it.filter { ch -> ch.isDigit() }.take(6)) },
        label = { Text("Repita a senha") },
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
        singleLine = true,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth(),
    )
}
