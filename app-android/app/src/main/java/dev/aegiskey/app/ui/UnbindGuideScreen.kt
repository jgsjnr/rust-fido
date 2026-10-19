package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.security.BindingKey

/**
 * Desfazer vinculo via reset fisico guiado: o dispositivo so solta o dono
 * com reset fisico; este app apaga o vinculo local (binding_id + chave).
 * Textos simples, sem Log com PII (so UI + evento).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun UnbindGuideScreen(onDone: () -> Unit) {
    val context = LocalContext.current
    var confirmUnbind by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("—") }

    Scaffold(topBar = { TopAppBar(title = { Text("Desfazer vinculo", maxLines = 1, overflow = TextOverflow.Ellipsis) }) }) { inner ->
        AegisScreenColumn(inner = inner) {
            SectionTitle("Reset fisico guiado")
            Card {
                Column(Modifier.padding(12.dp)) {
                    FriendlyText(text = "1. No dispositivo, faca o reset fisico: segure o botao ate o LED vermelho.", maxLines = 2)
                    FriendlyText(text = "2. Volte aqui e toque em \u201cApagar vinculo neste celular\u201d.", maxLines = 2)
                    FriendlyText(text = "3. Pronto: o dispositivo volta a ficar livre p/ um novo dono.", maxLines = 2)
                }
            }
            FriendlyText(
                text = "Apagar aqui so limpa este celular (binding_id + chave). O dispositivo so libera com o reset fisico.",
                maxLines = 3,
            )
            Button(
                onClick = { confirmUnbind = true },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Apagar vinculo neste celular", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            FriendlyText(text = "Resultado: " + message, maxLines = 2)
            OutlinedButton(onClick = onDone, modifier = Modifier.fillMaxWidth()) {
                Text("Voltar", maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            if (confirmUnbind) {
                ConfirmActionDialog(
                    title = "Apagar o vinculo?",
                    body = "Este app deixara de ser o dono. Faca o reset fisico no dispositivo tambem, senao ele continua preso.",
                    confirmLabel = "APAGAR",
                    onConfirm = {
                        confirmUnbind = false
                        BindingKey.clearBinding(context)
                        DeviceLog.append(DeviceLog.Category.PAIRING, "binding cleared locally (unbind guide)")
                        message = "vinculo apagado neste celular"
                    },
                    onDismiss = { confirmUnbind = false },
                )
            }
        }
    }
}
