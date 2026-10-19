package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * Sheet de autorizacao de assinatura (burra): explica a operacao em
 * linguagem simples e devolve consentimento via [onAuthorize]; o chamador
 * executa a biometria + assinatura (BindingKey.authenticateAndSign).
 * A chave nunca sai do celular — sem a digital, nada e assinado.
 */
@Composable
fun AuthorizeSignSheet(
    opTitle: String,
    opHelp: String,
    onAuthorize: () -> Unit,
    onCancel: () -> Unit,
) {
    Card {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            SectionTitle("Autorize com a digital")
            FriendlyText(text = opTitle, maxLines = 2)
            FriendlyText(
                text = opHelp,
                style = MaterialTheme.typography.bodySmall,
                maxLines = 4,
            )
            FriendlyText(
                text = "A chave nunca sai do celular. Sem a digital, nada e assinado.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 2,
            )
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Button(onClick = onAuthorize, modifier = Modifier.weight(1f)) {
                    Text("Autorizar", maxLines = 1)
                }
                OutlinedButton(onClick = onCancel, modifier = Modifier.weight(1f)) {
                    Text("Cancelar", maxLines = 1)
                }
            }
        }
    }
}
