package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

/**
 * Jornada 1 — estado de vinculo fail-closed no topo do cofre.
 * Nada de codigo sem vinculo: o banner bloqueia e explica o proximo passo.
 * Ordem dos gates: vinculo -> UP (botao) -> PIN.
 */
enum class VaultGate {
    NO_BLE,
    NEED_BINDING,
    NEED_UP,
    NEED_PIN,
    READY,
}

@Composable
fun GateBanner(
    gate: VaultGate,
    onConnect: () -> Unit = {},
    onBind: () -> Unit = {},
    modifier: Modifier = Modifier,
) {
    if (gate == VaultGate.READY) return
    val (title, body, action) = when (gate) {
        VaultGate.NO_BLE -> Triple(
            "Conecte o dispositivo primeiro",
            "Jornada 1: sem conexao BLE o cofre fica bloqueado. Va em Conectar e aproxime o aparelho.",
            "Entendi",
        )
        VaultGate.NEED_BINDING -> Triple(
            "Vincule o dispositivo primeiro",
            "Jornada 1: este aparelho ainda nao tem dono. Faca a primeira configuracao (vinculo) antes de ver codigos.",
            "Como vincular",
        )
        VaultGate.NEED_UP -> Triple(
            "Toque no botao do dispositivo",
            "Jornada 2: o aparelho pediu confirmacao fisica (UP). Aperte o botao dele e tente de novo.",
            "Entendi",
        )
        VaultGate.NEED_PIN -> Triple(
            "PIN necessario",
            "O aparelho pediu o PIN. Confira os digitos e tente de novo — salvar e apagar exigem UP+PIN.",
            "Entendi",
        )
        VaultGate.READY -> Triple("", "", "")
    }
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
    ) {
        Column(Modifier.padding(12.dp)) {
            FriendlyText(text = title, maxLines = 1)
            FriendlyText(
                text = body,
                style = MaterialTheme.typography.bodySmall,
                maxLines = 3,
            )
            if (gate == VaultGate.NO_BLE || gate == VaultGate.NEED_BINDING) {
                Button(onClick = { if (gate == VaultGate.NO_BLE) onConnect() else onBind() }) {
                    androidx.compose.material3.Text(action, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
        }
    }
}
