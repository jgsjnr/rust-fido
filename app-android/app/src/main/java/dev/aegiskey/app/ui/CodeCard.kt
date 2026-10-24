package dev.aegiskey.app.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.ProgressIndicatorDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

/**
 * Ponto de extensao: cada conta do cofre tem um [kind].
 * Hoje so OATH (TOTP/HOTP via 0x25/0x26). Wallet/PIV entram aqui
 * sem refazer a lista: basta novo kind + ramo em [fetchVaultCode].
 */
enum class VaultKind { OATH_TOTP, OATH_HOTP, WALLET, PIV }

data class VaultAccount(val name: String, val kind: VaultKind = VaultKind.OATH_TOTP)

/** "123456" -> "123 456" (mono, legivel de relance). */
fun formatCodeGrouped(code: String): String {
    val digits = code.filter { it.isDigit() }
    if (digits.length <= 3) return digits
    return digits.chunked(3).joinToString(" ")
}

/**
 * Jornada 2 — cartao de codigo: mono XXX XXX + barra countdown colorida
 * (verde > 10s, laranja 5..10s, vermelho < 5s) + Copiar via clipboard.
 * Tick de 1s atualiza so texto+progresso; animacao (fade 200ms) so na
 * troca do codigo.
 */
@Composable
fun CodeCard(
    account: VaultAccount,
    code: String?,
    remaining: Int,
    busy: Boolean,
    onCopy: (String) -> Unit,
    onRefresh: (VaultAccount) -> Unit,
    modifier: Modifier = Modifier,
) {
    val fraction = (remaining.coerceIn(0, 30) / 30f)
    val barColor = when {
        remaining <= 5 -> MaterialTheme.colorScheme.error
        remaining <= 10 -> MaterialTheme.colorScheme.tertiary
        else -> ProgressIndicatorDefaults.linearColor
    }
    Card(modifier = modifier.fillMaxWidth()) {
        Column(
            Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    account.name,
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    if (account.kind == VaultKind.OATH_HOTP) "HOTP" else "TOTP",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                )
            }
            AnimatedContent(
                targetState = code ?: "··· ···",
                transitionSpec = { fadeIn(initialAlpha = 0.4f) togetherWith fadeOut() },
                label = "codeSwap",
            ) { shown ->
                Text(
                    formatCodeGrouped(shown),
                    style = MaterialTheme.typography.displaySmall.copy(fontFamily = FontFamily.Monospace),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            LinearProgressIndicator(
                progress = { fraction },
                modifier = Modifier.fillMaxWidth(),
                color = barColor,
            )
            FriendlyText(text = "$remaining s restantes (janela 30s)", maxLines = 1)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = { code?.let(onCopy) },
                    enabled = !code.isNullOrBlank(),
                ) { Text("Copiar", maxLines = 1, overflow = TextOverflow.Ellipsis) }
                OutlinedButton(onClick = { onRefresh(account) }, enabled = !busy) {
                    Text("Atualizar", maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
        }
    }
}
