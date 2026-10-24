package dev.aegiskey.app.ui.atomic.molecules

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Key
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.ui.atomic.atoms.QuickActionPillButton
import dev.aegiskey.app.ui.atomic.atoms.TotpCountdownRingAtom
import dev.aegiskey.app.ui.theme.AegisCodeMonospaceStyle

/** Formata sequências numéricas em grupos de 3 dígitos (ex: "123456" -> "123 456"). */
private fun formatGroupedDigits(rawCode: String): String {
    val clean = rawCode.filter { it.isDigit() }
    if (clean.length <= 3) return rawCode
    return clean.chunked(3).joinToString(" ")
}

/**
 * Cartão compacto e responsivo de código de verificação TOTP.
 * Padding de 12.dp, código monoespaçado em linha única com anel de 40.dp e botão de cópia rápido.
 */
@Composable
fun TotpCodeCardMolecule(
    issuer: String,
    accountName: String,
    code: String,
    remainingSeconds: Int,
    totalSeconds: Int = 30,
    onCopyCode: (String) -> Unit,
    onDeleteAccount: (() -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    val formattedCode = formatGroupedDigits(code)

    ElevatedCard(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
        elevation = CardDefaults.elevatedCardElevation(defaultElevation = 1.dp),
        modifier = modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
        ) {
            // Cabeçalho: Ícone do serviço + Emissor / Conta + Botão de exclusão opcional
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = MaterialTheme.colorScheme.secondaryContainer,
                    modifier = Modifier.size(36.dp),
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(
                            imageVector = Icons.Filled.Key,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSecondaryContainer,
                            modifier = Modifier.size(18.dp),
                        )
                    }
                }

                Spacer(modifier = Modifier.width(10.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = issuer.ifBlank { "Código de Acesso" },
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        text = accountName.ifBlank { "Conta principal" },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }

                if (onDeleteAccount != null) {
                    IconButton(
                        onClick = onDeleteAccount,
                        modifier = Modifier.size(30.dp),
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Delete,
                            contentDescription = "Remover código",
                            tint = MaterialTheme.colorScheme.error.copy(alpha = 0.8f),
                            modifier = Modifier.size(16.dp),
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Linha Central: Código Monoespaçado com anel de tempo sem quebrar linha
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = formattedCode.ifBlank { "--- ---" },
                    style = AegisCodeMonospaceStyle,
                    color = MaterialTheme.colorScheme.primary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )

                Spacer(modifier = Modifier.width(8.dp))

                TotpCountdownRingAtom(
                    remainingSeconds = remainingSeconds,
                    totalSeconds = totalSeconds,
                )
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Rodapé: Botão de Cópia com 1 toque alinhado à direita
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
            ) {
                QuickActionPillButton(
                    text = "Copiar código",
                    icon = Icons.Filled.ContentCopy,
                    onClick = { onCopyCode(code.filter { it.isDigit() }) },
                )
            }
        }
    }
}
