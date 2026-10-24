package dev.aegiskey.app.ui.atomic.organisms

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
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
import androidx.compose.material.icons.filled.AccountBalanceWallet
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.ui.atomic.atoms.PrimaryNextButton

/**
 * Tipos de chaves suportadas para criação no cofre físico da AegisKey.
 */
enum class VaultKeyType(
    val title: String,
    val description: String,
    val icon: ImageVector,
) {
    PASSKEY(
        title = "Chave de Acesso (Passkey)",
        description = "Login sem senha para Google, Apple, GitHub e sites",
        icon = Icons.Filled.Fingerprint,
    ),
    BITCOIN(
        title = "Carteira Bitcoin",
        description = "Segurança em hardware para guardar e assinar BTC",
        icon = Icons.Filled.AccountBalanceWallet,
    ),
    ETHEREUM(
        title = "Carteira Ethereum",
        description = "Suporte para rede Ethereum, Polygon e EVM",
        icon = Icons.Filled.AccountBalanceWallet,
    ),
    SOLANA(
        title = "Carteira Solana",
        description = "Chave de alta velocidade para ecossistema Solana",
        icon = Icons.Filled.AccountBalanceWallet,
    ),
}

/**
 * Diálogo acolhedor e descomplicado para criar uma nova credencial ou carteira na chave física.
 */
@Composable
fun KeyGenerationDialogOrganism(
    onDismissRequest: () -> Unit,
    onConfirm: (name: String, keyType: VaultKeyType) -> Unit,
    isLoading: Boolean = false,
    modifier: Modifier = Modifier,
) {
    var accountName by remember { mutableStateOf("") }
    var selectedType by remember { mutableStateOf(VaultKeyType.PASSKEY) }
    val isFormValid = accountName.trim().isNotBlank()

    AlertDialog(
        onDismissRequest = { if (!isLoading) onDismissRequest() },
        shape = RoundedCornerShape(24.dp),
        title = {
            Text(
                text = "Criar nova chave no cofre",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
            )
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                Text(
                    text = "A nova chave será gravada e protegida exclusivamente pelo chip de segurança da sua AegisKey.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                OutlinedTextField(
                    value = accountName,
                    onValueChange = { accountName = it },
                    label = { Text("Nome ou identificador") },
                    placeholder = { Text("Ex: GitHub Trabalho ou Carteira Pessoal") },
                    singleLine = true,
                    enabled = !isLoading,
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth(),
                )

                Text(
                    text = "Tipo de Chave:",
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.SemiBold,
                )

                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    VaultKeyType.entries.forEach { keyType ->
                        val isSelected = keyType == selectedType
                        val borderColor = if (isSelected) {
                            MaterialTheme.colorScheme.primary
                        } else {
                            MaterialTheme.colorScheme.outlineVariant
                        }
                        val containerColor = if (isSelected) {
                            MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.25f)
                        } else {
                            MaterialTheme.colorScheme.surface
                        }

                        OutlinedCard(
                            shape = RoundedCornerShape(12.dp),
                            border = BorderStroke(if (isSelected) 2.dp else 1.dp, borderColor),
                            colors = CardDefaults.outlinedCardColors(containerColor = containerColor),
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(12.dp))
                                .clickable(enabled = !isLoading) { selectedType = keyType },
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(12.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Surface(
                                    shape = RoundedCornerShape(8.dp),
                                    color = if (isSelected) {
                                        MaterialTheme.colorScheme.primaryContainer
                                    } else {
                                        MaterialTheme.colorScheme.surfaceVariant
                                    },
                                    modifier = Modifier.size(36.dp),
                                ) {
                                    Box(contentAlignment = Alignment.Center) {
                                        Icon(
                                            imageVector = keyType.icon,
                                            contentDescription = null,
                                            tint = if (isSelected) {
                                                MaterialTheme.colorScheme.primary
                                            } else {
                                                MaterialTheme.colorScheme.onSurfaceVariant
                                            },
                                            modifier = Modifier.size(20.dp),
                                        )
                                    }
                                }

                                Spacer(modifier = Modifier.width(12.dp))

                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = keyType.title,
                                        style = MaterialTheme.typography.titleSmall,
                                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium,
                                    )
                                    Text(
                                        text = keyType.description,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            PrimaryNextButton(
                text = "Criar na minha chave",
                enabled = isFormValid,
                isLoading = isLoading,
                onClick = {
                    if (isFormValid) {
                        onConfirm(accountName.trim(), selectedType)
                    }
                },
            )
        },
        dismissButton = {
            TextButton(
                onClick = onDismissRequest,
                enabled = !isLoading,
            ) {
                Text(text = "Cancelar", style = MaterialTheme.typography.labelLarge)
            }
        },
        modifier = modifier,
    )
}
