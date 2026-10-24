package dev.aegiskey.app.ui.atomic.organisms

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.ui.atomic.atoms.PrimaryNextButton

/**
 * Diálogo amigável para cadastrar uma conta com código de autenticação em 2 etapas (TOTP).
 * Permite colar o segredo Base32 ou URL `otpauth://`, além de oferecer preenchimento
 * com 1 clique para testes e demonstrações rápidas.
 */
@Composable
fun AddTotpAccountDialogOrganism(
    onDismissRequest: () -> Unit,
    onSaveTotp: (issuer: String, account: String, secretOrUri: String) -> Unit,
    isLoading: Boolean = false,
    modifier: Modifier = Modifier,
) {
    var issuer by remember { mutableStateOf("") }
    var accountName by remember { mutableStateOf("") }
    var secretOrUri by remember { mutableStateOf("") }

    val isFormValid = issuer.trim().isNotBlank() && secretOrUri.trim().isNotBlank()

    AlertDialog(
        onDismissRequest = { if (!isLoading) onDismissRequest() },
        shape = RoundedCornerShape(24.dp),
        title = {
            Text(
                text = "Adicionar código temporário",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
            )
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    text = "Cadastre o código de 2 etapas (TOTP). A chave física gerará os números de 6 dígitos mesmo se seu celular estiver offline.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                // Botão de preenchimento rápido para demonstração/testes
                OutlinedButton(
                    onClick = {
                        issuer = "AegisKey Demo"
                        accountName = "usuario@aegiskey.dev"
                        secretOrUri = "JBSWY3DPEHPK3PXP" // Segredo Base32 de teste padrão RFC 6238
                    },
                    enabled = !isLoading,
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Filled.AutoAwesome,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp),
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Gerar dados de teste automaticamente",
                            style = MaterialTheme.typography.labelMedium,
                        )
                    }
                }

                OutlinedTextField(
                    value = issuer,
                    onValueChange = { issuer = it },
                    label = { Text("Nome do serviço") },
                    placeholder = { Text("Ex: Google, GitHub, Binance") },
                    singleLine = true,
                    enabled = !isLoading,
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth(),
                )

                OutlinedTextField(
                    value = accountName,
                    onValueChange = { accountName = it },
                    label = { Text("E-mail ou nome da conta") },
                    placeholder = { Text("Ex: junior@empresa.com") },
                    singleLine = true,
                    enabled = !isLoading,
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth(),
                )

                OutlinedTextField(
                    value = secretOrUri,
                    onValueChange = { secretOrUri = it },
                    label = { Text("Chave secreta ou link otpauth://") },
                    placeholder = { Text("Cole o código alfanumérico fornecido") },
                    minLines = 2,
                    maxLines = 4,
                    enabled = !isLoading,
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            PrimaryNextButton(
                text = "Salvar na chave",
                enabled = isFormValid,
                isLoading = isLoading,
                onClick = {
                    if (isFormValid) {
                        onSaveTotp(issuer.trim(), accountName.trim(), secretOrUri.trim())
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
