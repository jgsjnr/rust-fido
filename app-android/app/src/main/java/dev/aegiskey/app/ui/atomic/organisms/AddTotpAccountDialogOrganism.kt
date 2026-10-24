package dev.aegiskey.app.ui.atomic.organisms

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.data.debug.DebugHardwareChipMock
import dev.aegiskey.app.ui.atomic.atoms.PrimaryNextButton

/**
 * Diálogo compacto e responsivo para cadastrar uma conta com código TOTP.
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
        shape = RoundedCornerShape(16.dp),
        title = {
            Text(
                text = "Adicionar código temporário",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(
                    text = "A chave física gerará os códigos mesmo com o celular offline.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )

                // Botão de preenchimento rápido (somente em ambiente com mocks habilitados)
                if (DebugHardwareChipMock.IS_MOCK_ENABLED) {
                    OutlinedButton(
                        onClick = {
                            issuer = "AegisKey Demo"
                            accountName = "usuario@aegiskey.dev"
                            secretOrUri = "JBSWY3DPEHPK3PXP"
                        },
                        enabled = !isLoading,
                        shape = RoundedCornerShape(10.dp),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(34.dp),
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Filled.AutoAwesome,
                                contentDescription = null,
                                modifier = Modifier.size(14.dp),
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = "Preencher dados de teste",
                                style = MaterialTheme.typography.labelSmall,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }

                OutlinedTextField(
                    value = issuer,
                    onValueChange = { issuer = it },
                    label = { Text("Nome do serviço", maxLines = 1) },
                    placeholder = { Text("Ex: Google ou GitHub", maxLines = 1) },
                    singleLine = true,
                    enabled = !isLoading,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth(),
                )

                OutlinedTextField(
                    value = accountName,
                    onValueChange = { accountName = it },
                    label = { Text("E-mail ou conta", maxLines = 1) },
                    placeholder = { Text("Ex: usuario@empresa.com", maxLines = 1) },
                    singleLine = true,
                    enabled = !isLoading,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth(),
                )

                OutlinedTextField(
                    value = secretOrUri,
                    onValueChange = { secretOrUri = it },
                    label = { Text("Chave secreta ou link otpauth://", maxLines = 1) },
                    placeholder = { Text("Cole o código alfanumérico", maxLines = 1) },
                    singleLine = true,
                    enabled = !isLoading,
                    shape = RoundedCornerShape(10.dp),
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
                Text(
                    text = "Cancelar",
                    style = MaterialTheme.typography.labelMedium,
                    maxLines = 1,
                )
            }
        },
        modifier = modifier,
    )
}
