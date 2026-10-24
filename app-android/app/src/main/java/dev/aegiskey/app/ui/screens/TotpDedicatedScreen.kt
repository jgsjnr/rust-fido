package dev.aegiskey.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.LockClock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.domain.model.TotpAccountItem
import dev.aegiskey.app.ui.atomic.molecules.TotpCodeCardMolecule
import dev.aegiskey.app.ui.atomic.organisms.AddTotpAccountDialogOrganism
import dev.aegiskey.app.ui.atomic.organisms.DebugChipControlHooksCard
import dev.aegiskey.app.ui.viewmodel.TotpAuthenticatorViewModel

@Composable
fun TotpDedicatedScreen(
    viewModel: TotpAuthenticatorViewModel,
    modifier: Modifier = Modifier,
) {
    val uiState by viewModel.uiState.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }

    var showAddDialog by remember { mutableStateOf(false) }
    var accountToDelete by remember { mutableStateOf<TotpAccountItem?>(null) }

    LaunchedEffect(uiState.feedbackMessage) {
        uiState.feedbackMessage?.let {
            snackbarHostState.showSnackbar(it)
            viewModel.clearFeedback()
        }
    }

    LaunchedEffect(uiState.errorMessage) {
        uiState.errorMessage?.let {
            snackbarHostState.showSnackbar(it)
            viewModel.clearFeedback()
        }
    }

    Box(modifier = modifier.fillMaxSize()) {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 20.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            // Cartão de Topo / Botão Principal de Adicionar Código
            item {
                Button(
                    onClick = { showAddDialog = true },
                    shape = RoundedCornerShape(16.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.primary,
                        contentColor = MaterialTheme.colorScheme.onPrimary,
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(52.dp),
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(imageVector = Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(20.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Adicionar Código Temporário (TOTP)",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                        )
                    }
                }
            }

            // Cabeçalho de Lista com Indicador de Atualização
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = "Códigos de Verificação",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                    )

                    Row(verticalAlignment = Alignment.CenterVertically) {
                        if (uiState.isLoading) {
                            CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                            Spacer(modifier = Modifier.width(8.dp))
                        }
                        IconButton(
                            onClick = { viewModel.refreshCodes() },
                            modifier = Modifier.size(36.dp),
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Refresh,
                                contentDescription = "Sincronizar códigos",
                                modifier = Modifier.size(20.dp),
                            )
                        }
                    }
                }
            }

            // Estado Vazio
            if (uiState.accounts.isEmpty() && !uiState.isLoading) {
                item {
                    Surface(
                        shape = RoundedCornerShape(16.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Column(
                            modifier = Modifier.padding(24.dp),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            Icon(
                                imageVector = Icons.Filled.LockClock,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(40.dp),
                            )
                            Text(
                                text = "Nenhum código temporário cadastrado",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold,
                            )
                            Text(
                                text = "Adicione contas do Google, GitHub, redes sociais e bancos para gerar códigos mesmo sem internet.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }

            // Lista de Cartões TOTP com Anel Animado
            items(uiState.accounts, key = { it.id }) { item ->
                TotpCodeCardMolecule(
                    issuer = item.issuer,
                    accountName = item.accountName,
                    code = item.currentCode,
                    remainingSeconds = uiState.remainingSeconds,
                    totalSeconds = item.periodSeconds,
                    onCopyCode = { code ->
                        viewModel.copyCodeToClipboard(code)
                    },
                    onDeleteAccount = {
                        accountToDelete = item
                    },
                )
            }

            item {
                DebugChipControlHooksCard(
                    onInjectSampleData = { viewModel.injectExtraSampleForDebug() },
                    onSimulatePing = { viewModel.refreshCodes() },
                )
            }

            item {
                Spacer(modifier = Modifier.height(24.dp))
            }
        }

        SnackbarHost(
            hostState = snackbarHostState,
            modifier = Modifier.align(Alignment.BottomCenter).padding(bottom = 16.dp),
        )
    }

    // Diálogo Organismo de Adicionar TOTP
    if (showAddDialog) {
        AddTotpAccountDialogOrganism(
            onDismissRequest = { showAddDialog = false },
            onSaveTotp = { issuer, account, secretOrUri ->
                viewModel.addAccount(issuer, account, secretOrUri)
                showAddDialog = false
            },
            isLoading = uiState.isAddingAccount,
        )
    }

    // Diálogo de Confirmação para Remover Conta
    accountToDelete?.let { item ->
        AlertDialog(
            onDismissRequest = { accountToDelete = null },
            shape = RoundedCornerShape(20.dp),
            title = {
                Text(
                    text = "Remover Código?",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                )
            },
            text = {
                Text(
                    text = "Deseja remover o gerador de códigos para \"${item.issuer.ifBlank { item.accountName }}\"? Você precisará do segredo original se quiser reconfigurar.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        viewModel.deleteAccount(item.id)
                        accountToDelete = null
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                        contentColor = MaterialTheme.colorScheme.onError,
                    ),
                    shape = RoundedCornerShape(14.dp),
                ) {
                    Text("Remover Código")
                }
            },
            dismissButton = {
                TextButton(onClick = { accountToDelete = null }) {
                    Text("Cancelar")
                }
            },
        )
    }
}
