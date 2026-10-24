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
import androidx.compose.material.icons.filled.Backup
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.HealthAndSafety
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockPerson
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material.icons.filled.TouchApp
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.VaultKeyEntry
import dev.aegiskey.app.ui.atomic.atoms.ConnectionStatusBadgeAtom
import dev.aegiskey.app.ui.atomic.molecules.SettingToggleRowMolecule
import dev.aegiskey.app.ui.atomic.molecules.VaultEntryCardMolecule
import dev.aegiskey.app.ui.atomic.organisms.DebugChipControlHooksCard
import dev.aegiskey.app.ui.atomic.organisms.KeyGenerationDialogOrganism
import dev.aegiskey.app.ui.atomic.organisms.VaultKeyType
import dev.aegiskey.app.ui.viewmodel.KeyVaultViewModel

@Composable
fun KeyVaultHubScreen(
    viewModel: KeyVaultViewModel,
    onNavigateToBackup: () -> Unit = {},
    onNavigateToOta: () -> Unit = {},
    modifier: Modifier = Modifier,
) {
    val uiState by viewModel.uiState.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }

    var showCreateDialog by remember { mutableStateOf(false) }
    var entryToDelete by remember { mutableStateOf<VaultKeyEntry?>(null) }

    LaunchedEffect(uiState.userMessage) {
        uiState.userMessage?.let {
            snackbarHostState.showSnackbar(it)
            viewModel.clearMessages()
        }
    }

    LaunchedEffect(uiState.errorMessage) {
        uiState.errorMessage?.let {
            snackbarHostState.showSnackbar(it)
            viewModel.clearMessages()
        }
    }

    Box(modifier = modifier.fillMaxSize()) {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 20.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(18.dp),
        ) {
            // Cartão de Resumo da Chave Física Ativa
            item {
                ActiveKeySummaryCard(
                    activeKeyName = uiState.activeKey?.displayName ?: "Nenhuma chave ativa",
                    transport = uiState.activeKey?.transportType,
                    isConnected = uiState.activeKey?.isCurrentlyConnected == true,
                    onSimulateTouch = if (uiState.activeKey?.transportType == ConnectionTransportType.SIMULATOR) {
                        { viewModel.simulateTouchIfNeeded() }
                    } else null,
                )
            }

            // Botão Principal: Criar Nova Chave no Cofre
            item {
                Button(
                    onClick = { showCreateDialog = true },
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
                            text = "Criar Nova Chave de Acesso",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                        )
                    }
                }
            }

            // Seção de Chaves Guardadas no Cofre
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = "Guardadas no Cofre",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                    )
                    if (uiState.isLoading) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                    }
                }
            }

            if (uiState.entries.isEmpty() && !uiState.isLoading) {
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
                                imageVector = Icons.Filled.Lock,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(36.dp),
                            )
                            Text(
                                text = "Seu cofre está vazio",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold,
                            )
                            Text(
                                text = "Crie sua primeira Passkey ou carteira para proteger suas contas diretamente no chip da chave.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }

            items(uiState.entries, key = { it.slotId }) { entry ->
                val typeLabel = when (entry.type) {
                    AccessKeyType.PASSKEY_FIDO -> "Passkey"
                    AccessKeyType.CRYPTO_WALLET_BTC -> "Bitcoin"
                    AccessKeyType.CRYPTO_WALLET_ETH -> "Ethereum"
                    AccessKeyType.CRYPTO_WALLET_SOL -> "Solana"
                }

                VaultEntryCardMolecule(
                    title = entry.label,
                    subtitle = entry.publicSummary,
                    entryType = typeLabel,
                    identifierToCopy = entry.publicSummary,
                    onCopy = { viewModel.copyIdentifier(it) },
                    onDelete = { entryToDelete = entry },
                )
            }

            // Seção: Proteção Rápida
            item {
                Text(
                    text = "Proteção Rápida",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }

            item {
                val toggles = uiState.activeKey?.toggles
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    SettingToggleRowMolecule(
                        title = "Bloquear ao afastar a chave",
                        description = "O cofre fecha automaticamente caso o sinal sem fio da chave se distancie.",
                        icon = Icons.Filled.LockPerson,
                        checked = toggles?.lockOnWalkAway ?: true,
                        onCheckedChange = { viewModel.toggleLockOnWalkAway(it) },
                    )

                    SettingToggleRowMolecule(
                        title = "Pedir digital ao abrir o aplicativo",
                        description = "Exige sua impressão digital ou reconhecimento facial do celular para visualizar o cofre.",
                        icon = Icons.Filled.Fingerprint,
                        checked = toggles?.requireBiometricsOnOpen ?: false,
                        onCheckedChange = { viewModel.toggleRequireBiometrics(it) },
                    )

                    SettingToggleRowMolecule(
                        title = "Exigir toque físico na chave para cada código",
                        description = "Garante que nenhuma operação seja aprovada sem que você aperte o botão da chave.",
                        icon = Icons.Filled.TouchApp,
                        checked = toggles?.requireTouchForEveryCode ?: true,
                        onCheckedChange = { viewModel.toggleRequireTouchForCode(it) },
                    )
                }
            }

            // Seção: Cuidados com a Chave
            item {
                Text(
                    text = "Cuidados com a Chave",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }

            item {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    // Status de saúde caso tenha sido executado
                    if (!uiState.healthCheckStatus.isNullOrBlank()) {
                        Surface(
                            shape = RoundedCornerShape(14.dp),
                            color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.4f),
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Row(
                                modifier = Modifier.padding(14.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.CheckCircle,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(20.dp),
                                )
                                Spacer(modifier = Modifier.width(10.dp))
                                Text(
                                    text = uiState.healthCheckStatus ?: "",
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.Medium,
                                )
                            }
                        }
                    }

                    OutlinedButton(
                        onClick = { viewModel.runHealthCheck() },
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth().height(48.dp),
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(imageVector = Icons.Filled.HealthAndSafety, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Verificar Saúde da Chave")
                        }
                    }

                    OutlinedButton(
                        onClick = onNavigateToBackup,
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth().height(48.dp),
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(imageVector = Icons.Filled.Backup, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Fazer Backup de Segurança")
                        }
                    }

                    OutlinedButton(
                        onClick = onNavigateToOta,
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth().height(48.dp),
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(imageVector = Icons.Filled.SystemUpdate, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Atualizar Software da Chave")
                        }
                    }
                }
            }

            item {
                DebugChipControlHooksCard(
                    onSimulateTouch = { viewModel.simulateTouchIfNeeded() },
                    onInjectSampleData = { viewModel.injectExtraSampleForDebug() },
                    onSimulatePing = { viewModel.runHealthCheck() },
                )
            }

            item {
                Spacer(modifier = Modifier.height(20.dp))
            }
        }

        SnackbarHost(
            hostState = snackbarHostState,
            modifier = Modifier.align(Alignment.BottomCenter).padding(bottom = 16.dp),
        )
    }

    // Diálogo de Criação de Chave
    if (showCreateDialog) {
        KeyGenerationDialogOrganism(
            onDismissRequest = { showCreateDialog = false },
            onConfirm = { name, vaultType ->
                val type = when (vaultType) {
                    VaultKeyType.PASSKEY -> AccessKeyType.PASSKEY_FIDO
                    VaultKeyType.BITCOIN -> AccessKeyType.CRYPTO_WALLET_BTC
                    VaultKeyType.ETHEREUM -> AccessKeyType.CRYPTO_WALLET_ETH
                    VaultKeyType.SOLANA -> AccessKeyType.CRYPTO_WALLET_SOL
                }
                viewModel.generateKey(name, type)
                showCreateDialog = false
            },
            isLoading = uiState.isLoading,
        )
    }

    // Diálogo de Confirmação para Excluir Entrada do Cofre
    entryToDelete?.let { entry ->
        AlertDialog(
            onDismissRequest = { entryToDelete = null },
            shape = RoundedCornerShape(20.dp),
            title = {
                Text(
                    text = "Remover do Cofre?",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                )
            },
            text = {
                Text(
                    text = "Tem certeza de que deseja remover \"${entry.label}\" da sua chave? Esta ação não pode ser desfeita.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        viewModel.deleteEntry(entry.slotId)
                        entryToDelete = null
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                        contentColor = MaterialTheme.colorScheme.onError,
                    ),
                    shape = RoundedCornerShape(14.dp),
                ) {
                    Text("Remover Chave")
                }
            },
            dismissButton = {
                TextButton(onClick = { entryToDelete = null }) {
                    Text("Cancelar")
                }
            },
        )
    }
}

@Composable
private fun ActiveKeySummaryCard(
    activeKeyName: String,
    transport: ConnectionTransportType?,
    isConnected: Boolean,
    onSimulateTouch: (() -> Unit)? = null,
) {
    val transportLabel = when (transport) {
        ConnectionTransportType.BLE -> "Bluetooth"
        ConnectionTransportType.USB -> "Cabo USB"
        ConnectionTransportType.SIMULATOR -> "Simulador Virtual"
        null -> "Chave Física"
    }

    Card(
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.25f),
        ),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(18.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.primaryContainer,
                    modifier = Modifier.size(44.dp),
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(
                            imageVector = Icons.Filled.VpnKey,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onPrimaryContainer,
                            modifier = Modifier.size(24.dp),
                        )
                    }
                }

                Spacer(modifier = Modifier.width(12.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = activeKeyName,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                    )
                    Text(
                        text = "Cofre Físico Ativo",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }

                ConnectionStatusBadgeAtom(
                    isConnected = isConnected,
                    transportLabel = transportLabel,
                )
            }

            if (onSimulateTouch != null) {
                Spacer(modifier = Modifier.height(12.dp))
                OutlinedButton(
                    onClick = onSimulateTouch,
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(imageVector = Icons.Filled.TouchApp, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Simular Toque na Chave de Teste")
                }
            }
        }
    }
}
