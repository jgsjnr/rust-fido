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
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
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
import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.ui.atomic.atoms.PrimaryNextButton
import dev.aegiskey.app.ui.atomic.molecules.ConnectedKeyCardMolecule
import dev.aegiskey.app.ui.atomic.organisms.DebugChipControlHooksCard
import dev.aegiskey.app.ui.viewmodel.ConnectedKeysViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConnectedKeysRepositoryScreen(
    viewModel: ConnectedKeysViewModel,
    onConnectNewKey: () -> Unit,
    modifier: Modifier = Modifier,
    onBackClick: (() -> Unit)? = null,
) {
    val uiState by viewModel.uiState.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }

    var keyToRename by remember { mutableStateOf<ConnectedKeyDevice?>(null) }
    var newKeyName by remember { mutableStateOf("") }
    var keyToRemove by remember { mutableStateOf<ConnectedKeyDevice?>(null) }

    LaunchedEffect(uiState.userFeedbackMessage) {
        uiState.userFeedbackMessage?.let {
            snackbarHostState.showSnackbar(it)
            viewModel.clearFeedback()
        }
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Minhas Chaves Físicas",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                    )
                },
                navigationIcon = {
                    if (onBackClick != null) {
                        IconButton(onClick = onBackClick) {
                            Icon(imageVector = Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Voltar")
                        }
                    }
                },
            )
        },
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(horizontal = 20.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            // Cartão de Destaque para Conectar Nova Chave
            item {
                Button(
                    onClick = onConnectNewKey,
                    shape = RoundedCornerShape(16.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.primary,
                        contentColor = MaterialTheme.colorScheme.onPrimary,
                    ),
                    modifier = Modifier.fillMaxWidth().height(52.dp),
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(imageVector = Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(20.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Conectar Nova Chave",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                        )
                    }
                }
            }

            item {
                Text(
                    text = "Chaves Cadastradas no Celular",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }

            if (uiState.keys.isEmpty()) {
                item {
                    Surface(
                        shape = RoundedCornerShape(16.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Column(
                            modifier = Modifier.padding(24.dp),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            Icon(
                                imageVector = Icons.Filled.VpnKey,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(40.dp),
                            )
                            Text(
                                text = "Nenhuma chave vinculada",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold,
                            )
                            Text(
                                text = "Toque no botão acima para conectar sua primeira chave física AegisKey.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }

            items(uiState.keys, key = { it.id }) { device ->
                val isCurrent = device.id == uiState.activeKey?.id
                val transportText = when (device.transportType) {
                    ConnectionTransportType.BLE -> "Bluetooth Sem Fio"
                    ConnectionTransportType.USB -> "Cabo USB"
                    ConnectionTransportType.SIMULATOR -> "Simulador Virtual"
                }

                ConnectedKeyCardMolecule(
                    keyName = device.displayName,
                    transportLabel = transportText,
                    isConnected = device.isCurrentlyConnected,
                    isCurrentKey = isCurrent,
                    serialNumber = device.hardwareAddressOrId,
                    onSelectKey = { viewModel.selectKey(device.id) },
                    onRenameKey = {
                        keyToRename = device
                        newKeyName = device.displayName
                    },
                    onDisconnectKey = {
                        keyToRemove = device
                    },
                )
            }

            item {
                DebugChipControlHooksCard(
                    onResetAllKeys = { viewModel.resetAllKeysForDebug() },
                )
            }
        }
    }

    // Diálogo de Renomear Chave
    keyToRename?.let { device ->
        AlertDialog(
            onDismissRequest = { keyToRename = null },
            shape = RoundedCornerShape(20.dp),
            title = {
                Text(
                    text = "Renomear Chave",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(
                        text = "Escolha um apelido fácil de lembrar para identificar esta chave:",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    OutlinedTextField(
                        value = newKeyName,
                        onValueChange = { newKeyName = it },
                        label = { Text("Nome da chave") },
                        singleLine = true,
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            },
            confirmButton = {
                PrimaryNextButton(
                    text = "Salvar Nome",
                    enabled = newKeyName.trim().isNotBlank(),
                    onClick = {
                        viewModel.renameKey(device.id, newKeyName.trim())
                        keyToRename = null
                    },
                )
            },
            dismissButton = {
                TextButton(onClick = { keyToRename = null }) {
                    Text("Cancelar")
                }
            },
        )
    }

    // Diálogo de Confirmação para Desconectar / Remover
    keyToRemove?.let { device ->
        AlertDialog(
            onDismissRequest = { keyToRemove = null },
            shape = RoundedCornerShape(20.dp),
            title = {
                Text(
                    text = "Desconectar Chave?",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                )
            },
            text = {
                Text(
                    text = "Tem certeza de que deseja remover a chave \"${device.displayName}\"? Você poderá reconectá-la a qualquer momento.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        viewModel.removeKey(device.id)
                        keyToRemove = null
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                        contentColor = MaterialTheme.colorScheme.onError,
                    ),
                    shape = RoundedCornerShape(14.dp),
                ) {
                    Text("Desconectar")
                }
            },
            dismissButton = {
                TextButton(onClick = { keyToRemove = null }) {
                    Text("Cancelar")
                }
            },
        )
    }
}
