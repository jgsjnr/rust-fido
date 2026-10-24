package dev.aegiskey.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.ui.text.style.TextOverflow
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
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
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
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // Botão compacto para Conectar Nova Chave (46.dp)
            item {
                Button(
                    onClick = onConnectNewKey,
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.primary,
                        contentColor = MaterialTheme.colorScheme.onPrimary,
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(46.dp),
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(imageVector = Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "Conectar Nova Chave",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
            }

            item {
                Text(
                    text = "Chaves Vinculadas ao Celular",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            if (uiState.keys.isEmpty()) {
                item {
                    Surface(
                        shape = RoundedCornerShape(12.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Column(
                            modifier = Modifier.padding(18.dp),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Icon(
                                imageVector = Icons.Filled.VpnKey,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(32.dp),
                            )
                            Text(
                                text = "Nenhuma chave vinculada",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                text = "Toque no botão acima para conectar sua primeira chave física.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis,
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

    // Diálogo compacto de Renomear Chave
    keyToRename?.let { device ->
        AlertDialog(
            onDismissRequest = { keyToRename = null },
            shape = RoundedCornerShape(16.dp),
            title = {
                Text(
                    text = "Renomear Chave",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = "Escolha um apelido fácil de lembrar para identificar esta chave:",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                    OutlinedTextField(
                        value = newKeyName,
                        onValueChange = { newKeyName = it },
                        label = { Text("Nome da chave", maxLines = 1) },
                        singleLine = true,
                        shape = RoundedCornerShape(10.dp),
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
                    Text("Cancelar", maxLines = 1)
                }
            },
        )
    }

    // Diálogo compacto de Confirmação para Desconectar
    keyToRemove?.let { device ->
        AlertDialog(
            onDismissRequest = { keyToRemove = null },
            shape = RoundedCornerShape(16.dp),
            title = {
                Text(
                    text = "Desconectar Chave?",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            },
            text = {
                Text(
                    text = "Tem certeza de que deseja remover \"${device.displayName}\"? Você poderá reconectá-la a qualquer momento.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
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
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.height(40.dp),
                ) {
                    Text("Desconectar", maxLines = 1)
                }
            },
            dismissButton = {
                TextButton(onClick = { keyToRemove = null }) {
                    Text("Cancelar", maxLines = 1)
                }
            },
        )
    }
}
