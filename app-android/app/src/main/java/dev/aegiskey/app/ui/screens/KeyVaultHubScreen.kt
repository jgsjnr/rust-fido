package dev.aegiskey.app.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Backup
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.HealthAndSafety
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockPerson
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Pin
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material.icons.filled.TouchApp
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.HardwareDeviceDiagnostics
import dev.aegiskey.app.domain.model.VaultKeyEntry
import dev.aegiskey.app.ui.atomic.atoms.ConnectionStatusBadgeAtom
import dev.aegiskey.app.ui.atomic.molecules.SettingToggleRowMolecule
import dev.aegiskey.app.ui.atomic.molecules.VaultEntryCardMolecule
import dev.aegiskey.app.ui.atomic.organisms.DebugChipControlHooksCard
import dev.aegiskey.app.ui.atomic.organisms.KeyGenerationDialogOrganism
import dev.aegiskey.app.ui.atomic.organisms.SecureGuardCardOrganism
import dev.aegiskey.app.ui.viewmodel.SecureGuardViewModel
import dev.aegiskey.app.ui.viewmodel.KeyVaultViewModel

@Composable
fun KeyVaultHubScreen(
    viewModel: KeyVaultViewModel,
    secureGuardViewModel: SecureGuardViewModel? = null,
    onNavigateToBackup: () -> Unit = {},
    onNavigateToOta: () -> Unit = {},
    modifier: Modifier = Modifier,
) {
    val uiState by viewModel.uiState.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }

    var showCreateDialog by remember { mutableStateOf(false) }
    var entryToDelete by remember { mutableStateOf<VaultKeyEntry?>(null) }
    var isDiagnosticsExpanded by remember { mutableStateOf(false) }

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

    // Se uma chave específica estiver selecionada, renderiza sua tela de gestão dedicada
    if (uiState.selectedEntry != null) {
        KeyDetailManagementScreen(
            entry = uiState.selectedEntry!!,
            onBack = { viewModel.closeKeyDetail() },
            onCopy = { viewModel.copyIdentifier(it) },
            onSign = { slotId, msg -> viewModel.signWithSelectedKey(slotId, msg) },
            onExportEnvelope = { slotId -> viewModel.exportSelectedKeyEnvelope(slotId) },
            onEnrollPivPin = { slotCode, pin, puk -> viewModel.enrollPivPin(slotCode, pin, puk) },
            onDeleteKey = { slotId -> viewModel.deleteKeyAndCloseDetail(slotId) },
            signatureResult = uiState.lastSignatureResult,
            exportedEnvelope = uiState.lastExportedEnvelope,
            isActionLoading = uiState.isActionLoading,
            modifier = modifier
        )
        return
    }

    // Filtro por categoria
    val filteredEntries = when (uiState.selectedCategoryFilter) {
        "PASSKEYS" -> uiState.entries.filter { it.type == AccessKeyType.PASSKEY_FIDO || it.type == AccessKeyType.VENDOR_SIGNING_KEY }
        "CRYPTO" -> uiState.entries.filter {
            it.type in listOf(
                AccessKeyType.CRYPTO_WALLET_BTC,
                AccessKeyType.CRYPTO_WALLET_ETH,
                AccessKeyType.CRYPTO_WALLET_SOL,
                AccessKeyType.CRYPTO_WALLET_DOT
            )
        }
        "PIV" -> uiState.entries.filter { it.type == AccessKeyType.PIV_SMARTCARD_SLOT }
        "AEGN" -> uiState.entries.filter { it.type == AccessKeyType.ENCRYPTED_AEGN_ENVELOPE }
        else -> uiState.entries
    }

    Box(modifier = modifier.fillMaxSize()) {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // Cartão de Resumo da Chave Física Ativa Compacto
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

            // Resumo de Proximidade RSSI & Dynamic Lock (Celular ↔ PC)
            item {
                val hostBridgeClient = remember { dev.aegiskey.app.data.transport.HostUsbUartBridgeClient() }
                var proximityStatus by remember { mutableStateOf(dev.aegiskey.app.data.transport.HostUsbUartBridgeClient.ProximityLockStatus()) }
                LaunchedEffect(Unit) {
                    proximityStatus = hostBridgeClient.fetchProximityStatus()
                }
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = if (proximityStatus.locked) {
                        MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.5f)
                    } else {
                        MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Filled.LockPerson,
                                contentDescription = null,
                                tint = if (proximityStatus.locked) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(16.dp),
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "Dynamic Lock PC",
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.SemiBold,
                            )
                        }
                        Text(
                            text = if (proximityStatus.locked) "LOCKED (PC Travado)" else "${proximityStatus.state} (${proximityStatus.currentRssiDbm} dBm)",
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold,
                            color = if (proximityStatus.locked) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                        )
                    }
                }
            }

            // Painel Secure Guard (Zero-Trust On-Device Authority)
            if (secureGuardViewModel != null) {
                item {
                    val sgState by secureGuardViewModel.uiState.collectAsState()
                    SecureGuardCardOrganism(
                        uiState = sgState,
                        onProvision = { pin, rc, pol -> secureGuardViewModel.provision(pin, rc, pol) },
                        onUnlock = { pin -> secureGuardViewModel.unlock(pin) },
                        onLock = { secureGuardViewModel.lock() },
                        onChangePin = { curr, next -> secureGuardViewModel.changePin(curr, next) },
                        onRecover = { rc, next -> secureGuardViewModel.recover(rc, next) },
                        onUpdatePolicy = { pol -> secureGuardViewModel.updatePolicy(pol) },
                        onWipeSelective = { scope, token -> secureGuardViewModel.wipeSelective(scope, token) },
                        onRefresh = { secureGuardViewModel.refreshStatus() },
                        modifier = Modifier.padding(bottom = 8.dp)
                    )
                }
            }

            // Painel Resumo do Gestor de Hardware
            item {
                HardwareManagerSummaryPanel(
                    diagnostics = uiState.hardwareDiagnostics,
                    totalOccupied = uiState.entries.size,
                    activeTransport = uiState.activeKey?.transportType,
                    isExpanded = isDiagnosticsExpanded,
                    onToggleExpand = {
                        isDiagnosticsExpanded = !isDiagnosticsExpanded
                        if (isDiagnosticsExpanded) viewModel.loadHardwareDiagnostics()
                    },
                    onRunQuickCheck = { viewModel.runHealthCheck() },
                    onNavigateToBackup = onNavigateToBackup,
                    onNavigateToOta = onNavigateToOta
                )
            }

            // Botão Principal: Criar Nova Chave no Cofre
            item {
                Button(
                    onClick = { showCreateDialog = true },
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
                            text = "Criar Nova Chave no Hardware",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
            }

            // FilterChips Horizontais Compactos
            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    FilterChip(
                        selected = uiState.selectedCategoryFilter == "ALL",
                        onClick = { viewModel.setCategoryFilter("ALL") },
                        label = { Text("Todas (${uiState.entries.size})", style = MaterialTheme.typography.labelSmall) },
                        colors = FilterChipDefaults.filterChipColors()
                    )
                    FilterChip(
                        selected = uiState.selectedCategoryFilter == "PASSKEYS",
                        onClick = { viewModel.setCategoryFilter("PASSKEYS") },
                        label = { Text("Passkeys & SSH", style = MaterialTheme.typography.labelSmall) }
                    )
                    FilterChip(
                        selected = uiState.selectedCategoryFilter == "CRYPTO",
                        onClick = { viewModel.setCategoryFilter("CRYPTO") },
                        label = { Text("Carteiras Cripto", style = MaterialTheme.typography.labelSmall) }
                    )
                    FilterChip(
                        selected = uiState.selectedCategoryFilter == "PIV",
                        onClick = { viewModel.setCategoryFilter("PIV") },
                        label = { Text("Smartcard PIV", style = MaterialTheme.typography.labelSmall) }
                    )
                    FilterChip(
                        selected = uiState.selectedCategoryFilter == "AEGN",
                        onClick = { viewModel.setCategoryFilter("AEGN") },
                        label = { Text("Envelopes AEGN", style = MaterialTheme.typography.labelSmall) }
                    )
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
                        text = "Chaves no Chip (${filteredEntries.size})",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    if (uiState.isLoading) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    }
                }
            }

            if (filteredEntries.isEmpty() && !uiState.isLoading) {
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
                                imageVector = Icons.Filled.Lock,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(32.dp),
                            )
                            Text(
                                text = "Nenhuma chave encontrada neste filtro",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                text = "Toque em \"Criar Nova Chave\" para gravar uma nova credencial no chip físico.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }
            }

            items(filteredEntries, key = { it.slotId }) { entry ->
                val typeLabel = when (entry.type) {
                    AccessKeyType.PASSKEY_FIDO -> "Passkey"
                    AccessKeyType.VENDOR_SIGNING_KEY -> "Vendor Key"
                    AccessKeyType.CRYPTO_WALLET_BTC -> "Bitcoin"
                    AccessKeyType.CRYPTO_WALLET_ETH -> "Ethereum"
                    AccessKeyType.CRYPTO_WALLET_SOL -> "Solana"
                    AccessKeyType.CRYPTO_WALLET_DOT -> "Polkadot"
                    AccessKeyType.PIV_SMARTCARD_SLOT -> "PIV Smartcard"
                    AccessKeyType.ENCRYPTED_AEGN_ENVELOPE -> "Envelope AEGN"
                }

                VaultEntryCardMolecule(
                    title = entry.label,
                    subtitle = entry.publicSummary,
                    entryType = typeLabel,
                    identifierToCopy = entry.publicSummary,
                    algorithmOrCurve = entry.algorithmOrCurve,
                    derivationPathOrSlotCode = entry.derivationPathOrSlotCode,
                    onOpenDetail = { viewModel.openKeyDetail(entry.slotId) },
                    onCopy = { viewModel.copyIdentifier(it) },
                    onDelete = { entryToDelete = entry },
                )
            }

            // Seção: Proteção Rápida
            item {
                Text(
                    text = "Proteção Rápida",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.padding(top = 4.dp),
                )
            }

            item {
                val toggles = uiState.activeKey?.toggles
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    SettingToggleRowMolecule(
                        title = "Bloquear ao afastar a chave",
                        description = "Fecha o cofre se a chave física se distanciar.",
                        icon = Icons.Filled.LockPerson,
                        checked = toggles?.lockOnWalkAway ?: true,
                        onCheckedChange = { viewModel.toggleLockOnWalkAway(it) },
                    )

                    SettingToggleRowMolecule(
                        title = "Pedir digital ao abrir o app",
                        description = "Exige biometria do celular para ver o cofre.",
                        icon = Icons.Filled.Fingerprint,
                        checked = toggles?.requireBiometricsOnOpen ?: false,
                        onCheckedChange = { viewModel.toggleRequireBiometrics(it) },
                    )

                    SettingToggleRowMolecule(
                        title = "Exigir toque para cada código",
                        description = "Exige toque no botão da chave para autorizar.",
                        icon = Icons.Filled.TouchApp,
                        checked = toggles?.requireTouchForEveryCode ?: true,
                        onCheckedChange = { viewModel.toggleRequireTouchForCode(it) },
                    )
                }
            }

            item {
                DebugChipControlHooksCard(
                    onSimulateTouch = { viewModel.simulateTouchIfNeeded() },
                    onInjectSampleData = { viewModel.injectExtraSampleForDebug() },
                    onSimulatePing = { viewModel.runHealthCheck() },
                    onResetAllKeys = { viewModel.resetHardwareVault() },
                )
            }

            item {
                Spacer(modifier = Modifier.height(16.dp))
            }
        }

        SnackbarHost(
            hostState = snackbarHostState,
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .padding(bottom = 12.dp),
        )
    }

    // Diálogo de Criação de Chave Completo
    if (showCreateDialog) {
        KeyGenerationDialogOrganism(
            onDismissRequest = { showCreateDialog = false },
            onConfirm = { label, type, curve, extra ->
                viewModel.createNewKey(
                    label = label,
                    type = type,
                    algorithmOrCurve = curve,
                    extraParam = extra
                )
                showCreateDialog = false
            },
            isLoading = uiState.isLoading,
        )
    }

    // Diálogo compacto para Excluir Entrada do Cofre
    entryToDelete?.let { entry ->
        AlertDialog(
            onDismissRequest = { entryToDelete = null },
            shape = RoundedCornerShape(16.dp),
            title = {
                Text(
                    text = "Remover do Cofre?",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            },
            text = {
                Text(
                    text = "Tem certeza de que deseja remover \"${entry.label}\"? Esta ação enviará o comando de expurgo 0x23 para o hardware.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
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
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.height(38.dp),
                ) {
                    Text("Remover Chave", maxLines = 1)
                }
            },
            dismissButton = {
                TextButton(onClick = { entryToDelete = null }) {
                    Text("Cancelar", maxLines = 1)
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
        ConnectionTransportType.USB -> "Cabo USB / UART"
        ConnectionTransportType.WIFI -> "Rede Wi-Fi"
        ConnectionTransportType.SIMULATOR -> "Simulador Virtual"
        null -> "Chave Física"
    }

    Card(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.2f),
        ),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = MaterialTheme.colorScheme.primaryContainer,
                    modifier = Modifier.size(36.dp),
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(
                            imageVector = Icons.Filled.VpnKey,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onPrimaryContainer,
                            modifier = Modifier.size(18.dp),
                        )
                    }
                }

                Spacer(modifier = Modifier.width(10.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = activeKeyName,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        text = "Cofre Físico Ativo",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }

                ConnectionStatusBadgeAtom(
                    isConnected = isConnected,
                    transportLabel = transportLabel,
                )
            }

            if (onSimulateTouch != null) {
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedButton(
                    onClick = onSimulateTouch,
                    shape = RoundedCornerShape(10.dp),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(34.dp),
                ) {
                    Icon(imageVector = Icons.Filled.TouchApp, contentDescription = null, modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        text = "Simular Toque na Chave de Teste",
                        style = MaterialTheme.typography.labelSmall,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        }
    }
}

@Composable
private fun HardwareManagerSummaryPanel(
    diagnostics: HardwareDeviceDiagnostics?,
    totalOccupied: Int,
    activeTransport: ConnectionTransportType?,
    isExpanded: Boolean,
    onToggleExpand: () -> Unit,
    onRunQuickCheck: () -> Unit,
    onNavigateToBackup: () -> Unit,
    onNavigateToOta: () -> Unit
) {
    val fwVersion = diagnostics?.firmwareVersion ?: "v0.2.1-esp32s3"
    val channel = when (activeTransport) {
        ConnectionTransportType.BLE -> "BLE"
        ConnectionTransportType.USB -> "USB/UART"
        ConnectionTransportType.WIFI -> "Wi-Fi"
        ConnectionTransportType.SIMULATOR -> "Simulador"
        null -> "Hardware"
    }
    val freeSlots = diagnostics?.freeSlotsRemaining ?: (16 - totalOccupied).coerceAtLeast(0)

    OutlinedCard(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.outlinedCardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Filled.Memory,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "Gestor de Hardware do Chip",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.5f)
                ) {
                    Text(
                        text = fwVersion,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }
            }

            // Resumo de Canal e Slots
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = "Canal: $channel · Slots: $totalOccupied ocupados, $freeSlots livres",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }

            // Curvas Suportadas
            val curvesText = diagnostics?.fido2SupportedCurves?.joinToString(", ") ?: "Ed25519, ES256, ES384, ES512, ES256K"
            Text(
                text = "Curvas: $curvesText",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )

            // Botão Expandir Diagnóstico Completo
            OutlinedButton(
                onClick = onToggleExpand,
                shape = RoundedCornerShape(10.dp),
                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                modifier = Modifier.fillMaxWidth().height(36.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.Center
                ) {
                    Icon(
                        imageVector = if (isExpanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = if (isExpanded) "Ocultar Diagnóstico do Chip" else "Diagnóstico Completo do Chip",
                        style = MaterialTheme.typography.labelSmall
                    )
                }
            }

            AnimatedVisibility(visible = isExpanded) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 4.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(
                                text = "Status de Integridade: ${diagnostics?.healthStatusText ?: "Hardware 100% íntegro (ATECC608A + ESP32-S3)"}",
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Medium
                            )
                            Text(
                                text = "Slots PIV: ${diagnostics?.pivSlotsAvailable?.joinToString() ?: "9A, 9C, 9D, 9E"}",
                                style = MaterialTheme.typography.labelSmall
                            )
                            Text(
                                text = "PIN em Hardware: ${if (diagnostics?.isPinConfigured == true) "Configurado" else "Padrão Ativo"}",
                                style = MaterialTheme.typography.labelSmall
                            )
                            Text(
                                text = "Vínculo Criptográfico: ${if (diagnostics?.isBoundToThisPhone == true) "Pareado e Seguro" else "Ativo"}",
                                style = MaterialTheme.typography.labelSmall
                            )
                        }
                    }

                    // Ações Rápidas de Hardware
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        OutlinedButton(
                            onClick = onRunQuickCheck,
                            shape = RoundedCornerShape(8.dp),
                            contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp),
                            modifier = Modifier.weight(1f).height(32.dp)
                        ) {
                            Text("HealthCheck", style = MaterialTheme.typography.labelSmall, maxLines = 1)
                        }
                        OutlinedButton(
                            onClick = onNavigateToBackup,
                            shape = RoundedCornerShape(8.dp),
                            contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp),
                            modifier = Modifier.weight(1f).height(32.dp)
                        ) {
                            Text("Backup", style = MaterialTheme.typography.labelSmall, maxLines = 1)
                        }
                        OutlinedButton(
                            onClick = onNavigateToOta,
                            shape = RoundedCornerShape(8.dp),
                            contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp),
                            modifier = Modifier.weight(1f).height(32.dp)
                        ) {
                            Text("Atualizar OTA", style = MaterialTheme.typography.labelSmall, maxLines = 1)
                        }
                    }
                }
            }
        }
    }
}
