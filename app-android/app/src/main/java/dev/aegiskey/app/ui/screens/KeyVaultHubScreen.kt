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
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.HealthAndSafety
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CardDefaults
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.R
import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.ErrorLockedRecovery
import dev.aegiskey.app.domain.model.FirmwareVersion
import dev.aegiskey.app.domain.model.SecureGuardStateEnum
import dev.aegiskey.app.domain.model.HardwareDeviceDiagnostics
import dev.aegiskey.app.domain.model.VaultKeyEntry
import dev.aegiskey.app.touchpolicy.TouchPolicy
import dev.aegiskey.app.ui.atomic.molecules.VaultEntryCardMolecule
import dev.aegiskey.app.ui.atomic.organisms.DebugChipControlHooksCard
import dev.aegiskey.app.ui.atomic.organisms.KeyGenerationDialogOrganism
import dev.aegiskey.app.ui.atomic.organisms.SecureGuardCardOrganism
import dev.aegiskey.app.ui.atomic.organisms.HardwareSessionOperationType
import dev.aegiskey.app.ui.atomic.organisms.HardwareSessionPinPopupDialog
import androidx.compose.material.icons.filled.LockOpen
import dev.aegiskey.app.ui.viewmodel.KeyVaultViewModel
import dev.aegiskey.app.ui.viewmodel.SecureGuardViewModel

/**
 * Vault Hub Screen (Aba 1: Vault).
 * Exclusively responsible for Secure Guard Authority Card + Real Hardware Vault Keys & Wallets.
 * Standardized in ASD-STE100 technical English.
 */
@Suppress("UNUSED_PARAMETER")
@Composable
fun KeyVaultHubScreen(
    viewModel: KeyVaultViewModel,
    secureGuardViewModel: SecureGuardViewModel? = null,
    sessionTransport: ConnectionTransportType? = null,
    onNavigateToBackup: () -> Unit = {},
    onNavigateToOta: () -> Unit = {},
    onNavigateToPm: () -> Unit = {},
    modifier: Modifier = Modifier,
) {
    val uiState by viewModel.uiState.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }

    // Coletor único do SecureGuard (hoisted): um único collectAsState acima da
    // lista; os blocos abaixo recebem apenas valores simples. Evita recomposição
    // em cascata e refreshVault redundante por emissão.
    val sgUiState = if (secureGuardViewModel != null) {
        secureGuardViewModel.uiState.collectAsState().value
    } else {
        null
    }

    var showCreateDialog by remember { mutableStateOf(false) }
    var entryToDelete by remember { mutableStateOf<VaultKeyEntry?>(null) }
    var isDiagnosticsExpanded by remember { mutableStateOf(false) }

    LaunchedEffect(uiState.userMessage) {
        uiState.userMessage?.let {
            // Finding A3: key-gen success closes the sheet (it stayed open
            // while loading instead of closing silently on confirm).
            if (showCreateDialog && uiState.presenceRequest == null) showCreateDialog = false
            snackbarHostState.showSnackbar(it)
            viewModel.clearMessages()
        }
    }

    LaunchedEffect(uiState.errorMessage) {
        uiState.errorMessage?.let {
            // Finding A3: hard failures close the sheet; NEED_UP never lands
            // here (it keeps presenceRequest set and the sheet open).
            if (showCreateDialog && uiState.presenceRequest == null) showCreateDialog = false
            snackbarHostState.showSnackbar(it)
            viewModel.clearMessages()
        }
    }

    // Per-key touch outcome: structured result rendered via strings.xml
    // (PT+EN); NEED_PIN surfaces through the existing unlock flow.
    val touchAppliedOnText = stringResource(R.string.touch_on_ok)
    val touchAppliedOffText = stringResource(R.string.touch_off_ok)
    val touchNeedPinText = stringResource(R.string.touch_need_pin)
    val touchNoSlotText = stringResource(R.string.touch_no_slot)
    val touchFailFormat = stringResource(R.string.touch_fail)
    val guardLockedError = uiState.errorResId?.let { stringResource(it) }
    LaunchedEffect(guardLockedError) {
        guardLockedError?.let {
            // Click-through F4: fail-closed denial surfaces the localized
            // explanation; the sheet never opens while locked.
            if (showCreateDialog && uiState.presenceRequest == null) showCreateDialog = false
            snackbarHostState.showSnackbar(it)
            viewModel.clearMessages()
        }
    }
    LaunchedEffect(uiState.touchOutcome) {
        val outcome = uiState.touchOutcome ?: return@LaunchedEffect
        when (outcome) {
            is TouchPolicy.TouchOutcome.Applied ->
                snackbarHostState.showSnackbar(
                    if (outcome.requireTouch) touchAppliedOnText else touchAppliedOffText
                )
            TouchPolicy.TouchOutcome.NeedPin -> {
                snackbarHostState.showSnackbar(touchNeedPinText)
                secureGuardViewModel?.openUnlockPrompt()
            }
            TouchPolicy.TouchOutcome.NoSlot ->
                snackbarHostState.showSnackbar(touchNoSlotText)
            is TouchPolicy.TouchOutcome.Failed ->
                snackbarHostState.showSnackbar(touchFailFormat.format(outcome.label))
        }
        viewModel.consumeTouchOutcome()
    }

    // Auto-reload from hardware when key connects and Secure Guard is unlocked
    LaunchedEffect(uiState.isKeyConnected, uiState.isGuardUnlocked) {
        if (uiState.isKeyConnected && uiState.isGuardUnlocked) {
            viewModel.refreshVault()
        }
    }

    // Detail Screen when a specific key is selected
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
            touchRequired = uiState.selectedEntry!!.requiresPhysicalTouch,
            isTouchActionLoading = uiState.isTouchActionLoading,
            isGuardUnlocked = uiState.isGuardUnlocked,
            onTouchToggle = { requireTouch ->
                viewModel.setTouchRequired(uiState.selectedEntry!!.slotId, requireTouch)
            },
            onUnlockRequest = { secureGuardViewModel?.openUnlockPrompt() },
            modifier = modifier
        )
        return
    }

    // Category filter
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
            // 1. Secure Guard Authority Card
            if (secureGuardViewModel != null && sgUiState != null) {
                val sgState = sgUiState
                item {
                    SecureGuardCardOrganism(
                        uiState = sgState,
                        onProvision = { pin, rc, pol ->
                            secureGuardViewModel.provision(pin, rc, pol)
                            viewModel.refreshVault()
                        },
                        onUnlock = { pin ->
                            secureGuardViewModel.dismissUnlockPrompt()
                            secureGuardViewModel.unlock(pin)
                            viewModel.refreshVault()
                        },
                        onLock = {
                            secureGuardViewModel.lock()
                            viewModel.refreshVault()
                        },
                        onChangePin = { curr, next -> secureGuardViewModel.changePin(curr, next) },
                        onRecover = { rc, next -> secureGuardViewModel.recover(rc, next) },
                        onUpdatePolicy = { pol -> secureGuardViewModel.updatePolicy(pol) },
                        onWipeSelective = { scope, token ->
                            secureGuardViewModel.wipeSelective(scope, token)
                            viewModel.refreshVault()
                        },
                        onRefresh = {
                            secureGuardViewModel.refreshStatus()
                            viewModel.refreshVault()
                        },
                        modifier = Modifier.padding(bottom = 4.dp)
                    )
                }
            }

            // 2. Hardware Diagnostics Summary Panel
            item {
                HardwareManagerSummaryPanel(
                    diagnostics = uiState.hardwareDiagnostics,
                    totalOccupied = uiState.entries.size,
                    activeTransport = sessionTransport,
                    isExpanded = isDiagnosticsExpanded,
                    onToggleExpand = {
                        isDiagnosticsExpanded = !isDiagnosticsExpanded
                        if (isDiagnosticsExpanded) viewModel.loadHardwareDiagnostics()
                    },
                    onRunQuickCheck = { viewModel.runHealthCheck() },
                )
            }

            // 2b. Password vault viewer entry (F-PM2 blind transport).
            item {
                OutlinedButton(
                    onClick = onNavigateToPm,
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(46.dp),
                ) {
                    Text(
                        text = stringResource(R.string.vault_open_pm),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
            // 3. Primary Button: Generate New Key in Hardware (synchronized PIN prompt if session locked)
            // Click-through F4: fail-closed while LOCKED — the button is
            // disabled on connection alone; it enables only when the guard
            // session is unlocked, with the hint below explaining why.
            item {
                val canGenerate = uiState.isKeyConnected && uiState.isGuardUnlocked && !uiState.isLoading
                Button(
                    onClick = {
                        if (!uiState.isGuardUnlocked && secureGuardViewModel != null) {
                            secureGuardViewModel.openUnlockPrompt()
                        } else {
                            showCreateDialog = true
                        }
                    },
                    enabled = canGenerate,
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.primary,
                        contentColor = MaterialTheme.colorScheme.onPrimary,
                        disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant,
                        disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(46.dp),
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(imageVector = Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = stringResource(R.string.vault_btn_generate),
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
                if (uiState.isKeyConnected && !uiState.isGuardUnlocked) {
                    Text(
                        text = stringResource(R.string.vault_generate_locked_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 6.dp),
                    )
                }
            }

            // 4. Horizontal Category Filter Chips
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
                        label = { Text(stringResource(R.string.vault_filter_all, uiState.entries.size), style = MaterialTheme.typography.labelSmall) },
                        colors = FilterChipDefaults.filterChipColors()
                    )
                    FilterChip(
                        selected = uiState.selectedCategoryFilter == "PASSKEYS",
                        onClick = { viewModel.setCategoryFilter("PASSKEYS") },
                        label = { Text(stringResource(R.string.vault_filter_passkeys), style = MaterialTheme.typography.labelSmall) }
                    )
                    FilterChip(
                        selected = uiState.selectedCategoryFilter == "CRYPTO",
                        onClick = { viewModel.setCategoryFilter("CRYPTO") },
                        label = { Text(stringResource(R.string.vault_filter_crypto), style = MaterialTheme.typography.labelSmall) }
                    )
                    FilterChip(
                        selected = uiState.selectedCategoryFilter == "PIV",
                        onClick = { viewModel.setCategoryFilter("PIV") },
                        label = { Text(stringResource(R.string.vault_filter_piv), style = MaterialTheme.typography.labelSmall) }
                    )
                    FilterChip(
                        selected = uiState.selectedCategoryFilter == "AEGN",
                        onClick = { viewModel.setCategoryFilter("AEGN") },
                        label = { Text(stringResource(R.string.vault_filter_aegn), style = MaterialTheme.typography.labelSmall) }
                    )
                }
            }

            // 5. Responsive States: Disconnected vs Locked Guard vs Empty Hardware Vault vs Keys List
            if (!uiState.isKeyConnected) {
                // State 1: Key Disconnected
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
                                text = stringResource(R.string.vault_disconnected_title),
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                text = stringResource(R.string.vault_disconnected_desc),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }
            } else if (!uiState.isGuardUnlocked) {
                // State 2: Key Connected, BUT Secure Guard is LOCKED (Gatekeeper enforcement)
                item {
                    Surface(
                        shape = RoundedCornerShape(12.dp),
                        color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.25f),
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.error.copy(alpha = 0.5f)),
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
                                tint = MaterialTheme.colorScheme.error,
                                modifier = Modifier.size(32.dp),
                            )
                            Text(
                                text = stringResource(R.string.vault_guard_locked_title),
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.error,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                text = stringResource(R.string.vault_guard_locked_desc),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurface,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis,
                            )
                            if (secureGuardViewModel != null && sgUiState != null &&
                                !ErrorLockedRecovery.isErrorLocked(sgUiState.status.state)
                           ) {
                                Button(
                                    onClick = { secureGuardViewModel.openUnlockPrompt() },
                                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary),
                                    modifier = Modifier.padding(top = 4.dp)
                                ) {
                                    Icon(imageVector = Icons.Filled.LockOpen, contentDescription = null, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(stringResource(R.string.guard_btn_unlock_session))
                                }
                            }
                            if (sgUiState != null && ErrorLockedRecovery.isErrorLocked(sgUiState.status.state)) {
                                Text(
                                    text = stringResource(R.string.guard_error_locked_vault_hint),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.error,
                                    maxLines = 3,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                        }
                    }
                }
            } else if (filteredEntries.isEmpty() && !uiState.isLoading) {
                // State 3: Key Connected and Unlocked, but zero keys on hardware
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
                                text = stringResource(R.string.vault_empty_title),
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                text = stringResource(R.string.vault_empty_desc),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }
            } else {
                // State 4: List of verified Real Hardware Vault Keys
                items(filteredEntries, key = { it.slotId }) { entry ->
                    val typeLabel = when (entry.type) {
                        AccessKeyType.PASSKEY_FIDO -> "Passkey"
                        AccessKeyType.VENDOR_SIGNING_KEY -> "Vendor Key"
                        AccessKeyType.CRYPTO_WALLET_BTC -> "Bitcoin"
                        AccessKeyType.CRYPTO_WALLET_ETH -> "Ethereum"
                        AccessKeyType.CRYPTO_WALLET_SOL -> "Solana"
                        AccessKeyType.CRYPTO_WALLET_DOT -> "Polkadot"
                        AccessKeyType.PIV_SMARTCARD_SLOT -> "PIV Smartcard"
                        AccessKeyType.ENCRYPTED_AEGN_ENVELOPE -> "AEGN Envelope"
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
            }

            item {
                DebugChipControlHooksCard(
                    onInjectSampleData = { viewModel.injectMockKeysForDebug() },
                    onSimulatePing = { viewModel.runHealthCheck() },
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

    // Key Generation Dialog
    if (showCreateDialog) {
        KeyGenerationDialogOrganism(
            onDismissRequest = {
                // Finding A3: dismissing with a pending presence drops it.
                if (uiState.presenceRequest != null) viewModel.dismissPresenceRequest()
                showCreateDialog = false
            },
            onConfirm = { label, type, curve, extra ->
                // Finding A3: no optimistic close here; the outcome effects
                // above close the sheet on success/hard failure and keep it
                // open with the "touch the key" prompt on NEED_UP.
                viewModel.generateKey(label, type, curve, extra)
            },
            isLoading = uiState.isGeneratingKey,
            presenceRequest = uiState.presenceRequest,
            onRetryAfterPresence = { viewModel.retryPendingKeyGen() },
            isSimulatedMode = uiState.activeKey?.transportType == ConnectionTransportType.SIMULATOR,
            onSimulateTouch = { viewModel.simulateTouchIfNeeded() },
        )
    }

    // Delete Confirmation Dialog
    entryToDelete?.let { entry ->
        AlertDialog(
            onDismissRequest = { entryToDelete = null },
            shape = RoundedCornerShape(16.dp),
            title = {
                Text(
                    text = stringResource(R.string.vault_delete_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            },
            text = {
                Text(
                    text = stringResource(R.string.vault_delete_confirm_msg, entry.label),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        viewModel.deleteKey(entry.slotId)
                        entryToDelete = null
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                        contentColor = MaterialTheme.colorScheme.onError,
                    ),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.height(38.dp),
                ) {
                    Text(stringResource(R.string.vault_delete_btn), maxLines = 1)
                }
            },
            dismissButton = {
                TextButton(onClick = { entryToDelete = null }) {
                    Text(stringResource(R.string.vault_cancel_btn), maxLines = 1)
                }
            },
        )
    }

    // Modal Popup de PIN por Sessão Sincronizada com a Hardwallet
    if (secureGuardViewModel != null && sgUiState != null) {
        val sgState = sgUiState
        LaunchedEffect(sgState.status.isUnlocked, sgState.status.state) {
            if (sgState.status.isUnlocked || sgState.status.state == dev.aegiskey.app.domain.model.SecureGuardStateEnum.UNLOCKED) {
                secureGuardViewModel.dismissUnlockPrompt()
                viewModel.refreshVault()
            }
        }

        if (sgState.isUnlockPromptOpen) {
            HardwareSessionPinPopupDialog(
                isOpen = true,
                status = sgState.status,
                operationType = HardwareSessionOperationType.UNLOCK_SESSION,
                isLoading = sgState.isLoading,
                errorMessage = sgState.errorMessage,
                onDismissRequest = { secureGuardViewModel.dismissUnlockPrompt() },
                onConfirmPin = { pin, _ ->
                    secureGuardViewModel.dismissUnlockPrompt()
                    secureGuardViewModel.unlock(pin)
                }
            )
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
) {
    // Click-through F7: single source of truth — device-reported wins,
    // app version is the documented fallback (never a stale per-screen
    // default). Slots derive from FirmwareVersion.MAX_SLOTS (32).
    val fwVersion = FirmwareVersion.resolve(diagnostics?.firmwareVersion)
    val channel = when (activeTransport) {
        ConnectionTransportType.BLE -> stringResource(R.string.transport_ble)
        ConnectionTransportType.USB -> stringResource(R.string.transport_usb)
        ConnectionTransportType.WIFI -> stringResource(R.string.transport_wifi)
        ConnectionTransportType.SIMULATOR -> stringResource(R.string.transport_simulator)
        null -> stringResource(R.string.transport_unknown)
    }
    val freeSlots = diagnostics?.freeSlotsRemaining ?: FirmwareVersion.freeSlots(totalOccupied)

    OutlinedCard(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.outlinedCardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            // Header Row: title on left with weight(1f), fwVersion on right
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .weight(1f)
                        .padding(end = 8.dp)
                ) {
                    Icon(
                        imageVector = Icons.Filled.Memory,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = stringResource(R.string.vault_hardware_status_title),
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
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = stringResource(R.string.vault_channel_slots, channel, totalOccupied, freeSlots),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }

            val curvesText = diagnostics?.fido2SupportedCurves?.joinToString(", ") ?: "Ed25519, ES256, ES384, ES512, ES256K"
            Text(
                text = stringResource(R.string.vault_supported_curves, curvesText),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )

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
                        text = if (isExpanded) stringResource(R.string.vault_hide_diagnostics) else stringResource(R.string.vault_show_diagnostics),
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
                                text = stringResource(
                                    R.string.vault_diag_health,
                                    diagnostics?.healthStatusText ?: stringResource(R.string.vault_diag_health_ok)
                                ),
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Medium
                            )
                            Text(
                                text = stringResource(
                                    R.string.vault_diag_piv,
                                    diagnostics?.pivSlotsAvailable?.joinToString() ?: stringResource(R.string.vault_diag_piv_ok)
                                ),
                                style = MaterialTheme.typography.labelSmall
                            )
                            Text(
                                text = stringResource(
                                    R.string.vault_diag_pin,
                                    if (diagnostics?.isPinConfigured == true) stringResource(R.string.vault_diag_pin_ok) else stringResource(R.string.vault_diag_pin_default)
                                ),
                                style = MaterialTheme.typography.labelSmall
                            )
                            Text(
                                text = stringResource(
                                    R.string.vault_diag_bind,
                                    if (diagnostics?.isBoundToThisPhone == true) stringResource(R.string.vault_diag_bound) else stringResource(R.string.vault_diag_unbound)
                                ),
                                style = MaterialTheme.typography.labelSmall
                            )
                            Text(
                                text = stringResource(R.string.keepassxc_slot_status),
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.primary,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = stringResource(R.string.keepassxc_jit_zeroize),
                                style = MaterialTheme.typography.labelSmall
                            )
                            Text(
                                text = stringResource(R.string.keepassxc_crypto_ready),
                                style = MaterialTheme.typography.labelSmall
                            )
                            Text(
                                text = stringResource(R.string.keepassxc_psram_status),
                                style = MaterialTheme.typography.labelSmall
                            )
                        }
                    }

                    OutlinedButton(
                        onClick = onRunQuickCheck,
                        shape = RoundedCornerShape(10.dp),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                        modifier = Modifier.fillMaxWidth().height(34.dp)
                    ) {
                        Icon(imageVector = Icons.Filled.HealthAndSafety, contentDescription = null, modifier = Modifier.size(14.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(stringResource(R.string.vault_quick_check), style = MaterialTheme.typography.labelSmall)
                    }
                }
            }
        }
    }
}
