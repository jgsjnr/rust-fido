package dev.aegiskey.app.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bluetooth
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Computer
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Pin
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.TouchApp
import androidx.compose.material.icons.filled.Usb
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.R
import dev.aegiskey.app.data.debug.DebugHardwareChipMock
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.DiscoveredKeyCandidate
import dev.aegiskey.app.domain.model.OnboardingStep
import dev.aegiskey.app.security.RequestBlePermissionsEffect
import dev.aegiskey.app.security.rememberBlePermissionLauncher
import dev.aegiskey.app.ui.atomic.atoms.QuickActionPillButton
import dev.aegiskey.app.ui.atomic.molecules.PhysicalButtonPromptCardMolecule
import dev.aegiskey.app.ui.atomic.organisms.DebugChipControlHooksCard
import dev.aegiskey.app.ui.atomic.templates.WizardStepTemplate
import dev.aegiskey.app.ui.viewmodel.OnboardingWizardViewModel

/**
 * Friendly 5-step pairing wizard screen with persistent state across Bluetooth settings pairing,
 * 1-touch skip to Vault, automatic USB OTG detection, and simplified single-touch hardware button UX.
 */
@Composable
fun FriendlyOnboardingWizardScreen(
    viewModel: OnboardingWizardViewModel,
    onFinished: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val uiState by viewModel.uiState.collectAsState()

    // 2. Não reiniciar o Wizard ao sair e voltar do pareamento Bluetooth
    var savedStepName by rememberSaveable { mutableStateOf(uiState.currentStep.name) }
    var savedTransportName by rememberSaveable { mutableStateOf(uiState.selectedTransport.name) }

    LaunchedEffect(Unit) {
        runCatching {
            val restoredStep = OnboardingStep.valueOf(savedStepName)
            val restoredTransport = ConnectionTransportType.valueOf(savedTransportName)
            if (restoredStep != uiState.currentStep || restoredTransport != uiState.selectedTransport) {
                viewModel.restoreState(restoredStep, restoredTransport)
            }
        }
    }

    LaunchedEffect(uiState.currentStep, uiState.selectedTransport) {
        savedStepName = uiState.currentStep.name
        savedTransportName = uiState.selectedTransport.name
    }

    val requestBlePermissions = rememberBlePermissionLauncher { granted ->
        if (granted) {
            viewModel.refreshDiscovery()
        }
    }

    if (uiState.selectedTransport == ConnectionTransportType.BLE &&
        (uiState.currentStep == OnboardingStep.HOLD_PHYSICAL_BUTTON || uiState.currentStep == OnboardingStep.DISCOVER_AND_CONNECT)
    ) {
        RequestBlePermissionsEffect(
            onPermissionsResult = { granted ->
                if (granted) {
                    viewModel.refreshDiscovery()
                }
            }
        )
    }

    val stepNumber = uiState.currentStep.stepNumber
    val totalSteps = uiState.currentStep.totalSteps

    val stepTitle = when (uiState.currentStep) {
        OnboardingStep.WELCOME_TRANSPORT -> stringResource(R.string.wizard_title_transport)
        OnboardingStep.HOLD_PHYSICAL_BUTTON -> stringResource(R.string.wizard_title_hold)
        OnboardingStep.DISCOVER_AND_CONNECT -> stringResource(R.string.wizard_title_discover)
        OnboardingStep.TOUCH_AND_BIOMETRIC_BIND -> stringResource(R.string.wizard_title_bind)
        OnboardingStep.NAME_AND_FINISH -> stringResource(R.string.wizard_title_name)
    }

    val stepSubtitle = when (uiState.currentStep) {
        OnboardingStep.WELCOME_TRANSPORT -> stringResource(R.string.wizard_desc_transport)
        OnboardingStep.HOLD_PHYSICAL_BUTTON -> stringResource(R.string.wizard_desc_hold)
        OnboardingStep.DISCOVER_AND_CONNECT -> stringResource(R.string.wizard_desc_discover)
        OnboardingStep.TOUCH_AND_BIOMETRIC_BIND -> stringResource(R.string.onb_bind_hw_desc)
        OnboardingStep.NAME_AND_FINISH -> stringResource(R.string.wizard_desc_name)
    }

    val nextButtonText = when (uiState.currentStep) {
        OnboardingStep.NAME_AND_FINISH -> stringResource(R.string.wizard_btn_complete)
        else -> stringResource(R.string.wizard_btn_next)
    }

    val isNextLoading = uiState.isConnecting || uiState.isBinding

    WizardStepTemplate(
        currentStep = stepNumber,
        totalSteps = totalSteps,
        title = stepTitle,
        subtitle = stepSubtitle,
        nextButtonText = nextButtonText,
        isNextLoading = isNextLoading,
        onNextClick = {
            if (uiState.currentStep == OnboardingStep.WELCOME_TRANSPORT && uiState.selectedTransport == ConnectionTransportType.BLE) {
                requestBlePermissions()
                viewModel.nextStep()
            } else if (uiState.currentStep == OnboardingStep.NAME_AND_FINISH) {
                viewModel.completeWizardWithCustomName(
                    customName = uiState.keyAlias,
                    onCompleted = { onFinished() }
                )
            } else {
                viewModel.nextStep()
            }
        },
        onBackClick = if (stepNumber > 1) {
            { viewModel.previousStep() }
        } else null,
        modifier = modifier,
    ) {
        // 1. Botão no topo para Pular Configuração ou Conectar chave USB detectada
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            if (uiState.isUsbDetected) {
                Button(
                    onClick = { viewModel.connectUsbDeviceAndOpenVault(onFinished) },
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.tertiary),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(imageVector = Icons.Filled.Usb, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.onb_usb_open), fontWeight = FontWeight.Bold)
                }
            }

            OutlinedButton(
                onClick = { viewModel.skipOnboardingAndGoToVault(onFinished) },
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(imageVector = Icons.Filled.VpnKey, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(stringResource(R.string.onb_skip), fontWeight = FontWeight.SemiBold)
            }
        }

        Spacer(modifier = Modifier.height(6.dp))

        if (!uiState.errorMessage.isNullOrBlank()) {
            Surface(
                shape = RoundedCornerShape(12.dp),
                color = MaterialTheme.colorScheme.errorContainer,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Row(
                    modifier = Modifier.padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(
                        imageVector = Icons.Filled.ErrorOutline,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onErrorContainer,
                        modifier = Modifier.size(18.dp),
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(
                        text = uiState.errorMessage ?: "",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        }

        when (uiState.currentStep) {
            OnboardingStep.WELCOME_TRANSPORT -> {
                WelcomeTransportStepContent(
                    selectedTransport = uiState.selectedTransport,
                    isUsbDetected = uiState.isUsbDetected,
                    onSelectTransport = { viewModel.selectTransport(it) },
                    onSkipToVault = { viewModel.skipOnboardingAndGoToVault(onFinished) },
                    onConnectUsb = { viewModel.connectUsbDeviceAndOpenVault(onFinished) }
                )
            }
            OnboardingStep.HOLD_PHYSICAL_BUTTON -> {
                HoldPhysicalButtonStepContent(
                    selectedTransport = uiState.selectedTransport,
                    isSimulated = uiState.selectedTransport == ConnectionTransportType.SIMULATOR,
                    buttonHoldDetected = uiState.buttonHoldDetected,
                    onSimulateHold = { viewModel.simulateButtonHold5s() }
                )
            }
            OnboardingStep.DISCOVER_AND_CONNECT -> {
                DiscoverAndConnectStepContent(
                    selectedTransport = uiState.selectedTransport,
                    candidates = uiState.candidates,
                    selectedCandidate = uiState.selectedCandidate,
                    isScanning = uiState.isScanning,
                    onSelectCandidate = { viewModel.selectCandidateAndConnect(it) },
                    onUseSimulator = { viewModel.selectTransport(ConnectionTransportType.SIMULATOR) },
                    onRefresh = { viewModel.refreshDiscovery() }
                )
            }
            OnboardingStep.TOUCH_AND_BIOMETRIC_BIND -> {
                TouchAndBiometricBindStepContent(
                    isSimulated = uiState.selectedTransport == ConnectionTransportType.SIMULATOR,
                    buttonTouchDetected = uiState.buttonTouchDetected,
                    onSimulateTouch = { viewModel.simulateSingleButtonTouch() }
                )
            }
            OnboardingStep.NAME_AND_FINISH -> {
                NameAndFinishStepContent(
                    keyAlias = uiState.keyAlias,
                    recoveryPin = uiState.recoveryPin,
                    onKeyAliasChange = { viewModel.setKeyAlias(it) },
                    onRecoveryPinChange = { viewModel.setRecoveryPin(it) }
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))
        DebugChipControlHooksCard(
            onSimulateHold5s = { viewModel.simulateButtonHold5s() },
            onSimulateTouch = { viewModel.simulateSingleButtonTouch() },
        )
    }
}

@Suppress("UNUSED_PARAMETER")
@Composable
private fun WelcomeTransportStepContent(
    selectedTransport: ConnectionTransportType,
    isUsbDetected: Boolean,
    onSelectTransport: (ConnectionTransportType) -> Unit,
    onSkipToVault: () -> Unit,
    onConnectUsb: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        if (isUsbDetected) {
            Surface(
                shape = RoundedCornerShape(12.dp),
                color = MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.5f),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier.padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(imageVector = Icons.Filled.Usb, contentDescription = null, tint = MaterialTheme.colorScheme.tertiary, modifier = Modifier.size(20.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(stringResource(R.string.onb_usb_title), fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleSmall)
                        Text(stringResource(R.string.onb_usb_desc), style = MaterialTheme.typography.bodySmall)
                    }
                    Button(onClick = onConnectUsb, shape = RoundedCornerShape(8.dp)) {
                        Text(stringResource(R.string.onb_open_vault))
                    }
                }
            }
        }

        TransportOptionCard(
            title = stringResource(R.string.onb_transport_ble),
            description = stringResource(R.string.onb_transport_ble_desc),
            icon = Icons.Filled.Bluetooth,
            isSelected = selectedTransport == ConnectionTransportType.BLE,
            badgeText = stringResource(R.string.onb_transport_ble_badge),
            onSelect = { onSelectTransport(ConnectionTransportType.BLE) },
        )

        TransportOptionCard(
            title = stringResource(R.string.onb_transport_usb),
            description = stringResource(R.string.onb_transport_usb_desc),
            icon = Icons.Filled.Usb,
            isSelected = selectedTransport == ConnectionTransportType.USB,
            badgeText = stringResource(R.string.onb_transport_usb_badge),
            onSelect = { onSelectTransport(ConnectionTransportType.USB) },
        )

        TransportOptionCard(
            title = stringResource(R.string.onb_transport_wifi),
            description = stringResource(R.string.onb_transport_wifi_desc),
            icon = Icons.Filled.Wifi,
            isSelected = selectedTransport == ConnectionTransportType.WIFI,
            badgeText = stringResource(R.string.onb_transport_wifi_badge),
            onSelect = { onSelectTransport(ConnectionTransportType.WIFI) },
        )

        if (DebugHardwareChipMock.IS_MOCK_ENABLED) {
            TransportOptionCard(
                title = stringResource(R.string.onb_transport_sim),
                description = stringResource(R.string.onb_transport_sim_desc),
                icon = Icons.Filled.Computer,
                isSelected = selectedTransport == ConnectionTransportType.SIMULATOR,
                badgeText = stringResource(R.string.onb_transport_sim_badge),
                onSelect = { onSelectTransport(ConnectionTransportType.SIMULATOR) },
            )
        }
    }
}

@Composable
private fun HoldPhysicalButtonStepContent(
    selectedTransport: ConnectionTransportType,
    isSimulated: Boolean,
    buttonHoldDetected: Boolean,
    onSimulateHold: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        // 3. Explicação clara e real da função do botão físico BOOT (GPIO 0)
        Surface(
            shape = RoundedCornerShape(12.dp),
            color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.25f),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(imageVector = Icons.Filled.TouchApp, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(20.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.onb_boot_title), fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleSmall)
                }
                Text(
                    text = stringResource(R.string.onb_boot_desc),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        if (selectedTransport == ConnectionTransportType.USB) {
            Surface(
                shape = RoundedCornerShape(10.dp),
                color = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.45f),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(imageVector = Icons.Filled.CheckCircle, contentDescription = null, tint = MaterialTheme.colorScheme.secondary, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.onb_usb_otg), style = MaterialTheme.typography.bodySmall)
                }
            }
        } else {
            PhysicalButtonPromptCardMolecule(
                title = stringResource(R.string.onb_hold_btn),
                instruction = stringResource(R.string.onb_hold_instr),
                isLongPress = true,
                isSimulatedMode = isSimulated,
                onSimulateTouch = onSimulateHold,
            )
        }

        if (buttonHoldDetected) {
            Surface(
                shape = RoundedCornerShape(10.dp),
                color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Row(
                    modifier = Modifier.padding(10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(
                        imageVector = Icons.Filled.CheckCircle,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp),
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = stringResource(R.string.onb_activated),
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.Medium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        }
    }
}

@Composable
private fun DiscoverAndConnectStepContent(
    selectedTransport: ConnectionTransportType,
    candidates: List<DiscoveredKeyCandidate>,
    selectedCandidate: DiscoveredKeyCandidate?,
    isScanning: Boolean,
    onSelectCandidate: (DiscoveredKeyCandidate) -> Unit,
    onUseSimulator: () -> Unit,
    onRefresh: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.weight(1f),
            ) {
                if (isScanning) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(16.dp),
                        strokeWidth = 2.dp,
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                }
                Text(
                    text = if (isScanning) stringResource(R.string.onb_scanning) else stringResource(R.string.onb_discovered),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            QuickActionPillButton(
                text = stringResource(R.string.onb_refresh),
                icon = Icons.Filled.Refresh,
                onClick = onRefresh,
            )
        }

        if (selectedTransport == ConnectionTransportType.SIMULATOR) {
            Surface(
                shape = RoundedCornerShape(10.dp),
                color = MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.4f),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Row(
                    modifier = Modifier.padding(10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(
                        imageVector = Icons.Filled.Computer,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.tertiary,
                        modifier = Modifier.size(16.dp),
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = stringResource(R.string.onb_sim_active),
                        style = MaterialTheme.typography.bodySmall,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        }

        if (candidates.isEmpty() && !isScanning) {
            Surface(
                shape = RoundedCornerShape(12.dp),
                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        text = stringResource(R.string.onb_no_key),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        text = if (DebugHardwareChipMock.IS_MOCK_ENABLED) {
                            stringResource(R.string.onb_no_key_hint_mock)
                        } else {
                            stringResource(R.string.onb_no_key_hint)
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                    if (DebugHardwareChipMock.IS_MOCK_ENABLED) {
                        OutlinedButton(
                            onClick = onUseSimulator,
                            shape = RoundedCornerShape(10.dp),
                            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                            modifier = Modifier.height(34.dp),
                        ) {
                            Icon(imageVector = Icons.Filled.Computer, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = stringResource(R.string.onb_use_sim),
                                style = MaterialTheme.typography.labelSmall,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }
            }
        }

        candidates.forEach { candidate ->
            val isSelected = candidate.id == selectedCandidate?.id
            OutlinedCard(
                shape = RoundedCornerShape(12.dp),
                border = BorderStroke(
                    if (isSelected) 1.5.dp else 1.dp,
                    if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant,
                ),
                colors = CardDefaults.outlinedCardColors(
                    containerColor = if (isSelected) MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.2f) else MaterialTheme.colorScheme.surface,
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .clickable { onSelectCandidate(candidate) },
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = MaterialTheme.colorScheme.primaryContainer,
                        modifier = Modifier.size(32.dp),
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Icon(
                                imageVector = Icons.Filled.VpnKey,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.onPrimaryContainer,
                                modifier = Modifier.size(16.dp),
                            )
                        }
                    }

                    Spacer(modifier = Modifier.width(10.dp))

                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = candidate.name.ifBlank { stringResource(R.string.default_security_key_name) },
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Text(
                            text = stringResource(R.string.onb_tap_select),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }

                    if (isSelected) {
                        Icon(
                            imageVector = Icons.Filled.CheckCircle,
                            contentDescription = stringResource(R.string.cd_selected),
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(20.dp),
                        )
                    }
                }
            }
        }
    }
}

@Suppress("UNUSED_PARAMETER")
@Composable
private fun TouchAndBiometricBindStepContent(
    isSimulated: Boolean,
    buttonTouchDetected: Boolean,
    onSimulateTouch: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        // 3. Etapa 4 simplificada: Presença validada automaticamente via 0x2F
        Surface(
            shape = RoundedCornerShape(12.dp),
            color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.35f),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(modifier = Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Filled.CheckCircle,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(24.dp)
                )
                Spacer(modifier = Modifier.width(10.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.onb_presence_ok),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = stringResource(R.string.onb_presence_desc),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        Surface(
            shape = RoundedCornerShape(12.dp),
            color = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.25f),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Row(
                modifier = Modifier.padding(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = MaterialTheme.colorScheme.secondaryContainer,
                    modifier = Modifier.size(32.dp),
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(
                            imageVector = Icons.Filled.Fingerprint,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSecondaryContainer,
                            modifier = Modifier.size(18.dp),
                        )
                    }
                }
                Spacer(modifier = Modifier.width(10.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.onb_bind_title),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        text = stringResource(R.string.onb_bind_desc),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        }
    }
}

@Composable
private fun NameAndFinishStepContent(
    keyAlias: String,
    recoveryPin: String,
    onKeyAliasChange: (String) -> Unit,
    onRecoveryPinChange: (String) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        OutlinedTextField(
            value = keyAlias,
            onValueChange = onKeyAliasChange,
            label = { Text(stringResource(R.string.keys_name_label), maxLines = 1) },
            placeholder = { Text(stringResource(R.string.onb_name_hint), maxLines = 1) },
            leadingIcon = {
                Icon(imageVector = Icons.Filled.VpnKey, contentDescription = null, modifier = Modifier.size(18.dp))
            },
            singleLine = true,
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.fillMaxWidth(),
        )

        OutlinedTextField(
            value = recoveryPin,
            onValueChange = onRecoveryPinChange,
            label = { Text(stringResource(R.string.onb_pin_label), maxLines = 1) },
            placeholder = { Text(stringResource(R.string.onb_pin_hint), maxLines = 1) },
            leadingIcon = {
                Icon(imageVector = Icons.Filled.Pin, contentDescription = null, modifier = Modifier.size(18.dp))
            },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
            singleLine = true,
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.fillMaxWidth(),
        )

        Surface(
            shape = RoundedCornerShape(12.dp),
            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Row(
                modifier = Modifier.padding(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(
                    imageVector = Icons.Filled.Security,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(18.dp),
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = stringResource(R.string.onb_ready),
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}

@Composable
private fun TransportOptionCard(
    title: String,
    description: String,
    icon: ImageVector,
    isSelected: Boolean,
    onSelect: () -> Unit,
    badgeText: String? = null,
) {
    val borderColor = if (isSelected) {
        MaterialTheme.colorScheme.primary
    } else {
        MaterialTheme.colorScheme.outlineVariant
    }

    val containerColor = if (isSelected) {
        MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.2f)
    } else {
        MaterialTheme.colorScheme.surface
    }

    OutlinedCard(
        shape = RoundedCornerShape(14.dp),
        border = BorderStroke(if (isSelected) 1.5.dp else 1.dp, borderColor),
        colors = CardDefaults.outlinedCardColors(containerColor = containerColor),
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .clickable(onClick = onSelect),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Surface(
                shape = RoundedCornerShape(10.dp),
                color = if (isSelected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
                modifier = Modifier.size(36.dp),
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        imageVector = icon,
                        contentDescription = null,
                        tint = if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(18.dp),
                    )
                }
            }

            Spacer(modifier = Modifier.width(10.dp))

            Column(modifier = Modifier.weight(1f)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text(
                        text = title,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    if (badgeText != null) {
                        Surface(
                            shape = RoundedCornerShape(6.dp),
                            color = MaterialTheme.colorScheme.tertiaryContainer,
                        ) {
                            Text(
                                text = badgeText,
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onTertiaryContainer,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                modifier = Modifier.padding(horizontal = 5.dp, vertical = 1.dp),
                            )
                        }
                    }
                }
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}
