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
import dev.aegiskey.app.ui.viewmodel.OobArmState

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
        OnboardingStep.OOB_AUTO_EXCHANGE -> stringResource(R.string.wizard_title_oob)
        OnboardingStep.TOUCH_AND_BIOMETRIC_BIND -> stringResource(R.string.wizard_title_bind)
        OnboardingStep.NAME_AND_FINISH -> stringResource(R.string.wizard_title_name)
    }

    val stepSubtitle = when (uiState.currentStep) {
        OnboardingStep.WELCOME_TRANSPORT -> stringResource(R.string.wizard_desc_transport)
        OnboardingStep.HOLD_PHYSICAL_BUTTON -> stringResource(R.string.wizard_desc_hold)
        OnboardingStep.DISCOVER_AND_CONNECT -> stringResource(R.string.wizard_desc_discover)
        OnboardingStep.OOB_AUTO_EXCHANGE -> stringResource(R.string.wizard_desc_oob)
        OnboardingStep.TOUCH_AND_BIOMETRIC_BIND -> stringResource(R.string.onb_bind_hw_desc)
        OnboardingStep.NAME_AND_FINISH -> stringResource(R.string.wizard_desc_name)
    }

    val nextButtonText = when (uiState.currentStep) {
        OnboardingStep.NAME_AND_FINISH -> stringResource(R.string.wizard_btn_complete)
        else -> stringResource(R.string.wizard_btn_next)
    }

    val isNextLoading = uiState.isConnecting || uiState.isBinding ||
        uiState.oobArmState == OobArmState.Arming

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

        if (!uiState.errorMessage.isNullOrBlank() || uiState.errorResId != null) {
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
                        text = uiState.errorResId?.let { resId ->
                            val args = uiState.errorArgs
                            if (args.isEmpty()) stringResource(resId)
                            else stringResource(resId, args.joinToString("; "))
                        } ?: uiState.errorMessage ?: "",
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
            OnboardingStep.OOB_AUTO_EXCHANGE -> {
                OobAutoExchangeStepContent(
                    oobArmState = uiState.oobArmState,
                    onExchange = { viewModel.armOobExchange() }
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

