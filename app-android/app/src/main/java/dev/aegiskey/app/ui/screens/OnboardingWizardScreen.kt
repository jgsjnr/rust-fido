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
import androidx.compose.material.icons.filled.Usb
import androidx.compose.material.icons.filled.VpnKey
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
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
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

@Composable
fun OnboardingWizardScreen(
    viewModel: OnboardingWizardViewModel,
    onFinished: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val uiState by viewModel.uiState.collectAsState()

    // Launcher interativo de permissões BLE
    val requestBlePermissions = rememberBlePermissionLauncher { granted ->
        if (granted) {
            viewModel.refreshDiscovery()
        }
    }

    // Solicita permissões de Bluetooth Runtime no Android 12+ (API 31+) durante descoberta
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
        OnboardingStep.WELCOME_TRANSPORT -> "Conecte Sua Chave"
        OnboardingStep.HOLD_PHYSICAL_BUTTON -> "Ativar Sua AegisKey"
        OnboardingStep.DISCOVER_AND_CONNECT -> "Localizar e Parear"
        OnboardingStep.TOUCH_AND_BIOMETRIC_BIND -> "Confirmar Presença"
        OnboardingStep.NAME_AND_FINISH -> "Nomear Sua Chave"
    }

    val stepSubtitle = when (uiState.currentStep) {
        OnboardingStep.WELCOME_TRANSPORT -> "Escolha a forma mais conveniente para ligar sua chave ao celular."
        OnboardingStep.HOLD_PHYSICAL_BUTTON -> "Segure o botão físico para colocar a chave no modo de descoberta."
        OnboardingStep.DISCOVER_AND_CONNECT -> "Selecione sua chave na lista para conectar com segurança."
        OnboardingStep.TOUCH_AND_BIOMETRIC_BIND -> "Dê um toque no botão da chave e autorize o vínculo com a biometria."
        OnboardingStep.NAME_AND_FINISH -> "Defina um nome amigável e conclua a configuração do seu cofre."
    }

    val nextButtonText = when (uiState.currentStep) {
        OnboardingStep.NAME_AND_FINISH -> "Concluir e Abrir"
        else -> "Próximo"
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
                viewModel.performBiometricBinding(
                    alias = uiState.keyAlias,
                    recoveryPin = uiState.recoveryPin.ifBlank { null },
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
        // Mensagem de erro compacta caso exista
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
                    onSelectTransport = { viewModel.selectTransport(it) }
                )
            }
            OnboardingStep.HOLD_PHYSICAL_BUTTON -> {
                HoldPhysicalButtonStepContent(
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

@Composable
private fun WelcomeTransportStepContent(
    selectedTransport: ConnectionTransportType,
    onSelectTransport: (ConnectionTransportType) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        TransportOptionCard(
            title = "Bluetooth Sem Fio",
            description = "Conexão prática e sem fios para o dia a dia.",
            icon = Icons.Filled.Bluetooth,
            isSelected = selectedTransport == ConnectionTransportType.BLE,
            badgeText = "Recomendado",
            onSelect = { onSelectTransport(ConnectionTransportType.BLE) },
        )

        TransportOptionCard(
            title = "Cabo USB",
            description = "Conecte sua chave diretamente à porta USB do aparelho.",
            icon = Icons.Filled.Usb,
            isSelected = selectedTransport == ConnectionTransportType.USB,
            onSelect = { onSelectTransport(ConnectionTransportType.USB) },
        )

        TransportOptionCard(
            title = "Simulador Virtual (Renode / Teste)",
            description = "Permite testar funções mesmo sem ter a chave física.",
            icon = Icons.Filled.Computer,
            isSelected = selectedTransport == ConnectionTransportType.SIMULATOR,
            badgeText = "Teste",
            onSelect = { onSelectTransport(ConnectionTransportType.SIMULATOR) },
        )
    }
}

@Composable
private fun HoldPhysicalButtonStepContent(
    isSimulated: Boolean,
    buttonHoldDetected: Boolean,
    onSimulateHold: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        PhysicalButtonPromptCardMolecule(
            title = "Segure o botão da chave",
            instruction = "Pressione e segure o botão físico por ~5 segundos até a luz começar a piscar suavemente.",
            isLongPress = true,
            isSimulatedMode = isSimulated,
            onSimulateTouch = onSimulateHold,
        )

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
                        text = "Sinal de ativação recebido! Clique em Próximo para continuar.",
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
        // Barra de Ação de Busca com Botão Compacto "Atualizar busca"
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
                    text = if (isScanning) "Buscando dispositivos..." else "Dispositivos encontrados:",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            QuickActionPillButton(
                text = "Atualizar busca",
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
                        text = "Modo Simulador ativo: chave virtual conectada automaticamente.",
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
                        text = "Nenhuma chave física encontrada no momento.",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        text = "Verifique se o botão foi pressionado ou teste com a chave virtual.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                    OutlinedButton(
                        onClick = onUseSimulator,
                        shape = RoundedCornerShape(10.dp),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                        modifier = Modifier.height(34.dp),
                    ) {
                        Icon(imageVector = Icons.Filled.Computer, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "Usar Simulador de Teste",
                            style = MaterialTheme.typography.labelSmall,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
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
                            text = candidate.name.ifBlank { "AegisKey" },
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Text(
                            text = "Toque para selecionar",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }

                    if (isSelected) {
                        Icon(
                            imageVector = Icons.Filled.CheckCircle,
                            contentDescription = "Selecionada",
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(20.dp),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun TouchAndBiometricBindStepContent(
    isSimulated: Boolean,
    buttonTouchDetected: Boolean,
    onSimulateTouch: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        PhysicalButtonPromptCardMolecule(
            title = "Dê 1 toque rápido na chave",
            instruction = "Pressione o botão físico uma vez para confirmar que está com o dispositivo.",
            isLongPress = false,
            isSimulatedMode = isSimulated,
            onSimulateTouch = onSimulateTouch,
        )

        if (buttonTouchDetected) {
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
                        text = "Toque confirmado! Clique em Próximo para continuar.",
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.Medium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
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
                        text = "Vínculo Seguro com Este Celular",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        text = "Seu celular criará uma chave de proteção no KeyStore.",
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
            label = { Text("Nome da chave", maxLines = 1) },
            placeholder = { Text("Ex: Minha Chave Principal", maxLines = 1) },
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
            label = { Text("Código de Recuperação (Opcional)", maxLines = 1) },
            placeholder = { Text("4 a 6 dígitos numéricos", maxLines = 1) },
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
                    text = "Pronto! Sua chave estará conectada e protegida para uso imediato.",
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}
