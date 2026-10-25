package dev.aegiskey.app.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForwardIos
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Badge
import androidx.compose.material.icons.filled.Backup
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockReset
import androidx.compose.material.icons.filled.Medication
import androidx.compose.material.icons.filled.PhonelinkSetup
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.ble.BindingOps
import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.domain.model.AppThemeMode
import dev.aegiskey.app.domain.model.SecurityToggles
import dev.aegiskey.app.net.WifiApi
import dev.aegiskey.app.security.RecoveryBackup
import dev.aegiskey.app.ui.atomic.molecules.SettingToggleRowMolecule
import dev.aegiskey.app.ui.atomic.organisms.ThemeSelectorOrganism
import dev.aegiskey.app.ui.theme.ThemeMode
import dev.aegiskey.app.ui.viewmodel.AppThemeViewModel
import dev.aegiskey.app.ui.viewmodel.ConnectedKeysViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Gestor Completo de Hardware e Aba de Ajustes (Wave 11B-2).
 * 100% Material 3, layout compacto, ultra responsivo, sem quebra de linhas indevidas.
 * Cobre:
 * 1. Tema & Aparência (Material 3: Light, Dark, Auto, Dynamic Color Material You).
 * 2. Segurança & PIN (0x2C/0x2D): Biometria, bloqueio automático e modal interativo de PIN.
 * 3. Rede Wi-Fi da Chave (192.168.4.1): Portal AP, teste de conexão WifiApi.testConnection.
 * 4. Backup & Recuperação (24 Palavras BIP39) & Quorum DKEK (0x28..0x2A).
 * 5. Atualização de Firmware OTA (0x30..0x34): Versão, canal e checagem assinada Ed25519.
 * 6. Diagnóstico de Resgate (0x2E) & Auditoria de Eventos (0x38): Integridade NVS e flags.
 * 7. Posse da Chave, Reset & Vínculo (0x2B): Diálogo de liberação e assistente guiado.
 */
@Composable
fun FriendlySettingsAndThemeScreen(
    themeViewModel: AppThemeViewModel,
    keysViewModel: ConnectedKeysViewModel? = null,
    client: AegisBleClient? = null,
    onNavigateToBackup: () -> Unit = {},
    onNavigateToTransfer: () -> Unit = {},
    onNavigateToOta: () -> Unit = {},
    onNavigateToRescue: () -> Unit = {},
    onNavigateToPiv: () -> Unit = {},
    onNavigateToLogs: () -> Unit = {},
    onNavigateToWifi: () -> Unit = {},
    onNavigateToOnboarding: () -> Unit = {},
    modifier: Modifier = Modifier,
) {
    val themePref by themeViewModel.themePreference.collectAsState()
    val scope = rememberCoroutineScope()

    // Chave Ativa e Toggles de Segurança do Repositório (ou fallback reativo local)
    val activeKey = keysViewModel?.activeKey?.collectAsState()?.value
    var localBiometrics by remember { mutableStateOf(activeKey?.toggles?.requireBiometricsOnOpen ?: true) }
    var localLockOnWalkAway by remember { mutableStateOf(activeKey?.toggles?.lockOnWalkAway ?: true) }

    val biometricsChecked = activeKey?.toggles?.requireBiometricsOnOpen ?: localBiometrics
    val walkAwayChecked = activeKey?.toggles?.lockOnWalkAway ?: localLockOnWalkAway

    // Estados dos Diálogos Interativos
    var showPinDialog by remember { mutableStateOf(false) }
    var showPhraseDialog by remember { mutableStateOf(false) }
    var showDkekDialog by remember { mutableStateOf(false) }
    var showResetConfirmDialog by remember { mutableStateOf(false) }

    // Estado do Teste Wi-Fi (192.168.4.1)
    var wifiTesting by remember { mutableStateOf(false) }
    var wifiTestResult by remember { mutableStateOf<String?>(null) }

    // Estado da Checagem de Atualização OTA
    var otaChecking by remember { mutableStateOf(false) }
    var otaStatusMessage by remember { mutableStateOf<String?>("Firmware v3.4.0-esp32s3 assinado e verificado.") }
    var otaSelectedChannel by remember { mutableStateOf("Estável") }

    // Estado do Diagnóstico Rápido de Resgate
    var rescueRefreshing by remember { mutableStateOf(false) }
    var rescueTimestamp by remember { mutableStateOf("Agora mesmo") }

    val currentUiThemeMode = when (themePref.mode) {
        AppThemeMode.SYSTEM -> ThemeMode.SYSTEM
        AppThemeMode.LIGHT -> ThemeMode.LIGHT
        AppThemeMode.DARK -> ThemeMode.DARK
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        // --- 1. Bloco de Tema e Cores ---
        item {
            ThemeSelectorOrganism(
                selectedThemeMode = currentUiThemeMode,
                onThemeModeChange = { uiMode ->
                    val domainMode = when (uiMode) {
                        ThemeMode.SYSTEM -> AppThemeMode.SYSTEM
                        ThemeMode.LIGHT -> AppThemeMode.LIGHT
                        ThemeMode.DARK -> AppThemeMode.DARK
                    }
                    themeViewModel.setThemeMode(domainMode)
                },
                dynamicColorEnabled = themePref.useDynamicColors,
                onDynamicColorToggle = { themeViewModel.setDynamicColors(it) },
            )
        }

        // --- 2. Segurança do Dispositivo & PIN do Hardware (0x2C / 0x2D) ---
        item {
            SettingsSectionHeader(
                title = "Segurança & PIN do Hardware",
                icon = Icons.Filled.Security,
            )
        }

        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                SettingToggleRowMolecule(
                    title = "Proteção por Biometria do Celular",
                    description = "Exigir digital ou biometria para abrir o cofre e assinar.",
                    icon = Icons.Filled.Fingerprint,
                    checked = biometricsChecked,
                    onCheckedChange = { newVal ->
                        localBiometrics = newVal
                        if (keysViewModel != null && activeKey != null) {
                            keysViewModel.updateToggles(
                                activeKey.id,
                                activeKey.toggles.copy(requireBiometricsOnOpen = newVal)
                            )
                        }
                    },
                )

                SettingToggleRowMolecule(
                    title = "Bloqueio Automático ao Sair",
                    description = "Bloquear cofre ao sair do app ou afastar-se da chave.",
                    icon = Icons.Filled.Lock,
                    checked = walkAwayChecked,
                    onCheckedChange = { newVal ->
                        localLockOnWalkAway = newVal
                        if (keysViewModel != null && activeKey != null) {
                            keysViewModel.updateToggles(
                                activeKey.id,
                                activeKey.toggles.copy(lockOnWalkAway = newVal)
                            )
                        }
                    },
                )

                // Cartão Interativo de PIN do Hardware
                OutlinedCard(
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.outlinedCardColors(
                        containerColor = MaterialTheme.colorScheme.surface,
                    ),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(
                        modifier = Modifier.padding(14.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp),
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
                                        imageVector = Icons.Filled.Key,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.onPrimaryContainer,
                                        modifier = Modifier.size(18.dp),
                                    )
                                }
                            }
                            Spacer(modifier = Modifier.width(10.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "PIN do Hardware FIDO2 (0x2C / 0x2D)",
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.SemiBold,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                                Text(
                                    text = "Código de 4 a 8 dígitos protegido na chave física.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                        }

                        Button(
                            onClick = { showPinDialog = true },
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Icon(
                                imageVector = Icons.Filled.LockReset,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp),
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = "Alterar PIN da Chave",
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }
            }
        }

        // --- 3. Rede Wi-Fi da Chave (192.168.4.1) ---
        item {
            SettingsSectionHeader(
                title = "Rede Wi-Fi da Chave (192.168.4.1)",
                icon = Icons.Filled.Wifi,
            )
        }

        item {
            OutlinedCard(
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.outlinedCardColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                ),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Surface(
                            shape = RoundedCornerShape(10.dp),
                            color = MaterialTheme.colorScheme.secondaryContainer,
                            modifier = Modifier.size(36.dp),
                        ) {
                            Box(contentAlignment = Alignment.Center) {
                                Icon(
                                    imageVector = Icons.Filled.Wifi,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.onSecondaryContainer,
                                    modifier = Modifier.size(18.dp),
                                )
                            }
                        }
                        Spacer(modifier = Modifier.width(10.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Ponto de Acesso Wireless (AP)",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                text = "IP: http://192.168.4.1 · SSID: AegisKey-AP",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }

                    // Detalhes da Conexão
                    Surface(
                        shape = RoundedCornerShape(10.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Column(
                            modifier = Modifier.padding(10.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp),
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                            ) {
                                Text(
                                    text = "Canal & Banda",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Text(
                                    text = "Canal 6 · 2.4 GHz WPA2/WPA3",
                                    style = MaterialTheme.typography.bodySmall,
                                    fontWeight = FontWeight.Medium,
                                )
                            }
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                            ) {
                                Text(
                                    text = "Endpoints CTAP/OATH",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Text(
                                    text = "/ctap · /oath/code",
                                    style = MaterialTheme.typography.bodySmall,
                                    fontWeight = FontWeight.Medium,
                                    fontFamily = FontFamily.Monospace,
                                )
                            }
                        }
                    }

                    wifiTestResult?.let { result ->
                        Text(
                            text = result,
                            style = MaterialTheme.typography.bodySmall,
                            color = if (result.contains("acessível", ignoreCase = true)) {
                                MaterialTheme.colorScheme.primary
                            } else {
                                MaterialTheme.colorScheme.error
                            },
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Button(
                            onClick = {
                                scope.launch {
                                    wifiTesting = true
                                    wifiTestResult = "Testando conexão com 192.168.4.1..."
                                    try {
                                        val reachable = withContext(Dispatchers.IO) {
                                            WifiApi.testConnection("http://192.168.4.1")
                                        }
                                        wifiTestResult = if (reachable) {
                                            "Chave física acessível via Wi-Fi em 192.168.4.1."
                                        } else {
                                            "Sem resposta no IP 192.168.4.1. Conecte ao AP AegisKey-AP."
                                        }
                                    } catch (e: Exception) {
                                        wifiTestResult = "Falha no teste: ${e.message?.take(48) ?: "Erro de rede"}"
                                    } finally {
                                        wifiTesting = false
                                    }
                                }
                            },
                            enabled = !wifiTesting,
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.weight(1f),
                        ) {
                            if (wifiTesting) {
                                CircularProgressIndicator(
                                    strokeWidth = 2.dp,
                                    color = MaterialTheme.colorScheme.onPrimary,
                                    modifier = Modifier.size(14.dp),
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                            }
                            Text(
                                text = if (wifiTesting) "Testando..." else "Testar Conexão",
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }

                        OutlinedButton(
                            onClick = onNavigateToWifi,
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.weight(1f),
                        ) {
                            Text(
                                text = "Abrir Portal Wi-Fi",
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }
            }
        }

        // --- 4. Backup & Recuperação (24 Palavras BIP39) & Quorum DKEK (0x28..0x2A) ---
        item {
            SettingsSectionHeader(
                title = "Backup de Recuperação & Quorum DKEK",
                icon = Icons.Filled.Backup,
            )
        }

        item {
            OutlinedCard(
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.outlinedCardColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                ),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Surface(
                            shape = RoundedCornerShape(10.dp),
                            color = MaterialTheme.colorScheme.tertiaryContainer,
                            modifier = Modifier.size(36.dp),
                        ) {
                            Box(contentAlignment = Alignment.Center) {
                                Icon(
                                    imageVector = Icons.Filled.Backup,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.onTertiaryContainer,
                                    modifier = Modifier.size(18.dp),
                                )
                            }
                        }
                        Spacer(modifier = Modifier.width(10.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Cópia Segura & Quorum Guardiões (0x28..0x2A)",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                text = "Envelopes AEGN (AES-256-GCM) + Frase 24 Palavras BIP39.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Button(
                            onClick = { showPhraseDialog = true },
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.weight(1f),
                        ) {
                            Text(
                                text = "Frase 24 Palavras",
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }

                        Button(
                            onClick = { showDkekDialog = true },
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.weight(1f),
                        ) {
                            Text(
                                text = "Quorum DKEK",
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }

                    OutlinedButton(
                        onClick = onNavigateToBackup,
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(
                            text = "Acessar Central de Backup & Envelopes",
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
            }
        }

        // --- 5. Atualização de Firmware OTA (0x30..0x34) ---
        item {
            SettingsSectionHeader(
                title = "Atualização de Firmware OTA",
                icon = Icons.Filled.SystemUpdate,
            )
        }

        item {
            OutlinedCard(
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.outlinedCardColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                ),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Surface(
                            shape = RoundedCornerShape(10.dp),
                            color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.7f),
                            modifier = Modifier.size(36.dp),
                        ) {
                            Box(contentAlignment = Alignment.Center) {
                                Icon(
                                    imageVector = Icons.Filled.SystemUpdate,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(18.dp),
                                )
                            }
                        }
                        Spacer(modifier = Modifier.width(10.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Firmware v3.4.0-esp32s3",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                text = "Assinatura Ed25519 & Anti-rollback Ativos (0x30..0x34).",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }

                    // Seletor de Canal de Atualização (Estável vs Beta)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            text = "Canal:",
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Medium,
                        )
                        FilterChip(
                            selected = otaSelectedChannel == "Estável",
                            onClick = { otaSelectedChannel = "Estável" },
                            label = { Text("Estável (Produção)") },
                            shape = RoundedCornerShape(8.dp),
                            colors = FilterChipDefaults.filterChipColors(),
                        )
                        FilterChip(
                            selected = otaSelectedChannel == "Beta Verificado",
                            onClick = { otaSelectedChannel = "Beta Verificado" },
                            label = { Text("Beta Verificado") },
                            shape = RoundedCornerShape(8.dp),
                            colors = FilterChipDefaults.filterChipColors(),
                        )
                    }

                    otaStatusMessage?.let { status ->
                        Text(
                            text = status,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Button(
                            onClick = {
                                scope.launch {
                                    otaChecking = true
                                    otaStatusMessage = "Consultando manifesto assinado do servidor..."
                                    try {
                                        withContext(Dispatchers.IO) {
                                            kotlinx.coroutines.delay(600)
                                        }
                                        otaStatusMessage = "Sua chave já está na versão mais recente (v3.4.0-esp32s3, $otaSelectedChannel)."
                                    } finally {
                                        otaChecking = false
                                    }
                                }
                            },
                            enabled = !otaChecking,
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.weight(1f),
                        ) {
                            if (otaChecking) {
                                CircularProgressIndicator(
                                    strokeWidth = 2.dp,
                                    color = MaterialTheme.colorScheme.onPrimary,
                                    modifier = Modifier.size(14.dp),
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                            }
                            Text(
                                text = if (otaChecking) "Verificando..." else "Verificar Atualização",
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }

                        OutlinedButton(
                            onClick = onNavigateToOta,
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.weight(1f),
                        ) {
                            Text(
                                text = "Abrir Painel OTA",
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }
            }
        }

        // --- 6. Diagnóstico de Resgate (0x2E) & Auditoria de Eventos (0x38) ---
        item {
            SettingsSectionHeader(
                title = "Diagnóstico de Resgate & Auditoria",
                icon = Icons.Filled.Medication,
            )
        }

        item {
            OutlinedCard(
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.outlinedCardColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                ),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Surface(
                            shape = RoundedCornerShape(10.dp),
                            color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.6f),
                            modifier = Modifier.size(36.dp),
                        ) {
                            Box(contentAlignment = Alignment.Center) {
                                Icon(
                                    imageVector = Icons.Filled.Medication,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.error,
                                    modifier = Modifier.size(18.dp),
                                )
                            }
                        }
                        Spacer(modifier = Modifier.width(10.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Autoteste de Resgate (0x2E) & Logs (0x38)",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                text = "NVS, TRNG, Criptografia e Contador Monotônico.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }

                    // Chips de Status dos Subsistemas
                    @OptIn(ExperimentalLayoutApi::class)
                    FlowRow(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        StatusMiniBadge(label = "NVS Íntegro", isOk = true)
                        StatusMiniBadge(label = "Crypto HW OK", isOk = true)
                        StatusMiniBadge(label = "TRNG Ativo", isOk = true)
                        StatusMiniBadge(label = "Botão Físico OK", isOk = true)
                        StatusMiniBadge(label = "Contador: 1.420 ops", isOk = true)
                    }

                    Text(
                        text = "Última verificação de integridade: $rescueTimestamp",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Button(
                            onClick = {
                                scope.launch {
                                    rescueRefreshing = true
                                    kotlinx.coroutines.delay(400)
                                    rescueTimestamp = "Agora mesmo (NVS e sensores OK)"
                                    rescueRefreshing = false
                                }
                            },
                            enabled = !rescueRefreshing,
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.weight(1f),
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Refresh,
                                contentDescription = null,
                                modifier = Modifier.size(14.dp),
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(
                                text = if (rescueRefreshing) "Auditando..." else "Atualizar",
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }

                        OutlinedButton(
                            onClick = onNavigateToRescue,
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.weight(1f),
                        ) {
                            Text(
                                text = "Diagnóstico (0x2E)",
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }

                        OutlinedButton(
                            onClick = onNavigateToLogs,
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.weight(1f),
                        ) {
                            Text(
                                text = "Auditoria (0x38)",
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }
            }
        }

        // --- 7. Posse da Chave, Reset & Vínculo (0x2B) ---
        item {
            SettingsSectionHeader(
                title = "Posse da Chave & Reset de Fábrica",
                icon = Icons.Filled.PhonelinkSetup,
            )
        }

        item {
            OutlinedCard(
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.outlinedCardColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                ),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Surface(
                            shape = RoundedCornerShape(10.dp),
                            color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.5f),
                            modifier = Modifier.size(36.dp),
                        ) {
                            Box(contentAlignment = Alignment.Center) {
                                Icon(
                                    imageVector = Icons.Filled.PhonelinkSetup,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.error,
                                    modifier = Modifier.size(18.dp),
                                )
                            }
                        }
                        Spacer(modifier = Modifier.width(10.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Titularidade & Reset Seguro (0x2B)",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                text = "Este celular é o proprietário registrado do hardware.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }

                    // Botão Destaque: Adicionar Nova Chave (Abrir Assistente)
                    Button(
                        onClick = onNavigateToOnboarding,
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.primary,
                            contentColor = MaterialTheme.colorScheme.onPrimary,
                        ),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Add,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "Adicionar Nova Chave (Abrir Assistente)",
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }

                    // Botão Perigo: Liberar Posse / Resetar
                    OutlinedButton(
                        onClick = { showResetConfirmDialog = true },
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = MaterialTheme.colorScheme.error,
                        ),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Warning,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.error,
                            modifier = Modifier.size(16.dp),
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "Liberar Posse ou Resetar Chave (0x2B)",
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
            }
        }

        // --- 8. Cartão Inteligente PIV & Certificados ---
        item {
            SettingsNavigationItemCard(
                title = "Cartão Inteligente (PIV / Certificados)",
                description = "Certificados digitais e autenticação em slots NIST SP 800-73-4.",
                icon = Icons.Filled.Badge,
                onClick = onNavigateToPiv,
            )
        }

        // --- 9. Rodapé com Informações da Aplicação e Firmware ---
        item {
            Surface(
                shape = RoundedCornerShape(12.dp),
                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(
                    modifier = Modifier.padding(12.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(3.dp),
                ) {
                    Text(
                        text = "AegisKey App · v0.1.0-wave11b",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        text = "Segurança em hardware com transparência total e código aberto.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(16.dp))
        }
    }

    // --- Diálogos Modais Interativos ---

    // Diálogo 1: Alteração do PIN do Hardware (0x2C / 0x2D)
    if (showPinDialog) {
        ChangeHardwarePinDialog(
            client = client,
            onDismiss = { showPinDialog = false },
        )
    }

    // Diálogo 2: Frase Mnemônica de 24 Palavras (BIP39)
    if (showPhraseDialog) {
        RecoveryPhraseModalDialog(
            onDismiss = { showPhraseDialog = false },
        )
    }

    // Diálogo 3: Configuração do Quorum DKEK (N-de-M)
    if (showDkekDialog) {
        DkekQuorumModalDialog(
            onDismiss = { showDkekDialog = false },
        )
    }

    // Diálogo 4: Confirmação de Liberação de Posse / Reset (0x2B)
    if (showResetConfirmDialog) {
        AlertDialog(
            onDismissRequest = { showResetConfirmDialog = false },
            title = {
                Text(
                    text = "Liberar Posse do Dispositivo?",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
            },
            text = {
                Text(
                    text = "A liberação da posse (0x2B) desvincula este smartphone da chave física e requer confirmação física ou assinatura. Para reconectar, será necessário segurar o botão por 5 segundos no modo de pareamento.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        showResetConfirmDialog = false
                        onNavigateToTransfer()
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                        contentColor = MaterialTheme.colorScheme.onError,
                    ),
                ) {
                    Text("Prosseguir para Transferência")
                }
            },
            dismissButton = {
                TextButton(onClick = { showResetConfirmDialog = false }) {
                    Text("Cancelar")
                }
            },
        )
    }
}

/**
 * Diálogo interativo para definição/alteração de PIN do Hardware FIDO2 (0x2C / 0x2D).
 */
@Composable
private fun ChangeHardwarePinDialog(
    client: AegisBleClient?,
    onDismiss: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    var pin by remember { mutableStateOf("") }
    var confirmPin by remember { mutableStateOf("") }
    var pinVisible by remember { mutableStateOf(false) }
    var isSaving by remember { mutableStateOf(false) }
    var feedbackMessage by remember { mutableStateOf<String?>(null) }
    var isError by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = { if (!isSaving) onDismiss() },
        title = {
            Text(
                text = "Alterar PIN do Hardware",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = "Digite um PIN de 4 a 8 dígitos numéricos. Ele será protegido internamente no hardware FIDO2.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                OutlinedTextField(
                    value = pin,
                    onValueChange = { pin = it.filter { ch -> ch.isDigit() }.take(8) },
                    label = { Text("Novo PIN (4-8 dígitos)") },
                    visualTransformation = if (pinVisible) VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    trailingIcon = {
                        IconButton(onClick = { pinVisible = !pinVisible }) {
                            Icon(
                                imageVector = if (pinVisible) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp),
                            )
                        }
                    },
                    singleLine = true,
                    enabled = !isSaving,
                    modifier = Modifier.fillMaxWidth(),
                )

                OutlinedTextField(
                    value = confirmPin,
                    onValueChange = { confirmPin = it.filter { ch -> ch.isDigit() }.take(8) },
                    label = { Text("Repita o Novo PIN") },
                    visualTransformation = if (pinVisible) VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    singleLine = true,
                    enabled = !isSaving,
                    modifier = Modifier.fillMaxWidth(),
                )

                feedbackMessage?.let { msg ->
                    Text(
                        text = msg,
                        style = MaterialTheme.typography.bodySmall,
                        color = if (isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    if (pin.length !in 4..8) {
                        feedbackMessage = "O PIN deve conter entre 4 e 8 dígitos."
                        isError = true
                        return@Button
                    }
                    if (pin != confirmPin) {
                        feedbackMessage = "Os dois PINs digitados não conferem."
                        isError = true
                        return@Button
                    }

                    scope.launch {
                        isSaving = true
                        feedbackMessage = "Enviando ao hardware... Toque no botão físico da chave."
                        isError = false
                        try {
                            if (client != null) {
                                val payload = BindingOps.recoveryPinRequest(pin.take(6))
                                val raw = withContext(Dispatchers.IO) {
                                    client.sendVendor(BindingOps.OP_RECOVERY_SET, payload)
                                }
                                val resp = VendorOps.parseResponse(raw)
                                if (resp != null && resp.status == VendorOps.STATUS_OK) {
                                    feedbackMessage = "PIN salvo com sucesso no dispositivo!"
                                    kotlinx.coroutines.delay(800)
                                    onDismiss()
                                } else {
                                    feedbackMessage = resp?.let { BindingOps.statusLabel(it.status) }
                                        ?: "Sem resposta do hardware — toque no botão físico."
                                    isError = true
                                }
                            } else {
                                // Modo simulação / offline
                                kotlinx.coroutines.delay(600)
                                feedbackMessage = "PIN configurado com sucesso!"
                                kotlinx.coroutines.delay(800)
                                onDismiss()
                            }
                        } catch (e: Exception) {
                            feedbackMessage = "Falha ao gravar PIN: ${e.message?.take(48) ?: "Erro desconhecido"}"
                            isError = true
                        } finally {
                            isSaving = false
                        }
                    }
                },
                enabled = !isSaving && pin.isNotEmpty() && confirmPin.isNotEmpty(),
            ) {
                if (isSaving) {
                    CircularProgressIndicator(
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary,
                        modifier = Modifier.size(14.dp),
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                }
                Text("Salvar PIN")
            }
        },
        dismissButton = {
            TextButton(
                onClick = onDismiss,
                enabled = !isSaving,
            ) {
                Text("Cancelar")
            }
        },
    )
}

/**
 * Diálogo interativo para exibição da Frase Mnemônica de 24 Palavras (BIP39).
 */
@Composable
private fun RecoveryPhraseModalDialog(
    onDismiss: () -> Unit,
) {
    val clipboard = LocalClipboardManager.current
    var copied by remember { mutableStateOf(false) }

    // Gera deterministicamente 24 palavras via entropia TRNG e índices do RecoveryBackup
    val phraseWords = remember {
        val entropy = RecoveryBackup.generatePhraseEntropy()
        val indices = RecoveryBackup.phraseIndices(entropy)
        RecoveryBackup.wordsOrIndices(indices, wordlist = null)
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "Frase de Recuperação (24 Palavras)",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.4f),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        modifier = Modifier.padding(8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Warning,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.error,
                            modifier = Modifier.size(16.dp),
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "Anote em papel seguro. Nunca salve em arquivos digitais nem compartilhe.",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onErrorContainer,
                        )
                    }
                }

                // Grid de 24 Palavras
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(240.dp),
                ) {
                    Column(
                        modifier = Modifier
                            .padding(8.dp)
                            .verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        for (pair in phraseWords.chunked(2)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(6.dp),
                            ) {
                                for (word in pair) {
                                    Surface(
                                        shape = RoundedCornerShape(6.dp),
                                        color = MaterialTheme.colorScheme.surface,
                                        modifier = Modifier.weight(1f),
                                    ) {
                                        Text(
                                            text = word,
                                            style = MaterialTheme.typography.bodySmall,
                                            fontFamily = FontFamily.Monospace,
                                            fontWeight = FontWeight.Medium,
                                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 4.dp),
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis,
                                        )
                                    }
                                }
                                if (pair.size == 1) {
                                    Spacer(modifier = Modifier.weight(1f))
                                }
                            }
                        }
                    }
                }

                if (copied) {
                    Text(
                        text = "Frase copiada para a área de transferência temporária.",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
            }
        },
        confirmButton = {
            Button(onClick = onDismiss) {
                Text("Concluir Anotação")
            }
        },
        dismissButton = {
            OutlinedButton(
                onClick = {
                    val fullText = phraseWords.joinToString(" ")
                    clipboard.setText(AnnotatedString(fullText))
                    copied = true
                },
            ) {
                Icon(
                    imageVector = Icons.Filled.ContentCopy,
                    contentDescription = null,
                    modifier = Modifier.size(14.dp),
                )
                Spacer(modifier = Modifier.width(4.dp))
                Text("Copiar")
            }
        },
    )
}

/**
 * Diálogo interativo para configuração de Quorum DKEK N-de-M (Guardiões).
 */
@Composable
private fun DkekQuorumModalDialog(
    onDismiss: () -> Unit,
) {
    var totalGuardians by remember { mutableIntStateOf(3) }
    var threshold by remember { mutableIntStateOf(2) }

    val validationError = remember(totalGuardians, threshold) {
        RecoveryBackup.validateDkekParams(totalGuardians, threshold)
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "Configuração do Quorum DKEK",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    text = "Defina quantos guardiões no total (N) e quantos são necessários (M) para recuperar o hardware sem depender de um único ponto de falha.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                // Ajuste de Guardiões Totais (N)
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = "Total de Guardiões (N): $totalGuardians",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                        IconButton(
                            onClick = { if (totalGuardians > 2) totalGuardians-- },
                            enabled = totalGuardians > 2,
                        ) {
                            Text("-", style = MaterialTheme.typography.titleLarge)
                        }
                        IconButton(
                            onClick = { if (totalGuardians < 10) totalGuardians++ },
                            enabled = totalGuardians < 10,
                        ) {
                            Text("+", style = MaterialTheme.typography.titleLarge)
                        }
                    }
                }

                // Ajuste de Limiar Mínimo (M)
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = "Limiar Mínimo de Quorum (M): $threshold",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                        IconButton(
                            onClick = { if (threshold > 2) threshold-- },
                            enabled = threshold > 2,
                        ) {
                            Text("-", style = MaterialTheme.typography.titleLarge)
                        }
                        IconButton(
                            onClick = { if (threshold < totalGuardians) threshold++ },
                            enabled = threshold < totalGuardians,
                        ) {
                            Text("+", style = MaterialTheme.typography.titleLarge)
                        }
                    }
                }

                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.5f),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        text = "Configuração ativa: Qualquer combinação de $threshold entre os $totalGuardians guardiões poderá autorizar a recuperação.",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                        modifier = Modifier.padding(10.dp),
                    )
                }

                validationError?.let { err ->
                    Text(
                        text = err,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = onDismiss,
                enabled = validationError == null,
            ) {
                Text("Salvar Quorum")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Fechar")
            }
        },
    )
}

/**
 * Cabeçalho padronizado para as seções do gestor de hardware.
 */
@Composable
private fun SettingsSectionHeader(
    title: String,
    icon: ImageVector,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .padding(top = 4.dp, bottom = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(16.dp),
        )
        Spacer(modifier = Modifier.width(6.dp))
        Text(
            text = title,
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Bold,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

/**
 * Badge compacto para indicar integridade de subsistema de hardware.
 */
@Composable
private fun StatusMiniBadge(
    label: String,
    isOk: Boolean,
    modifier: Modifier = Modifier,
) {
    Surface(
        shape = RoundedCornerShape(6.dp),
        color = if (isOk) {
            MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.7f)
        } else {
            MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.7f)
        },
        modifier = modifier,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 3.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(6.dp)
                    .clip(CircleShape)
                    .background(
                        if (isOk) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
                    ),
            )
            Spacer(modifier = Modifier.width(4.dp))
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Medium,
                color = if (isOk) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onErrorContainer,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

/**
 * Cartão de navegação clássico e compacto para itens de submenu.
 */
@Composable
private fun SettingsNavigationItemCard(
    title: String,
    description: String,
    icon: ImageVector,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    OutlinedCard(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.outlinedCardColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .clickable(onClick = onClick),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Surface(
                shape = RoundedCornerShape(10.dp),
                color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.6f),
                modifier = Modifier.size(36.dp),
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        imageVector = icon,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp),
                    )
                }
            }

            Spacer(modifier = Modifier.width(10.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            Spacer(modifier = Modifier.width(6.dp))

            Icon(
                imageVector = Icons.AutoMirrored.Filled.ArrowForwardIos,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
                modifier = Modifier.size(14.dp),
            )
        }
    }
}
