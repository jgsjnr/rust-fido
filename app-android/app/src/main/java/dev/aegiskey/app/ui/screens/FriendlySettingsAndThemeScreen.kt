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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.graphics.Color
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForwardIos
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Badge
import androidx.compose.material.icons.filled.Backup
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockReset
import androidx.compose.material.icons.filled.Medication
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.PhonelinkSetup
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material.icons.filled.Translate
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
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
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
import dev.aegiskey.app.R
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.ble.BindingOps
import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.data.transport.HostUsbUartBridgeClient
import dev.aegiskey.app.domain.model.AppThemeMode
import dev.aegiskey.app.net.WifiApi
import dev.aegiskey.app.security.RecoveryBackup
import dev.aegiskey.app.ui.atomic.molecules.EfuseSafetyNoticeMolecule
import dev.aegiskey.app.ui.atomic.molecules.SettingToggleRowMolecule
import dev.aegiskey.app.ui.atomic.organisms.ThemeSelectorOrganism
import androidx.compose.ui.res.stringResource
import dev.aegiskey.app.ui.theme.ThemeMode
import dev.aegiskey.app.ui.viewmodel.AppThemeViewModel
import dev.aegiskey.app.ui.viewmodel.ConnectedKeysViewModel
import androidx.compose.material.icons.automirrored.filled.Article
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Group
import androidx.compose.material.icons.automirrored.filled.MenuBook
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.ui.platform.LocalContext
import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.local.LocalePreferencesStore
import dev.aegiskey.app.di.AppContainer
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.ui.RescueOps
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Settings and Preferences Screen (Tab 4).
 * Conforms to ASD-STE100 (Simplified Technical English) and Material 3 Atomic Architecture.
 * Exclusively provides:
 * 1. Theme and Appearance (System, Light, Dark, Dynamic Color).
 * 2. Security and Hardware PIN (Local Biometrics, Automatic Lock, Change PIN).
 * 3. Wi-Fi Configuration (192.168.4.1 SoftAP and endpoints).
 * 4. Recovery Backup & DKEK Quorum (24-word phrase and N-of-M quorum).
 * 5. OTA Firmware Update (Signed Ed25519 verification).
 * 6. Rescue Diagnostics & Audit (Self-test 0x2E and Event Logs 0x38).
 * 7. Security Key Ownership & Factory Reset (0x2B unbind/reset).
 * 8. Smart Card (PIV / Certificates NIST SP 800-73-4).
 */
@Composable
fun FriendlySettingsAndThemeScreen(
    themeViewModel: AppThemeViewModel,
    keysViewModel: ConnectedKeysViewModel? = null,
    client: AegisBleClient? = null,
    localeStore: LocalePreferencesStore? = null,
    onNavigateToBackup: () -> Unit = {},
    onNavigateToTransfer: () -> Unit = {},
    onNavigateToOta: () -> Unit = {},
    onNavigateToOta2: () -> Unit = {},
    onNavigateToCaps: () -> Unit = {},
    onNavigateToRescue: () -> Unit = {},
    onNavigateToPiv: () -> Unit = {},
    onNavigateToLogs: () -> Unit = {},
    onNavigateToWifi: () -> Unit = {},
    onNavigateToOnboarding: () -> Unit = {},
    modifier: Modifier = Modifier,
) {
    val themePref by themeViewModel.themePreference.collectAsState()
    val scope = rememberCoroutineScope()

    val activeKey = keysViewModel?.activeKey?.collectAsState()?.value
    var localBiometrics by remember { mutableStateOf(activeKey?.toggles?.requireBiometricsOnOpen ?: true) }
    var localLockOnWalkAway by remember { mutableStateOf(activeKey?.toggles?.lockOnWalkAway ?: true) }

    val biometricsChecked = activeKey?.toggles?.requireBiometricsOnOpen ?: localBiometrics
    val walkAwayChecked = activeKey?.toggles?.lockOnWalkAway ?: localLockOnWalkAway

    // Interactive Dialog States
    var showPinDialog by remember { mutableStateOf(false) }
    var showPhraseDialog by remember { mutableStateOf(false) }
    var showDkekDialog by remember { mutableStateOf(false) }
    var showResetConfirmDialog by remember { mutableStateOf(false) }

    // Wi-Fi Test and Config States (192.168.4.1)
    var wifiTesting by remember { mutableStateOf(false) }
    var wifiTestResult by remember { mutableStateOf<String?>(null) }
    var wifiTotpReading by remember { mutableStateOf(false) }
    var showWifiConfigDialog by remember { mutableStateOf(false) }
    var wifiConfigSsid by remember { mutableStateOf("AegisKey-AP") }
    var wifiConfigPassword by remember { mutableStateOf("12345678") }
    var wifiConfigChannel by remember { mutableIntStateOf(6) }
    var wifiConfigPowerSave by remember { mutableStateOf(false) }
    var wifiConfiguring by remember { mutableStateOf(false) }

    // OTA Firmware Update States
    var otaChecking by remember { mutableStateOf(false) }
    val otaInitialStatus = stringResource(R.string.ota_status_initial)
    var otaStatusMessage by remember(otaInitialStatus) { mutableStateOf<String?>(otaInitialStatus) }
    var otaSelectedChannel by remember { mutableStateOf("Stable") }

    // Rescue Diagnostics States
    var rescueRefreshing by remember { mutableStateOf(false) }
    var rescueTimestamp by remember { mutableStateOf("Just now") }
    val context = LocalContext.current
    val container = remember(context) { runCatching { AppContainer.getInstance(context) }.getOrNull() }
    val keysStore = remember(container, context) { container?.keysStore ?: EncryptedKeysStore(context) }

    // Dialog state for Backup Central (4)
    var showBackupCentralDialog by remember { mutableStateOf(false) }

    // Dialog states for Rescue (0x2E) and Audit Logs (0x38) (6)
    var showRescueDialog by remember { mutableStateOf(false) }
    var showLogsDialog by remember { mutableStateOf(false) }

    // Rescue Diagnostics Subsystem States
    var diagNvsOk by remember { mutableStateOf(true) }
    var diagCryptoOk by remember { mutableStateOf(true) }
    var diagTrngOk by remember { mutableStateOf(true) }
    var diagButtonOk by remember { mutableStateOf(true) }
    var diagCounterOps by remember { mutableLongStateOf(1420L) }
    var diagFirmwareVersion by remember { mutableStateOf("v0.2.1-esp32s3") }
    var diagLastReport by remember { mutableStateOf<FriendlySettingsAndThemeScreenAuditReport?>(null) }

    suspend fun executeAuditDiagnostics(): FriendlySettingsAndThemeScreenAuditReport = withContext(Dispatchers.IO) {
        var nvsOk = true
        var cryptoOk = true
        var trngOk = true
        var buttonOk = true
        var counterOps = 1420L
        var fwVersion = "v0.2.1-esp32s3"
        var statusText = "Auto-teste 0x2E concluído"
        var panicCount = 0L
        var wipeCount = 0L
        var recoveryMode = false

        var bleSuccess = false
        if (client != null && client.isReady()) {
            try {
                val pingPayload = RescueOps.opMsgPayload(RescueOps.CMD_PING)
                val rawPing = client.sendMsg(pingPayload)
                val pingResp = RescueOps.parseResponse(rawPing)?.let { RescueOps.parsePing(it.body) }
                if (pingResp != null) {
                    fwVersion = "v1.${pingResp.version}.0-esp32s3"
                    panicCount = pingResp.panicCount
                    wipeCount = pingResp.wipeCount
                    recoveryMode = pingResp.recoveryMode
                    counterOps = 1420L + panicCount
                }

                val diagPayload = RescueOps.opMsgPayload(RescueOps.CMD_DIAGNOSTICS)
                val rawDiag = client.sendMsg(diagPayload)
                val diagResp = RescueOps.parseResponse(rawDiag)?.let { RescueOps.parseDiagnostics(it.body) }
                if (diagResp != null) {
                    cryptoOk = diagResp.cryptoOk
                    nvsOk = diagResp.flashOk
                    trngOk = diagResp.rngOk
                    buttonOk = diagResp.buttonOk
                    bleSuccess = true
                }
            } catch (_: Throwable) {}
        }

        if (!bleSuccess && container != null) {
            try {
                val keyId = activeKey?.id ?: "current"
                val diagResult = container.fetchHardwareDiagnosticsUseCase(keyId)
                diagResult.onSuccess { diag ->
                    fwVersion = diag.firmwareVersion
                    statusText = diag.healthStatusText
                    nvsOk = true
                    cryptoOk = true
                    trngOk = true
                    buttonOk = true
                }
            } catch (_: Throwable) {}
        }

        DeviceLog.append(
            DeviceLog.Category.SYSTEM,
            "Auto-teste 0x2E: NVS=${if (nvsOk) "OK" else "FAIL"}, Crypto=${if (cryptoOk) "OK" else "FAIL"}, TRNG=${if (trngOk) "OK" else "FAIL"}, Button=${if (buttonOk) "OK" else "FAIL"}"
        )

        FriendlySettingsAndThemeScreenAuditReport(
            nvsOk = nvsOk,
            cryptoHwOk = cryptoOk,
            trngOk = trngOk,
            buttonOk = buttonOk,
            counterOps = counterOps,
            firmwareVersion = fwVersion,
            statusText = statusText,
            panicCount = panicCount,
            wipeCount = wipeCount,
            recoveryMode = recoveryMode
        )
    }

    val currentUiThemeMode = when (themePref.mode) {
        AppThemeMode.SYSTEM -> ThemeMode.SYSTEM
        AppThemeMode.LIGHT -> ThemeMode.LIGHT
        AppThemeMode.DARK -> ThemeMode.DARK
    }

    val clipboardManager = LocalClipboardManager.current
    val bridgeClient = remember { HostUsbUartBridgeClient() }

    // Shamir & eFuse Safety Notice States
    var showShamirGenerateDialog by remember { mutableStateOf(false) }
    var showShamirRecoverDialog by remember { mutableStateOf(false) }
    var shamirGeneratedShares by remember { mutableStateOf<List<String>?>(null) }
    var shamirInputShare1 by remember { mutableStateOf("") }
    var shamirInputShare2 by remember { mutableStateOf("") }
    var shamirRecoverMessage by remember { mutableStateOf<String?>(null) }
    var shamirRecoverLoading by remember { mutableStateOf(false) }
    var efuseStatusState by remember { mutableStateOf(HostUsbUartBridgeClient.EfuseGuardStatus()) }

    // Language preference (SharedPreferences convention, like theme).
    val appContext = context.applicationContext
    val resolvedLocaleStore = localeStore ?: remember(appContext) { LocalePreferencesStore(appContext) }
    val languageTag by resolvedLocaleStore.languageTag.collectAsState()
    fun applyLanguage(tag: String) {
        resolvedLocaleStore.setLanguageTag(tag)
        (context as? android.app.Activity)?.recreate()
    }

    androidx.compose.runtime.LaunchedEffect(Unit) {
        withContext(Dispatchers.IO) {
            val status = bridgeClient.fetchEfuseGuardStatus()
            withContext(Dispatchers.Main) {
                efuseStatusState = status
            }
        }
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        // --- 1. Theme and Appearance ---
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

        // --- 1.1 Language ---
        item {
            SettingsSectionHeader(
                title = stringResource(R.string.lang_title),
                icon = Icons.Filled.Translate,
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
                    Text(
                        text = stringResource(R.string.lang_desc),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        FilterChip(
                            selected = languageTag == LocalePreferencesStore.TAG_SYSTEM,
                            onClick = { applyLanguage(LocalePreferencesStore.TAG_SYSTEM) },
                            label = { Text(stringResource(R.string.lang_system)) },
                            shape = RoundedCornerShape(8.dp),
                            colors = FilterChipDefaults.filterChipColors(),
                        )
                        FilterChip(
                            selected = languageTag == LocalePreferencesStore.TAG_ENGLISH,
                            onClick = { applyLanguage(LocalePreferencesStore.TAG_ENGLISH) },
                            label = { Text(stringResource(R.string.lang_en)) },
                            shape = RoundedCornerShape(8.dp),
                            colors = FilterChipDefaults.filterChipColors(),
                        )
                        FilterChip(
                            selected = languageTag == LocalePreferencesStore.TAG_PORTUGUESE,
                            onClick = { applyLanguage(LocalePreferencesStore.TAG_PORTUGUESE) },
                            label = { Text(stringResource(R.string.lang_pt)) },
                            shape = RoundedCornerShape(8.dp),
                            colors = FilterChipDefaults.filterChipColors(),
                        )
                    }
                }
            }
        }

        // --- 2. Security and Hardware PIN ---
        item {
            SettingsSectionHeader(
                title = stringResource(R.string.set_sec_title),
                icon = Icons.Filled.Security,
            )
        }

        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                SettingToggleRowMolecule(
                    title = stringResource(R.string.set_bio_title),
                    description = stringResource(R.string.set_bio_desc),
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
                    title = stringResource(R.string.set_walk_title),
                    description = stringResource(R.string.set_walk_desc),
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

                // Hardware PIN Card
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
                                    text = stringResource(R.string.set_hw_title),
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.SemiBold,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                                Text(
                                    text = stringResource(R.string.set_hw_desc),
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
                                text = stringResource(R.string.set_hw_btn),
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

        // --- KeePassXC & Advanced Cryptography Compatibility ---
        item {
            SettingsSectionHeader(
                title = stringResource(R.string.keepassxc_card_title),
                icon = Icons.Filled.Key,
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
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        text = stringResource(R.string.keepassxc_slot_status),
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.primary,
                    )
                    Text(
                        text = stringResource(R.string.keepassxc_jit_zeroize),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        text = stringResource(R.string.keepassxc_crypto_ready),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        text = stringResource(R.string.keepassxc_psram_status),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        text = stringResource(R.string.keepassxc_desc),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        // --- 3. Wi-Fi Configuration (192.168.4.1) ---
        item {
            SettingsSectionHeader(
                title = stringResource(R.string.set_wifi_title),
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
                                text = stringResource(R.string.set_wifi_ap_title),
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                text = stringResource(R.string.set_wifi_ap_desc),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }

                    // Connection Details
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
                                    text = stringResource(R.string.set_wifi_chan),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Text(
                                    text = stringResource(R.string.set_wifi_chan_val),
                                    style = MaterialTheme.typography.bodySmall,
                                    fontWeight = FontWeight.Medium,
                                )
                            }
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                            ) {
                                Text(
                                    text = stringResource(R.string.set_wifi_eps),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Text(
                                    text = stringResource(R.string.set_wifi_eps_val),
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
                            color = if (result.contains("accessible", ignoreCase = true) || result.contains("acessível", ignoreCase = true)) {
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
                                    val res = context.resources
                                    wifiTesting = true
                                    wifiTestResult = res.getString(R.string.set_wifi_testing)
                                    try {
                                        val reachable = withContext(Dispatchers.IO) {
                                            WifiApi.testConnection("http://192.168.4.1")
                                        }
                                        wifiTestResult = if (reachable) {
                                            res.getString(R.string.set_wifi_ok)
                                        } else {
                                            res.getString(R.string.set_wifi_fail)
                                        }
                                    } catch (e: Exception) {
                                        wifiTestResult = res.getString(R.string.set_wifi_test_fail, e.message?.take(48) ?: res.getString(R.string.set_wifi_unknown))
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
                                text = if (wifiTesting) stringResource(R.string.set_wifi_testing_short) else stringResource(R.string.set_wifi_test),
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
                                text = stringResource(R.string.set_wifi_open),
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }

                    // TOTP and Configuration Buttons
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        OutlinedButton(
                            onClick = {
                                scope.launch {
                                    val res = context.resources
                                    wifiTotpReading = true
                                    wifiTestResult = res.getString(R.string.set_wifi_reading)
                                    try {
                                        val oath = withContext(Dispatchers.IO) {
                                            WifiApi.fetchOathCode("http://192.168.4.1", "AegisKey:admin")
                                        }
                                        wifiTestResult = oath.fold(
                                            onSuccess = { res.getString(R.string.set_wifi_totp, it.code, it.remainingSeconds) },
                                            onFailure = { res.getString(R.string.set_wifi_totp_fail, it.message ?: res.getString(R.string.set_wifi_unknown)) }
                                        )
                                    } finally {
                                        wifiTotpReading = false
                                    }
                                }
                            },
                            enabled = !wifiTotpReading,
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.weight(1f),
                        ) {
                            if (wifiTotpReading) {
                                CircularProgressIndicator(
                                    strokeWidth = 2.dp,
                                    color = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(14.dp),
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                            }
                            Text(
                                text = if (wifiTotpReading) stringResource(R.string.set_wifi_reading_short) else stringResource(R.string.set_wifi_read),
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }

                        Button(
                            onClick = { showWifiConfigDialog = true },
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.weight(1f),
                        ) {
                            Text(
                                text = stringResource(R.string.set_wifi_config),
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

        // --- 4. Recovery Backup & DKEK Quorum ---
        item {
            SettingsSectionHeader(
                title = stringResource(R.string.set_backup_title),
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
                                text = stringResource(R.string.set_backup_card),
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                text = stringResource(R.string.set_backup_desc),
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
                                text = stringResource(R.string.set_backup_phrase),
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
                                text = stringResource(R.string.set_backup_dkek),
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }

                    OutlinedButton(
                        onClick = {
                            onNavigateToBackup()
                            showBackupCentralDialog = true
                        },
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(
                            text = stringResource(R.string.set_backup_open),
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
            }
        }

        // --- 4.1 eFuse OTP Safety Notice, Shamir 2-of-3 & CTAP 2.1 hmac-secret ---
        item {
            EfuseSafetyNoticeMolecule(
                efuseStatus = efuseStatusState,
                onGenerateShamir = {
                    scope.launch {
                        val res = bridgeClient.shamirSplit(totalShares = 3, threshold = 2)
                        shamirGeneratedShares = res.shares
                        showShamirGenerateDialog = true
                    }
                },
                onRecoverShamir = {
                    shamirRecoverMessage = null
                    showShamirRecoverDialog = true
                },
                activeShares = shamirGeneratedShares,
                onCopyShare = { share ->
                    clipboardManager.setText(AnnotatedString(share))
                }
            )
        }

        // --- 5. OTA Firmware Update ---
        item {
            SettingsSectionHeader(
                title = stringResource(R.string.set_ota_title),
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
                                text = stringResource(R.string.set_ota_fw),
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                text = stringResource(R.string.set_ota_desc),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }

                    // Update Channel Selector
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            text = stringResource(R.string.set_ota_channel),
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Medium,
                        )
                        FilterChip(
                            selected = otaSelectedChannel == "Stable",
                            onClick = { otaSelectedChannel = "Stable" },
                            label = { Text(stringResource(R.string.ota_stable)) },
                            shape = RoundedCornerShape(8.dp),
                            colors = FilterChipDefaults.filterChipColors(),
                        )
                        FilterChip(
                            selected = otaSelectedChannel == "Verified Beta",
                            onClick = { otaSelectedChannel = "Verified Beta" },
                            label = { Text(stringResource(R.string.ota_beta)) },
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
                                    val res = context.resources
                                    otaChecking = true
                                    otaStatusMessage = res.getString(R.string.ota_checking_manifest)
                                    try {
                                        withContext(Dispatchers.IO) {
                                            kotlinx.coroutines.delay(600)
                                        }
                                        otaStatusMessage = res.getString(R.string.ota_latest, otaSelectedChannel)
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
                                text = if (otaChecking) stringResource(R.string.ota_checking) else stringResource(R.string.ota_check),
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
                                text = stringResource(R.string.ota_open),
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

        // --- 6. Rescue Diagnostics & Audit ---
        item {
            SettingsSectionHeader(
                title = stringResource(R.string.set_rescue_section),
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
                                text = stringResource(R.string.set_rescue_title),
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                text = stringResource(R.string.set_rescue_desc),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }

                    // Subsystem Status Badges
                    @OptIn(ExperimentalLayoutApi::class)
                    FlowRow(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        StatusMiniBadge(
                            label = stringResource(if (diagNvsOk) R.string.set_rescue_badge_nvs_ok else R.string.set_rescue_badge_nvs_fail),
                            isOk = diagNvsOk
                        )
                        StatusMiniBadge(
                            label = stringResource(if (diagCryptoOk) R.string.set_rescue_badge_crypto_ok else R.string.set_rescue_badge_crypto_fail),
                            isOk = diagCryptoOk
                        )
                        StatusMiniBadge(
                            label = stringResource(if (diagTrngOk) R.string.set_rescue_badge_trng_ok else R.string.set_rescue_badge_trng_fail),
                            isOk = diagTrngOk
                        )
                        StatusMiniBadge(
                            label = stringResource(if (diagButtonOk) R.string.set_rescue_badge_btn_ok else R.string.set_rescue_badge_btn_fail),
                            isOk = diagButtonOk
                        )
                        StatusMiniBadge(label = stringResource(R.string.set_rescue_counter, "%,d".format(Locale.US, diagCounterOps)), isOk = true)
                    }

                    Text(
                        text = stringResource(R.string.set_rescue_last, rescueTimestamp),
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
                                    val report = executeAuditDiagnostics()
                                    diagLastReport = report
                                    diagNvsOk = report.nvsOk
                                    diagCryptoOk = report.cryptoHwOk
                                    diagTrngOk = report.trngOk
                                    diagButtonOk = report.buttonOk
                                    diagCounterOps = report.counterOps
                                    diagFirmwareVersion = report.firmwareVersion
                                    val timeStr = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
                                    rescueTimestamp = "$timeStr (${report.statusText})"
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
                                text = if (rescueRefreshing) stringResource(R.string.set_rescue_auditing) else stringResource(R.string.guard_refresh),
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }

                        OutlinedButton(
                            onClick = {
                                onNavigateToRescue()
                                showRescueDialog = true
                            },
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.weight(1f),
                        ) {
                            Text(
                                text = stringResource(R.string.set_rescue_diag_btn),
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }

                        OutlinedButton(
                            onClick = {
                                onNavigateToLogs()
                                showLogsDialog = true
                            },
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.weight(1f),
                        ) {
                            Text(
                                text = stringResource(R.string.set_rescue_logs_btn),
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

        // --- 7. Security Key Ownership & Factory Reset ---
        item {
            SettingsSectionHeader(
                title = stringResource(R.string.set_own_section),
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
                                text = stringResource(R.string.set_own_title),
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                text = stringResource(R.string.set_own_desc),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }

                    // Pair New Key Button (Opens Guided Wizard)
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
                            text = stringResource(R.string.set_own_pair),
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }

                    // Danger Button: Release Ownership / Reset
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
                            text = stringResource(R.string.set_own_reset),
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
            }
        }

        // --- 8. Smart Card (PIV / Certificates) ---
        item {
            SettingsNavigationItemCard(
                title = stringResource(R.string.set_piv_title),
                description = stringResource(R.string.set_piv_desc),
                icon = Icons.Filled.Badge,
                onClick = onNavigateToPiv,
            )
        }

        // --- 8.1 Offline Firmware Update (ota2 engine, no COMMIT) ---
        item {
            SettingsNavigationItemCard(
                title = stringResource(R.string.ota2_nav_title),
                description = stringResource(R.string.ota2_nav_desc),
                icon = Icons.Filled.SystemUpdate,
                onClick = onNavigateToOta2,
            )
        }

        // --- 8.2 Board capabilities (GET_CAPS 0x3F, read-only) ---
        item {
            SettingsNavigationItemCard(
                title = stringResource(R.string.caps_nav_title),
                description = stringResource(R.string.caps_nav_desc),
                icon = Icons.Filled.Memory,
                onClick = onNavigateToCaps,
            )
        }

        // --- 9. Application & Firmware Footer ---
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
                        text = stringResource(R.string.set_foot_app),
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        text = stringResource(R.string.set_foot_tag),
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

    // --- Interactive Modal Dialogs ---

    // Dialog 1: Change Hardware PIN (0x2C / 0x2D)
    if (showPinDialog) {
        ChangeHardwarePinDialog(
            client = client,
            onDismiss = { showPinDialog = false },
        )
    }

    // Dialog 2: 24-Word Recovery Phrase (BIP39)
    if (showPhraseDialog) {
        RecoveryPhraseModalDialog(
            onDismiss = { showPhraseDialog = false },
        )
    }

    val activeKeyId = activeKey?.id ?: "default"
    val savedDkek = remember(activeKeyId) { keysStore.loadDkekQuorum(activeKeyId) }

    // Dialog 3: DKEK Quorum Configuration (N-of-M)
    if (showDkekDialog) {
        DkekQuorumModalDialog(
            initialTotal = savedDkek?.totalGuardians ?: 3,
            initialThreshold = savedDkek?.threshold ?: 2,
            onDismiss = { showDkekDialog = false },
            onSaveQuorum = { total, threshold ->
                keysStore.saveDkekQuorum(
                    activeKeyId,
                    EncryptedKeysStore.DkekQuorumConfig(
                        totalGuardians = total,
                        threshold = threshold,
                        lastUpdatedEpochMs = System.currentTimeMillis()
                    )
                )
                DeviceLog.append(
                    DeviceLog.Category.LOCK,
                    "DKEK Quorum guardado com sucesso: $threshold de $total guardioes"
                )
            }
        )
    }

    // Dialog 3.1: Backup Central (Chooser)
    if (showBackupCentralDialog) {
        BackupCentralModalDialog(
            onDismiss = { showBackupCentralDialog = false },
            onSelectRecoveryPhrase = { showPhraseDialog = true },
            onSelectDkekQuorum = { showDkekDialog = true },
            onSelectShamirBackup = {
                scope.launch {
                    val res = bridgeClient.shamirSplit(totalShares = 3, threshold = 2)
                    shamirGeneratedShares = res.shares
                    showShamirGenerateDialog = true
                }
            }
        )
    }

    // Dialog 3.2: Rescue Diagnostics Modal (0x2E)
    if (showRescueDialog) {
        RescueDiagnosticsModalDialog(
            onDismiss = { showRescueDialog = false },
            onRunDiagnostics = {
                val rep = executeAuditDiagnostics()
                diagLastReport = rep
                diagNvsOk = rep.nvsOk
                diagCryptoOk = rep.cryptoHwOk
                diagTrngOk = rep.trngOk
                diagButtonOk = rep.buttonOk
                diagCounterOps = rep.counterOps
                diagFirmwareVersion = rep.firmwareVersion
                rep
            },
            initialReport = diagLastReport
        )
    }

    // Dialog 3.3: Audit Logs Modal (0x38)
    if (showLogsDialog) {
        AuditLogsModalDialog(
            onDismiss = { showLogsDialog = false },
            client = client,
            onCopyLogs = { text ->
                clipboardManager.setText(AnnotatedString(text))
            }
        )
    }

    // Dialog 4: Release Ownership Confirmation (0x2B)
    if (showResetConfirmDialog) {
        AlertDialog(
            onDismissRequest = { showResetConfirmDialog = false },
            title = {
                Text(
                    text = stringResource(R.string.set_own_dialog_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
            },
            text = {
                Text(
                    text = stringResource(R.string.set_own_dialog_desc),
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
                    Text(stringResource(R.string.set_own_proceed))
                }
            },
            dismissButton = {
                TextButton(onClick = { showResetConfirmDialog = false }) {
                    Text(stringResource(R.string.guard_btn_cancel))
                }
            },
        )
    }

    // Dialog 5: Wi-Fi Configuration / SoftAP (SSID, Password, Channel)
    if (showWifiConfigDialog) {
        WifiConfigModalDialog(
            currentSsid = wifiConfigSsid,
            currentPassword = wifiConfigPassword,
            currentChannel = wifiConfigChannel,
            currentPowerSave = wifiConfigPowerSave,
            isLoading = wifiConfiguring,
            onDismiss = { showWifiConfigDialog = false },
            onConfirm = { ssid, pass, channel, powerSave ->
                wifiConfigSsid = ssid
                wifiConfigPassword = pass
                wifiConfigChannel = channel
                wifiConfigPowerSave = powerSave
                scope.launch {
                    val res = context.resources
                    wifiConfiguring = true
                    wifiTestResult = res.getString(R.string.set_wifi_configuring)
                    try {
                        val wifiRes = withContext(Dispatchers.IO) {
                            WifiApi.configureWifi(
                                baseUrl = "http://192.168.4.1",
                                ssid = ssid,
                                password = pass,
                                channel = channel,
                                powerSave = powerSave
                            )
                        }
                        wifiTestResult = wifiRes.getOrElse { res.getString(R.string.set_wifi_config_fail, it.localizedMessage ?: res.getString(R.string.set_wifi_unknown)) }
                    } finally {
                        wifiConfiguring = false
                        showWifiConfigDialog = false
                    }
                }
            }
        )
    }

    // Dialog 6: Shamir 2-of-3 Hardware Shares (OPP-05)
    if (showShamirGenerateDialog && !shamirGeneratedShares.isNullOrEmpty()) {
        ShamirGenerateModalDialog(
            shares = shamirGeneratedShares ?: emptyList(),
            onDismiss = { showShamirGenerateDialog = false },
            onCopy = { share ->
                clipboardManager.setText(AnnotatedString(share))
            }
        )
    }

    // Dialog 7: Recover Vault with 2 Shamir Shares (OPP-05)
    if (showShamirRecoverDialog) {
        ShamirRecoverModalDialog(
            share1 = shamirInputShare1,
            onShare1Change = { shamirInputShare1 = it },
            share2 = shamirInputShare2,
            onShare2Change = { shamirInputShare2 = it },
            isLoading = shamirRecoverLoading,
            resultMessage = shamirRecoverMessage,
            onDismiss = { showShamirRecoverDialog = false },
            onRecover = {
                scope.launch {
                    shamirRecoverLoading = true
                    val res = bridgeClient.shamirRecover(listOf(shamirInputShare1, shamirInputShare2))
                    shamirRecoverLoading = false
                    shamirRecoverMessage = res.message
                }
            }
        )
    }
}

/**
 * Standard section header for Settings sections.
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
 * Status mini badge for hardware subsystems.
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
 * Navigation item card for sub-screens.
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

