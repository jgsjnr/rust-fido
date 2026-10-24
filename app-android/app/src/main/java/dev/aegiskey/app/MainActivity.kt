package dev.aegiskey.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStoreOwner
import androidx.navigation.NavController
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.di.AppContainer
import dev.aegiskey.app.domain.model.AppThemeMode
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.security.applyScreenshotProtection
import dev.aegiskey.app.ui.AccountsScreen
import dev.aegiskey.app.ui.AegisTheme
import dev.aegiskey.app.ui.AuthScreen
import dev.aegiskey.app.ui.BindingWizardScreen
import dev.aegiskey.app.ui.DeviceControlScreen
import dev.aegiskey.app.ui.ForeignDeviceScreen
import dev.aegiskey.app.ui.LogScreen
import dev.aegiskey.app.ui.OnboardingScreen
import dev.aegiskey.app.ui.OtaScreen
import dev.aegiskey.app.ui.PivScreen
import dev.aegiskey.app.ui.RecoveryUnlockScreen
import dev.aegiskey.app.ui.RescueScreen
import dev.aegiskey.app.ui.ScanPairScreen
import dev.aegiskey.app.ui.SettingsScreen
import dev.aegiskey.app.ui.SetupDeviceBleScreen
import dev.aegiskey.app.ui.SetupDeviceUsbScreen
import dev.aegiskey.app.ui.TransferOwnershipScreen
import dev.aegiskey.app.ui.UnbindGuideScreen
import dev.aegiskey.app.ui.UsbScreen
import dev.aegiskey.app.ui.VaultScreen
import dev.aegiskey.app.ui.WalletScreen
import dev.aegiskey.app.ui.WelcomeScreen
import dev.aegiskey.app.ui.WifiScreen
import dev.aegiskey.app.ui.atomic.templates.HubDestination
import dev.aegiskey.app.ui.atomic.templates.MainHubScaffoldTemplate
import dev.aegiskey.app.ui.screens.ConnectedKeysRepositoryScreen
import dev.aegiskey.app.ui.screens.FriendlySettingsAndThemeScreen
import dev.aegiskey.app.ui.screens.KeyVaultHubScreen
import dev.aegiskey.app.ui.screens.OnboardingWizardScreen
import dev.aegiskey.app.ui.screens.TotpDedicatedScreen
import dev.aegiskey.app.ui.viewmodel.AppThemeViewModel
import dev.aegiskey.app.ui.viewmodel.ConnectedKeysViewModel
import dev.aegiskey.app.ui.viewmodel.KeyVaultViewModel
import dev.aegiskey.app.ui.viewmodel.OnboardingWizardViewModel
import dev.aegiskey.app.ui.viewmodel.TotpAuthenticatorViewModel

class MainActivity : ComponentActivity() {
    private lateinit var container: AppContainer
    private lateinit var ble: AegisBleClient

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        applyScreenshotProtection(window)

        container = AppContainer.getInstance(applicationContext)
        ble = container.bleClient

        setContent {
            AegisApp(container = container, client = ble)
        }
    }

    override fun onDestroy() {
        ble.release()
        super.onDestroy()
    }
}

/**
 * Função utilitária para obter ViewModel com factory desacoplada de forma segura e idiomática.
 */
@Composable
private inline fun <reified VM : ViewModel> aegisViewModel(factory: ViewModelProvider.Factory): VM {
    val context = LocalContext.current
    val owner = context as? ViewModelStoreOwner
        ?: error("Context não implementa ViewModelStoreOwner")
    return remember(owner, VM::class.java) {
        ViewModelProvider(owner, factory)[VM::class.java]
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AegisApp(container: AppContainer, client: AegisBleClient) {
    val themeViewModel = aegisViewModel<AppThemeViewModel>(AppThemeViewModel.provideFactory(container))
    val onboardingViewModel = aegisViewModel<OnboardingWizardViewModel>(OnboardingWizardViewModel.provideFactory(container))
    val keysViewModel = aegisViewModel<ConnectedKeysViewModel>(ConnectedKeysViewModel.provideFactory(container))
    val vaultViewModel = aegisViewModel<KeyVaultViewModel>(KeyVaultViewModel.provideFactory(container))
    val totpViewModel = aegisViewModel<TotpAuthenticatorViewModel>(TotpAuthenticatorViewModel.provideFactory(container))

    val themePref by themeViewModel.themePreference.collectAsState()
    val isSystemDark = isSystemInDarkTheme()
    val darkTheme = when (themePref.mode) {
        AppThemeMode.SYSTEM -> isSystemDark
        AppThemeMode.LIGHT -> false
        AppThemeMode.DARK -> true
    }

    val hasAnyKey by keysViewModel.hasAnyConnectedKey.collectAsState()
    val activeKey by keysViewModel.activeKey.collectAsState()

    AegisTheme(darkTheme = darkTheme, dynamicColor = themePref.useDynamicColors) {
        // Guarda Reativo de Navegação:
        // Se o usuário ainda não conectou nenhuma chave física ou desconectou todas as chaves,
        // exibe imediatamente a jornada guiada de Boas-vindas (Onboarding Wizard) em tela cheia.
        if (!hasAnyKey) {
            OnboardingWizardScreen(
                viewModel = onboardingViewModel,
                onFinished = {
                    // A conclusão do onboarding já cadastra a chave no repositório,
                    // fazendo hasAnyKey transitar automaticamente para true.
                }
            )
        } else {
            val nav = rememberNavController()

            DisposableEffect(nav) {
                val listener = NavController.OnDestinationChangedListener { _, dest, _ ->
                    DeviceLog.append(DeviceLog.Category.SYSTEM, "tela=" + (dest.route ?: "?"))
                }
                nav.addOnDestinationChangedListener(listener)
                onDispose { nav.removeOnDestinationChangedListener(listener) }
            }

            val navBackStackEntry by nav.currentBackStackEntryAsState()
            val currentRoute = navBackStackEntry?.destination?.route ?: HubDestination.VAULT.route

            val currentDestination = when (currentRoute) {
                HubDestination.VAULT.route -> HubDestination.VAULT
                HubDestination.CODES.route -> HubDestination.CODES
                HubDestination.KEYS.route -> HubDestination.KEYS
                HubDestination.SETTINGS.route -> HubDestination.SETTINGS
                else -> when (currentRoute) {
                    "accounts", "control", "scan", "binding", "foreign", "transfer", "unbind" -> HubDestination.KEYS
                    "setup-usb", "setup-ble", "welcome", "vault-legacy" -> HubDestination.VAULT
                    else -> HubDestination.SETTINGS
                }
            }

            val transportLabel = when (activeKey?.transportType) {
                ConnectionTransportType.BLE -> "Bluetooth"
                ConnectionTransportType.USB -> "Cabo USB / UART"
                ConnectionTransportType.WIFI -> "Rede Wi-Fi"
                ConnectionTransportType.SIMULATOR -> "Simulador Virtual"
                null -> "Chave Física"
            }

            MainHubScaffoldTemplate(
                currentDestination = currentDestination,
                onNavigateToDestination = { destination ->
                    nav.navigate(destination.route) {
                        popUpTo(nav.graph.findStartDestination().id) { saveState = true }
                        launchSingleTop = true
                        restoreState = true
                    }
                },
                activeKeyName = activeKey?.displayName ?: "Minha AegisKey",
                isConnected = activeKey?.isCurrentlyConnected == true,
                transportLabel = transportLabel,
                onSwitchKeyClick = {
                    nav.navigate(HubDestination.KEYS.route) {
                        popUpTo(nav.graph.findStartDestination().id) { saveState = true }
                        launchSingleTop = true
                        restoreState = true
                    }
                },
                onToggleThemeClick = {
                    themeViewModel.cycleThemeMode()
                },
            ) { innerPadding ->
                NavHost(
                    navController = nav,
                    startDestination = HubDestination.VAULT.route,
                    modifier = Modifier.padding(innerPadding)
                ) {
                    // --- 4 Destinos Principais da Barra Inferior ---
                    composable(HubDestination.VAULT.route) {
                        KeyVaultHubScreen(
                            viewModel = vaultViewModel,
                            onNavigateToBackup = { nav.navigate("transfer") },
                            onNavigateToOta = { nav.navigate("ota") }
                        )
                    }
                    composable(HubDestination.CODES.route) {
                        TotpDedicatedScreen(
                            viewModel = totpViewModel
                        )
                    }
                    composable(HubDestination.KEYS.route) {
                        ConnectedKeysRepositoryScreen(
                            viewModel = keysViewModel,
                            onConnectNewKey = { nav.navigate("onboarding-wizard") }
                        )
                    }
                    composable(HubDestination.SETTINGS.route) {
                        FriendlySettingsAndThemeScreen(
                            themeViewModel = themeViewModel,
                            onNavigateToBackup = { nav.navigate("recovery") },
                            onNavigateToTransfer = { nav.navigate("transfer") },
                            onNavigateToOta = { nav.navigate("ota") },
                            onNavigateToRescue = { nav.navigate("rescue") },
                            onNavigateToPiv = { nav.navigate("piv") },
                            onNavigateToLogs = { nav.navigate("log") }
                        )
                    }

                    // --- Wizard de Pareamento Chamável a Qualquer Momento ---
                    composable("onboarding-wizard") {
                        OnboardingWizardScreen(
                            viewModel = onboardingViewModel,
                            onFinished = {
                                nav.navigate(HubDestination.VAULT.route) {
                                    popUpTo(HubDestination.VAULT.route) { inclusive = false }
                                }
                            }
                        )
                    }

                    // --- Rotas de Ferramentas Avançadas & Legadas Mantidas ---
                    composable("setup-usb") {
                        SetupDeviceUsbScreen(
                            onDone = { nav.navigate(HubDestination.VAULT.route) },
                            onBack = { nav.popBackStack() },
                        )
                    }
                    composable("setup-ble") {
                        SetupDeviceBleScreen(
                            onDone = { nav.navigate(HubDestination.VAULT.route) },
                            onBack = { nav.popBackStack() },
                            onOpenScan = { nav.navigate("scan") },
                            client = client,
                        )
                    }
                    composable("onboarding") {
                        OnboardingScreen(
                            onStart = { nav.navigate("scan") },
                            onOpenKeys = { nav.navigate("accounts") },
                            onOpenVault = { nav.navigate(HubDestination.VAULT.route) },
                            onOpenLog = { nav.navigate("log") },
                            client = client
                        )
                    }
                    composable("scan") {
                        ScanPairScreen(client, onOpenControl = { nav.navigate("control") })
                    }
                    composable("control") {
                        DeviceControlScreen(
                            client = client,
                            onOpenKeys = { nav.navigate("accounts") },
                            onOpenAuth = { nav.navigate("auth") },
                            onOpenVault = { nav.navigate(HubDestination.VAULT.route) },
                            onOpenWallet = { nav.navigate("wallet") },
                            onOpenPiv = { nav.navigate("piv") },
                            onOpenLog = { nav.navigate("log") },
                            onBack = { nav.popBackStack() },
                        )
                    }
                    composable("accounts") { AccountsScreen(client) }
                    composable("wallet") { WalletScreen(client) }
                    composable("piv") { PivScreen(client, onOpenPairing = { nav.navigate("scan") }) }
                    composable("auth") { AuthScreen(client) }
                    composable("vault-legacy") { VaultScreen(client) }
                    composable("usb") { UsbScreen(onUseBle = { nav.navigate("scan") }) }
                    composable("wifi") { WifiScreen() }
                    composable("log") { LogScreen(client) }
                    composable("settings-legacy") { SettingsScreen(onOpenLog = { nav.navigate("log") }, client = client) }
                    composable("binding") {
                        BindingWizardScreen(client, onDone = { nav.navigate(HubDestination.VAULT.route) }, onForeignDevice = { nav.navigate("foreign") })
                    }
                    composable("foreign") {
                        ForeignDeviceScreen(onUseUsb = { nav.navigate("usb") }, onBack = { nav.navigate(HubDestination.VAULT.route) })
                    }
                    composable("transfer") {
                        TransferOwnershipScreen(client, onDone = { nav.navigate(HubDestination.VAULT.route) })
                    }
                    composable("unbind") {
                        UnbindGuideScreen(onDone = { nav.navigate(HubDestination.KEYS.route) })
                    }
                    composable("recovery") {
                        RecoveryUnlockScreen(client, onReclaim = { nav.navigate("binding") }, onBack = { nav.navigate(HubDestination.VAULT.route) })
                    }
                    composable("rescue") {
                        RescueScreen(client, onBack = { nav.navigate(HubDestination.VAULT.route) })
                    }
                    composable("ota") {
                        OtaScreen(client, onBack = { nav.popBackStack() })
                    }
                }
            }
        }
    }
}
