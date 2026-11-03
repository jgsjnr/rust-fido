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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import dev.aegiskey.app.data.local.LocaleHelper
import dev.aegiskey.app.data.local.LocalePreferencesStore
import dev.aegiskey.app.ui.screens.FriendlyOnboardingWizardScreen
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
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
import dev.aegiskey.app.ota2.Ota2Screen
import dev.aegiskey.app.caps.CapsScreen
import dev.aegiskey.app.security.applyScreenshotProtection
import dev.aegiskey.app.ui.AegisTheme
import dev.aegiskey.app.ui.atomic.templates.HubDestination
import dev.aegiskey.app.ui.atomic.templates.MainHubScaffoldTemplate
import dev.aegiskey.app.ui.screens.ConnectedKeysRepositoryScreen
import dev.aegiskey.app.ui.screens.FriendlySettingsAndThemeScreen
import dev.aegiskey.app.ui.screens.KeyVaultHubScreen
import dev.aegiskey.app.ui.screens.OnboardingWizardScreen
import dev.aegiskey.app.ui.screens.TotpDedicatedScreen

class MainActivity : ComponentActivity() {
    private lateinit var container: AppContainer
    private lateinit var ble: AegisBleClient

    override fun attachBaseContext(newBase: android.content.Context) {
        // Apply persisted in-app language before inflation (SharedPreferences convention).
        val tag = runCatching {
            val prefs = newBase.getSharedPreferences("aegis_locale_preferences", android.content.Context.MODE_PRIVATE)
            prefs.getString("app_language_tag", LocalePreferencesStore.TAG_SYSTEM)
                ?: LocalePreferencesStore.TAG_SYSTEM
        }.getOrDefault(LocalePreferencesStore.TAG_SYSTEM)
        super.attachBaseContext(LocaleHelper.wrap(newBase, tag))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        applyScreenshotProtection(window)

        container = AppContainer.getInstance(applicationContext)
        ble = container.bleClient

        setContent {
            AegisApp(container = container, client = ble)
        }
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
    }

    override fun onDestroy() {
        ble.release()
        super.onDestroy()
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AegisApp(container: AppContainer, client: AegisBleClient) {
    val themeViewModel = container.appThemeViewModel
    val onboardingViewModel = container.onboardingWizardViewModel
    val keysViewModel = container.connectedKeysViewModel
    val vaultViewModel = container.keyVaultViewModel
    val secureGuardViewModel = container.secureGuardViewModel
    val totpViewModel = container.totpAuthenticatorViewModel

    val themePref by themeViewModel.themePreference.collectAsState()
    val isSystemDark = isSystemInDarkTheme()
    val darkTheme = when (themePref.mode) {
        AppThemeMode.SYSTEM -> isSystemDark
        AppThemeMode.LIGHT -> false
        AppThemeMode.DARK -> true
    }

    val hasAnyKey by keysViewModel.hasAnyConnectedKey.collectAsState()
    val activeKey by keysViewModel.activeKey.collectAsState()
    val guardUiState by secureGuardViewModel.uiState.collectAsState()

    var showWizard by rememberSaveable { mutableStateOf(!hasAnyKey) }

    LaunchedEffect(hasAnyKey) {
        if (hasAnyKey) {
            showWizard = false
        }
    }

    AegisTheme(darkTheme = darkTheme, dynamicColor = themePref.useDynamicColors) {
        // Guided onboarding displays in full screen when no security key is connected.
        if (!hasAnyKey && showWizard) {
            FriendlyOnboardingWizardScreen(
                viewModel = onboardingViewModel,
                onFinished = {
                    showWizard = false
                }
            )
        } else {
            val nav = rememberNavController()

            DisposableEffect(nav) {
                val listener = NavController.OnDestinationChangedListener { _, dest, _ ->
                    DeviceLog.append(DeviceLog.Category.SYSTEM, "screen=" + (dest.route ?: "?"))
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
                else -> HubDestination.VAULT
            }

            val transportLabel = when (activeKey?.transportType) {
                ConnectionTransportType.BLE -> stringResource(R.string.transport_ble)
                ConnectionTransportType.USB -> stringResource(R.string.transport_usb)
                ConnectionTransportType.WIFI -> stringResource(R.string.transport_wifi)
                ConnectionTransportType.SIMULATOR -> stringResource(R.string.transport_simulator)
                null -> stringResource(R.string.default_security_key_name)
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
                activeKeyName = activeKey?.displayName ?: stringResource(R.string.default_security_key_name),
                isConnected = activeKey?.isCurrentlyConnected == true,
                transportLabel = transportLabel,
                guardState = guardUiState.status.state,
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
                    // 1. Vault Tab
                    composable(HubDestination.VAULT.route) {
                        KeyVaultHubScreen(
                            viewModel = vaultViewModel,
                            secureGuardViewModel = secureGuardViewModel,
                            onNavigateToBackup = {
                                nav.navigate(HubDestination.SETTINGS.route) {
                                    popUpTo(nav.graph.findStartDestination().id) { saveState = true }
                                    launchSingleTop = true
                                }
                            },
                            onNavigateToOta = {
                                nav.navigate(HubDestination.SETTINGS.route) {
                                    popUpTo(nav.graph.findStartDestination().id) { saveState = true }
                                    launchSingleTop = true
                                }
                            }
                        )
                    }

                    // 2. TOTP Tab
                    composable(HubDestination.CODES.route) {
                        TotpDedicatedScreen(
                            viewModel = totpViewModel
                        )
                    }

                    // 3. Devices Tab
                    composable(HubDestination.KEYS.route) {
                        ConnectedKeysRepositoryScreen(
                            viewModel = keysViewModel,
                            onConnectNewKey = { nav.navigate("onboarding-wizard") }
                        )
                    }

                    // 4. Settings Tab
                    composable(HubDestination.SETTINGS.route) {
                        FriendlySettingsAndThemeScreen(
                            themeViewModel = themeViewModel,
                            keysViewModel = keysViewModel,
                            client = client,
                            localeStore = container.localeStore,
                            onNavigateToOnboarding = { nav.navigate("onboarding-wizard") },
                            onNavigateToOta2 = { nav.navigate("ota2") },
                            onNavigateToCaps = { nav.navigate("caps") }
                        )
                    }

                    // Offline firmware update (ota2 engine, no COMMIT)
                    composable("ota2") {
                        val otaTransport =
                            if (client.isReady()) container.bleTransport else container.usbTransport
                        Ota2Screen(
                            transport = otaTransport,
                            currentVersion = activeKey?.firmwareRevision?.toLong() ?: 0L,
                        )
                    }

                    // Board capabilities (GET_CAPS 0x3F, read-only, no auth)
                    composable("caps") {
                        val capsTransport =
                            if (client.isReady()) container.bleTransport else container.usbTransport
                        CapsScreen(
                            transport = capsTransport,
                        )
                    }

                    // Pairing Wizard flow
                    composable("onboarding-wizard") {
                        FriendlyOnboardingWizardScreen(
                            viewModel = onboardingViewModel,
                            onFinished = {
                                nav.navigate(HubDestination.VAULT.route) {
                                    popUpTo(HubDestination.VAULT.route) { inclusive = false }
                                }
                            }
                        )
                    }
                }
            }
        }
    }
}
