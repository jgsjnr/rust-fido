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
import androidx.compose.ui.Modifier
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

    AegisTheme(darkTheme = darkTheme, dynamicColor = themePref.useDynamicColors) {
        // Guided onboarding displays in full screen when no security key is connected.
        if (!hasAnyKey) {
            OnboardingWizardScreen(
                viewModel = onboardingViewModel,
                onFinished = {
                    // Completing onboarding registers the key, transitioning hasAnyKey to true.
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
                ConnectionTransportType.BLE -> "Bluetooth"
                ConnectionTransportType.USB -> "USB Cable"
                ConnectionTransportType.WIFI -> "Wi-Fi"
                ConnectionTransportType.SIMULATOR -> "Virtual Simulator"
                null -> "Security Key"
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
                activeKeyName = activeKey?.displayName ?: "Security Key",
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
                            onNavigateToOnboarding = { nav.navigate("onboarding-wizard") }
                        )
                    }

                    // Pairing Wizard flow
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
                }
            }
        }
    }
}
