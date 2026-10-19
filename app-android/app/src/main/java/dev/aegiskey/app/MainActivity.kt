package dev.aegiskey.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bluetooth
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.security.applyScreenshotProtection
import dev.aegiskey.app.ui.AccountsScreen
import dev.aegiskey.app.ui.AegisTheme
import dev.aegiskey.app.ui.AuthScreen
import dev.aegiskey.app.ui.LogScreen
import dev.aegiskey.app.ui.OnboardingScreen
import dev.aegiskey.app.ui.ScanPairScreen
import dev.aegiskey.app.ui.SettingsScreen
import dev.aegiskey.app.ui.VaultScreen

class MainActivity : ComponentActivity() {
    private lateinit var ble: AegisBleClient

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // FLAG_SECURE app-wide: TOTP codes never leak to screenshots/recents.
        applyScreenshotProtection(window)
        ble = AegisBleClient(applicationContext)
        setContent { AegisApp(ble) }
    }

    override fun onDestroy() {
        ble.release()
        super.onDestroy()
    }
}

private data class Destination(val route: String, val label: String, val icon: ImageVector)

private val DESTINATIONS = listOf(
    Destination("onboarding", "Journey", Icons.Filled.Home),
    Destination("scan", "Pair", Icons.Filled.Bluetooth),
    Destination("accounts", "Keys", Icons.Filled.VpnKey),
    Destination("auth", "Auth", Icons.Filled.Fingerprint),
    Destination("vault", "Vault", Icons.Filled.Lock),
    Destination("log", "Log", Icons.Filled.List),
    Destination("settings", "Settings", Icons.Filled.Settings),
)

@Composable
fun AegisApp(client: AegisBleClient) {
    val nav = rememberNavController()
    AegisTheme {
        Scaffold(
            bottomBar = {
                NavigationBar {
                    val entry by nav.currentBackStackEntryAsState()
                    val current = entry?.destination?.route
                    for (dest in DESTINATIONS) {
                        NavigationBarItem(
                            selected = current == dest.route,
                            onClick = {
                                nav.navigate(dest.route) {
                                    popUpTo(nav.graph.findStartDestination().id) { saveState = true }
                                    launchSingleTop = true
                                    restoreState = true
                                }
                            },
                            icon = { Icon(dest.icon, contentDescription = dest.label) },
                            label = { Text(dest.label) }
                        )
                    }
                }
            }
        ) { inner ->
            NavHost(nav, startDestination = "onboarding", Modifier.padding(inner)) {
                composable("onboarding") { OnboardingScreen(onStart = { nav.navigate("scan") }) }
                composable("scan") { ScanPairScreen(client) }
                composable("accounts") { AccountsScreen(client) }
                composable("auth") { AuthScreen(client) }
                composable("vault") { VaultScreen() }
                composable("log") { LogScreen() }
                composable("settings") { SettingsScreen(onOpenLog = { nav.navigate("log") }) }
            }
        }
    }
}
