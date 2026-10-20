package dev.aegiskey.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.security.applyScreenshotProtection
import dev.aegiskey.app.ui.AccountsScreen
import dev.aegiskey.app.ui.AegisScreenColumn
import dev.aegiskey.app.ui.AegisTheme
import dev.aegiskey.app.ui.AuthScreen
import dev.aegiskey.app.ui.BindingWizardScreen
import dev.aegiskey.app.ui.DeviceControlScreen
import dev.aegiskey.app.ui.FriendlyText
import dev.aegiskey.app.ui.ForeignDeviceScreen
import dev.aegiskey.app.ui.LogScreen
import dev.aegiskey.app.ui.OnboardingScreen
import dev.aegiskey.app.ui.RecoveryUnlockScreen
import dev.aegiskey.app.ui.ScanPairScreen
import dev.aegiskey.app.ui.TestModeBanner
import dev.aegiskey.app.ui.SectionTitle
import dev.aegiskey.app.ui.SettingsScreen
import dev.aegiskey.app.ui.TransferOwnershipScreen
import dev.aegiskey.app.ui.UnbindGuideScreen
import dev.aegiskey.app.ui.UsbScreen
import dev.aegiskey.app.ui.VaultScreen
import dev.aegiskey.app.ui.WifiScreen

class MainActivity : ComponentActivity() {
    private lateinit var ble: AegisBleClient

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
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

/**
 * Facilidade (licao: botoes de baixo encavalando):
 * - Barra inferior com 5 itens (maximo confortavel Material3), labels curtas
 *   com ellipsis/maxLines, alwaysShowLabel=false (so a selecionada mostra).
 * - Todas as rotas seguem no NavHost; as secundarias (scan/usb/wifi/log/
 *   settings) saem do hub "Conectar" — sem sobreposicao de conteudo
 *   (Scaffold innerPadding respeitado em TODAS as telas via AegisScreenColumn
 *   ou Modifier.padding(inner) + scroll).
 */
private val BOTTOM_DESTINATIONS = listOf(
    Destination("onboarding", "Inicio", Icons.Filled.Home),
    Destination("accounts", "Chaves", Icons.Filled.VpnKey),
    Destination("auth", "Auth", Icons.Filled.Fingerprint),
    Destination("vault", "Cofre", Icons.Filled.Lock),
    Destination("connect", "Conectar", Icons.Filled.Link),
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AegisApp(client: AegisBleClient) {
    val nav = rememberNavController()
    AegisTheme {
        Scaffold(
            bottomBar = {
                NavigationBar {
                    val entry by nav.currentBackStackEntryAsState()
                    val current = entry?.destination?.route
                    val activeTop = when (current) {
                        "scan", "control", "usb", "wifi", "settings", "log", "binding", "foreign", "transfer", "unbind", "recovery" -> "connect"
                        else -> current
                    }
                    for (dest in BOTTOM_DESTINATIONS) {
                        NavigationBarItem(
                            selected = activeTop == dest.route,
                            onClick = {
                                nav.navigate(dest.route) {
                                    popUpTo(nav.graph.findStartDestination().id) { saveState = true }
                                    launchSingleTop = true
                                    restoreState = true
                                }
                            },
                            icon = { Icon(dest.icon, contentDescription = dest.label) },
                            label = {
                                Text(dest.label, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            },
                            alwaysShowLabel = false,
                        )
                    }
                }
            }
        ) { inner ->
            NavHost(nav, startDestination = "onboarding", Modifier.padding(inner)) {
                composable("onboarding") { OnboardingScreen(onStart = { nav.navigate("scan") }, onOpenKeys = { nav.navigate("accounts") }, onOpenVault = { nav.navigate("vault") }, onOpenLog = { nav.navigate("log") }, client = client) }
                composable("scan") { ScanPairScreen(client, onOpenControl = { nav.navigate("control") }) }
                composable("control") {
                    DeviceControlScreen(
                        client = client,
                        onOpenKeys = { nav.navigate("accounts") },
                        onOpenAuth = { nav.navigate("auth") },
                        onOpenVault = { nav.navigate("vault") },
                        onOpenLog = { nav.navigate("log") },
                        onBack = { nav.popBackStack() },
                    )
                }
                composable("accounts") { AccountsScreen(client) }
                composable("auth") { AuthScreen(client) }
                composable("vault") { VaultScreen(client) }
                composable("usb") { UsbScreen(onUseBle = { nav.navigate("scan") }) }
                composable("wifi") { WifiScreen() }
                composable("connect") { ConnectHub(nav, client) }
                composable("log") { LogScreen() }
                composable("settings") { SettingsScreen(onOpenLog = { nav.navigate("log") }, client = client) }
                composable("binding") { BindingWizardScreen(client, onDone = { nav.navigate("connect") }, onForeignDevice = { nav.navigate("foreign") }) }
                composable("foreign") { ForeignDeviceScreen(onUseUsb = { nav.navigate("usb") }, onBack = { nav.navigate("connect") }) }
                composable("transfer") { TransferOwnershipScreen(client, onDone = { nav.navigate("connect") }) }
                composable("unbind") { UnbindGuideScreen(onDone = { nav.navigate("connect") }) }
                composable("recovery") { RecoveryUnlockScreen(client, onReclaim = { nav.navigate("binding") }, onBack = { nav.navigate("connect") }) }
            }
        }
    }
}

/** Hub Conectar: BLE + USB + WiFi + ajustes (evita 7+ itens na barra). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ConnectHub(nav: NavController, client: AegisBleClient) {
    androidx.compose.material3.Scaffold(
        topBar = { androidx.compose.material3.TopAppBar(title = { Text("Conectar", maxLines = 1, overflow = TextOverflow.Ellipsis) }) },
    ) { inner ->
        AegisScreenColumn(inner = inner) {
            TestModeBanner(client)
            SectionTitle("Como ligar o dispositivo")
            FriendlyText(
                text = "BLE e o caminho principal. USB via cabo e WiFi sao alternativos.",
                maxLines = 3,
            )
            Button(
                onClick = { nav.navigate("scan") },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("BLE: procurar e parear", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            Button(
                onClick = { nav.navigate("control") },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Controle: usar após parear", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            OutlinedButton(
                onClick = { nav.navigate("usb") },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("USB: conectar via cabo", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            OutlinedButton(
                onClick = { nav.navigate("wifi") },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("WiFi: endereco e redes", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            androidx.compose.foundation.layout.Spacer(Modifier.padding(top = 8.dp))
            SectionTitle("Dono e vinculo")
            FriendlyText(
                text = "Uma chave no celular prova que este app e o dono. Sem ela, o dispositivo e de outra pessoa.",
                maxLines = 3,
            )
            Button(
                onClick = { nav.navigate("binding") },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Primeira configuracao (ser dono)", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            OutlinedButton(
                onClick = { nav.navigate("transfer") },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Transferir posse p/ outro celular", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            OutlinedButton(
                onClick = { nav.navigate("unbind") },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Desfazer vinculo", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            OutlinedButton(
                onClick = { nav.navigate("recovery") },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Perdi meu app - recuperar com senha", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            FriendlyText(
                text = "Instalou de novo? Use a senha de 4 a 6 numeros + o botao do dispositivo.",
                maxLines = 2,
                style = androidx.compose.material3.MaterialTheme.typography.bodySmall,
            )
            SectionTitle("Ajustes e diagnostico")
            OutlinedButton(
                onClick = { nav.navigate("settings") },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Ajustes", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            OutlinedButton(
                onClick = { nav.navigate("log") },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Log do dispositivo", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            FriendlyText(
                text = "Dica nao-tecnica: segure o botao do dispositivo 5s para parear; confirme o codigo na tela BLE.",
                maxLines = 4,
                style = androidx.compose.material3.MaterialTheme.typography.bodySmall,
            )
        }
    }
}

// Mantem Arrangement import usado pelo hub via FQN; evita warning de unused.
@Suppress("unused")
private val HubSpacing = Arrangement.spacedBy(12.dp)

