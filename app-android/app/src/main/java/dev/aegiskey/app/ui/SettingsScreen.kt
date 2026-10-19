package dev.aegiskey.app.ui

import android.Manifest
import android.bluetooth.BluetoothManager
import android.content.Context
import android.content.pm.PackageManager
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.net.WifiApi
import dev.aegiskey.app.security.SanitizedLog
import dev.aegiskey.app.security.SecureStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Settings (contract section 6 + hygiene): AP password swap via UP+PIN
 * (POST /config/wifi), bonded-device list, double-confirmed LOCAL wipe
 * (app data only -- device state untouched, no wipe endpoint in contract),
 * and the sanitized event log (names only, never values).
 *
 * The bonded list requires BLUETOOTH_CONNECT (API 31+ runtime). The
 * permission itself is requested once in ScanPairScreen (single owner);
 * here we only gate the read so the screen never throws
 * SecurityException when the permission is missing.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(onOpenLog: () -> Unit = {}) {
    val context = LocalContext.current
    val store = remember { SecureStore(context) }
    val scope = rememberCoroutineScope()
    var baseUrl by remember { mutableStateOf("http://192.168.4.1") }
    var newPass by remember { mutableStateOf("") }
    var passMsg by remember { mutableStateOf("—") }
    var wipeStep by remember { mutableIntStateOf(0) }
    var logTick by remember { mutableIntStateOf(0) }

    val hasConnect = ContextCompat.checkSelfPermission(
        context, Manifest.permission.BLUETOOTH_CONNECT
    ) == PackageManager.PERMISSION_GRANTED
    val bonded = remember(hasConnect) {
        if (!hasConnect) emptyList()
        else {
            val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
            runCatching {
                manager.adapter?.bondedDevices?.map { it.address }?.sorted().orEmpty()
            }.getOrDefault(emptyList())
        }
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Settings") }) }) { inner ->
        Column(
            Modifier.padding(inner).verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text("WiFi AP password (UP+PIN)", style = MaterialTheme.typography.titleMedium)
            OutlinedTextField(value = baseUrl, onValueChange = { baseUrl = it }, label = { Text("Device base URL") })
            OutlinedTextField(value = newPass, onValueChange = { newPass = it }, label = { Text("New AP password") })
            if (!AegisBridge.wifiPasswordValid(newPass) && newPass.isNotEmpty()) {
                Text("Hint: 8..63 ASCII chars.", color = MaterialTheme.colorScheme.error)
            }
            Button(onClick = {
                scope.launch {
                    try {
                        withContext(Dispatchers.IO) { WifiApi.postWifiPassword(baseUrl, newPass) }
                        passMsg = "changed (device confirmed UP+PIN)"
                    } catch (e: Exception) {
                        passMsg = (e.message ?: "change failed").take(64)
                    }
                }
            }) { Text("Change AP password") }
            Text("Result: $passMsg")

            Text("Bonded devices", style = MaterialTheme.typography.titleMedium)
            if (!hasConnect) {
                Text(
                    "Bluetooth permission needed -- grant Scan + Conexao on the Pair screen.",
                    style = MaterialTheme.typography.bodySmall,
                )
            } else if (bonded.isEmpty()) Text("none")
            for (address in bonded) {
                ListItem(headlineContent = { Text("Bonded device") }, supportingContent = { Text(address) })
            }
            Text("Unpair from system Bluetooth settings.", style = MaterialTheme.typography.bodySmall)

            Text("Local data", style = MaterialTheme.typography.titleMedium)
            OutlinedButton(onClick = { wipeStep = 1 }) { Text("Wipe local app data") }
            Text("Erases encrypted prefs + saved envelopes on THIS phone. Device untouched.")

            OutlinedButton(onClick = onOpenLog) { Text("Abrir Log do dispositivo") }
            Text(
                "Texto ao vivo do device (FFF1/FFF2 + HTTP). ltrace completo via serial.",
                style = MaterialTheme.typography.bodySmall
            )
            Text("Sanitized log", style = MaterialTheme.typography.titleMedium)
            for (line in SanitizedLog.snapshot().takeLast(20)) {
                Text(line, style = MaterialTheme.typography.bodySmall)
            }
            OutlinedButton(onClick = { logTick += 1 }) { Text("Refresh log ($logTick)") }
        }
    }

    if (wipeStep == 1) {
        AlertDialog(
            onDismissRequest = { wipeStep = 0 },
            title = { Text("Wipe local app data?") },
            text = { Text("Step 1/2: this erases encrypted prefs and saved envelopes on this phone.") },
            confirmButton = { TextButton(onClick = { wipeStep = 2 }) { Text("Continue") } },
            dismissButton = { TextButton(onClick = { wipeStep = 0 }) { Text("Cancel") } }
        )
    }
    if (wipeStep == 2) {
        AlertDialog(
            onDismissRequest = { wipeStep = 0 },
            title = { Text("Really erase?") },
            text = { Text("Step 2/2: confirm local wipe. The device is NOT affected.") },
            confirmButton = {
                TextButton(onClick = {
                    store.wipeAll()
                    wipeStep = 0
                }) { Text("Erase") }
            },
            dismissButton = { TextButton(onClick = { wipeStep = 0 }) { Text("Cancel") } }
        )
    }
}