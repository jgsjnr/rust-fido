package dev.aegiskey.app.ui

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.ble.BleContract

/**
 * Scan/Pair (contract sections 1, 2, 4): 0xFFFD filter, bonding,
 * FFF4 revision check, FFF2 subscribe. UP stays on the device button.
 */
private fun hasBtPermissions(context: Context): Boolean =
    ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_SCAN) ==
        PackageManager.PERMISSION_GRANTED &&
        ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) ==
        PackageManager.PERMISSION_GRANTED

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanPairScreen(client: AegisBleClient) {
    val context = LocalContext.current
    val state by client.state.collectAsState()
    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { grants ->
        if (grants.values.all { it }) client.startScan()
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Scan / Pair") }) }) { inner ->
        Column(
            Modifier.padding(inner).verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text("Link: ${state.connection} · FFF2: ${BleContract.statusLabel(state.status)}")
            state.revision?.let { Text("GATT revision: 0x%02X (expected 0x01)".format(it)) }
            if (state.connection == AegisBleClient.Connection.SCANNING) CircularProgressIndicator()
            Button(onClick = {
                if (hasBtPermissions(context)) client.startScan()
                else launcher.launch(arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT))
            }) { Text("Scan 0xFFFD") }
            OutlinedButton(onClick = { client.stopScan() }) { Text("Stop") }
            for (device in state.devices) {
                ListItem(
                    headlineContent = { Text(device.name) },
                    supportingContent = { Text(device.address) },
                    trailingContent = {
                        Button(onClick = {
                            client.ensureBonded(device.address)
                            client.connect(device.address)
                        }) { Text("Pair") }
                    }
                )
            }
            if (state.bonded) Text("Bonded (JustWorks+bonding+UP)")
            state.error?.let { Text("Error: $it", color = MaterialTheme.colorScheme.error) }
            Text(
                "UP comes from the device button (hold 5s). The app only surfaces up-needed.",
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}
