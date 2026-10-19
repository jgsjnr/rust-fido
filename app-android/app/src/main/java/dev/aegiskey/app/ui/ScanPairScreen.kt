package dev.aegiskey.app.ui

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.ble.BleContract

/**
 * Scan/Pair (contract sections 1, 2, 4): 0xFFFD filter, bonding,
 * FFF4 revision check, FFF2 subscribe. UP stays on the device button.
 *
 * Permissions (minSdk 31 / target 34, API 31+ model):
 * - BLUETOOTH_SCAN (neverForLocation, see Manifest) + BLUETOOTH_CONNECT
 *   are requested here via RequestMultiplePermissions. All BLE actions
 *   (scan, bond, connect) are gated behind [hasBtPermissions].
 * - ACCESS_FINE/COARSE_LOCATION is NEVER requested: the 0xFFFD filter
 *   needs no location and the app never derives physical location.
 *   Do NOT add a location request "to fix scan" — scan works with
 *   neverForLocation on API 31+.
 * - BLUETOOTH_ADVERTISE / NEARBY_WIFI_DEVICES / POST_NOTIFICATIONS are
 *   not used by this app (central only, plain HTTP to AP IP, no FGS).
 */
private val REQUIRED_BT_PERMISSIONS = arrayOf(
    Manifest.permission.BLUETOOTH_SCAN,
    Manifest.permission.BLUETOOTH_CONNECT,
)

private fun hasBtPermissions(context: Context): Boolean =
    ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_SCAN) ==
        PackageManager.PERMISSION_GRANTED &&
        ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) ==
        PackageManager.PERMISSION_GRANTED

private fun shouldShowBtRationale(activity: Activity?): Boolean {
    if (activity == null) return false
    return REQUIRED_BT_PERMISSIONS.any { activity.shouldShowRequestPermissionRationale(it) }
}

private fun openAppSettings(context: Context) {
    val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
        data = Uri.fromParts("package", context.packageName, null)
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    context.startActivity(intent)
}

@Composable
private fun PermissionRationaleDialog(onConfirm: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Bluetooth necessário") },
        text = {
            Text(
                "Scan encontra AegisKey-XXXX pelo filtro 0xFFFD sem usar " +
                    "localizacao, e Conexão pareia via bonding. " +
                    "Localizacao nunca e pedida nem usada."
            )
        },
        confirmButton = { TextButton(onClick = onConfirm) { Text("Continuar") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Agora não") } },
    )
}

@Composable
private fun PermanentlyDeniedCard(onOpenSettings: () -> Unit, onRetry: () -> Unit) {
    Text(
        "Permissão negada permanentemente. Ative Bluetooth em Ajustes " +
            "para escanear e parear.",
        color = MaterialTheme.colorScheme.error,
    )
    OutlinedButton(onClick = onOpenSettings) { Text("Abrir Ajustes") }
    OutlinedButton(onClick = onRetry) { Text("Tentar novamente") }
}

@Composable
private fun DeviceRow(
    name: String,
    address: String,
    gated: Boolean,
    onPair: () -> Unit,
    onNeedPermissions: () -> Unit,
) {
    ListItem(
        headlineContent = { Text(name, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        supportingContent = { Text(address, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        trailingContent = {
            Button(onClick = { if (gated) onPair() else onNeedPermissions() }) { Text("Pair") }
        },
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanPairScreen(client: AegisBleClient) {
    val context = LocalContext.current
    val activity = context as? Activity
    val state by client.state.collectAsState()
    var showRationale by remember { mutableStateOf(false) }
    var permanentlyDenied by remember { mutableStateOf(false) }
    val granted = hasBtPermissions(context)

    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { grants ->
        if (grants.values.all { it }) {
            permanentlyDenied = false
            showRationale = false
            client.startScan()
        } else {
            permanentlyDenied = !shouldShowBtRationale(activity)
            showRationale = !permanentlyDenied
        }
    }

    fun requestScanPermissions() {
        when {
            permanentlyDenied -> openAppSettings(context)
            shouldShowBtRationale(activity) -> showRationale = true
            else -> launcher.launch(REQUIRED_BT_PERMISSIONS)
        }
    }

    if (showRationale) {
        PermissionRationaleDialog(
            onConfirm = {
                showRationale = false
                launcher.launch(REQUIRED_BT_PERMISSIONS)
            },
            onDismiss = { showRationale = false },
        )
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Scan / Pair") }) }) { inner ->
        Column(
            Modifier.padding(inner).verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text("Link: ${state.connection} · FFF2: ${BleContract.statusLabel(state.status)}", maxLines = 2, overflow = TextOverflow.Ellipsis)
            state.revision?.let { Text("GATT revision: 0x%02X (expected 0x01)".format(it)) }
            if (state.connection == AegisBleClient.Connection.SCANNING) CircularProgressIndicator()
            if (!granted) {
                Text(
                    "Para teste IRL: permita Scan + Conexão quando solicitado. " +
                        "Sem isso o botao abaixo só abre o pedido.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (permanentlyDenied && !granted) {
                PermanentlyDeniedCard(
                    onOpenSettings = { openAppSettings(context) },
                    onRetry = { launcher.launch(REQUIRED_BT_PERMISSIONS) },
                )
            }
            Button(onClick = {
                if (granted) client.startScan() else requestScanPermissions()
            }) { Text("Scan 0xFFFD") }
            OutlinedButton(
                onClick = { if (granted) client.stopScan() },
                enabled = state.connection == AegisBleClient.Connection.SCANNING && granted,
            ) { Text("Stop") }
            for (device in state.devices) {
                DeviceRow(
                    name = device.name,
                    address = device.address,
                    gated = granted,
                    onPair = {
                        client.ensureBonded(device.address)
                        client.connect(device.address)
                    },
                    onNeedPermissions = { requestScanPermissions() },
                )
            }
            if (state.bonded) Text("Bonded (JustWorks+bonding+UP)")
            state.error?.let { Text("Error: $it", color = MaterialTheme.colorScheme.error, maxLines = 2, overflow = TextOverflow.Ellipsis) }
            Text(
                "UP comes from the device button (hold 5s). The app only surfaces up-needed.",
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}