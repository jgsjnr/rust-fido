package dev.aegiskey.app.ui

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.hardware.usb.UsbManager
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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.ble.BleContract
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.security.SanitizedLog
import dev.aegiskey.app.security.SdkGate
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Scan/Pair + proximidade A7 (contrato secoes 1, 2, 4 + plano A7):
 * 0xFFFD scan/bond, FFF4 revisao, FFF2 subscribe. UP fica no botao do device.
 * Proximidade: pares bonded com anuncio 0xFFFE, walkaway com trava em
 * -75 dBm por 10 s (voltar NAO destrava), USB ativo veta BLE-proximidade
 * por desenho. Sem par = ExternalBlocked honesto (sem fantasma).
 *
 * Gates: toda acao passa por SdkGate.requireProximity(); denies viram
 * aviso proprio da tela (nunca crash, nunca GateBanner emprestado).
 * Sem telemetria inventada: sem RSSI ao vivo, sem beacon fantasma.
 * Sem segredo em log: so tokens fixos (ver DeviceLog/SanitizedLog).
 *
 * Permissoes (minSdk 31 / target 34, API 31+):
 * - BLUETOOTH_SCAN (neverForLocation) + BLUETOOTH_CONNECT via
 *   RequestMultiplePermissions. Scan/bond/connect so com permissao.
 * - ACCESS_FINE/COARSE_LOCATION nunca pedida: filtro 0xFFFD nao precisa
 *   e o app nunca deriva localizacao fisica.
 */
private val REQUIRED_BT_PERMISSIONS = arrayOf(
    Manifest.permission.BLUETOOTH_SCAN,
    Manifest.permission.BLUETOOTH_CONNECT,
)

/** Anuncio de proximidade: so par bonded ve 0xFFFE (nunca inventado). */
private const val PROXIMITY_ADV_UUID16 = 0xFFFE

/** Politica walkaway fixa (texto honesto; sem RSSI ao vivo nesta tela). */
private const val WALK_AWAY_RSSI_DBM = -75
private const val WALK_AWAY_SECONDS = 10

/** USB veto por desenho: VID/PID do firmware (mesmo de UsbCtaphid). */
private const val USB_VID = 0x303A
private const val USB_PID = 0xAE61

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

/** USB ativo = AegisKey plugada (VID/PID); veta proximidade por desenho. */
private fun isUsbActive(context: Context): Boolean {
    return try {
        val usb = context.getSystemService(Context.USB_SERVICE) as? UsbManager ?: return false
        usb.deviceList.values.any { it.vendorId == USB_VID && it.productId == USB_PID }
    } catch (_: Exception) {
        false
    }
}

/**
 * Aviso proprio p/ denies do gate de proximidade (R4 sem banner honesto).
 * Null = liberado (Success/RealVerified).
 */
private fun proximityGateNotice(outcome: SdkGate.GateOutcome): String? = when (outcome) {
    SdkGate.GateOutcome.Success, SdkGate.GateOutcome.RealVerified -> null
    is SdkGate.GateOutcome.NotCompiled ->
        "Proximidade fora deste build (NotCompiled honesto): nada foi enviado ao device."
    is SdkGate.GateOutcome.ExternalBlocked ->
        when (outcome.reason) {
            SdkGate.BlockReason.NO_NATIVE_LIB -> "Proximidade bloqueada: lib nativa ausente. Nada foi enviado."
            SdkGate.BlockReason.NO_TRANSPORT -> "Proximidade bloqueada: sem transporte BLE. Nada foi enviado."
            SdkGate.BlockReason.NO_PEER -> "Proximidade bloqueada: sem par pareado (NO_PEER). Nada foi enviado."
            SdkGate.BlockReason.LAB_MOCKS_OFF -> "Proximidade bloqueada: sem caminho real (mocks off). Nada foi enviado."
        }
    SdkGate.GateOutcome.PermissionDenied ->
        "Proximidade pede prova no device (vinculo -> botao -> PIN). Toque no aparelho e tente de novo."
    SdkGate.GateOutcome.Unsupported -> "Proximidade nao suportada aqui. Nada foi inventado."
    SdkGate.GateOutcome.Unavailable -> "Proximidade indisponivel agora. Tente de novo."
}

@Composable
private fun PermissionRationaleDialog(onConfirm: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Bluetooth necessario") },
        text = {
            Text(
                "Scan encontra AegisKey-XXXX pelo filtro 0xFFFD sem usar " +
                    "localizacao, e Conexao pareia via bonding. " +
                    "Localizacao nunca e pedida nem usada."
            )
        },
        confirmButton = { TextButton(onClick = onConfirm) { Text("Continuar") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Agora nao") } },
    )
}

@Composable
private fun PermanentlyDeniedCard(onOpenSettings: () -> Unit, onRetry: () -> Unit) {
    Text(
        "Permissao negada permanentemente. Ative Bluetooth em Ajustes " +
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
fun ScanPairScreen(client: AegisBleClient, onOpenControl: () -> Unit = {}) {
    val context = LocalContext.current
    val activity = context as? Activity
    val scope = rememberCoroutineScope()
    val state by client.state.collectAsState()
    var showRationale by remember { mutableStateOf(false) }
    var permanentlyDenied by remember { mutableStateOf(false) }
    val granted = hasBtPermissions(context)

    var proximityNotice by remember { mutableStateOf<String?>(null) }
    var usbActive by remember { mutableStateOf(false) }
    var everReady by remember { mutableStateOf(false) }

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

    fun refreshUsbActive() {
        usbActive = isUsbActive(context)
    }

    /** Toda acao de proximidade passa aqui primeiro (deny = aviso proprio). */
    fun checkProximityGate(): Boolean {
        val warning = proximityGateNotice(SdkGate.requireProximity())
        proximityNotice = warning
        if (warning != null) {
            DeviceLog.append(DeviceLog.Category.SYSTEM, "proximity gate denied")
            return false
        }
        return true
    }

    /** Coex por desenho: USB ativo veta BLE-proximidade (aviso honesto). */
    fun checkCoex(): Boolean {
        refreshUsbActive()
        if (usbActive) {
            proximityNotice =
                "USB ativo veta BLE-proximidade por desenho: desconecte o cabo para usar proximidade. Nada foi enviado via BLE."
            DeviceLog.append(DeviceLog.Category.SYSTEM, "proximity usb veto")
            return false
        }
        return true
    }

    fun gatedStartScan() {
        if (!checkProximityGate()) return
        if (!checkCoex()) return
        if (granted) {
            proximityNotice = null
            client.startScan()
            DeviceLog.append(DeviceLog.Category.BLE, "proximity scan started")
        } else {
            requestScanPermissions()
        }
    }

    fun gatedStopScan() {
        if (!checkProximityGate()) return
        client.stopScan()
        DeviceLog.append(DeviceLog.Category.BLE, "proximity scan stopped")
    }

    fun gatedPair(address: String, name: String) {
        if (!checkProximityGate()) return
        if (!checkCoex()) return
        // Sem segredo em log: so prefixo fixo do nome, nunca endereco/segredo.
        DeviceLog.append(DeviceLog.Category.PAIRING, "proximity pair tocado: " + name.take(24))
        client.ensureBonded(address)
        client.connect(address)
    }

    fun gatedResubscribe() {
        if (!checkProximityGate()) return
        if (!checkCoex()) return
        proximityNotice = null
        client.resubscribe()
        DeviceLog.append(DeviceLog.Category.BLE, "proximity resubscribe")
    }

    fun gatedCancelUp() {
        if (!checkProximityGate()) return
        scope.launch(Dispatchers.IO) {
            client.cancel()
            SanitizedLog.record(SanitizedLog.Event.DEVICE_PRESS_CANCELLED)
        }
    }

    // Sonda do gate uma vez (efeito, nao composicao) + estado USB inicial.
    LaunchedEffect(Unit) {
        val warning = proximityGateNotice(SdkGate.requireProximity())
        proximityNotice = warning
        refreshUsbActive()
    }

    // Walkaway: trava apos sair de READY tendo estado READY antes.
    // Derivado so de connection (sem RSSI inventado); voltar sozinho
    // NAO destrava: precisa de Pair/Conectar explicito (gated).
    LaunchedEffect(state.connection) {
        if (state.connection == AegisBleClient.Connection.READY) {
            everReady = true
            refreshUsbActive()
        } else if (everReady && state.connection != AegisBleClient.Connection.READY) {
            DeviceLog.append(DeviceLog.Category.LOCK, "proximity walkaway locked")
        }
    }
    val walkawayLocked = everReady && state.connection != AegisBleClient.Connection.READY

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
            Text("Link: ${connectionLabel(state.connection)} · FFF2: ${BleContract.statusLabel(state.status)}", maxLines = 2, overflow = TextOverflow.Ellipsis)
            state.revision?.let { Text("Revisão: 0x%02X (esperado 0x01)".format(it)) }
            if (state.connection == AegisBleClient.Connection.SCANNING) CircularProgressIndicator()
            if (state.status == BleContract.STATUS_UP_NEEDED) {
                PressDeviceSheet(
                    statusLabel = BleContract.statusLabel(state.status),
                    onCancel = { gatedCancelUp() },
                )
            }
            if (state.connection == AegisBleClient.Connection.READY) {
                Button(onClick = onOpenControl) { Text("Abrir controle") }
                OutlinedButton(onClick = { gatedResubscribe() }) { Text("Re-assinar avisos") }
            }
            if (state.connection == AegisBleClient.Connection.ERROR) {
                OutlinedButton(onClick = { gatedResubscribe() }) { Text("Tentar de novo (re-assinar)") }
                OutlinedButton(onClick = onOpenControl) { Text("Abrir controle") }
            }
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
            Button(onClick = { gatedStartScan() }) { Text("Scan 0xFFFD") }
            OutlinedButton(
                onClick = { gatedStopScan() },
                enabled = state.connection == AegisBleClient.Connection.SCANNING && granted,
            ) { Text("Stop") }
            for (device in state.devices) {
                DeviceRow(
                    name = device.name,
                    address = device.address,
                    gated = granted,
                    onPair = { gatedPair(device.address, device.name) },
                    onNeedPermissions = { requestScanPermissions() },
                )
            }
            if (state.bonded) Text("Pareado (botão + código confirmados)")
            state.error?.let { Text("Erro: $it", color = MaterialTheme.colorScheme.error, maxLines = 2, overflow = TextOverflow.Ellipsis) }
            Text(
                "O toque vem do botão do aparelho (segure 5s). O app só mostra quando precisa tocar.",
                style = MaterialTheme.typography.bodySmall
            )

            // ---- A7 proximidade (0xFFFE bonded + walkaway + coex USB) ----
            Text(
                "Proximidade (par bonded, anuncio 0xFFFE)",
                style = MaterialTheme.typography.titleMedium,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                "Pares de proximidade sao bonded com anuncio 0xFFFE. " +
                    "Esta tela nunca inventa beacon: sem par, a lista fica vazia.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 4,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                "Walkaway: trava em <= " + WALK_AWAY_RSSI_DBM + " dBm por " + WALK_AWAY_SECONDS + " s. " +
                    "Voltar NAO destrava: toque em Pair/Conectar de novo (com gate).",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 4,
                overflow = TextOverflow.Ellipsis,
            )
            if (usbActive) {
                Text(
                    "USB ativo veta BLE-proximidade por desenho: desconecte o cabo para usar proximidade.",
                    color = MaterialTheme.colorScheme.error,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
                )
                OutlinedButton(onClick = { refreshUsbActive() }) { Text("Verificar USB de novo") }
            }
            if (walkawayLocked) {
                Text(
                    "Travado por afastamento (walkaway): voltar sozinho NAO destrava. " +
                        "Toque em Pair/Conectar do par bonded para liberar.",
                    color = MaterialTheme.colorScheme.error,
                    maxLines = 4,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            proximityNotice?.let {
                Text(it, color = MaterialTheme.colorScheme.error, maxLines = 4, overflow = TextOverflow.Ellipsis)
            }
            if (!state.bonded) {
                Text(
                    "Sem par pareado (ExternalBlocked NO_PEER honesto): pareie pelo scan 0xFFFD acima. " +
                        "Nenhum par de proximidade listado ate la (sem fantasma).",
                    maxLines = 4,
                    overflow = TextOverflow.Ellipsis,
                )
            } else if (state.devices.isEmpty()) {
                Text(
                    "Pareado, mas sem anuncio 0xFFFE visivel agora: aproxime o par bonded e toque em Scan. " +
                        "Nenhum beacon inventado.",
                    maxLines = 4,
                    overflow = TextOverflow.Ellipsis,
                )
            } else {
                Text(
                    "Par bonded visivel (" + state.devices.size + " no scan): anuncio 0xFFFE so para par bonded. " +
                        "Pair passa pelo gate de proximidade.",
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 4,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            OutlinedButton(onClick = onOpenControl) { Text("Voltar ao controle") }
        }
    }
}

private fun connectionLabel(connection: AegisBleClient.Connection): String = when (connection) {
    AegisBleClient.Connection.IDLE -> "desligado"
    AegisBleClient.Connection.SCANNING -> "procurando"
    AegisBleClient.Connection.CONNECTING -> "ligando"
    AegisBleClient.Connection.READY -> "ligado"
    AegisBleClient.Connection.ERROR -> "erro"
}
