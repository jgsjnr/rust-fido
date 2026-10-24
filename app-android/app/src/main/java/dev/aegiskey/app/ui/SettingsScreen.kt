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
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
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
import androidx.compose.runtime.collectAsState
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
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.net.WifiApi
import dev.aegiskey.app.security.SanitizedLog
import dev.aegiskey.app.security.SdkGate
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
fun SettingsScreen(onOpenLog: () -> Unit = {}, client: AegisBleClient? = null) {
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
            Text("Result: $passMsg", maxLines = 2, overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis)

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

            Text("Protecao e recuperacao", style = MaterialTheme.typography.titleMedium)
            ProtectionRecoverySection(client)

            Text("Politicas do device", style = MaterialTheme.typography.titleMedium)
            DevicePolicySection(client)

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

/**
 * A8 — "Politicas do device": UP vinculado por operacao + LED policy.
 *
 * O app nao configura politica no device (sem opcode p/ isso): as politicas
 * sao aplicadas pelo firmware e aqui sao PROVADAS por comando autenticado.
 * Ordem canonica: binding -> UP -> PIN (dispatch_bind.rs); sem vinculo o
 * device responde 0x05 e o app nem envia (aviso PermissionDenied). Cada acao
 * passa por `SdkGate.requirePolicy()` antes de qualquer fio; deny/NotCompiled
 * vira aviso proprio, nunca crash, nunca `todo()`. A sonda eh o OATH_LIST
 * (0x25): so leitura (binding+UP, sem efeito colateral); o resultado mostra
 * opcode+status e a contagem de contas — nomes e segredos nunca saem do
 * device, e nada sensivel entra no Log.
 */
@Composable
private fun DevicePolicySection(client: AegisBleClient?) {
    val scope = rememberCoroutineScope()
    val link = client?.state?.collectAsState()?.value
    var policyGate by remember { mutableStateOf<SdkGate.GateOutcome?>(null) }
    var gateNote by remember { mutableStateOf<String?>(null) }
    var upResult by remember { mutableStateOf("-") }
    var ledResult by remember { mutableStateOf("-") }
    var busy by remember { mutableStateOf(false) }

    /** Gate + link + vinculo; false = nao enviar (aviso ja preenchido). */
    fun precheck(): Boolean {
        val warning = policyGateNotice(SdkGate.requirePolicy().also { policyGate = it })
        if (warning != null) {
            gateNote = warning
            DeviceLog.append(DeviceLog.Category.SYSTEM, "policy gate denied")
            return false
        }
        val ble = client
        if (ble == null || link == null) {
            gateNote = "conecte via BLE primeiro (tela Conectar) - nada foi enviado"
            return false
        }
        if (link.connection != AegisBleClient.Connection.READY) {
            gateNote = "conecte primeiro (Conectar -> BLE) - nada foi enviado"
            return false
        }
        if (!link.bonded) {
            gateNote = "sem vinculo - faca a primeira configuracao (PermissionDenied, nada foi enviado)"
            DeviceLog.append(DeviceLog.Category.SYSTEM, "policy sem vinculo (nao enviado)")
            return false
        }
        gateNote = null
        return true
    }

    /** Sonda autenticada 0x25 (binding+UP, so leitura); resultado so metadados. */
    fun runProbe(tag: String, setResult: (String) -> Unit) {
        if (!precheck()) return
        val ble = client ?: return
        scope.launch {
            busy = true
            setResult("enviando 0x25... toque no botao do dispositivo se pedir")
            try {
                val raw = withContext(Dispatchers.IO) {
                    ble.sendVendor(VendorOps.OP_OATH_LIST, ByteArray(0))
                }
                val resp = VendorOps.parseResponse(raw)
                setResult(
                    when {
                        resp == null -> "sem resposta - toque no botao e tente de novo"
                        resp.status == VendorOps.STATUS_OK -> {
                            val n = VendorOps.parseOathList(resp.tlv).size
                            DeviceLog.append(
                                DeviceLog.Category.BLE,
                                tag + " 0x25 ok " + n + " contas",
                            )
                            "0x25 ok - " + n + " contas (so contagem, sem nomes)"
                        }
                        else -> {
                            val wire = SdkGate.mapWireStatus(resp.status)
                            DeviceLog.append(
                                DeviceLog.Category.BLE,
                                tag + " 0x25 status=" + resp.status,
                            )
                            when (wire) {
                                SdkGate.GateOutcome.PermissionDenied ->
                                    if (resp.status == VendorOps.STATUS_NEED_BINDING) {
                                        "sem vinculo - faca a primeira configuracao"
                                    } else {
                                        "toque no botao do dispositivo (UP) e tente de novo"
                                    }
                                else -> VendorOps.statusLabel(resp.status)
                            }
                        }
                    },
                )
            } catch (e: Exception) {
                setResult((e.message ?: "falha na prova").take(64))
            } finally {
                busy = false
            }
        }
    }

    val banner = policyGate?.let { SdkGate.gateBannerState(it) }
    if (banner != null) {
        GateBanner(gate = banner)
    }
    gateNote?.let {
        Text(it, style = MaterialTheme.typography.bodySmall)
    }
    if (busy) CircularProgressIndicator()
    Card {
        Column(Modifier.padding(12.dp)) {
            Text("UP vinculado por operacao", style = MaterialTheme.typography.titleSmall)
            Text(
                "Cada toque no botao autoriza UMA operacao (grant de uso unico, " +
                    "janela de 60 s). Repetir a operacao exige novo toque.",
                style = MaterialTheme.typography.bodySmall,
            )
            OutlinedButton(
                onClick = { runProbe("policy up-check", { upResult = it }) },
                enabled = !busy,
            ) { Text("Verificar UP (comando autenticado)") }
            Text("Resultado: " + upResult, style = MaterialTheme.typography.bodySmall)
        }
    }
    Card {
        Column(Modifier.padding(12.dp)) {
            Text("LED so sob comando autenticado", style = MaterialTheme.typography.titleSmall)
            Text(
                "O app nao acende o LED (sem opcode p/ isso): o LED so muda por " +
                    "comando autenticado do device. Observe durante a prova: pedido " +
                    "de toque, pulso de sucesso ou clarao de erro.",
                style = MaterialTheme.typography.bodySmall,
            )
            OutlinedButton(
                onClick = { runProbe("policy led-check", { ledResult = it }) },
                enabled = !busy,
            ) { Text("Verificar LED (comando autenticado)") }
            Text("Resultado: " + ledResult, style = MaterialTheme.typography.bodySmall)
        }
    }
}

/**
 * Gate R4 p/ aviso proprio (nunca crash): null = pode operar
 * (Success/RealVerified); resto = texto honesto p/ a tela.
 */
private fun policyGateNotice(outcome: SdkGate.GateOutcome): String? = when (outcome) {
    SdkGate.GateOutcome.Success, SdkGate.GateOutcome.RealVerified -> null
    is SdkGate.GateOutcome.NotCompiled ->
        "Politica fora da compilacao deste app (NotCompiled honesto) - sem acao no device."
    is SdkGate.GateOutcome.ExternalBlocked ->
        "sem transporte nativo (bloqueado) - conecte o device e tente de novo."
    SdkGate.GateOutcome.PermissionDenied ->
        "device pediu prova (binding -> UP -> PIN) - vincule/toque e tente de novo."
    SdkGate.GateOutcome.Unsupported ->
        "device recusou a prova - firmware antiga?"
    SdkGate.GateOutcome.Unavailable ->
        "device indisponivel agora - tente de novo."
}