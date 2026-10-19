package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.security.AppLock
import dev.aegiskey.app.security.FeatureFlags
import dev.aegiskey.app.security.SanitizedLog
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.ble.BleContract
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Parses even-length hex (no payload is ever logged). */
private fun hexToBytes(hex: String): ByteArray {
    val clean = hex.filterNot { it.isWhitespace() }
    require(clean.length % 2 == 0 && clean.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
        "bad hex"
    }
    return clean.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

/**
 * Accounts (contract section 2): authenticatorGetInfo (0x04) + MakeCredential
 * (0x01) over FFF1 as OP_MSG `[cmd, CBOR...]`. MakeCredential takes raw CBOR
 * hex (dev flow); the transport framing is enforced by the Rust bridge.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AccountsScreen(client: AegisBleClient) {
    val state by client.state.collectAsState()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val appLock = remember { AppLock(context) }
    var unlocked by remember { mutableStateOf(!FeatureFlags.ENABLE_APP_LOCK) }
    if (FeatureFlags.ENABLE_APP_LOCK && !unlocked) {
        LockScreen(appLock = appLock, onUnlocked = { unlocked = true })
        return
    }
    var busy by remember { mutableStateOf(false) }
    var mcHex by remember { mutableStateOf("") }
    var result by remember { mutableStateOf("—") }

    fun send(cmd: Int, cborHex: String) {
        scope.launch {
            busy = true
            try {
                val cbor = hexToBytes(cborHex)
                val response = withContext(Dispatchers.IO) {
                    client.sendMsg(byteArrayOf(cmd.toByte()) + cbor)
                }
                result = if (response == null) "no response (UP? timeout?)" else "OK · ${response.size} bytes"
            } catch (e: Exception) {
                result = "failed: ${(e.message ?: "error").take(48)}"
            } finally {
                busy = false
            }
        }
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Accounts") }) }) { inner ->
        Column(
            Modifier.padding(inner).verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text("Link: ${state.connection} · FFF2: ${BleContract.statusLabel(state.status)}")
            if (FeatureFlags.ENABLE_DEVICE_PRESS && state.status == BleContract.STATUS_UP_NEEDED) {
                PressDeviceSheet(
                    statusLabel = BleContract.statusLabel(state.status),
                    onCancel = {
                        scope.launch(Dispatchers.IO) {
                            client.cancel()
                            SanitizedLog.record(SanitizedLog.Event.DEVICE_PRESS_CANCELLED)
                        }
                    }
                )
            }
            if (busy) CircularProgressIndicator()
            Button(onClick = { send(BleContract.CTAP_CMD_GET_INFO, "") }, enabled = !busy) {
                Text("GetInfo (0x04)")
            }
            OutlinedTextField(
                value = mcHex,
                onValueChange = { mcHex = it },
                label = { Text("MakeCredential CBOR (hex)") },
                supportingText = { Text("Raw params CBOR; sent as [0x01 + CBOR] via OP_MSG.") }
            )
            Button(
                onClick = { send(BleContract.CTAP_CMD_MAKE_CREDENTIAL, mcHex) },
                enabled = !busy && mcHex.isNotBlank()
            ) { Text("MakeCredential (0x01)") }
            Text("Result: $result")
            Text(
                "Credential private material never leaves the device.",
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}
