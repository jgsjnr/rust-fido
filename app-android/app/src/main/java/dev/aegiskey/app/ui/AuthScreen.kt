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
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.security.AppLock
import dev.aegiskey.app.security.FeatureFlags
import dev.aegiskey.app.security.SanitizedLog
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.ble.BleContract
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Auth (contract section 2): GetAssertion (0x02) over FFF1 plus a dedicated
 * CANCEL (0xBE) action that aborts the active transaction device-side.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AuthScreen(client: AegisBleClient) {
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
    var gaHex by remember { mutableStateOf("") }
    var result by remember { mutableStateOf("—") }

    Scaffold(topBar = { TopAppBar(title = { Text("Auth") }) }) { inner ->
        Column(
            Modifier.padding(inner).verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text("Link: ${state.connection} · FFF2: ${BleContract.statusLabel(state.status)}", maxLines = 2, overflow = TextOverflow.Ellipsis)
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
            OutlinedTextField(
                value = gaHex,
                onValueChange = { gaHex = it },
                label = { Text("GetAssertion CBOR (hex)") },
                supportingText = { Text("Raw params CBOR; sent as [0x02 + CBOR] via OP_MSG.") }
            )
            Button(
                onClick = {
                    scope.launch {
                        busy = true
                        try {
                            val cbor = gaHex.filterNot { it.isWhitespace() }
                                .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                            val response = withContext(Dispatchers.IO) {
                                client.sendMsg(byteArrayOf(BleContract.CTAP_CMD_GET_ASSERTION.toByte()) + cbor)
                            }
                            result = if (response == null) "no response (UP? timeout?)" else "OK · ${response.size} bytes"
                        } catch (e: Exception) {
                            result = "failed: ${(e.message ?: "error").take(48)}"
                        } finally {
                            busy = false
                        }
                    }
                },
                enabled = !busy && gaHex.isNotBlank()
            ) { Text("GetAssertion (0x02)") }
            OutlinedButton(
                onClick = {
                    scope.launch(Dispatchers.IO) {
                        result = if (client.cancel()) "cancel sent (0xBE)" else "cancel failed"
                    }
                }
            ) { Text("Cancel transaction (0xBE)") }
            Text("Result: $result", maxLines = 2, overflow = TextOverflow.Ellipsis)
            Text(
                "User verification happens on the device (ClientPIN + button).",
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}
