package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.security.AppLock
import dev.aegiskey.app.security.FeatureFlags
import dev.aegiskey.app.net.WifiApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

/**
 * OATH vault (contract section 7): TOTP codes are generated ON the device via
 * GET /oath/code and shown display-only with a live 30s countdown.
 * Secrets are never transported, displayed or stored — only account + code.
 * Import/export handles AEGN envelopes (validated by the Rust bridge,
 * at rest only inside EncryptedFile).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultScreen() {
    val context = LocalContext.current
    val appLock = remember { AppLock(context) }
    var unlocked by remember { mutableStateOf(!FeatureFlags.ENABLE_APP_LOCK) }
    if (FeatureFlags.ENABLE_APP_LOCK && !unlocked) {
        LockScreen(appLock = appLock, onUnlocked = { unlocked = true })
        return
    }
    val clipboard = LocalClipboardManager.current
    val scope = rememberCoroutineScope()
    var baseUrl by remember { mutableStateOf("http://192.168.4.1") }
    var account by remember { mutableStateOf("") }
    var entries by remember { mutableStateOf(listOf<AegisBridge.OathEntry>()) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var envHex by remember { mutableStateOf("") }
    var envInfo by remember { mutableStateOf("—") }
    var savedCount by remember { mutableStateOf(0) }
    var nowSec by remember { mutableStateOf(System.currentTimeMillis() / 1000) }

    LaunchedEffect(Unit) {
        while (true) {
            delay(1000)
            nowSec = System.currentTimeMillis() / 1000
        }
    }

    fun fetch() {
        scope.launch {
            busy = true
            error = null
            try {
                val entry = withContext(Dispatchers.IO) { WifiApi.getOathCode(baseUrl, account.trim()) }
                entries = (entries.filterNot { it.account == entry.account } + entry).take(32)
            } catch (e: Exception) {
                error = (e.message ?: "fetch failed").take(64)
            } finally {
                busy = false
            }
        }
    }

    fun importEnvelope() {
        scope.launch(Dispatchers.Default) {
            try {
                val clean = envHex.filterNot { it.isWhitespace() }
                require(clean.length % 2 == 0) { "bad hex" }
                val bytes = clean.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                val ctLen = AegisBridge.envelopeValidate(bytes).getOrThrow()
                envInfo = "valid AEGN envelope · ct $ctLen bytes"
                val key = MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
                val file = File(context.filesDir, "envelope_${System.currentTimeMillis()}.aegn")
                val enc = EncryptedFile.Builder(
                    context, file, key,
                    EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
                ).build()
                withContext(Dispatchers.IO) { enc.openFileOutput().use { it.write(bytes) } }
                savedCount += 1
            } catch (e: Exception) {
                envInfo = "invalid: ${(e.message ?: "error").take(48)}"
            }
        }
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Vault (OATH)") }) }) { inner ->
        Column(
            Modifier.padding(inner).verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedTextField(value = baseUrl, onValueChange = { baseUrl = it }, label = { Text("Device base URL") })
            OutlinedTextField(value = account, onValueChange = { account = it }, label = { Text("Account (e.g. GitHub:alice)") })
            Button(onClick = ::fetch, enabled = !busy && account.isNotBlank()) { Text("Fetch code") }
            if (busy) CircularProgressIndicator()
            error?.let { Text("Error: $it", color = MaterialTheme.colorScheme.error) }
            for (entry in entries) {
                val remaining = AegisBridge.remainingSeconds(nowSec)
                Card {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(entry.account, style = MaterialTheme.typography.titleMedium)
                        Text(entry.code, style = MaterialTheme.typography.displaySmall)
                        LinearProgressIndicator(progress = remaining / 30f)
                        Text("$remaining s left in the 30s window")
                        OutlinedButton(onClick = { clipboard.setText(AnnotatedString(entry.code)) }) {
                            Text("Copy code")
                        }
                    }
                }
            }
            Text("Import / export AEGN envelope", style = MaterialTheme.typography.titleMedium)
            OutlinedTextField(value = envHex, onValueChange = { envHex = it }, label = { Text("Envelope (hex)") })
            Button(onClick = ::importEnvelope, enabled = envHex.isNotBlank()) { Text("Validate + save encrypted") }
            Text("Envelope: $envInfo · saved files: $savedCount")
            Text(
                "Only codes and account labels ever leave the device. Secrets stay put.",
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}
