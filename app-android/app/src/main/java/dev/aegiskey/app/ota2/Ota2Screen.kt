package dev.aegiskey.app.ota2

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.R
import dev.aegiskey.app.data.transport.KeyTransport
import dev.aegiskey.app.ota2.Ota2Constants.MANIFEST_WIRE_LEN
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * ota2 settings entry UI (unwired: see OTA_HOOK.md).
 *
 * Offline flow: SAF firmware.bin picker -> app cache copy (size cap) ->
 * SHA-256 + version shown BEFORE send -> staged BEGIN/CHUNK/FINISH over
 * [transport] (BLE preferred, USB fallback). No COMMIT here by design.
 *
 * File layout: manifest (104 B) || image. Manifest size must equal the
 * trailing image length; anything else reads BadManifest, nothing sent.
 */
@Composable
fun Ota2Screen(
    transport: KeyTransport,
    currentVersion: Long,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var staged by remember { mutableStateOf<StagedImage?>(null) }
    var manifest by remember { mutableStateOf<Ota2Manifest?>(null) }
    var failure by remember { mutableStateOf<Ota2Failure?>(null) }
    var sent by remember { mutableIntStateOf(0) }
    var total by remember { mutableIntStateOf(0) }
    var busy by remember { mutableStateOf(false) }
    var done by remember { mutableStateOf(false) }
    var session by remember { mutableStateOf<Ota2Session?>(null) }

    val picker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
        onResult = { uri ->
            if (uri == null) return@rememberLauncherForActivityResult
            scope.launch {
                busy = true
                failure = null
                done = false
                sent = 0
                total = 0
                val outcome = withContext(Dispatchers.IO) {
                    runCatching {
                        val bytes = context.contentResolver.openInputStream(uri)?.use {
                            Ota2FileStore.stageImage(it).bytes
                        } ?: throw Ota2Exception(Ota2Failure.EmptyImage)
                        if (bytes.size < MANIFEST_WIRE_LEN + 1) throw Ota2Exception(Ota2Failure.BadManifest)
                        val m = parseOta2Manifest(bytes.copyOfRange(0, MANIFEST_WIRE_LEN))
                        val img = bytes.copyOfRange(MANIFEST_WIRE_LEN, bytes.size)
                        if (img.size != m.size) throw Ota2Exception(Ota2Failure.BadManifest)
                        checkOta2Version(m, currentVersion)
                        val sha = sha256Of(img)
                        m to StagedImage(bytes = img, sha256 = sha, shaHex = sha.toHexLower())
                    }
                }
                outcome.onSuccess { (m, img) ->
                    manifest = m
                    staged = img
                    total = img.bytes.size
                    session = Ota2Session(manifest = m, image = img)
                }.onFailure { e ->
                    failure = (e as? Ota2Exception)?.failure ?: Ota2Failure.BadManifest
                    manifest = null
                    staged = null
                    session = null
                }
                busy = false
            }
        },
    )

    Column(
        modifier = Modifier.fillMaxWidth().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(stringResource(R.string.ota2_title))
        OutlinedButton(onClick = { picker.launch(arrayOf("application/octet-stream")) }, enabled = !busy) {
            Text(stringResource(R.string.ota2_pick))
        }
        val m = manifest
        val img = staged
        if (m != null && img != null) {
            Text(stringResource(R.string.ota2_sha, img.shaHex))
            Text(stringResource(R.string.ota2_size, img.bytes.size))
            Text(stringResource(R.string.ota2_version, m.version, currentVersion))
        }
        if (total > 0) {
            LinearProgressIndicator(progress = { sent.toFloat() / total.coerceAtLeast(1) })
            Text(stringResource(R.string.ota2_progress, sent, total))
        }
        failure?.let { Text(stringResource(it.stringRes())) }
        if (done) Text(stringResource(R.string.ota2_verified))
        val s = session
        Button(
            onClick = {
                if (s == null) return@Button
                scope.launch {
                    busy = true
                    failure = null
                    val result = withContext(Dispatchers.IO) {
                        Ota2Engine.run(
                            session = s,
                            currentVersion = currentVersion,
                            pubkey = Ota2Keys.activePubkey(),
                            transport = transport.asOta2Transport(),
                            onProgress = { sentNow, totalNow ->
                                sent = sentNow
                                total = totalNow
                            },
                        )
                    }
                    when (result) {
                        is Ota2Result.Success -> done = true
                        is Ota2Result.Paused -> failure = Ota2Failure.TransportLost
                        is Ota2Result.Failed -> failure = result.failure
                    }
                    busy = false
                }
            },
            enabled = !busy && s != null && !done,
        ) {
            Text(stringResource(if (failure == Ota2Failure.TransportLost) R.string.ota2_retry else R.string.ota2_send))
        }
    }
}
