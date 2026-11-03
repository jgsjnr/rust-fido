package dev.aegiskey.app.caps

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.R
import dev.aegiskey.app.data.transport.KeyTransport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * caps module entrypoint: "Capacidades da placa" screen.
 *
 * Queries GET_CAPS (0x3F) when opened and on refresh, over the shared
 * [KeyTransport] seam (BLE preferred, USB fallback — chosen by the
 * caller like Ota2Screen). Authority data only: fw version, preset
 * badge, reported caps list, unsupported count with explanation.
 * Old firmware (no 0x3F) renders [R.string.caps_unknown]
 * ("desconhecido") — never invented values.
 */
@Composable
fun CapsScreen(
    transport: KeyTransport,
) {
    val scope = rememberCoroutineScope()
    var result by remember { mutableStateOf<CapsResult?>(null) }
    var busy by remember { mutableStateOf(false) }

    fun refresh() {
        scope.launch {
            busy = true
            result = withContext(Dispatchers.IO) { CapsRepository.query(transport) }
            busy = false
        }
    }

    LaunchedEffect(transport) { refresh() }

    Column(
        modifier = Modifier.fillMaxWidth().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            text = stringResource(R.string.caps_title),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
        )
        when (val r = result) {
            null -> Text(stringResource(R.string.caps_querying))
            is CapsResult.Unknown -> Text(stringResource(R.string.caps_unknown))
            is CapsResult.Known -> CapsReportBody(report = r.report)
        }
        OutlinedButton(onClick = { refresh() }, enabled = !busy) {
            Text(stringResource(R.string.caps_refresh))
        }
    }
}

@Composable
private fun CapsReportBody(report: CapsReport) {
    Text(stringResource(R.string.caps_fw, report.fwVersion))
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(stringResource(R.string.caps_preset, report.preset))
        Surface(
            shape = androidx.compose.foundation.shape.RoundedCornerShape(6.dp),
            color = MaterialTheme.colorScheme.primaryContainer,
        ) {
            Text(
                text = report.preset,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
            )
        }
    }
    Text(
        text = stringResource(R.string.caps_list),
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.SemiBold,
    )
    if (report.caps.isEmpty()) {
        Text(stringResource(R.string.caps_empty))
    } else {
        report.caps.forEach { id ->
            val nameRes = capsNameRes(id)
            if (nameRes != null) {
                Text(stringResource(nameRes))
            } else {
                Text(id)
            }
        }
    }
    Text(stringResource(R.string.caps_unsupported, report.unsupportedCount))
    Text(
        text = stringResource(R.string.caps_unsupported_desc),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

/**
 * Friendly short names (ota_strings.xml style: ASD-STE100, no emoji).
 * Unknown ids fall back to the raw authority id (never invented).
 */
private fun capsNameRes(id: String): Int? = when (id) {
    "ctap-makecred" -> R.string.caps_name_ctap_makecred
    "ctap-getassert" -> R.string.caps_name_ctap_getassert
    "ctap-clientpin" -> R.string.caps_name_ctap_clientpin
    "ccid" -> R.string.caps_name_ccid
    "piv" -> R.string.caps_name_piv
    "openpgp" -> R.string.caps_name_openpgp
    "oath-totp" -> R.string.caps_name_oath_totp
    "oath-hotp" -> R.string.caps_name_oath_hotp
    "otp-challenge-response" -> R.string.caps_name_otp_challenge_response
    "wallet" -> R.string.caps_name_wallet
    "vault" -> R.string.caps_name_vault
    "ble" -> R.string.caps_name_ble
    "wifi-sntp" -> R.string.caps_name_wifi_sntp
    "display" -> R.string.caps_name_display
    "proximity" -> R.string.caps_name_proximity
    "vendor-mgmt" -> R.string.caps_name_vendor_mgmt
    "debug-terminal" -> R.string.caps_name_debug_terminal
    "test-hooks" -> R.string.caps_name_test_hooks
    else -> null
}
