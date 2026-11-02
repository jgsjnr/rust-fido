package dev.aegiskey.app.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.graphics.Color
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForwardIos
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Badge
import androidx.compose.material.icons.filled.Backup
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockReset
import androidx.compose.material.icons.filled.Medication
import androidx.compose.material.icons.filled.PhonelinkSetup
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material.icons.filled.Translate
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.R
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.ble.BindingOps
import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.data.transport.HostUsbUartBridgeClient
import dev.aegiskey.app.domain.model.AppThemeMode
import dev.aegiskey.app.net.WifiApi
import dev.aegiskey.app.security.RecoveryBackup
import dev.aegiskey.app.ui.atomic.molecules.EfuseSafetyNoticeMolecule
import dev.aegiskey.app.ui.atomic.molecules.SettingToggleRowMolecule
import dev.aegiskey.app.ui.atomic.organisms.ThemeSelectorOrganism
import androidx.compose.ui.res.stringResource
import dev.aegiskey.app.ui.theme.ThemeMode
import dev.aegiskey.app.ui.viewmodel.AppThemeViewModel
import dev.aegiskey.app.ui.viewmodel.ConnectedKeysViewModel
import androidx.compose.material.icons.automirrored.filled.Article
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Group
import androidx.compose.material.icons.automirrored.filled.MenuBook
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.ui.platform.LocalContext
import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.local.LocalePreferencesStore
import dev.aegiskey.app.di.AppContainer
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.ui.RescueOps
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext


/**
 * Settings dialog organisms extracted from FriendlySettingsAndThemeScreen.kt.
 * Move-only split: same package, same signatures, same behavior, no UI change.
 */

@Composable
internal fun ShamirGenerateModalDialog(
    shares: List<String>,
    onDismiss: () -> Unit,
    onCopy: (String) -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(18.dp),
        icon = {
            Icon(
                imageVector = Icons.Filled.Key,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(28.dp)
            )
        },
        title = {
            Text(
                text = stringResource(R.string.shamir_dialog_generate_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = stringResource(R.string.shamir_backup_desc),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                shares.forEachIndexed { idx, share ->
                    Surface(
                        shape = RoundedCornerShape(10.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(10.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = when (idx) {
                                        0 -> stringResource(R.string.shamir_share_1_label)
                                        1 -> stringResource(R.string.shamir_share_2_label)
                                        else -> stringResource(R.string.shamir_share_3_label)
                                    },
                                    style = MaterialTheme.typography.labelSmall,
                                    fontWeight = FontWeight.Bold,
                                    color = MaterialTheme.colorScheme.primary
                                )
                                Text(
                                    text = share,
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onSurface,
                                    maxLines = 3,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                            IconButton(
                                onClick = { onCopy(share) },
                                modifier = Modifier.size(32.dp)
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.ContentCopy,
                                    contentDescription = stringResource(R.string.shamir_copy_share),
                                    modifier = Modifier.size(16.dp)
                                )
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = onDismiss,
                shape = RoundedCornerShape(10.dp)
            ) {
                Text(text = stringResource(R.string.guard_btn_close))
            }
        }
    )
}

@Composable
internal fun ShamirRecoverModalDialog(
    share1: String,
    onShare1Change: (String) -> Unit,
    share2: String,
    onShare2Change: (String) -> Unit,
    isLoading: Boolean,
    resultMessage: String?,
    onDismiss: () -> Unit,
    onRecover: () -> Unit
) {
    AlertDialog(
        onDismissRequest = { if (!isLoading) onDismiss() },
        shape = RoundedCornerShape(18.dp),
        icon = {
            Icon(
                imageVector = Icons.Filled.LockReset,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(28.dp)
            )
        },
        title = {
            Text(
                text = stringResource(R.string.shamir_dialog_recover_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = stringResource(R.string.shamir_backup_desc),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                OutlinedTextField(
                    value = share1,
                    onValueChange = onShare1Change,
                    label = { Text(stringResource(R.string.shamir_enter_share_1)) },
                    placeholder = { Text(stringResource(R.string.shamir_share_hint_1)) },
                    singleLine = false,
                    maxLines = 3,
                    enabled = !isLoading,
                    modifier = Modifier.fillMaxWidth()
                )

                OutlinedTextField(
                    value = share2,
                    onValueChange = onShare2Change,
                    label = { Text(stringResource(R.string.shamir_enter_share_2)) },
                    placeholder = { Text(stringResource(R.string.shamir_share_hint_2)) },
                    singleLine = false,
                    maxLines = 3,
                    enabled = !isLoading,
                    modifier = Modifier.fillMaxWidth()
                )

                if (!resultMessage.isNullOrBlank()) {
                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = Color(0xFF16A34A).copy(alpha = 0.15f),
                        border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFF16A34A)),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = resultMessage,
                            style = MaterialTheme.typography.bodySmall,
                            color = Color(0xFF16A34A),
                            fontWeight = FontWeight.SemiBold,
                            modifier = Modifier.padding(10.dp)
                        )
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = onRecover,
                enabled = !isLoading && share1.isNotBlank() && share2.isNotBlank(),
                shape = RoundedCornerShape(10.dp)
            ) {
                if (isLoading) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    Spacer(modifier = Modifier.width(6.dp))
                }
                Text(stringResource(R.string.shamir_execute_recover_btn))
            }
        },
        dismissButton = {
            TextButton(
                onClick = onDismiss,
                enabled = !isLoading
            ) {
                Text(stringResource(R.string.guard_btn_cancel))
            }
        }
    )
}

@Composable
internal fun WifiConfigModalDialog(
    currentSsid: String,
    currentPassword: String,
    currentChannel: Int,
    currentPowerSave: Boolean,
    isLoading: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (String, String, Int, Boolean) -> Unit
) {
    var ssid by remember { mutableStateOf(currentSsid) }
    var password by remember { mutableStateOf(currentPassword) }
    var channel by remember { mutableIntStateOf(currentChannel) }
    var powerSave by remember { mutableStateOf(currentPowerSave) }
    var passwordVisible by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = { if (!isLoading) onDismiss() },
        title = {
            Text(
                text = stringResource(R.string.wifi_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = stringResource(R.string.wifi_desc),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                OutlinedTextField(
                    value = ssid,
                    onValueChange = { ssid = it },
                    label = { Text(stringResource(R.string.wifi_ssid_label)) },
                    singleLine = true,
                    enabled = !isLoading,
                    modifier = Modifier.fillMaxWidth()
                )

                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text(stringResource(R.string.wifi_pass_label)) },
                    singleLine = true,
                    enabled = !isLoading,
                    visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                    trailingIcon = {
                        IconButton(onClick = { passwordVisible = !passwordVisible }) {
                            Icon(
                                imageVector = if (passwordVisible) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                contentDescription = null
                            )
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                )

                Text(text = stringResource(R.string.wifi_chan_title), style = MaterialTheme.typography.labelMedium)
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceEvenly
                ) {
                    listOf(1, 6, 11).forEach { ch ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.clickable(enabled = !isLoading) { channel = ch }
                        ) {
                            RadioButton(selected = channel == ch, onClick = { channel = ch }, enabled = !isLoading)
                            Text(stringResource(R.string.wifi_channel, ch), style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(stringResource(R.string.wifi_power_save), style = MaterialTheme.typography.bodySmall)
                    Switch(checked = powerSave, onCheckedChange = { powerSave = it }, enabled = !isLoading)
                }
            }
        },
        confirmButton = {
            Button(
                onClick = { onConfirm(ssid, password, channel, powerSave) },
                enabled = !isLoading && ssid.isNotBlank() && password.length >= 8
            ) {
                if (isLoading) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    Spacer(modifier = Modifier.width(6.dp))
                }
                Text(stringResource(R.string.wifi_save))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !isLoading) {
                Text(stringResource(R.string.guard_btn_cancel))
            }
        }
    )
}

/**
 * Interactive dialog to set/change FIDO2 Hardware PIN (0x2C / 0x2D).
 */
@Composable
internal fun ChangeHardwarePinDialog(
    client: AegisBleClient?,
    onDismiss: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    var pin by remember { mutableStateOf("") }
    var confirmPin by remember { mutableStateOf("") }
    var pinVisible by remember { mutableStateOf(false) }
    var isSaving by remember { mutableStateOf(false) }
    var feedbackMessage by remember { mutableStateOf<String?>(null) }
    var isError by remember { mutableStateOf(false) }
    val dialogResources = LocalContext.current.resources

    AlertDialog(
        onDismissRequest = { if (!isSaving) onDismiss() },
        title = {
            Text(
                text = stringResource(R.string.set_pin_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = stringResource(R.string.set_pin_desc),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                OutlinedTextField(
                    value = pin,
                    onValueChange = { pin = it.filter { ch -> ch.isDigit() }.take(8) },
                    label = { Text(stringResource(R.string.set_pin_new)) },
                    visualTransformation = if (pinVisible) VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    trailingIcon = {
                        IconButton(onClick = { pinVisible = !pinVisible }) {
                            Icon(
                                imageVector = if (pinVisible) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp),
                            )
                        }
                    },
                    singleLine = true,
                    enabled = !isSaving,
                    modifier = Modifier.fillMaxWidth(),
                )

                OutlinedTextField(
                    value = confirmPin,
                    onValueChange = { confirmPin = it.filter { ch -> ch.isDigit() }.take(8) },
                    label = { Text(stringResource(R.string.set_pin_confirm)) },
                    visualTransformation = if (pinVisible) VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    singleLine = true,
                    enabled = !isSaving,
                    modifier = Modifier.fillMaxWidth(),
                )

                feedbackMessage?.let { msg ->
                    Text(
                        text = msg,
                        style = MaterialTheme.typography.bodySmall,
                        color = if (isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    if (pin.length !in 4..8) {
                        feedbackMessage = dialogResources.getString(R.string.set_pin_err_len)
                        isError = true
                        return@Button
                    }
                    if (pin != confirmPin) {
                        feedbackMessage = dialogResources.getString(R.string.set_pin_err_match)
                        isError = true
                        return@Button
                    }

                    scope.launch {
                        isSaving = true
                        feedbackMessage = dialogResources.getString(R.string.set_pin_sending)
                        isError = false
                        try {
                            if (client != null) {
                                val payload = BindingOps.recoveryPinRequest(pin.take(6))
                                val raw = withContext(Dispatchers.IO) {
                                    client.sendVendor(BindingOps.OP_RECOVERY_SET, payload)
                                }
                                val resp = VendorOps.parseResponse(raw)
                                if (resp != null && resp.status == VendorOps.STATUS_OK) {
                                    feedbackMessage = dialogResources.getString(R.string.set_pin_ok)
                                    kotlinx.coroutines.delay(800)
                                    onDismiss()
                                } else {
                                    feedbackMessage = resp?.let { BindingOps.statusLabel(it.status) }
                                        ?: dialogResources.getString(R.string.set_pin_no_resp)
                                    isError = true
                                }
                            } else {
                                kotlinx.coroutines.delay(600)
                                feedbackMessage = dialogResources.getString(R.string.set_pin_ok)
                                kotlinx.coroutines.delay(800)
                                onDismiss()
                            }
                        } catch (e: Exception) {
                            feedbackMessage = dialogResources.getString(R.string.set_pin_fail, e.message?.take(48) ?: dialogResources.getString(R.string.set_wifi_unknown))
                            isError = true
                        } finally {
                            isSaving = false
                        }
                    }
                },
                enabled = !isSaving && pin.isNotEmpty() && confirmPin.isNotEmpty(),
            ) {
                if (isSaving) {
                    CircularProgressIndicator(
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary,
                        modifier = Modifier.size(14.dp),
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                }
                Text(stringResource(R.string.set_pin_save))
            }
        },
        dismissButton = {
            TextButton(
                onClick = onDismiss,
                enabled = !isSaving,
            ) {
                Text(stringResource(R.string.guard_btn_cancel))
            }
        },
    )
}

/**
 * Interactive dialog to display 24-Word Recovery Phrase (BIP39).
 */
@Composable
internal fun RecoveryPhraseModalDialog(
    onDismiss: () -> Unit,
) {
    val clipboard = LocalClipboardManager.current
    var copied by remember { mutableStateOf(false) }

    val phraseWords = remember {
        val entropy = RecoveryBackup.generatePhraseEntropy()
        val indices = RecoveryBackup.phraseIndices(entropy)
        RecoveryBackup.wordsOrIndices(indices, wordlist = null)
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = stringResource(R.string.set_phrase_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.4f),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        modifier = Modifier.padding(8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Warning,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.error,
                            modifier = Modifier.size(16.dp),
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = stringResource(R.string.set_phrase_warn),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onErrorContainer,
                        )
                    }
                }

                // Grid of 24 Words
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(240.dp),
                ) {
                    Column(
                        modifier = Modifier
                            .padding(8.dp)
                            .verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        for (pair in phraseWords.chunked(2)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(6.dp),
                            ) {
                                for (word in pair) {
                                    Surface(
                                        shape = RoundedCornerShape(6.dp),
                                        color = MaterialTheme.colorScheme.surface,
                                        modifier = Modifier.weight(1f),
                                    ) {
                                        Text(
                                            text = word,
                                            style = MaterialTheme.typography.bodySmall,
                                            fontFamily = FontFamily.Monospace,
                                            fontWeight = FontWeight.Medium,
                                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 4.dp),
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis,
                                        )
                                    }
                                }
                                if (pair.size == 1) {
                                    Spacer(modifier = Modifier.weight(1f))
                                }
                            }
                        }
                    }
                }

                if (copied) {
                    Text(
                        text = stringResource(R.string.set_phrase_copied),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
            }
        },
        confirmButton = {
            Button(onClick = onDismiss) {
                Text(stringResource(R.string.action_done))
            }
        },
        dismissButton = {
            OutlinedButton(
                onClick = {
                    val fullText = phraseWords.joinToString(" ")
                    clipboard.setText(AnnotatedString(fullText))
                    copied = true
                },
            ) {
                Icon(
                    imageVector = Icons.Filled.ContentCopy,
                    contentDescription = null,
                    modifier = Modifier.size(14.dp),
                )
                Spacer(modifier = Modifier.width(4.dp))
                Text(stringResource(R.string.action_copy))
            }
        },
    )
}

/**
 * Interactive dialog to configure DKEK N-of-M Quorum (Guardians).
 */
@Composable
internal fun DkekQuorumModalDialog(
    initialTotal: Int = 3,
    initialThreshold: Int = 2,
    onDismiss: () -> Unit,
    onSaveQuorum: (total: Int, threshold: Int) -> Unit = { _, _ -> },
) {
    var totalGuardians by remember(initialTotal) { mutableIntStateOf(initialTotal) }
    var threshold by remember(initialThreshold) { mutableIntStateOf(initialThreshold) }

    val validationError = remember(totalGuardians, threshold) {
        RecoveryBackup.validateDkekParams(totalGuardians, threshold)
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = stringResource(R.string.set_dkek_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    text = stringResource(R.string.set_dkek_desc),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                // Total Guardians (N)
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = stringResource(R.string.set_dkek_total, totalGuardians),
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                        IconButton(
                            onClick = { if (totalGuardians > 2) totalGuardians-- },
                            enabled = totalGuardians > 2,
                        ) {
                            Text("-", style = MaterialTheme.typography.titleLarge)
                        }
                        IconButton(
                            onClick = { if (totalGuardians < 10) totalGuardians++ },
                            enabled = totalGuardians < 10,
                        ) {
                            Text("+", style = MaterialTheme.typography.titleLarge)
                        }
                    }
                }

                // Minimum Quorum (M)
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = stringResource(R.string.set_dkek_quorum, threshold),
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                        IconButton(
                            onClick = { if (threshold > 2) threshold-- },
                            enabled = threshold > 2,
                        ) {
                            Text("-", style = MaterialTheme.typography.titleLarge)
                        }
                        IconButton(
                            onClick = { if (threshold < totalGuardians) threshold++ },
                            enabled = threshold < totalGuardians,
                        ) {
                            Text("+", style = MaterialTheme.typography.titleLarge)
                        }
                    }
                }

                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.5f),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        text = stringResource(R.string.set_dkek_active, threshold, totalGuardians),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                        modifier = Modifier.padding(10.dp),
                    )
                }

                validationError?.let { err ->
                    Text(
                        text = err,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    onSaveQuorum(totalGuardians, threshold)
                    onDismiss()
                },
                enabled = validationError == null,
            ) {
                Text(stringResource(R.string.set_dkek_save))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.guard_btn_close))
            }
        },
    )
}


data class FriendlySettingsAndThemeScreenAuditReport(
    val nvsOk: Boolean,
    val cryptoHwOk: Boolean,
    val trngOk: Boolean,
    val buttonOk: Boolean,
    val counterOps: Long,
    val firmwareVersion: String,
    val statusText: String,
    val panicCount: Long = 0,
    val wipeCount: Long = 0,
    val recoveryMode: Boolean = false,
)

@Composable
internal fun RescueDiagnosticsModalDialog(
    onDismiss: () -> Unit,
    onRunDiagnostics: suspend () -> FriendlySettingsAndThemeScreenAuditReport,
    initialReport: FriendlySettingsAndThemeScreenAuditReport? = null,
) {
    var report by remember { mutableStateOf(initialReport) }
    var isRunning by remember { mutableStateOf(initialReport == null) }
    val scope = rememberCoroutineScope()

    androidx.compose.runtime.LaunchedEffect(Unit) {
        if (report == null) {
            isRunning = true
            report = onRunDiagnostics()
            isRunning = false
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(18.dp),
        icon = {
            Icon(
                imageVector = Icons.Filled.Medication,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(28.dp)
            )
        },
        title = {
            Text(
                text = stringResource(R.string.set_diag_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(
                    text = stringResource(R.string.set_diag_desc),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                if (isRunning) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 16.dp),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(stringResource(R.string.set_diag_running), style = MaterialTheme.typography.bodyMedium)
                    }
                } else {
                    val rep = report ?: FriendlySettingsAndThemeScreenAuditReport(
                        nvsOk = true, cryptoHwOk = true, trngOk = true, buttonOk = true,
                        counterOps = 1420L, firmwareVersion = "v0.2.1-esp32s3",
                        statusText = stringResource(R.string.set_diag_default)
                    )

                    Surface(
                        shape = RoundedCornerShape(10.dp),
                        color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.4f),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(
                                text = stringResource(R.string.set_diag_verdict, rep.statusText),
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onPrimaryContainer
                            )
                            Text(
                                text = stringResource(R.string.set_diag_fw, rep.firmwareVersion),
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onPrimaryContainer
                            )
                        }
                    }

                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        DiagnosticSubsystemRow(label = stringResource(R.string.set_diag_nvs), isOk = rep.nvsOk, detail = if (rep.nvsOk) stringResource(R.string.set_diag_nvs_ok) else stringResource(R.string.set_diag_nvs_fail))
                        DiagnosticSubsystemRow(label = stringResource(R.string.set_diag_trng), isOk = rep.trngOk, detail = if (rep.trngOk) stringResource(R.string.set_diag_trng_ok) else stringResource(R.string.set_diag_trng_fail))
                        DiagnosticSubsystemRow(label = stringResource(R.string.set_diag_crypto), isOk = rep.cryptoHwOk, detail = if (rep.cryptoHwOk) stringResource(R.string.set_diag_crypto_ok) else stringResource(R.string.set_diag_crypto_fail))
                        DiagnosticSubsystemRow(label = stringResource(R.string.set_diag_btn), isOk = rep.buttonOk, detail = if (rep.buttonOk) stringResource(R.string.set_diag_btn_ok) else stringResource(R.string.set_diag_btn_fail))
                        DiagnosticSubsystemRow(
                            label = stringResource(R.string.set_diag_counter),
                            isOk = true,
                            detail = stringResource(R.string.set_diag_counter_val, rep.counterOps, rep.panicCount, rep.wipeCount)
                        )
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    scope.launch {
                        isRunning = true
                        report = onRunDiagnostics()
                        isRunning = false
                    }
                },
                enabled = !isRunning
            ) {
                Text(stringResource(R.string.set_diag_rerun))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.guard_btn_close))
            }
        }
    )
}

@Composable
internal fun DiagnosticSubsystemRow(
    label: String,
    isOk: Boolean,
    detail: String
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f))
            .padding(horizontal = 10.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = if (isOk) Icons.Filled.CheckCircle else Icons.Filled.Error,
            contentDescription = null,
            tint = if (isOk) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
            modifier = Modifier.size(18.dp)
        )
        Spacer(modifier = Modifier.width(8.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(text = label, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold)
            Text(text = detail, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
internal fun AuditLogsModalDialog(
    onDismiss: () -> Unit,
    client: AegisBleClient? = null,
    onCopyLogs: (String) -> Unit
) {
    val entries by DeviceLog.entries.collectAsState()
    val scope = rememberCoroutineScope()
    var isFetchingFwLog by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(18.dp),
        icon = {
            Icon(
                imageVector = Icons.AutoMirrored.Filled.Article,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(28.dp)
            )
        },
        title = {
            Text(
                text = stringResource(R.string.set_logs_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(380.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = stringResource(R.string.set_logs_desc),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = { onCopyLogs(DeviceLog.snapshotText()) },
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(imageVector = Icons.Filled.ContentCopy, contentDescription = null, modifier = Modifier.size(14.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(stringResource(R.string.action_copy_all), style = MaterialTheme.typography.labelSmall)
                    }

                    OutlinedButton(
                        onClick = { DeviceLog.clear() },
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(stringResource(R.string.action_clear_logs), style = MaterialTheme.typography.labelSmall)
                    }

                    if (client != null) {
                        OutlinedButton(
                            onClick = {
                                scope.launch {
                                    isFetchingFwLog = true
                                    try {
                                        val fwRes = client.fetchFwLog()
                                        fwRes.onSuccess { txt ->
                                            if (txt.isNotBlank()) {
                                                txt.lines().forEach { l ->
                                                    DeviceLog.append(DeviceLog.Category.SYSTEM, "FW: $l")
                                                }
                                            } else {
                                                DeviceLog.append(DeviceLog.Category.SYSTEM, "FW: log vazio (0x38)")
                                            }
                                        }.onFailure { err ->
                                            DeviceLog.append(DeviceLog.Category.SYSTEM, "FW log erro: ${err.message}")
                                        }
                                    } finally {
                                        isFetchingFwLog = false
                                    }
                                }
                            },
                            enabled = !isFetchingFwLog,
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text(if (isFetchingFwLog) "..." else stringResource(R.string.set_logs_fw), style = MaterialTheme.typography.labelSmall)
                        }
                    }
                }

                if (entries.isEmpty()) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .weight(1f),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = stringResource(R.string.set_logs_empty),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                } else {
                    LazyColumn(
                        modifier = Modifier
                            .fillMaxWidth()
                            .weight(1f)
                            .clip(RoundedCornerShape(8.dp))
                            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.25f))
                            .padding(6.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        items(entries, key = { it.id }) { item ->
                            val catColor = when (item.category) {
                                DeviceLog.Category.BLE -> MaterialTheme.colorScheme.primary
                                DeviceLog.Category.SYSTEM -> MaterialTheme.colorScheme.secondary
                                DeviceLog.Category.PAIRING -> MaterialTheme.colorScheme.tertiary
                                DeviceLog.Category.LOCK -> MaterialTheme.colorScheme.error
                                DeviceLog.Category.WIFI -> MaterialTheme.colorScheme.primaryContainer
                            }

                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 2.dp),
                                verticalAlignment = Alignment.Top
                            ) {
                                Text(
                                    text = DeviceLog.formatTime(item.ts),
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.width(76.dp)
                                )
                                Surface(
                                    shape = RoundedCornerShape(4.dp),
                                    color = catColor.copy(alpha = 0.2f),
                                    modifier = Modifier.padding(horizontal = 4.dp)
                                ) {
                                    Text(
                                        text = item.category.name,
                                        style = MaterialTheme.typography.labelSmall,
                                        fontWeight = FontWeight.Bold,
                                        color = catColor,
                                        modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp)
                                    )
                                }
                                Text(
                                    text = item.line,
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace,
                                    modifier = Modifier.weight(1f)
                                )
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(onClick = onDismiss) {
                Text(stringResource(R.string.guard_btn_close))
            }
        }
    )
}

@Composable
internal fun BackupCentralModalDialog(
    onDismiss: () -> Unit,
    onSelectRecoveryPhrase: () -> Unit,
    onSelectDkekQuorum: () -> Unit,
    onSelectShamirBackup: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(18.dp),
        icon = {
            Icon(
                imageVector = Icons.Filled.Backup,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(28.dp)
            )
        },
        title = {
            Text(
                text = stringResource(R.string.set_backup_central_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = stringResource(R.string.set_backup_central_desc),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                // Opção 1: BIP-39
                OutlinedCard(
                    onClick = {
                        onDismiss()
                        onSelectRecoveryPhrase()
                    },
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.outlinedCardColors(
                        containerColor = MaterialTheme.colorScheme.surface
                    ),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.MenuBook,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = stringResource(R.string.set_backup_opt1_title),
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = stringResource(R.string.set_backup_opt1_desc),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowForwardIos,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(14.dp)
                        )
                    }
                }

                // Opção 2: DKEK Quorum
                OutlinedCard(
                    onClick = {
                        onDismiss()
                        onSelectDkekQuorum()
                    },
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.outlinedCardColors(
                        containerColor = MaterialTheme.colorScheme.surface
                    ),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Group,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = stringResource(R.string.set_backup_opt2_title),
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = stringResource(R.string.set_backup_opt2_desc),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowForwardIos,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(14.dp)
                        )
                    }
                }

                // Opção 3: Shamir SLIP-39
                OutlinedCard(
                    onClick = {
                        onDismiss()
                        onSelectShamirBackup()
                    },
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.outlinedCardColors(
                        containerColor = MaterialTheme.colorScheme.surface
                    ),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Share,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = stringResource(R.string.set_backup_opt3_title),
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = stringResource(R.string.set_backup_opt3_desc),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowForwardIos,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(14.dp)
                        )
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.guard_btn_cancel))
            }
        }
    )
}
