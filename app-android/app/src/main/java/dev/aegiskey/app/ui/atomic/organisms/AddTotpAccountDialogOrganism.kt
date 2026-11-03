package dev.aegiskey.app.ui.atomic.organisms

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import dev.aegiskey.app.R
import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.data.debug.DebugHardwareChipMock
import dev.aegiskey.app.ui.atomic.atoms.PrimaryNextButton
import dev.aegiskey.app.ui.atomic.molecules.PhysicalButtonPromptCardMolecule
import dev.aegiskey.app.ui.viewmodel.PresenceRequest

/**
 * Add TOTP / HOTP account dialog organism.
 */
@Composable
fun AddTotpAccountDialogOrganism(
    onDismissRequest: () -> Unit,
    onSaveTotp: (
        issuer: String,
        account: String,
        secretOrUri: String,
        digits: Int,
        periodSeconds: Int,
        isHotp: Boolean
    ) -> Unit,
    isLoading: Boolean = false,
    initialIssuer: String = "",
    initialAccountName: String = "",
    initialSecretOrUri: String = "",
    initialDigits: Int = 6,
    initialPeriodSeconds: Int = 30,
    initialIsHotp: Boolean = false,
    /**
     * Finding A3: outstanding device presence request. While non-null the
     * dialog stays open and shows the existing "touch the key" prompt with a
     * retry action instead of closing silently.
     */
    presenceRequest: PresenceRequest? = null,
    onRetryAfterPresence: (() -> Unit)? = null,
    isSimulatedMode: Boolean = false,
    onSimulateTouch: (() -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    var issuer by remember(initialIssuer) { mutableStateOf(initialIssuer) }
    var accountName by remember(initialAccountName) { mutableStateOf(initialAccountName) }
    var secretOrUri by remember(initialSecretOrUri) { mutableStateOf(initialSecretOrUri) }
    var isHotp by remember(initialIsHotp) { mutableStateOf(initialIsHotp) }
    var digits by remember(initialDigits) { mutableIntStateOf(initialDigits) }
    var periodSeconds by remember(initialPeriodSeconds) { mutableIntStateOf(initialPeriodSeconds) }

    val qrLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        val content = result.contents
        if (!content.isNullOrBlank()) {
            val parsed = AegisBridge.parseOtpInput(content)
            if (parsed != null) {
                if (parsed.issuer.isNotBlank()) issuer = parsed.issuer
                if (parsed.accountName.isNotBlank()) accountName = parsed.accountName
                secretOrUri = parsed.secretBase32
                digits = parsed.digits
                periodSeconds = parsed.periodSeconds
                isHotp = parsed.isHotp
            } else {
                secretOrUri = content.trim()
            }
        }
    }

    val isFormValid = issuer.trim().isNotBlank() && secretOrUri.trim().isNotBlank()
    val scanPrompt = stringResource(R.string.addtotp_scan_prompt)

    AlertDialog(
        onDismissRequest = { if (!isLoading) onDismissRequest() },
        shape = RoundedCornerShape(16.dp),
        title = {
            Text(
                text = if (isHotp) stringResource(R.string.addtotp_title_hotp) else stringResource(R.string.addtotp_title_totp),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
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
                    text = stringResource(R.string.addtotp_desc),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )

                if (presenceRequest != null) {
                    PhysicalButtonPromptCardMolecule(
                        instruction = stringResource(R.string.totp_presence_body),
                        title = stringResource(R.string.gate_up_title),
                        isSimulatedMode = isSimulatedMode,
                        onSimulateTouch = onSimulateTouch,
                    )
                    if (onRetryAfterPresence != null) {
                        OutlinedButton(
                            onClick = onRetryAfterPresence,
                            enabled = !isLoading,
                            shape = RoundedCornerShape(10.dp),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(38.dp),
                        ) {
                            Text(
                                text = stringResource(R.string.presence_retry),
                                style = MaterialTheme.typography.labelLarge,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }

                // Scan QR Code Button
                Button(
                    onClick = {
                        val options = ScanOptions().apply {
                            setPrompt(scanPrompt)
                            setBeepEnabled(false)
                            setOrientationLocked(false)
                        }
                        qrLauncher.launch(options)
                    },
                    enabled = !isLoading,
                    shape = RoundedCornerShape(10.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.secondaryContainer,
                        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
                    ),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(38.dp),
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Filled.QrCodeScanner,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = stringResource(R.string.addtotp_scan_qr),
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }

                if (DebugHardwareChipMock.IS_MOCK_ENABLED) {
                    OutlinedButton(
                        onClick = {
                            issuer = "AegisKey Demo"
                            accountName = "user@aegiskey.dev"
                            secretOrUri = "JBSWY3DPEHPK3PXP"
                        },
                        enabled = !isLoading,
                        shape = RoundedCornerShape(10.dp),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(34.dp),
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Filled.AutoAwesome,
                                contentDescription = null,
                                modifier = Modifier.size(14.dp),
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = stringResource(R.string.addtotp_fill_test),
                                style = MaterialTheme.typography.labelSmall,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }

                Text(
                    text = stringResource(R.string.addtotp_code_type),
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    FilterChip(
                        selected = !isHotp,
                        onClick = { isHotp = false },
                        label = { Text(stringResource(R.string.addtotp_type_totp), style = MaterialTheme.typography.labelSmall) }
                    )
                    FilterChip(
                        selected = isHotp,
                        onClick = { isHotp = true },
                        label = { Text(stringResource(R.string.addtotp_type_hotp), style = MaterialTheme.typography.labelSmall) }
                    )
                }

                Text(
                    text = stringResource(R.string.addtotp_code_len),
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    FilterChip(
                        selected = digits == 6,
                        onClick = { digits = 6 },
                        label = { Text(stringResource(R.string.addtotp_len_6), style = MaterialTheme.typography.labelSmall) }
                    )
                    FilterChip(
                        selected = digits == 8,
                        onClick = { digits = 8 },
                        label = { Text(stringResource(R.string.addtotp_len_8), style = MaterialTheme.typography.labelSmall) }
                    )
                }

                OutlinedTextField(
                    value = issuer,
                    onValueChange = { issuer = it },
                    label = { Text(stringResource(R.string.addtotp_svc_label), maxLines = 1) },
                    placeholder = { Text(stringResource(R.string.addtotp_svc_hint), maxLines = 1) },
                    singleLine = true,
                    enabled = !isLoading,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth(),
                )

                OutlinedTextField(
                    value = accountName,
                    onValueChange = { accountName = it },
                    label = { Text(stringResource(R.string.addtotp_acc_label), maxLines = 1) },
                    placeholder = { Text(stringResource(R.string.addtotp_acc_hint), maxLines = 1) },
                    singleLine = true,
                    enabled = !isLoading,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth(),
                )

                OutlinedTextField(
                    value = secretOrUri,
                    onValueChange = { secretOrUri = it },
                    label = { Text(stringResource(R.string.addtotp_sec_label), maxLines = 1) },
                    placeholder = { Text(stringResource(R.string.addtotp_sec_hint), maxLines = 1) },
                    singleLine = true,
                    enabled = !isLoading,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            PrimaryNextButton(
                text = stringResource(R.string.addtotp_save),
                enabled = isFormValid,
                isLoading = isLoading,
                onClick = {
                    if (isFormValid) {
                        onSaveTotp(
                            issuer.trim(),
                            accountName.trim(),
                            secretOrUri.trim(),
                            digits,
                            periodSeconds,
                            isHotp
                        )
                    }
                },
            )
        },
        dismissButton = {
            TextButton(
                onClick = onDismissRequest,
                enabled = !isLoading,
            ) {
                Text(
                    text = stringResource(R.string.guard_btn_cancel),
                    style = MaterialTheme.typography.labelMedium,
                    maxLines = 1,
                )
            }
        },
        modifier = modifier,
    )
}
