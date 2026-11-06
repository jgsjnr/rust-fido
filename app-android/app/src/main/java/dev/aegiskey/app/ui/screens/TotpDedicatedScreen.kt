package dev.aegiskey.app.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.LockClock
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import dev.aegiskey.app.R
import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.TotpAccountItem
import dev.aegiskey.app.ui.atomic.molecules.PhysicalButtonPromptCardMolecule
import dev.aegiskey.app.ui.atomic.molecules.TotpCodeCardMolecule
import dev.aegiskey.app.ui.atomic.organisms.AddTotpAccountDialogOrganism
import dev.aegiskey.app.ui.atomic.organisms.DebugChipControlHooksCard
import dev.aegiskey.app.ui.viewmodel.TotpAuthenticatorViewModel

/**
 * Dedicated TOTP / HOTP screen (Aba 2: TOTP).
 * Standardized in ASD-STE100 technical English.
 */
@Composable
fun TotpDedicatedScreen(
    viewModel: TotpAuthenticatorViewModel,
    modifier: Modifier = Modifier,
) {
    val uiState by viewModel.uiState.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }

    var showAddDialog by remember { mutableStateOf(false) }
    var accountToDelete by remember { mutableStateOf<TotpAccountItem?>(null) }

    var scannedIssuer by remember { mutableStateOf("") }
    var scannedAccount by remember { mutableStateOf("") }
    var scannedSecret by remember { mutableStateOf("") }
    var scannedDigits by remember { mutableIntStateOf(6) }
    var scannedPeriodSeconds by remember { mutableIntStateOf(30) }
    var scannedIsHotp by remember { mutableStateOf(false) }
    val scanPrompt = stringResource(R.string.addtotp_scan_prompt)

    val qrLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        val content = result.contents
        if (!content.isNullOrBlank()) {
            val parsed = AegisBridge.parseOtpInput(content)
            if (parsed != null) {
                scannedIssuer = parsed.issuer
                scannedAccount = parsed.accountName
                scannedSecret = parsed.secretBase32
                scannedDigits = parsed.digits
                scannedPeriodSeconds = parsed.periodSeconds
                scannedIsHotp = parsed.isHotp
            } else {
                scannedIssuer = ""
                scannedAccount = ""
                scannedSecret = content.trim()
                scannedDigits = 6
                scannedPeriodSeconds = 30
                scannedIsHotp = false
            }
            showAddDialog = true
        }
    }

    LaunchedEffect(uiState.feedbackMessage) {
        uiState.feedbackMessage?.let {
            // Finding A3: add success closes the sheet (it stayed open while saving).
            if (showAddDialog && uiState.presenceRequest == null) showAddDialog = false
            snackbarHostState.showSnackbar(it)
            viewModel.clearFeedback()
        }
    }

    LaunchedEffect(uiState.errorMessage) {
        uiState.errorMessage?.let {
            // Finding A3: hard failures close the sheet; NEED_UP never lands
            // here (it keeps presenceRequest set and the sheet open).
            if (showAddDialog && uiState.presenceRequest == null) showAddDialog = false
            snackbarHostState.showSnackbar(it)
            viewModel.clearFeedback()
        }
    }

    // Click-through F1: typed device failures resolve via strings.xml
    // (EN + values-pt) in the active locale.
    val localizedError = uiState.errorResId?.let { resId ->
        val args = uiState.errorArgs
        if (args.isEmpty() || args.all { it.isBlank() }) stringResource(resId)
        else stringResource(resId, args.joinToString("; "))
    }
    LaunchedEffect(localizedError) {
        localizedError?.let {
            if (showAddDialog && uiState.presenceRequest == null) showAddDialog = false
            snackbarHostState.showSnackbar(it)
            viewModel.clearFeedback()
        }
    }

    Box(modifier = modifier.fillMaxSize()) {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // Primary Add Code and Scan QR Code Buttons
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Button(
                        onClick = {
                            scannedIssuer = ""
                            scannedAccount = ""
                            scannedSecret = ""
                            scannedDigits = 6
                            scannedPeriodSeconds = 30
                            scannedIsHotp = false
                            showAddDialog = true
                        },
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.primary,
                            contentColor = MaterialTheme.colorScheme.onPrimary,
                        ),
                        modifier = Modifier
                            .weight(1f)
                            .height(46.dp),
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(imageVector = Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = stringResource(R.string.totp_add_short),
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }

                    OutlinedButton(
                        onClick = {
                            val options = ScanOptions().apply {
                                setPrompt(scanPrompt)
                                setBeepEnabled(false)
                                setOrientationLocked(false)
                            }
                            qrLauncher.launch(options)
                        },
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier
                            .weight(1f)
                            .height(46.dp),
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(imageVector = Icons.Filled.QrCodeScanner, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = stringResource(R.string.addtotp_scan_qr),
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }
            }

            // Section Header with Refresh Action
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = stringResource(R.string.totp_section_title),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )

                    Row(verticalAlignment = Alignment.CenterVertically) {
                        if (uiState.isLoading) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                            Spacer(modifier = Modifier.width(6.dp))
                        }
                        IconButton(
                            onClick = { viewModel.refreshCodes() },
                            modifier = Modifier.size(32.dp),
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Refresh,
                                contentDescription = stringResource(R.string.totp_sync_codes),
                                modifier = Modifier.size(18.dp),
                            )
                        }
                    }
                }
            }

            // Finding A3: outstanding device presence request — the existing
            // "touch the key" prompt instead of silent codes.
            if (uiState.presenceRequest != null) {
                item {
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        PhysicalButtonPromptCardMolecule(
                            instruction = stringResource(R.string.totp_presence_body),
                            title = stringResource(R.string.gate_up_title),
                            isSimulatedMode = uiState.activeKey?.transportType == ConnectionTransportType.SIMULATOR,
                            onSimulateTouch = { viewModel.refreshCodes() },
                        )
                        Button(
                            onClick = { viewModel.retryAfterPresence() },
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(44.dp),
                        ) {
                            Text(
                                text = stringResource(R.string.presence_retry),
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }
            }

            // Empty State: without a live session the backing rows are all
            // placeholders ("------") and already hidden by the ViewModel —
            // render an empty list with a neutral "connect the key" hint
            // instead of a counting placeholder row.
            if (uiState.accounts.isEmpty() && !uiState.isLoading) {
                val emptyTitleRes = if (uiState.hasNoLiveSession) R.string.totp_no_session_title else R.string.totp_empty_alt_title
                val emptyDescRes = if (uiState.hasNoLiveSession) R.string.totp_no_session_desc else R.string.totp_empty_alt_desc
                item {
                    Surface(
                        shape = RoundedCornerShape(12.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Column(
                            modifier = Modifier.padding(18.dp),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Icon(
                                imageVector = Icons.Filled.LockClock,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(32.dp),
                            )
                            Text(
                                text = stringResource(emptyTitleRes),
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                text = stringResource(emptyDescRes),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }
            }

            // List of TOTP/HOTP Account Cards
            items(uiState.accounts, key = { it.id }) { item ->
                TotpCodeCardMolecule(
                    issuer = item.issuer,
                    accountName = item.accountName,
                    code = item.currentCode,
                    remainingSeconds = uiState.remainingSeconds,
                    totalSeconds = item.periodSeconds,
                    isHotp = item.isHotp,
                    counter = item.counter,
                    onIncrementHotp = { viewModel.incrementHotp(item.id) },
                    onCopyCode = { code ->
                        viewModel.copyCodeToClipboard(code)
                    },
                    onDeleteAccount = {
                        accountToDelete = item
                    },
                    isOnDeviceBacked = item.isOnDeviceBacked,
                )
            }

            item {
                DebugChipControlHooksCard(
                    onInjectSampleData = { viewModel.injectExtraSampleForDebug() },
                    onSimulatePing = { viewModel.refreshCodes() },
                )
            }

            item {
                Spacer(modifier = Modifier.height(16.dp))
            }
        }

        SnackbarHost(
            hostState = snackbarHostState,
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .padding(bottom = 12.dp),
        )
    }

    // Add TOTP Dialog
    if (showAddDialog) {
        AddTotpAccountDialogOrganism(
            onDismissRequest = {
                // Finding A3: dismissing with a pending presence drops it.
                if (uiState.presenceRequest != null) viewModel.dismissPresence()
                showAddDialog = false
            },
            onSaveTotp = { issuer, account, secretOrUri, digits, periodSeconds, isHotp ->
                // Finding A3: no optimistic close; outcome effects close the
                // sheet on success/hard failure and keep it open on NEED_UP.
                viewModel.addAccount(
                    issuer = issuer,
                    accountName = account,
                    secretOrUri = secretOrUri,
                    digits = digits,
                    periodSeconds = periodSeconds,
                    isHotp = isHotp
                )
            },
            isLoading = uiState.isAddingAccount,
            initialIssuer = scannedIssuer,
            initialAccountName = scannedAccount,
            initialSecretOrUri = scannedSecret,
            initialDigits = scannedDigits,
            initialPeriodSeconds = scannedPeriodSeconds,
            initialIsHotp = scannedIsHotp,
            presenceRequest = uiState.presenceRequest,
            onRetryAfterPresence = { viewModel.retryAfterPresence() },
            isSimulatedMode = uiState.activeKey?.transportType == ConnectionTransportType.SIMULATOR,
            onSimulateTouch = { viewModel.refreshCodes() },
        )
    }

    // Remove Confirmation Dialog
    accountToDelete?.let { item ->
        AlertDialog(
            onDismissRequest = { accountToDelete = null },
            shape = RoundedCornerShape(16.dp),
            title = {
                Text(
                    text = stringResource(R.string.totp_del_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            },
            text = {
                Text(
                    text = stringResource(R.string.totp_del_desc, item.issuer.ifBlank { item.accountName }),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        viewModel.deleteAccount(item.id)
                        accountToDelete = null
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                        contentColor = MaterialTheme.colorScheme.onError,
                    ),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.height(38.dp),
                ) {
                    Text(stringResource(R.string.totp_del_btn), maxLines = 1)
                }
            },
            dismissButton = {
                TextButton(onClick = { accountToDelete = null }) {
                    Text(stringResource(R.string.guard_btn_cancel), maxLines = 1)
                }
            },
        )
    }
}
