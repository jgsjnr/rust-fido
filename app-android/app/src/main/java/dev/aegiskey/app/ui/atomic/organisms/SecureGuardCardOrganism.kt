package dev.aegiskey.app.ui.atomic.organisms

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.aegiskey.app.R
import dev.aegiskey.app.domain.model.ErrorLockedRecovery
import dev.aegiskey.app.domain.model.SecureGuardPolicy
import dev.aegiskey.app.domain.model.SecureGuardStateEnum
import dev.aegiskey.app.domain.model.SecureGuardStatus
import dev.aegiskey.app.ui.atomic.atoms.SecureGuardBadgeAtom
import dev.aegiskey.app.ui.atomic.molecules.RateLimitTimerMolecule
import dev.aegiskey.app.ui.atomic.molecules.SessionExpiryTimerMolecule
import dev.aegiskey.app.ui.viewmodel.SecureGuardUiState

/**
 * Secure Guard authority organism (Zero-Trust On-Device Authority Vault).
 * Standardized in ASD-STE100 technical English with 100% responsive Layouts.
 *
 * Utiliza o HardwareSessionPinPopupDialog modal para solicitar PIN por sessão sincronizada,
 * mantendo o card limpo e compacto sem teclado gigante estático ocupando a tela.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun SecureGuardCardOrganism(
    uiState: SecureGuardUiState,
    onProvision: (String, String?, SecureGuardPolicy?) -> Unit,
    onUnlock: (String) -> Unit,
    onLock: () -> Unit,
    onChangePin: (String, String) -> Unit,
    onRecover: (String, String) -> Unit,
    onUpdatePolicy: (SecureGuardPolicy) -> Unit,
    onWipeSelective: (Int, String) -> Unit,
    onRefresh: () -> Unit,
    modifier: Modifier = Modifier
) {
    val status = uiState.status
    var activePopupOperation by remember { mutableStateOf<HardwareSessionOperationType?>(null) }
    var showChangePinDialog by remember { mutableStateOf(false) }
    var showRecoverDialog by remember { mutableStateOf(false) }
    var showPolicySettings by remember { mutableStateOf(false) }

    // Close modal if status becomes unlocked or operation finished successfully
    LaunchedEffect(status.isUnlocked, status.state, uiState.successMessage) {
        if (status.isUnlocked || status.state == SecureGuardStateEnum.UNLOCKED) {
            activePopupOperation = null
        }
    }

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f))
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Header: Title + Badge + Refresh Action (Responsive)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .padding(end = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(2.dp)
                ) {
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        Text(
                            text = stringResource(R.string.guard_title),
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        SecureGuardBadgeAtom(state = status.state)
                    }
                    Text(
                        text = stringResource(R.string.guard_subtitle),
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    if (uiState.isLoading) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                    }
                    OutlinedButton(
                        onClick = onRefresh,
                        modifier = Modifier.padding(0.dp)
                    ) {
                        Icon(imageVector = Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.size(14.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(stringResource(R.string.guard_refresh), fontSize = 12.sp)
                    }
                }
            }

            // Synchronized Hardware Session Status Bar
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(10.dp))
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = if (status.isUnlocked) Icons.Filled.LockOpen else Icons.Filled.Lock,
                        contentDescription = null,
                        tint = if (status.isUnlocked) Color(0xFF10B981) else Color(0xFFF59E0B),
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = if (status.isUnlocked) stringResource(R.string.guard_session_active_badge) else stringResource(R.string.guard_session_locked_badge),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = if (status.isUnlocked) Color(0xFF10B981) else MaterialTheme.colorScheme.onSurface
                    )
                }

                // Attempt counters: ErrorLocked freezes them on-device, so label
                // them frozen with reason instead of showing live values.
                if (ErrorLockedRecovery.isAttemptsCounterFrozen(status.state)) {
                    Text(
                        text = stringResource(
                            R.string.guard_error_locked_frozen,
                            status.remainingAttempts,
                            status.maxAttempts
                        ),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.error
                    )
                } else {
                    Text(
                        text = "[ ${status.remainingAttempts} / ${status.maxAttempts} ]",
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (status.remainingAttempts <= 2) Color(0xFFEF4444) else MaterialTheme.colorScheme.onSurface
                    )
                }
            }

            // Live Timers (Rate Limit or Session Expiry)
            if (status.state == SecureGuardStateEnum.RATE_LIMITED && status.rateLimitRemainingMs > 0) {
                RateLimitTimerMolecule(remainingMs = status.rateLimitRemainingMs)
            } else if (status.state == SecureGuardStateEnum.UNLOCKED && status.sessionRemainingMs > 0) {
                SessionExpiryTimerMolecule(remainingMs = status.sessionRemainingMs)
            }

            // Feedback Messages
            if (uiState.errorMessage != null && activePopupOperation == null) {
                Text(
                    text = uiState.errorMessage,
                    color = MaterialTheme.colorScheme.error,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Medium
                )
            }
            if (uiState.successMessage != null || uiState.successResId != null) {
                Text(
                    text = uiState.successResId?.let { stringResource(it) } ?: uiState.successMessage.orEmpty(),
                    color = Color(0xFF16A34A),
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Medium
                )
            }

            // Generated Recovery Code Display
            if (uiState.generatedRecoveryCode != null) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(Color(0xFF0F172A), RoundedCornerShape(10.dp))
                        .border(1.dp, Color(0xFF0284C7), RoundedCornerShape(10.dp))
                        .padding(12.dp)
                ) {
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(
                            text = stringResource(R.string.guard_recovery_code_label),
                            fontSize = 11.sp,
                            color = Color(0xFF94A3B8)
                        )
                        Text(
                            text = uiState.generatedRecoveryCode,
                            fontSize = 14.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace,
                            color = Color(0xFF38BDF8)
                        )
                        Text(
                            text = stringResource(R.string.guard_recovery_code_hint),
                            fontSize = 10.sp,
                            color = Color(0xFF64748B)
                        )
                    }
                }
            }

            // Clean, Compact Actions Bar (Triggering Modal Popups for PIN)
            when (status.state) {
                SecureGuardStateEnum.UNPROVISIONED -> {
                    Text(
                        text = stringResource(R.string.guard_unprovisioned_desc),
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Button(
                        onClick = { activePopupOperation = HardwareSessionOperationType.PROVISION_SESSION },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary)
                    ) {
                        Icon(imageVector = Icons.Filled.Security, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(stringResource(R.string.guard_init_btn))
                    }
                }

                SecureGuardStateEnum.LOCKED, SecureGuardStateEnum.RATE_LIMITED -> {
                    FlowRow(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = { activePopupOperation = HardwareSessionOperationType.UNLOCK_SESSION },
                            enabled = !uiState.isLoading && status.state != SecureGuardStateEnum.RATE_LIMITED,
                            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary),
                        ) {
                            Icon(imageVector = Icons.Filled.LockOpen, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(stringResource(R.string.guard_btn_unlock_session))
                        }

                        OutlinedButton(
                            onClick = { showRecoverDialog = !showRecoverDialog }
                        ) {
                            Text(stringResource(R.string.guard_emergency_recovery), fontSize = 12.sp, color = Color(0xFFF59E0B))
                        }
                    }
                }

                SecureGuardStateEnum.UNLOCKED -> {
                    FlowRow(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = onLock,
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                        ) {
                            Text(stringResource(R.string.guard_lock_now))
                        }
                        OutlinedButton(
                            onClick = { showChangePinDialog = !showChangePinDialog }
                        ) {
                            Text(stringResource(R.string.guard_change_pin))
                        }
                        TextButton(onClick = { showPolicySettings = !showPolicySettings }) {
                            Text(stringResource(R.string.guard_security_policies), fontSize = 12.sp)
                        }
                        TextButton(onClick = { activePopupOperation = HardwareSessionOperationType.WIPE_SELECTIVE }) {
                            Text(stringResource(R.string.guard_selective_wipe), fontSize = 12.sp, color = MaterialTheme.colorScheme.error)
                        }
                    }
                }

                SecureGuardStateEnum.RECOVERY_REQUIRED -> {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(Color(0xFF7C2D12).copy(alpha = 0.2f), RoundedCornerShape(10.dp))
                            .padding(12.dp)
                    ) {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(
                                text = stringResource(R.string.guard_max_attempts_reached),
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFFF97316)
                            )
                            Text(
                                text = stringResource(R.string.guard_recovery_desc),
                                fontSize = 12.sp,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Button(
                                onClick = { showRecoverDialog = true },
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFF97316))
                            ) {
                                Text(stringResource(R.string.guard_emergency_recovery))
                            }
                        }
                    }
                }

                SecureGuardStateEnum.ERROR_LOCKED -> {
                    // Dedicated recovery screen: the secure record is stale or
                    // unreadable, so no PIN can succeed. Never offer PIN retry.
                    ErrorLockedRecoveryPanel(
                        onUseRecoveryCode = { showRecoverDialog = true },
                        onRefresh = onRefresh,
                    )
                }

                else -> {
                    OutlinedButton(onClick = onRefresh, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.guard_check_connection))
                    }
                }
            }

            // Sub-Panel: Change PIN
            AnimatedVisibility(visible = showChangePinDialog) {
                var currPin by remember { mutableStateOf("") }
                var nextPin by remember { mutableStateOf("") }

                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(12.dp))
                        .padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(stringResource(R.string.guard_dialog_change_pin_title), fontWeight = FontWeight.Bold, fontSize = 14.sp)
                    OutlinedTextField(
                        value = currPin,
                        onValueChange = { currPin = it },
                        label = { Text(stringResource(R.string.guard_curr_pin_label)) },
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = nextPin,
                        onValueChange = { nextPin = it },
                        label = { Text(stringResource(R.string.guard_next_pin_label)) },
                        modifier = Modifier.fillMaxWidth()
                    )
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        TextButton(onClick = { showChangePinDialog = false }) { Text(stringResource(R.string.guard_btn_cancel)) }
                        Button(
                            onClick = {
                                onChangePin(currPin, nextPin)
                                showChangePinDialog = false
                            },
                            enabled = currPin.isNotEmpty() && nextPin.length >= 4
                        ) {
                            Text(stringResource(R.string.guard_save_pin_btn))
                        }
                    }
                }
            }

            // Sub-Panel: Emergency Recovery
            AnimatedVisibility(visible = showRecoverDialog) {
                var rcInput by remember { mutableStateOf("") }
                var newPinInput by remember { mutableStateOf("") }

                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(12.dp))
                        .padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(stringResource(R.string.guard_recovery_dialog_title), fontWeight = FontWeight.Bold, fontSize = 14.sp, color = Color(0xFFF59E0B))
                    OutlinedTextField(
                        value = rcInput,
                        onValueChange = { rcInput = it },
                        label = { Text(stringResource(R.string.guard_recovery_code_input_label)) },
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = newPinInput,
                        onValueChange = { newPinInput = it },
                        label = { Text(stringResource(R.string.guard_next_pin_label)) },
                        modifier = Modifier.fillMaxWidth()
                    )
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        TextButton(onClick = { showRecoverDialog = false }) { Text(stringResource(R.string.guard_btn_cancel)) }
                        Button(
                            onClick = {
                                onRecover(rcInput, newPinInput)
                                showRecoverDialog = false
                            },
                            enabled = rcInput.length >= 16 && newPinInput.length >= 4,
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFF59E0B))
                        ) {
                            Text(stringResource(R.string.guard_recover_and_save_btn))
                        }
                    }
                }
            }

            // Sub-Panel: Security Policies
            AnimatedVisibility(visible = showPolicySettings) {
                var wipeOn5 by remember(status.policy) { mutableStateOf(status.policy.wipeOn5Failures) }
                var protectKeys by remember(status.policy) { mutableStateOf(status.policy.protectKeysAndAegn) }
                var protectOath by remember(status.policy) { mutableStateOf(status.policy.protectOath) }
                var testModeWipe by remember(status.policy) { mutableStateOf(status.policy.testModeNonDestructiveWipe) }

                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(12.dp))
                        .padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Text(stringResource(R.string.guard_policies_title), fontWeight = FontWeight.Bold, fontSize = 14.sp)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Checkbox(checked = wipeOn5, onCheckedChange = { wipeOn5 = it })
                        Text(
                            stringResource(R.string.guard_policy_wipe_on_5),
                            fontSize = 12.sp,
                            modifier = Modifier.weight(1f)
                        )
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Checkbox(checked = protectKeys, onCheckedChange = { protectKeys = it })
                        Text(
                            stringResource(R.string.guard_policy_protect_keys),
                            fontSize = 12.sp,
                            modifier = Modifier.weight(1f)
                        )
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Checkbox(checked = protectOath, onCheckedChange = { protectOath = it })
                        Text(
                            stringResource(R.string.guard_policy_protect_oath),
                            fontSize = 12.sp,
                            modifier = Modifier.weight(1f)
                        )
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Checkbox(checked = testModeWipe, onCheckedChange = { testModeWipe = it })
                        Text(
                            stringResource(R.string.guard_policy_test_mode),
                            fontSize = 12.sp,
                            modifier = Modifier.weight(1f)
                        )
                    }
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        TextButton(onClick = { showPolicySettings = false }) { Text(stringResource(R.string.guard_btn_close)) }
                        Button(
                            onClick = {
                                onUpdatePolicy(
                                    status.policy.copy(
                                        wipeOn5Failures = wipeOn5,
                                        protectKeysAndAegn = protectKeys,
                                        protectOath = protectOath,
                                        testModeNonDestructiveWipe = testModeWipe
                                    )
                                )
                                showPolicySettings = false
                            }
                        ) {
                            Text(stringResource(R.string.guard_save_policies_btn))
                        }
                    }
                }
            }
        }
    }

    // Modal Popup de PIN por Sessão Sincronizada
    // Never opened for ErrorLocked: that state routes to the recovery
    // panel above instead of any PIN entry.
    if (!ErrorLockedRecovery.isErrorLocked(status.state)) {
        activePopupOperation?.let { opType ->
            HardwareSessionPinPopupDialog(
                isOpen = true,
                status = status,
                operationType = opType,
                isLoading = uiState.isLoading,
                errorMessage = uiState.errorMessage,
                onDismissRequest = { activePopupOperation = null },
                onConfirmPin = { pin, token ->
                    val prevOp = opType
                    activePopupOperation = null
                    when (prevOp) {
                        HardwareSessionOperationType.PROVISION_SESSION -> {
                            onProvision(pin, null, null)
                        }
                        HardwareSessionOperationType.UNLOCK_SESSION -> {
                            onUnlock(pin)
                        }
                        HardwareSessionOperationType.WIPE_SELECTIVE -> {
                            onWipeSelective(0, token ?: "CONFIRM_WIPE_AEGIS_GUARD")
                        }
                        else -> {
                            onUnlock(pin)
                        }
                    }
                }
            )
        }
    }
}

/**
 * Dedicated ErrorLocked recovery panel. Explains the frozen state and
 * offers only the firmware-supported exits: the recovery-code flow, or
 * documented reprovisioning after an NVS clear. Executes nothing
 * destructive from here and never suggests retrying the PIN.
 */
@Composable
private fun ErrorLockedRecoveryPanel(
    onUseRecoveryCode: () -> Unit,
    onRefresh: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(Color(0xFF450A0A).copy(alpha = 0.12f), RoundedCornerShape(10.dp))
            .border(1.dp, Color(0xFFDC2626).copy(alpha = 0.5f), RoundedCornerShape(10.dp))
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text(
            text = stringResource(R.string.guard_error_locked_title),
            fontSize = 13.sp,
            fontWeight = FontWeight.Bold,
            color = Color(0xFFDC2626)
        )
        Text(
            text = stringResource(R.string.guard_error_locked_desc),
            fontSize = 12.sp,
            color = MaterialTheme.colorScheme.onSurface
        )
        Text(
            text = stringResource(R.string.guard_error_locked_no_retry),
            fontSize = 12.sp,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.error
        )
        Button(
            onClick = onUseRecoveryCode,
            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary),
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(stringResource(R.string.guard_error_locked_recovery_btn))
        }
        Text(
            text = stringResource(R.string.guard_error_locked_reprovision_hint),
            fontSize = 11.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            lineHeight = 15.sp
        )
        OutlinedButton(onClick = onRefresh, modifier = Modifier.fillMaxWidth()) {
            Icon(imageVector = Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.size(14.dp))
            Spacer(modifier = Modifier.width(4.dp))
            Text(stringResource(R.string.guard_refresh), fontSize = 12.sp)
        }
    }
}
