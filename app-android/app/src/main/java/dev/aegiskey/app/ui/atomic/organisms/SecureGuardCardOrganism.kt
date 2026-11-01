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
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
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
import dev.aegiskey.app.domain.model.SecureGuardPolicy
import dev.aegiskey.app.domain.model.SecureGuardStateEnum
import dev.aegiskey.app.ui.atomic.atoms.SecureGuardBadgeAtom
import dev.aegiskey.app.ui.atomic.molecules.RateLimitTimerMolecule
import dev.aegiskey.app.ui.atomic.molecules.SecurePinKeypadMolecule
import dev.aegiskey.app.ui.atomic.molecules.SessionExpiryTimerMolecule
import dev.aegiskey.app.ui.viewmodel.SecureGuardUiState

/**
 * Secure Guard authority organism (Zero-Trust On-Device Authority Vault).
 * Standardized in ASD-STE100 technical English with 100% responsive Layouts.
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
    var showChangePinDialog by remember { mutableStateOf(false) }
    var showRecoverDialog by remember { mutableStateOf(false) }
    var showPolicySettings by remember { mutableStateOf(false) }
    var showWipeConfirm by remember { mutableStateOf(false) }

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f))
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
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
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "🛡️ ${stringResource(R.string.guard_title)}",
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
                        CircularProgressIndicator(modifier = Modifier.padding(end = 4.dp), strokeWidth = 2.dp)
                    }
                    OutlinedButton(
                        onClick = onRefresh,
                        modifier = Modifier.padding(0.dp)
                    ) {
                        Text(stringResource(R.string.guard_refresh), fontSize = 12.sp)
                    }
                }
            }

            // Attempts Badge & Telemetry Bar
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(10.dp))
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = stringResource(R.string.guard_remaining_attempts),
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.weight(1f, fill = false)
                )
                Text(
                    text = "[ ${status.remainingAttempts} / ${status.maxAttempts} ]",
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    color = if (status.remainingAttempts <= 2) Color(0xFFEF4444) else MaterialTheme.colorScheme.onSurface
                )
            }

            // Live Timers
            if (status.state == SecureGuardStateEnum.RATE_LIMITED && status.rateLimitRemainingMs > 0) {
                RateLimitTimerMolecule(remainingMs = status.rateLimitRemainingMs)
            } else if (status.state == SecureGuardStateEnum.UNLOCKED && status.sessionRemainingMs > 0) {
                SessionExpiryTimerMolecule(remainingMs = status.sessionRemainingMs)
            }

            // Feedback Messages
            if (uiState.errorMessage != null) {
                Text(
                    text = "⚠️ ${uiState.errorMessage}",
                    color = MaterialTheme.colorScheme.error,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Medium
                )
            }
            if (uiState.successMessage != null) {
                Text(
                    text = "✅ ${uiState.successMessage}",
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

            // State-Specific Action Panels
            when (status.state) {
                SecureGuardStateEnum.UNPROVISIONED -> {
                    Text(
                        text = stringResource(R.string.guard_unprovisioned_desc),
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    SecurePinKeypadMolecule(
                        label = stringResource(R.string.guard_new_pin),
                        buttonText = stringResource(R.string.guard_init_btn),
                        enabled = !uiState.isLoading,
                        errorMessage = uiState.errorMessage,
                        onSubmit = { pin -> onProvision(pin, null, null) }
                    )
                }

                SecureGuardStateEnum.LOCKED, SecureGuardStateEnum.RATE_LIMITED -> {
                    SecurePinKeypadMolecule(
                        label = stringResource(R.string.guard_unlock_pin),
                        buttonText = stringResource(R.string.guard_unlock_btn),
                        enabled = !uiState.isLoading && status.state != SecureGuardStateEnum.RATE_LIMITED,
                        errorMessage = uiState.errorMessage,
                        onSubmit = onUnlock
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        TextButton(onClick = { showRecoverDialog = !showRecoverDialog }) {
                            Text(stringResource(R.string.guard_emergency_recovery), fontSize = 12.sp, color = Color(0xFFF59E0B))
                        }
                    }
                }

                SecureGuardStateEnum.UNLOCKED -> {
                    // FlowRow to prevent clipping/wrapping collisions on narrow screens
                    FlowRow(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = onLock,
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                        ) {
                            Text("🔒 ${stringResource(R.string.guard_lock_now)}")
                        }
                        OutlinedButton(
                            onClick = { showChangePinDialog = !showChangePinDialog }
                        ) {
                            Text(stringResource(R.string.guard_change_pin))
                        }
                        TextButton(onClick = { showPolicySettings = !showPolicySettings }) {
                            Text("⚙️ ${stringResource(R.string.guard_security_policies)}", fontSize = 12.sp)
                        }
                        TextButton(onClick = { showWipeConfirm = !showWipeConfirm }) {
                            Text("🔥 ${stringResource(R.string.guard_selective_wipe)}", fontSize = 12.sp, color = MaterialTheme.colorScheme.error)
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
                                text = "⚠️ ${stringResource(R.string.guard_max_attempts_reached)}",
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFFF97316)
                            )
                            Text(
                                text = stringResource(R.string.guard_recovery_desc),
                                fontSize = 12.sp,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                        }
                    }
                    showRecoverDialog = true
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

            // Sub-Panel: Selective Wipe
            AnimatedVisibility(visible = showWipeConfirm) {
                var confirmToken by remember { mutableStateOf("") }

                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.3f), RoundedCornerShape(12.dp))
                        .border(1.dp, MaterialTheme.colorScheme.error, RoundedCornerShape(12.dp))
                        .padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "⚠️ ${stringResource(R.string.guard_wipe_title)}",
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp,
                        color = MaterialTheme.colorScheme.error
                    )
                    Text(
                        text = stringResource(R.string.guard_wipe_instruction),
                        fontSize = 11.sp
                    )
                    OutlinedTextField(
                        value = confirmToken,
                        onValueChange = { confirmToken = it },
                        label = { Text(stringResource(R.string.guard_confirm_token_label)) },
                        modifier = Modifier.fillMaxWidth()
                    )
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        TextButton(onClick = { showWipeConfirm = false }) { Text(stringResource(R.string.guard_btn_cancel)) }
                        Button(
                            onClick = {
                                onWipeSelective(0, confirmToken)
                                showWipeConfirm = false
                            },
                            enabled = confirmToken == "CONFIRM_WIPE_AEGIS_GUARD",
                            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                        ) {
                            Text(stringResource(R.string.guard_confirm_wipe_btn))
                        }
                    }
                }
            }
        }
    }
}
