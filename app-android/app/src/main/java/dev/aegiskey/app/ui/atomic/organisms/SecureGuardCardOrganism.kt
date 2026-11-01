package dev.aegiskey.app.ui.atomic.organisms

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.aegiskey.app.domain.model.SecureGuardPolicy
import dev.aegiskey.app.domain.model.SecureGuardStateEnum
import dev.aegiskey.app.ui.atomic.atoms.SecureGuardBadgeAtom
import dev.aegiskey.app.ui.atomic.molecules.RateLimitTimerMolecule
import dev.aegiskey.app.ui.atomic.molecules.SecurePinKeypadMolecule
import dev.aegiskey.app.ui.atomic.molecules.SessionExpiryTimerMolecule
import dev.aegiskey.app.ui.viewmodel.SecureGuardUiState

/**
 * Secure Guard authority organism (Zero-Trust On-Device Authority Vault).
 * Standardized in ASD-STE100 technical English.
 */
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
            // Header: Title + Badge + Refresh
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            text = "🛡️ Secure Guard",
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        SecureGuardBadgeAtom(state = status.state)
                    }
                    Text(
                        text = "Zero-Trust On-Device Authority",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    if (uiState.isLoading) {
                        CircularProgressIndicator(modifier = Modifier.padding(end = 4.dp), strokeWidth = 2.dp)
                    }
                    OutlinedButton(onClick = onRefresh, modifier = Modifier.padding(0.dp)) {
                        Text("Refresh", fontSize = 12.sp)
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
                    text = "Remaining Attempts:",
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
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
                            text = "Emergency Recovery Code:",
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
                            text = "Store this recovery code in a secure offline location.",
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
                        text = "Secure Guard is not initialized. Enter a 4 to 16 digit PIN to protect your crypto wallets.",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    SecurePinKeypadMolecule(
                        label = "New Vault PIN",
                        buttonText = "Initialize Secure Guard",
                        enabled = !uiState.isLoading,
                        errorMessage = uiState.errorMessage,
                        onSubmit = { pin -> onProvision(pin, null, null) }
                    )
                }

                SecureGuardStateEnum.LOCKED, SecureGuardStateEnum.RATE_LIMITED -> {
                    SecurePinKeypadMolecule(
                        label = "Unlock PIN",
                        buttonText = "Unlock",
                        enabled = !uiState.isLoading && status.state != SecureGuardStateEnum.RATE_LIMITED,
                        errorMessage = uiState.errorMessage,
                        onSubmit = onUnlock
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        TextButton(onClick = { showRecoverDialog = !showRecoverDialog }) {
                            Text("Emergency Recovery", fontSize = 12.sp, color = Color(0xFFF59E0B))
                        }
                    }
                }

                SecureGuardStateEnum.UNLOCKED -> {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Button(
                            onClick = onLock,
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("🔒 Lock Now")
                        }
                        OutlinedButton(
                            onClick = { showChangePinDialog = !showChangePinDialog },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Change PIN")
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        TextButton(onClick = { showPolicySettings = !showPolicySettings }) {
                            Text("⚙️ Security Policies", fontSize = 12.sp)
                        }
                        TextButton(onClick = { showWipeConfirm = !showWipeConfirm }) {
                            Text("🔥 Selective Wipe", fontSize = 12.sp, color = MaterialTheme.colorScheme.error)
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
                                text = "⚠️ Maximum attempts limit reached",
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFFF97316)
                            )
                            Text(
                                text = "Secure Guard is locked for security. Enter your 16-character Recovery Code to restore access.",
                                fontSize = 12.sp,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                        }
                    }
                    showRecoverDialog = true
                }

                else -> {
                    OutlinedButton(onClick = onRefresh, modifier = Modifier.fillMaxWidth()) {
                        Text("Check Security Key Connection")
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
                    Text("Change Vault PIN", fontWeight = FontWeight.Bold, fontSize = 14.sp)
                    OutlinedTextField(
                        value = currPin,
                        onValueChange = { currPin = it },
                        label = { Text("Current PIN") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = nextPin,
                        onValueChange = { nextPin = it },
                        label = { Text("New PIN (4 to 16 digits)") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Row(horizontalArrangement = Arrangement.End, modifier = Modifier.fillMaxWidth()) {
                        TextButton(onClick = { showChangePinDialog = false }) { Text("Cancel") }
                        Button(
                            onClick = {
                                onChangePin(currPin, nextPin)
                                showChangePinDialog = false
                            },
                            enabled = currPin.isNotEmpty() && nextPin.length >= 4
                        ) {
                            Text("Save New PIN")
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
                    Text("Emergency Recovery with Recovery Code", fontWeight = FontWeight.Bold, fontSize = 14.sp, color = Color(0xFFF59E0B))
                    OutlinedTextField(
                        value = rcInput,
                        onValueChange = { rcInput = it },
                        label = { Text("Recovery Code (XXXX-XXXX-XXXX-XXXX)") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = newPinInput,
                        onValueChange = { newPinInput = it },
                        label = { Text("New PIN (4 to 16 digits)") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Row(horizontalArrangement = Arrangement.End, modifier = Modifier.fillMaxWidth()) {
                        TextButton(onClick = { showRecoverDialog = false }) { Text("Cancel") }
                        Button(
                            onClick = {
                                onRecover(rcInput, newPinInput)
                                showRecoverDialog = false
                            },
                            enabled = rcInput.length >= 16 && newPinInput.length >= 4,
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFF59E0B))
                        ) {
                            Text("Recover and Save")
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
                    Text("On-Chip Security Policies", fontWeight = FontWeight.Bold, fontSize = 14.sp)
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = wipeOn5, onCheckedChange = { wipeOn5 = it })
                        Text("Automatic wipe after 5 consecutive failed attempts", fontSize = 12.sp)
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = protectKeys, onCheckedChange = { protectKeys = it })
                        Text("Protect private keys and AEGN envelopes", fontSize = 12.sp)
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = protectOath, onCheckedChange = { protectOath = it })
                        Text("Protect OATH accounts (TOTP / HOTP)", fontSize = 12.sp)
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = testModeWipe, onCheckedChange = { testModeWipe = it })
                        Text("Non-destructive test mode (Simulated wipe)", fontSize = 12.sp)
                    }
                    Row(horizontalArrangement = Arrangement.End, modifier = Modifier.fillMaxWidth()) {
                        TextButton(onClick = { showPolicySettings = false }) { Text("Close") }
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
                            Text("Save Policies")
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
                    Text("⚠️ Selective Wipe of Protected Resources", fontWeight = FontWeight.Bold, fontSize = 14.sp, color = MaterialTheme.colorScheme.error)
                    Text("Type CONFIRM_WIPE_AEGIS_GUARD to confirm selective wipe.", fontSize = 11.sp)
                    OutlinedTextField(
                        value = confirmToken,
                        onValueChange = { confirmToken = it },
                        label = { Text("Confirmation Token") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Row(horizontalArrangement = Arrangement.End, modifier = Modifier.fillMaxWidth()) {
                        TextButton(onClick = { showWipeConfirm = false }) { Text("Cancel") }
                        Button(
                            onClick = {
                                onWipeSelective(0, confirmToken)
                                showWipeConfirm = false
                            },
                            enabled = confirmToken == "CONFIRM_WIPE_AEGIS_GUARD",
                            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                        ) {
                            Text("Confirm Wipe")
                        }
                    }
                }
            }
        }
    }
}
