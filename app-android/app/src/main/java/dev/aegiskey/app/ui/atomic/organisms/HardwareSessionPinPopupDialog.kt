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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
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
import dev.aegiskey.app.domain.model.ErrorLockedRecovery
import dev.aegiskey.app.domain.model.SecureGuardStateEnum
import dev.aegiskey.app.domain.model.SecureGuardStatus
import dev.aegiskey.app.ui.atomic.atoms.SecureGuardBadgeAtom
import dev.aegiskey.app.ui.atomic.molecules.SecurePinKeypadMolecule

/**
 * Operações que requerem sessão sincronizada com a hardwallet via PIN Popup Modal.
 */
enum class HardwareSessionOperationType(
    val titleRes: Int,
    val confirmBtnRes: Int
) {
    UNLOCK_SESSION(R.string.guard_session_pin_title, R.string.guard_unlock_btn),
    PROVISION_SESSION(R.string.guard_new_pin, R.string.guard_init_btn),
    WIPE_SELECTIVE(R.string.guard_wipe_title, R.string.guard_confirm_wipe_btn),
    FACTORY_RESET(R.string.guard_reset_title, R.string.guard_confirm_reset_btn),
    UPDATE_POLICY(R.string.guard_policies_title, R.string.guard_save_policies_btn),
    CREATE_KEY(R.string.vault_btn_generate, R.string.pin_btn_confirm),
    DELETE_KEY(R.string.vault_delete_title, R.string.vault_delete_btn),
    CREATE_WALLET(R.string.vault_filter_crypto, R.string.pin_btn_confirm),
    SHAMIR_BACKUP(R.string.shamir_backup_title, R.string.pin_btn_confirm),
    SIGN_TRANSACTION(R.string.vault_sign_btn, R.string.pin_btn_confirm)
}

/**
 * Popup Modal de Senha/PIN por Sessão Sincronizada com a Hardwallet.
 *
 * Garante que:
 * 1. Zero PIN hardcoded em hardware: o PIN é sempre digitado pelo usuário.
 * 2. As operações de Wipe, Reset, Config, Criação/Exclusão de Chaves e Shamir batam com o PIN
 *    real do usuário configurado na hardwallet.
 * 3. A sessão é aberta/sincronizada com o timer e tentativas da hardwallet em tempo real.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun HardwareSessionPinPopupDialog(
    isOpen: Boolean,
    status: SecureGuardStatus,
    operationType: HardwareSessionOperationType,
    isLoading: Boolean = false,
    errorMessage: String? = null,
    onDismissRequest: () -> Unit,
    onConfirmPin: (pin: String, confirmationToken: String?) -> Unit,
    modifier: Modifier = Modifier,
) {
    if (!isOpen) return

    var confirmationTokenInput by remember { mutableStateOf("") }
    val isWipe = operationType == HardwareSessionOperationType.WIPE_SELECTIVE
    val isUnprovisioned = status.state == SecureGuardStateEnum.UNPROVISIONED || !status.isProvisioned
    val isRateLimited = status.state == SecureGuardStateEnum.RATE_LIMITED
    // ErrorLocked must never render a PIN form: no PIN can succeed while
    // the secure record is unreadable, so the dialog shows recovery
    // guidance instead of PIN entry.
    val isErrorLocked = ErrorLockedRecovery.isErrorLocked(status.state)

    AlertDialog(
        onDismissRequest = { if (!isLoading) onDismissRequest() },
        shape = RoundedCornerShape(20.dp),
        containerColor = MaterialTheme.colorScheme.surface,
        modifier = modifier.fillMaxWidth(),
        title = {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.weight(1f, fill = false)
                ) {
                    Icon(
                        imageVector = if (isWipe) Icons.Filled.Warning else Icons.Filled.Shield,
                        contentDescription = null,
                        tint = if (isWipe) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(24.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = stringResource(operationType.titleRes),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                SecureGuardBadgeAtom(state = status.state)
            }
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                // Operation Context Description
                val desc = if (isErrorLocked) {
                    stringResource(R.string.guard_error_locked_desc)
                } else when (operationType) {
                    HardwareSessionOperationType.UNLOCK_SESSION -> stringResource(R.string.guard_session_pin_desc_unlock)
                    HardwareSessionOperationType.PROVISION_SESSION -> stringResource(R.string.guard_unprovisioned_desc)
                    HardwareSessionOperationType.WIPE_SELECTIVE -> stringResource(R.string.guard_session_pin_desc_wipe)
                    HardwareSessionOperationType.FACTORY_RESET -> stringResource(R.string.guard_session_pin_desc_reset)
                    HardwareSessionOperationType.UPDATE_POLICY -> stringResource(R.string.guard_session_pin_desc_config)
                    else -> stringResource(R.string.guard_session_pin_desc_key_op)
                }

                Text(
                    text = desc,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                // If device is unprovisioned, show explicit suggestion hint (Zero PIN stored in hardware)
                if (isUnprovisioned) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(Color(0xFF0284C7).copy(alpha = 0.12f), RoundedCornerShape(10.dp))
                            .border(1.dp, Color(0xFF0284C7).copy(alpha = 0.4f), RoundedCornerShape(10.dp))
                            .padding(10.dp)
                    ) {
                        Row(verticalAlignment = Alignment.Top) {
                            Icon(
                                imageVector = Icons.Filled.Info,
                                contentDescription = null,
                                tint = Color(0xFF0284C7),
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = stringResource(R.string.guard_session_unprovisioned_hint),
                                fontSize = 11.sp,
                                color = MaterialTheme.colorScheme.onSurface,
                                lineHeight = 16.sp
                            )
                        }
                    }
                } else if (!isErrorLocked) {
                    // Synchronized Telemetry Status Bar (Hardware state & attempts)
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f), RoundedCornerShape(8.dp))
                            .padding(horizontal = 10.dp, vertical = 6.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = stringResource(R.string.guard_remaining_attempts),
                            fontSize = 11.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = "[ ${status.remainingAttempts} / ${status.maxAttempts} ]",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            color = if (status.remainingAttempts <= 2) Color(0xFFEF4444) else MaterialTheme.colorScheme.onSurface
                        )
                    }
                } else {
                    // Frozen counters: hide live values, label them frozen.
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
                }

                // Rate limit notice if active
                if (isRateLimited && status.rateLimitRemainingMs > 0) {
                    Text(
                        text = stringResource(R.string.guard_rate_limit_wait, (status.rateLimitRemainingMs / 1000).coerceAtLeast(1)),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = Color(0xFFF59E0B)
                    )
                }

                // Error feedback directly from hardware validation
                if (errorMessage != null) {
                    Text(
                        text = errorMessage,
                        color = MaterialTheme.colorScheme.error,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Medium
                    )
                }

                // If selective wipe, require the explicit confirmation token
                if (isWipe) {
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(
                            text = stringResource(R.string.guard_wipe_instruction),
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Medium,
                            color = MaterialTheme.colorScheme.error
                        )
                        OutlinedTextField(
                            value = confirmationTokenInput,
                            onValueChange = { confirmationTokenInput = it },
                            label = { Text(stringResource(R.string.guard_confirm_token_label)) },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                }

                // Masked PIN entry keypad molecule. Never rendered for
                // ErrorLocked: PIN entry cannot succeed, so show the
                // firmware-supported exits instead.
                if (isErrorLocked) {
                    Text(
                        text = stringResource(R.string.guard_error_locked_no_retry),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.error
                    )
                    Text(
                        text = stringResource(R.string.guard_error_locked_reprovision_hint),
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        lineHeight = 15.sp
                    )
                } else {
                    SecurePinKeypadMolecule(
                        label = if (isUnprovisioned) stringResource(R.string.guard_new_pin) else stringResource(R.string.guard_unlock_pin),
                        buttonText = stringResource(operationType.confirmBtnRes),
                        enabled = !isLoading && !isRateLimited && (!isWipe || confirmationTokenInput == "CONFIRM_WIPE_AEGIS_GUARD"),
                        errorMessage = errorMessage,
                        onSubmit = { pin ->
                            val token = if (isWipe) confirmationTokenInput else null
                            onConfirmPin(pin, token)
                        }
                    )
                }

                if (isLoading) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 4.dp),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(20.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = stringResource(R.string.hw_sync),
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(
                onClick = onDismissRequest,
                enabled = !isLoading
            ) {
                Text(stringResource(R.string.guard_btn_cancel))
            }
        }
    )
}
