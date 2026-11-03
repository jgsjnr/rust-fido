package dev.aegiskey.app.touchpolicy

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.TouchApp
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.R
import dev.aegiskey.app.ui.atomic.atoms.AegisSwitchAtom

/**
 * Per-credential touch (UP) policy — single entrypoint of the touchpolicy module.
 *
 * Wire contract (firmware `CAPABILITY_DIET.md` §8.4, executor
 * `ctap_cmd::set_credential_up_policy`): SET travels as `CMD_MSG` opcode
 * `0x40` with body `[up_flag:1][cred_id_len:1][cred_id]`
 * (`up_flag in {0,1}`, `1 <= cred_id_len <= 128`); response is
 * status-first (`0x00` ok, `0x02` NEED_PIN, `0x03` NO_SLOT, `0x04` fail).
 * Transports frame it as `sendVendor(0x40, body)` (CTAPHID MSG payload
 * `[0x40, ...]`, USB answers `[0x40, status, ...]`); the parser also
 * tolerates the status-first bridge framing (`[status, ...]`).
 *
 * `cred_id` carries the vault slot identity (single byte). The app has no
 * CTAP credential id for vendor slots; the dispatcher follow-up resolves
 * the slot to its credential. The local default is fail-safe:
 * require-touch is assumed whenever the device state is unknown.
 *
 * GET state: the key list exposes no per-slot flag, so the app tracks the
 * flag locally per `(keyId, slotId)` in the sealed vault cache
 * (`VaultKeyEntry.requiresPhysicalTouch`, default `true`) and refreshes it
 * on connect. The device answer is the authority on SET; the local flag
 * only changes on `0x00`.
 *
 * This module invents no telemetry: every state change translates a
 * structured device response. No core crates are imported.
 */
object TouchPolicy {
    /** `CMD_MSG` opcode for the UP-policy SET (first free byte after `GET_CAPS 0x3F`). */
    const val OP_UP_POLICY_SET: Int = 0x40

    /** Maximum `cred_id` length accepted on the wire (firmware `CRED_ID_MAX_BYTES`). */
    const val CRED_ID_MAX_BYTES: Int = 128

    /** Fail-safe default: touch required when the device state is unknown. */
    const val DEFAULT_REQUIRE_TOUCH: Boolean = true

    fun upFlag(requireTouch: Boolean): Int = if (requireTouch) 1 else 0

    /**
     * Slot identity carried as `cred_id`. Single byte, always `1..=128 B`
     * on the wire. Never empty, never a secret.
     */
    fun credIdForSlot(slotId: Int): ByteArray {
        require(slotId in 0..255) { "slot fora de 0..255" }
        return byteArrayOf(slotId.toByte())
    }

    /** Request body: `[up_flag:1][cred_id_len:1][cred_id]`. */
    fun buildSetRequest(requireTouch: Boolean, slotId: Int): ByteArray {
        val credId = credIdForSlot(slotId)
        require(credId.size in 1..CRED_ID_MAX_BYTES) { "cred_id fora de 1..128 B" }
        return byteArrayOf(upFlag(requireTouch).toByte(), credId.size.toByte()) + credId
    }

    /**
     * Status byte of a SET response. Prefers the `[op, status, ...]` echo
     * framing; falls back to status-first (`[status, ...]`) used by the
     * host bridge JSON path. Null when absent or empty — never invented.
     */
    fun statusOf(raw: ByteArray?): Int? {
        if (raw == null || raw.isEmpty()) return null
        if (raw.size >= 2 && (raw[0].toInt() and 0xFF) == OP_UP_POLICY_SET) {
            return raw[1].toInt() and 0xFF
        }
        return raw[0].toInt() and 0xFF
    }

    /** Structured outcome of a SET response. Unknown bytes are failures, never success. */
    sealed interface SetResult {
        data object Ok : SetResult
        data object NeedPin : SetResult
        data object NoSlot : SetResult
        data class Failure(val status: Int) : SetResult
    }

    fun parseSetResponse(raw: ByteArray?): SetResult {
        return when (val status = statusOf(raw)) {
            0x00 -> SetResult.Ok
            0x02 -> SetResult.NeedPin
            0x03 -> SetResult.NoSlot
            else -> SetResult.Failure(status ?: -1)
        }
    }

    /** Session locked (local gate) or device answered NEED_PIN (`0x02`). */
    class TouchNeedPinException(op: String = "touch-policy-set") :
        IllegalStateException("Device denied $op: PIN required (0x02)")

    /** Device answered NO_SLOT (`0x03`): fail-closed, local flag untouched. */
    class TouchNoSlotException(val slotId: Int) :
        IllegalStateException("No credential at slot #$slotId (0x03)")

    /** Local resolution with the fail-safe default. */
    fun resolveLocal(cached: Boolean?): Boolean = cached ?: DEFAULT_REQUIRE_TOUCH

    /** Structured UI outcome for a toggle attempt. Rendered via `strings.xml` (PT+EN). */
    sealed interface TouchOutcome {
        data class Applied(val requireTouch: Boolean) : TouchOutcome
        data object NeedPin : TouchOutcome
        data object NoSlot : TouchOutcome
        data class Failed(val label: String) : TouchOutcome
    }
}

/**
 * Per-key touch toggle card. Same theme as the other key-detail cards
 * (no redesign): `OutlinedCard`, `MaterialTheme`, `AegisSwitchAtom`.
 * Turning the toggle ON applies directly (safe direction). Turning it OFF
 * requires the explicit confirm dialog below (phishing-resistance warning,
 * user choice recorded by the repository on success).
 */
@Composable
fun TouchPolicyCard(
    requireTouch: Boolean,
    isLoading: Boolean,
    isGuardUnlocked: Boolean,
    onToggle: (Boolean) -> Unit,
    onUnlockRequest: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var showDisableConfirm by remember { mutableStateOf(false) }

    OutlinedCard(
        shape = RoundedCornerShape(16.dp),
        modifier = modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.weight(1f).padding(end = 8.dp)
            ) {
                Icon(
                    imageVector = Icons.Filled.TouchApp,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.touch_require_title),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = stringResource(
                            if (requireTouch) R.string.touch_require_on_desc
                            else R.string.touch_require_off_desc
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
            if (isLoading) {
                CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
            } else {
                AegisSwitchAtom(
                    checked = requireTouch,
                    onCheckedChange = { checked ->
                        if (!isGuardUnlocked) {
                            onUnlockRequest()
                        } else if (!checked) {
                            showDisableConfirm = true
                        } else {
                            onToggle(true)
                        }
                    }
                )
            }
        }
    }

    if (showDisableConfirm) {
        TouchPolicyConfirmDialog(
            onConfirm = {
                showDisableConfirm = false
                onToggle(false)
            },
            onDismiss = { showDisableConfirm = false }
        )
    }
}

/**
 * Explicit-choice confirm dialog for disabling touch. Short ASD-STE100
 * text, one concept per string, no emoji.
 */
@Composable
fun TouchPolicyConfirmDialog(
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(18.dp),
        icon = {
            Icon(
                imageVector = Icons.Filled.WarningAmber,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.error,
                modifier = Modifier.size(32.dp)
            )
        },
        title = {
            Text(
                text = stringResource(R.string.touch_confirm_title),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold
            )
        },
        text = {
            Text(
                text = stringResource(R.string.touch_confirm_desc),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        },
        confirmButton = {
            Button(
                onClick = onConfirm,
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error,
                    contentColor = MaterialTheme.colorScheme.onError
                )
            ) {
                Text(stringResource(R.string.touch_confirm_disable))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.vault_cancel_btn))
            }
        }
    )
}
