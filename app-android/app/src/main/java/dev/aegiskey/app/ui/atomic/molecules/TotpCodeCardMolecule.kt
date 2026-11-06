package dev.aegiskey.app.ui.atomic.molecules

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.PlusOne
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.R
import dev.aegiskey.app.domain.model.isLiveTotpCode
import dev.aegiskey.app.ui.atomic.atoms.QuickActionPillButton
import dev.aegiskey.app.ui.atomic.atoms.TotpCountdownRingAtom
import dev.aegiskey.app.ui.theme.AegisCodeMonospaceStyle

private fun formatGroupedDigits(rawCode: String): String {
    val clean = rawCode.filter { it.isDigit() }
    if (clean.length <= 3) return rawCode
    return clean.chunked(3).joinToString(" ")
}

/**
 * TOTP and HOTP verification code card molecule (RFC 4226 / RFC 6238).
 */
@Composable
fun TotpCodeCardMolecule(
    issuer: String,
    accountName: String,
    code: String,
    remainingSeconds: Int,
    totalSeconds: Int = 30,
    isHotp: Boolean = false,
    counter: Long = 0L,
    onCopyCode: (String) -> Unit,
    onIncrementHotp: (() -> Unit)? = null,
    onDeleteAccount: (() -> Unit)? = null,
    /**
     * Finding A3: honest code provenance. True only when [code] was just
     * returned by the device; false (fail-safe) labels it as local so the
     * user never mistakes a locally-computed code for a device-backed one.
     */
    isOnDeviceBacked: Boolean = false,
    modifier: Modifier = Modifier,
) {
    // Detail guard: without a live session there is no code — hide the
    // row entirely instead of rendering the "------" placeholder line.
    // The list stays empty with a neutral "connect the key" hint.
    if (!isLiveTotpCode(code)) return
    val formattedCode = formatGroupedDigits(code)
    val issuerFallback = stringResource(R.string.totp_card_fallback_issuer)
    val accountFallback = stringResource(R.string.totp_card_fallback_account)

    ElevatedCard(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
        elevation = CardDefaults.elevatedCardElevation(defaultElevation = 1.dp),
        modifier = modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = MaterialTheme.colorScheme.secondaryContainer,
                    modifier = Modifier.size(36.dp),
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(
                            imageVector = Icons.Filled.Key,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSecondaryContainer,
                            modifier = Modifier.size(18.dp),
                        )
                    }
                }

                Spacer(modifier = Modifier.width(10.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Text(
                            text = issuer.ifBlank { issuerFallback },
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f, fill = false)
                        )

                        Surface(
                            shape = RoundedCornerShape(6.dp),
                            color = if (isHotp) MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.5f)
                            else MaterialTheme.colorScheme.surfaceVariant
                        ) {
                            Text(
                                text = if (isHotp) "HOTP" else "TOTP",
                                style = MaterialTheme.typography.labelSmall,
                                color = if (isHotp) MaterialTheme.colorScheme.onTertiaryContainer
                                else MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp)
                            )
                        }
                    }

                    Text(
                        text = accountName.ifBlank { accountFallback },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )

                    Text(
                        text = stringResource(
                            if (isOnDeviceBacked) R.string.totp_source_device
                            else R.string.totp_source_local
                        ),
                        style = MaterialTheme.typography.labelSmall,
                        color = if (isOnDeviceBacked) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                }

                if (onDeleteAccount != null) {
                    IconButton(
                        onClick = onDeleteAccount,
                        modifier = Modifier.size(30.dp),
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Delete,
                            contentDescription = stringResource(R.string.cd_delete_code),
                            tint = MaterialTheme.colorScheme.error.copy(alpha = 0.8f),
                            modifier = Modifier.size(16.dp),
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = formattedCode.ifBlank { "--- ---" },
                    style = AegisCodeMonospaceStyle,
                    color = MaterialTheme.colorScheme.primary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )

                Spacer(modifier = Modifier.width(8.dp))

                if (isHotp) {
                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.5f)
                    ) {
                        Text(
                            text = stringResource(R.string.totp_card_counter, counter),
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onTertiaryContainer,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                        )
                    }
                } else {
                    TotpCountdownRingAtom(
                        remainingSeconds = remainingSeconds,
                        totalSeconds = totalSeconds,
                    )
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (isHotp && onIncrementHotp != null) {
                    OutlinedButton(
                        onClick = onIncrementHotp,
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.height(34.dp)
                    ) {
                        Icon(imageVector = Icons.Filled.PlusOne, contentDescription = null, modifier = Modifier.size(14.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(stringResource(R.string.totp_card_next_code), style = MaterialTheme.typography.labelSmall)
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                }

                QuickActionPillButton(
                    text = stringResource(R.string.totp_card_copy),
                    icon = Icons.Filled.ContentCopy,
                    onClick = { onCopyCode(code.filter { it.isDigit() }) },
                )
            }
        }
    }
}
