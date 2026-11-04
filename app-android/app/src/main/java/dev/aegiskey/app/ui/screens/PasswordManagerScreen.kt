package dev.aegiskey.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.R
import dev.aegiskey.app.pm.PmCbor
import dev.aegiskey.app.ui.GateBanner
import dev.aegiskey.app.ui.VaultGate
import dev.aegiskey.app.ui.viewmodel.PasswordManagerViewModel
import dev.aegiskey.app.ui.viewmodel.SecureGuardViewModel

/**
 * Password vault viewer (F-PM2, blind transport).
 *
 * - Lists opaque device record ids only (truncated-hex handles; the
 *   device never sends labels to this edge).
 * - Search filters the loaded opaque-id handles in RAM (no index, no
 *   cache, no disk).
 * - The released username/secret shows once in a dialog and is zeroized
 *   on dismiss via [PasswordManagerViewModel.closeRelease].
 * - Gate denials (NeedBinding/PresenceRequired/PinRequired) reuse the
 *   vault [GateBanner] UX and the existing unlock flow.
 */
@Composable
fun PasswordManagerScreen(
    viewModel: PasswordManagerViewModel,
    secureGuardViewModel: SecureGuardViewModel? = null,
    onNavigateToDevices: () -> Unit = {},
    onCopyText: (String) -> Unit = {},
    modifier: Modifier = Modifier,
) {
    val uiState by viewModel.uiState.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(uiState.errorMessage, uiState.userMessage) {
        uiState.errorMessage?.let { snackbarHostState.showSnackbar(it); viewModel.clearMessages() }
        uiState.userMessage?.let { snackbarHostState.showSnackbar(it); viewModel.clearMessages() }
    }

    Column(modifier = modifier.fillMaxSize()) {
        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                Text(
                    text = stringResource(R.string.pm_title),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = stringResource(R.string.pm_subtitle),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            // Gate banner (same UX as the vault tabs).
            if (uiState.gate != VaultGate.READY) {
                item {
                    GateBanner(
                        gate = uiState.gate,
                        onConnect = onNavigateToDevices,
                        onBind = onNavigateToDevices,
                    )
                    if (uiState.gate == VaultGate.NEED_UP && secureGuardViewModel != null) {
                        OutlinedButton(
                            onClick = { viewModel.refresh() },
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 8.dp),
                        ) {
                            Text(stringResource(R.string.pm_retry_after_touch))
                        }
                    }
                    if (uiState.gate == VaultGate.NEED_PIN && secureGuardViewModel != null) {
                        Button(
                            onClick = { secureGuardViewModel.openUnlockPrompt() },
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 8.dp),
                        ) {
                            Text(stringResource(R.string.guard_btn_unlock_session))
                        }
                    }
                }
            }

            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    OutlinedTextField(
                        value = uiState.query,
                        onValueChange = { viewModel.setQuery(it) },
                        label = { Text(stringResource(R.string.pm_search_hint)) },
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    OutlinedButton(
                        onClick = { viewModel.refresh() },
                        enabled = !uiState.isLoading,
                    ) {
                        Icon(imageVector = Icons.Filled.Refresh, contentDescription = null)
                    }
                }
                val census = if (uiState.entryCount != null) {
                    stringResource(
                        R.string.pm_census,
                        uiState.entryCount!!,
                        uiState.maxEntries ?: 0L,
                    )
                } else {
                    stringResource(R.string.pm_census_unknown)
                }
                Text(
                    text = census,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 6.dp),
                )
            }

            if (uiState.visibleIds.isEmpty() && !uiState.isLoading) {
                item {
                    OutlinedCard(
                        shape = RoundedCornerShape(12.dp),
                        colors = CardDefaults.outlinedCardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f)
                        ),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Column(modifier = Modifier.padding(18.dp)) {
                            Text(
                                text = stringResource(R.string.pm_empty_title),
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold,
                            )
                            Text(
                                text = stringResource(R.string.pm_empty_desc),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            } else {
                items(uiState.visibleIds, key = { PmCbor.opaqueIdHex(it) }) { id ->
                    OutlinedCard(
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = PmCbor.opaqueIdLabel(id),
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.SemiBold,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                                Text(
                                    text = stringResource(R.string.pm_id_hint),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                            Spacer(modifier = Modifier.width(8.dp))
                            Button(
                                onClick = { viewModel.openRelease(id) },
                                enabled = !uiState.isReleaseLoading,
                            ) {
                                Text(stringResource(R.string.pm_reveal_btn))
                            }
                        }
                    }
                }
                if (uiState.hasMore) {
                    item {
                        OutlinedButton(
                            onClick = { viewModel.loadMore() },
                            enabled = !uiState.isLoading,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text(stringResource(R.string.pm_load_more))
                        }
                    }
                }
            }

            item { Spacer(modifier = Modifier.height(16.dp)) }
        }

        SnackbarHost(
            hostState = snackbarHostState,
            modifier = Modifier.padding(bottom = 12.dp),
        )
    }

    // Punctual release dialog: single display, zeroized on ANY dismiss.
    val release = uiState.release
    if (release != null) {
        val secretText = remember(release) { String(release.secret) }
        AlertDialog(
            onDismissRequest = {
                viewModel.closeRelease()
            },
            shape = RoundedCornerShape(16.dp),
            title = {
                Text(
                    text = stringResource(R.string.pm_release_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = stringResource(R.string.pm_release_user, release.username),
                        style = MaterialTheme.typography.bodyMedium,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        text = secretText,
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.Bold,
                    )
                    Text(
                        text = stringResource(R.string.pm_release_wipe_note),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        onCopyText(secretText)
                        viewModel.closeRelease()
                    },
                ) {
                    Text(stringResource(R.string.pm_copy_and_close))
                }
            },
            dismissButton = {
                TextButton(onClick = { viewModel.closeRelease() }) {
                    Text(stringResource(R.string.pm_close_and_wipe))
                }
            },
        )
    }
}
