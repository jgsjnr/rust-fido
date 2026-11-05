package dev.aegiskey.app.ui.screens

import android.app.Activity
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.R
import dev.aegiskey.app.pm.PmCbor
import dev.aegiskey.app.ui.GateBanner
import dev.aegiskey.app.ui.VaultGate
import dev.aegiskey.app.ui.viewmodel.PasswordManagerViewModel
import dev.aegiskey.app.ui.viewmodel.SecureGuardViewModel
import kotlinx.coroutines.launch

/**
 * Password vault viewer + creator (F-PM2, blind transport).
 *
 * - Lists opaque device record ids only (truncated-hex handles; the
 *   device never sends labels to this edge).
 * - Search filters the loaded opaque-id handles in RAM (no index, no
 *   cache, no disk).
 * - "New password" opens a create form (service/account/secret → PUT
 *   `0x43`); typed fields are transient RAM only, sealed device-side,
 *   never logged or persisted. Blank fields never reach the transport.
 * - Each row has a scoped per-item delete (`0x46`, confirm dialog): only
 *   that record is removed — FIDO2 keys and other slots are untouched.
 * - Tapping a row opens a detail popup (no navigation): opaque id plus
 *   a masked secret field with a closed-by-default eye button.
 * - The eye runs a framework [BiometricPrompt] (fingerprint). Only after
 *   a successful authentication does it call
 *   [PasswordManagerViewModel.openRelease] (ReleaseUseCase); the released
 *   username/secret shows transiently and is zeroized on ANY dismiss via
 *   [PasswordManagerViewModel.closeRelease]. Without a usable sensor the
 *   eye falls back to the existing session unlock prompt
 *   ([SecureGuardViewModel.openUnlockPrompt]) — the secret is never
 *   fetched without an explicit user gate.
 * - Gate denials (NeedBinding/PresenceRequired/PinRequired) reuse the
 *   vault [GateBanner] UX and the existing unlock flow.
 * - Screenshots of secrets rely on the app-wide FLAG_SECURE policy
 *   (release builds; debug clears it for QA) — this screen adds no
 *   cache, log, disk, or screenshot payload of its own.
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
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    // Opaque id handle selected for the detail popup (copy of the
    // device-chosen bytes already held in RAM; never persisted, never
    // logged). Null = popup closed.
    var selectedId by remember { mutableStateOf<ByteArray?>(null) }
    // Create form visibility (transient typed fields live in the dialog).
    var showCreate by remember { mutableStateOf(false) }
    // Opaque id awaiting delete confirmation (copy; wiped on dismiss).
    var pendingDelete by remember { mutableStateOf<ByteArray?>(null) }
    fun dismissPopup() {
        viewModel.closeRelease()
        selectedId = null
    }
    fun dismissDelete() {
        pendingDelete?.fill(0)
        pendingDelete = null
    }

    LaunchedEffect(uiState.errorMessage, uiState.userMessage) {
        uiState.errorMessage?.let { snackbarHostState.showSnackbar(it); viewModel.clearMessages() }
        uiState.userMessage?.let { snackbarHostState.showSnackbar(it); viewModel.clearMessages() }
    }

    // Device-confirmed outcomes tick nonces; the screen maps them to its
    // own i18n strings (the ViewModel carries no prose of its own).
    var shownPutNonce by remember { mutableStateOf(0L) }
    var shownDeleteNonce by remember { mutableStateOf(0L) }
    LaunchedEffect(uiState.putOkNonce) {
        if (uiState.putOkNonce > shownPutNonce) {
            shownPutNonce = uiState.putOkNonce
            snackbarHostState.showSnackbar(context.getString(R.string.pm_saved))
        }
    }
    LaunchedEffect(uiState.deleteOkNonce) {
        if (uiState.deleteOkNonce > shownDeleteNonce) {
            shownDeleteNonce = uiState.deleteOkNonce
            snackbarHostState.showSnackbar(context.getString(R.string.pm_deleted))
        }
    }

    /**
     * Eye gate: fingerprint first. The release use-case runs only inside
     * [BiometricPrompt.AuthenticationCallback.onAuthenticationSucceeded].
     * Fail-closed: any failure, error, or cancel leaves the popup masked
     * and never touches [PasswordManagerViewModel.openRelease]. Without
     * a usable sensor, falls back to the existing Secure Guard session
     * unlock prompt — the masked secret stays masked either way.
     */
    fun onEyeClick(id: ByteArray, revealed: Boolean) {
        if (revealed) {
            // Tapping the open eye re-hides and wipes immediately; the
            // next view needs a fresh fingerprint.
            viewModel.closeRelease()
            return
        }
        val activity = context as? Activity
        val manager = activity?.getSystemService(BiometricManager::class.java)
        val biometricReady = manager?.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_WEAK,
        ) == BiometricManager.BIOMETRIC_SUCCESS
        if (activity == null || !biometricReady) {
            scope.launch {
                snackbarHostState.showSnackbar(context.getString(R.string.pm_biometric_unavailable))
            }
            secureGuardViewModel?.openUnlockPrompt()
            return
        }
        val prompt = BiometricPrompt.Builder(activity)
            .setTitle(activity.getString(R.string.biogate_title))
            .setSubtitle(activity.getString(R.string.biogate_subtitle))
            .setNegativeButton(
                activity.getString(R.string.guard_btn_cancel),
                activity.mainExecutor,
            ) { _, _ -> }
            .build()
        // No CryptoObject: the fingerprint gates the *fetch* of the
        // transient release (punctual display + zeroize), not a key
        // unwrap. Framework-only APIs (minSdk 31), no new dependency.
        prompt.authenticate(
            CancellationSignal(),
            activity.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult?) {
                    viewModel.openRelease(id)
                }

                override fun onAuthenticationFailed() {
                    // Stay masked (fail closed); no snackbar spam while
                    // the finger is still on the sensor.
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                    // Stay masked (fail closed), including user cancel.
                }
            },
        )
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
                Button(
                    onClick = { showCreate = true },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp),
                ) {
                    Icon(imageVector = Icons.Filled.Add, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.pm_new_entry))
                }
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
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { selectedId = id.copyOf() },
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
                            IconButton(
                                onClick = { selectedId = id.copyOf() },
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.Visibility,
                                    contentDescription = stringResource(R.string.pm_eye_show_cd),
                                )
                            }
                            // Scoped per-item delete (0x46): confirm dialog,
                            // only this record is removed device-side.
                            val deleteHex = PmCbor.opaqueIdHex(id)
                            val isDeletingThis = uiState.deletingIdHex == deleteHex
                            if (isDeletingThis) {
                                CircularProgressIndicator(modifier = Modifier.size(24.dp))
                            } else {
                                IconButton(
                                    onClick = { pendingDelete = id.copyOf() },
                                    enabled = uiState.deletingIdHex == null && !uiState.isSaving,
                                ) {
                                    Icon(
                                        imageVector = Icons.Filled.Delete,
                                        contentDescription = stringResource(R.string.pm_delete_cd),
                                    )
                                }
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

    // Detail popup (dialog, not navigation): opaque id + masked secret
    // field with a closed-by-default eye. The transient release renders
    // only after fingerprint success; ANY dismiss wipes via closeRelease.
    val popupId = selectedId
    if (popupId != null) {
        val popupHex = PmCbor.opaqueIdHex(popupId)
        val release = uiState.release
        val revealed = release != null && uiState.releaseIdHex == popupHex
        val secretText = remember(release, popupHex) {
            if (revealed && release != null) String(release.secret) else null
        }
        AlertDialog(
            onDismissRequest = { dismissPopup() },
            shape = RoundedCornerShape(16.dp),
            title = {
                Text(
                    text = stringResource(R.string.pm_detail_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = PmCbor.opaqueIdLabel(popupId),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        text = popupHex,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    OutlinedTextField(
                        value = secretText ?: stringResource(R.string.pm_masked_secret),
                        onValueChange = {},
                        readOnly = true,
                        label = { Text(stringResource(R.string.pm_secret_label)) },
                        trailingIcon = {
                            IconButton(
                                onClick = { onEyeClick(popupId, revealed) },
                                enabled = !uiState.isReleaseLoading,
                            ) {
                                Icon(
                                    imageVector = if (revealed) {
                                        Icons.Filled.VisibilityOff
                                    } else {
                                        Icons.Filled.Visibility
                                    },
                                    contentDescription = stringResource(
                                        if (revealed) {
                                            R.string.pm_eye_hide_cd
                                        } else {
                                            R.string.pm_eye_show_cd
                                        }
                                    ),
                                )
                            }
                        },
                        visualTransformation = if (revealed) {
                            VisualTransformation.None
                        } else {
                            PasswordVisualTransformation()
                        },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    if (uiState.isReleaseLoading) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            CircularProgressIndicator(modifier = Modifier.size(20.dp))
                            Text(
                                text = stringResource(R.string.pm_authenticating),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                    if (revealed && release != null) {
                        Text(
                            text = stringResource(R.string.pm_release_user, release.username),
                            style = MaterialTheme.typography.bodyMedium,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Text(
                            text = stringResource(R.string.pm_release_wipe_note),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
            },
            confirmButton = {
                if (revealed && secretText != null) {
                    TextButton(
                        onClick = {
                            onCopyText(secretText)
                            dismissPopup()
                        },
                    ) {
                        Text(stringResource(R.string.pm_copy_and_close))
                    }
                }
            },
            dismissButton = {
                TextButton(onClick = { dismissPopup() }) {
                    Text(stringResource(R.string.pm_close_and_wipe))
                }
            },
        )
    }

    // Create form (PUT 0x43): service/account/secret are user-typed
    // transient RAM only. The device seals them and assigns the opaque id;
    // nothing is logged, cached, or persisted on the phone. Blank fields
    // never reach the transport (fail-closed at the edge).
    if (showCreate) {
        var service by remember { mutableStateOf("") }
        var account by remember { mutableStateOf("") }
        var secretText by remember { mutableStateOf("") }
        var showTyped by remember { mutableStateOf(false) }
        var blankError by remember { mutableStateOf(false) }
        fun dismissCreate() {
            service = ""
            account = ""
            secretText = ""
            showTyped = false
            blankError = false
            showCreate = false
        }
        AlertDialog(
            onDismissRequest = { dismissCreate() },
            shape = RoundedCornerShape(16.dp),
            title = {
                Text(
                    text = stringResource(R.string.pm_create_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = service,
                        onValueChange = { service = it; blankError = false },
                        label = { Text(stringResource(R.string.pm_create_service_label)) },
                        placeholder = { Text(stringResource(R.string.pm_create_service_hint)) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = account,
                        onValueChange = { account = it; blankError = false },
                        label = { Text(stringResource(R.string.pm_create_account_label)) },
                        placeholder = { Text(stringResource(R.string.pm_create_account_hint)) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = secretText,
                        onValueChange = { secretText = it; blankError = false },
                        label = { Text(stringResource(R.string.pm_secret_label)) },
                        placeholder = { Text(stringResource(R.string.pm_create_secret_hint)) },
                        trailingIcon = {
                            IconButton(onClick = { showTyped = !showTyped }) {
                                Icon(
                                    imageVector = if (showTyped) {
                                        Icons.Filled.VisibilityOff
                                    } else {
                                        Icons.Filled.Visibility
                                    },
                                    contentDescription = stringResource(
                                        if (showTyped) {
                                            R.string.pm_create_hide_cd
                                        } else {
                                            R.string.pm_create_show_cd
                                        }
                                    ),
                                )
                            }
                        },
                        visualTransformation = if (showTyped) {
                            VisualTransformation.None
                        } else {
                            PasswordVisualTransformation()
                        },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    if (blankError) {
                        Text(
                            text = stringResource(R.string.pm_create_blank_error),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                    if (uiState.isSaving) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            CircularProgressIndicator(modifier = Modifier.size(20.dp))
                            Text(
                                text = stringResource(R.string.pm_authenticating),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        if (service.isBlank() || account.isBlank() || secretText.isEmpty()) {
                            blankError = true
                            return@TextButton
                        }
                        viewModel.putEntry(
                            service.trim(),
                            account.trim(),
                            secretText.toByteArray(Charsets.UTF_8),
                            null,
                        )
                        dismissCreate()
                    },
                    enabled = !uiState.isSaving,
                ) {
                    Text(stringResource(R.string.pm_create_save))
                }
            },
            dismissButton = {
                TextButton(onClick = { dismissCreate() }) {
                    Text(stringResource(R.string.guard_btn_cancel))
                }
            },
        )
    }

    // Scoped per-item delete (DELETE 0x46): confirm dialog. Only this
    // record is removed device-side; FIDO2 keys and other slots stay.
    // Any dismiss wipes the pending id copy without touching the device.
    val deleteId = pendingDelete
    if (deleteId != null) {
        val deleteHex = PmCbor.opaqueIdHex(deleteId)
        val isDeletingThis = uiState.deletingIdHex == deleteHex
        AlertDialog(
            onDismissRequest = { dismissDelete() },
            shape = RoundedCornerShape(16.dp),
            title = {
                Text(
                    text = stringResource(R.string.pm_delete_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = PmCbor.opaqueIdLabel(deleteId),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        text = stringResource(R.string.pm_delete_desc),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (isDeletingThis) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            CircularProgressIndicator(modifier = Modifier.size(20.dp))
                            Text(
                                text = stringResource(R.string.pm_authenticating),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        val id = deleteId.copyOf()
                        dismissDelete()
                        viewModel.deleteEntry(id)
                    },
                    enabled = !isDeletingThis,
                ) {
                    Text(stringResource(R.string.pm_delete_confirm_btn))
                }
            },
            dismissButton = {
                TextButton(onClick = { dismissDelete() }) {
                    Text(stringResource(R.string.guard_btn_cancel))
                }
            },
        )
    }
}
