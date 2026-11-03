package dev.aegiskey.app.ui.screens

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
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Badge
import androidx.compose.material3.Button
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.R
import dev.aegiskey.app.domain.model.FirmwareVersion
import dev.aegiskey.app.ui.viewmodel.KeyVaultViewModel

/**
 * Smart Card (PIV / Certificates) destination (click-through F2).
 *
 * Previously the Settings PIV card was dead navigation: `MainActivity` never
 * passed `onNavigateToPiv` and `NavHost` had no `"piv"` route. This screen is
 * the real destination registered as [dev.aegiskey.app.ui.navigation.AppRoutes.PIV].
 *
 * Content is authority data only: slot list comes from the connected key
 * diagnostics ([pivSlotsAvailable]) with the four NIST SP 800-73-4 slots as
 * the documented fallback. PIN/PUK enrollment delegates to
 * [KeyVaultViewModel.enrollPivPin] and stays disabled while the Secure Guard
 * session is locked (fail-closed, same rule as key generation).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PivScreen(
    viewModel: KeyVaultViewModel,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val uiState by viewModel.uiState.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }

    val slots = remember(uiState.hardwareDiagnostics) {
        val reported = uiState.hardwareDiagnostics?.pivSlotsAvailable?.filter { it.isNotBlank() }
        if (!reported.isNullOrEmpty()) reported else listOf("9A", "9C", "9D", "9E")
    }
    val fwVersion = FirmwareVersion.resolve(uiState.hardwareDiagnostics?.firmwareVersion)

    LaunchedEffect(uiState.userMessage) {
        uiState.userMessage?.let {
            snackbarHostState.showSnackbar(it)
            viewModel.clearMessages()
        }
    }
    LaunchedEffect(uiState.errorMessage) {
        uiState.errorMessage?.let {
            snackbarHostState.showSnackbar(it)
            viewModel.clearMessages()
        }
    }
    val guardLockedError = uiState.errorResId?.let { stringResource(it) }
    LaunchedEffect(guardLockedError) {
        guardLockedError?.let {
            snackbarHostState.showSnackbar(it)
            viewModel.clearMessages()
        }
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(
                            text = stringResource(R.string.piv_title),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            text = stringResource(R.string.vault_diag_health, fwVersion),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.cd_back)
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) }
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item {
                Text(
                    text = stringResource(R.string.piv_desc),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            if (slots.isEmpty()) {
                item {
                    Surface(
                        shape = RoundedCornerShape(12.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = stringResource(R.string.piv_empty),
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(18.dp)
                        )
                    }
                }
            }

            items(slots, key = { it }) { slot ->
                PivSlotCard(
                    slotCode = extractSlotCode(slot),
                    slotLine = slot,
                    isLoading = uiState.isActionLoading,
                    isGuardUnlocked = uiState.isGuardUnlocked,
                    onEnroll = { code, pin, puk -> viewModel.enrollPivPin(code, pin, puk) }
                )
            }

            item {
                Text(
                    text = stringResource(R.string.piv_enroll_hint),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(16.dp))
            }
        }
    }
}

private fun extractSlotCode(slotLine: String): String {
    val upper = slotLine.uppercase()
    return listOf("9A", "9C", "9D", "9E").firstOrNull { upper.contains(it) } ?: slotLine.take(8)
}

@Composable
private fun PivSlotCard(
    slotCode: String,
    slotLine: String,
    isLoading: Boolean,
    isGuardUnlocked: Boolean,
    onEnroll: (slotCode: String, pin: String, puk: String) -> Unit,
    modifier: Modifier = Modifier,
) {
    var pin by remember(slotCode) { mutableStateOf("") }
    var puk by remember(slotCode) { mutableStateOf("") }
    val pinValid = pin.length in 6..8 && pin.all { it.isDigit() }
    val pukValid = puk.length == 8 && puk.all { it.isDigit() }

    val slotDescription = when (slotCode) {
        "9A" -> stringResource(R.string.kd_piv_9a)
        "9C" -> stringResource(R.string.kd_piv_9c)
        "9D" -> stringResource(R.string.kd_piv_9d)
        "9E" -> stringResource(R.string.kd_piv_9e)
        else -> slotLine
    }

    OutlinedCard(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.outlinedCardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        modifier = modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Filled.Badge,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = stringResource(R.string.piv_slot_label, slotCode),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f)
                )
            }
            Text(
                text = slotDescription,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            OutlinedTextField(
                value = pin,
                onValueChange = { pin = it.filter { c -> c.isDigit() }.take(8) },
                label = { Text(stringResource(R.string.kd_pin_new)) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
                enabled = isGuardUnlocked && !isLoading,
                modifier = Modifier.fillMaxWidth()
            )
            OutlinedTextField(
                value = puk,
                onValueChange = { puk = it.filter { c -> c.isDigit() }.take(8) },
                label = { Text(stringResource(R.string.kd_puk_new)) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
                enabled = isGuardUnlocked && !isLoading,
                modifier = Modifier.fillMaxWidth()
            )
            Button(
                onClick = { onEnroll(slotCode, pin, puk) },
                enabled = isGuardUnlocked && !isLoading && pinValid && pukValid,
                shape = RoundedCornerShape(10.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = stringResource(R.string.kd_pin_save),
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            if (!isGuardUnlocked) {
                Text(
                    text = stringResource(R.string.vault_generate_locked_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }
        }
    }
}
