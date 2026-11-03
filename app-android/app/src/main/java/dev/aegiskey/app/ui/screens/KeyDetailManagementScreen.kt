package dev.aegiskey.app.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.AccountBalanceWallet
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.DeleteForever
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockReset
import androidx.compose.material.icons.filled.Pin
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.TouchApp
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.aegiskey.app.R
import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.domain.model.VaultKeyEntry
import dev.aegiskey.app.touchpolicy.TouchPolicyCard
import dev.aegiskey.app.ui.atomic.atoms.QuickActionPillButton
import dev.aegiskey.app.ui.atomic.molecules.ClearSigningPreviewMolecule
import dev.aegiskey.app.ui.theme.AegisAddressMonospaceStyle

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyDetailManagementScreen(
    entry: VaultKeyEntry,
    onBack: () -> Unit,
    onCopy: (String) -> Unit,
    onSign: (slotId: Int, message: String) -> Unit,
    onExportEnvelope: (slotId: Int) -> Unit,
    onEnrollPivPin: (slotCode: String, newPin: String, newPuk: String) -> Unit,
    onDeleteKey: (slotId: Int) -> Unit,
    signatureResult: String? = null,
    exportedEnvelope: String? = null,
    isActionLoading: Boolean = false,
    touchRequired: Boolean = true,
    isTouchActionLoading: Boolean = false,
    isGuardUnlocked: Boolean = true,
    onTouchToggle: (Boolean) -> Unit = {},
    onUnlockRequest: () -> Unit = {},
    modifier: Modifier = Modifier,
) {
    var showDeleteConfirmDialog by remember { mutableStateOf(false) }

    // Estados locais para inputs interativos
    var challengeInput by remember(entry.slotId) {
        mutableStateOf(
            when (entry.type) {
                AccessKeyType.PASSKEY_FIDO -> "clientDataHash:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                AccessKeyType.CRYPTO_WALLET_BTC -> "TX:0200000001bc1q...->bc1qdest 0.05 BTC"
                AccessKeyType.CRYPTO_WALLET_ETH -> "ETH_TX:0x02f87...to:0x71C...value:1.2ether"
                AccessKeyType.CRYPTO_WALLET_SOL -> "SOL_TX:Transfer 5.0 SOL to 9WzDXwB..."
                AccessKeyType.CRYPTO_WALLET_DOT -> "DOT_TX:Balances.transfer_keep_alive(120 DOT)"
                AccessKeyType.VENDOR_SIGNING_KEY -> "git-commit:8a9b2c3d: AegisKey v0.2.0 release tag"
                AccessKeyType.PIV_SMARTCARD_SLOT -> "AUTH_CHALLENGE:7f28a9b1c2d3e4f5"
                AccessKeyType.ENCRYPTED_AEGN_ENVELOPE -> "PAYLOAD_VERIFY_CHALLENGE"
            }
        )
    }

    var pivNewPin by remember { mutableStateOf("123456") }
    var pivNewPuk by remember { mutableStateOf("12345678") }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(
                            text = stringResource(R.string.kd_title),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            text = stringResource(R.string.kd_subtitle, entry.slotId, entry.label),
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
                            contentDescription = stringResource(R.string.kd_back_cd)
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        }
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // 1. Cabeçalho Principal do Hardware & Chave
            item {
                KeyHeaderCard(entry = entry, onCopy = onCopy)
            }

            // 1b. Política de toque por credencial (0x40, CAPABILITY_DIET §8)
            item {
                TouchPolicyCard(
                    requireTouch = touchRequired,
                    isLoading = isTouchActionLoading,
                    isGuardUnlocked = isGuardUnlocked,
                    onToggle = onTouchToggle,
                    onUnlockRequest = onUnlockRequest
                )
            }

            // 2. Seções Customizadas por Tipo de Chave
            when (entry.type) {
                AccessKeyType.PASSKEY_FIDO -> {
                    item {
                        PasskeyFidoSection(
                            entry = entry,
                            challengeInput = challengeInput,
                            onChallengeChange = { challengeInput = it },
                            onSignClick = { onSign(entry.slotId, challengeInput) },
                            onExportEnvelopeClick = { onExportEnvelope(entry.slotId) },
                            signatureResult = signatureResult,
                            exportedEnvelope = exportedEnvelope,
                            isActionLoading = isActionLoading,
                            onCopy = onCopy
                        )
                    }
                }
                AccessKeyType.CRYPTO_WALLET_BTC,
                AccessKeyType.CRYPTO_WALLET_ETH,
                AccessKeyType.CRYPTO_WALLET_SOL,
                AccessKeyType.CRYPTO_WALLET_DOT -> {
                    item {
                        CryptoWalletSection(
                            entry = entry,
                            txInput = challengeInput,
                            onTxInputChange = { challengeInput = it },
                            onSignClick = { onSign(entry.slotId, challengeInput) },
                            onExportEnvelopeClick = { onExportEnvelope(entry.slotId) },
                            signatureResult = signatureResult,
                            exportedEnvelope = exportedEnvelope,
                            isActionLoading = isActionLoading,
                            onCopy = onCopy
                        )
                    }
                }
                AccessKeyType.VENDOR_SIGNING_KEY -> {
                    item {
                        VendorSigningSection(
                            entry = entry,
                            messageInput = challengeInput,
                            onMessageChange = { challengeInput = it },
                            onSignClick = { onSign(entry.slotId, challengeInput) },
                            onExportEnvelopeClick = { onExportEnvelope(entry.slotId) },
                            signatureResult = signatureResult,
                            exportedEnvelope = exportedEnvelope,
                            isActionLoading = isActionLoading,
                            onCopy = onCopy
                        )
                    }
                }
                AccessKeyType.PIV_SMARTCARD_SLOT -> {
                    item {
                        PivSmartcardSection(
                            entry = entry,
                            challengeInput = challengeInput,
                            onChallengeChange = { challengeInput = it },
                            newPin = pivNewPin,
                            onPinChange = { pivNewPin = it },
                            newPuk = pivNewPuk,
                            onPukChange = { pivNewPuk = it },
                            onEnrollPinClick = {
                                val slotCode = entry.derivationPathOrSlotCode.ifBlank { "9A" }
                                onEnrollPivPin(slotCode, pivNewPin, pivNewPuk)
                            },
                            onSignClick = { onSign(entry.slotId, challengeInput) },
                            signatureResult = signatureResult,
                            isActionLoading = isActionLoading,
                            onCopy = onCopy
                        )
                    }
                }
                AccessKeyType.ENCRYPTED_AEGN_ENVELOPE -> {
                    item {
                        AegnEnvelopeSection(
                            entry = entry,
                            challengeInput = challengeInput,
                            onChallengeChange = { challengeInput = it },
                            onExportEnvelopeClick = { onExportEnvelope(entry.slotId) },
                            onSignClick = { onSign(entry.slotId, challengeInput) },
                            signatureResult = signatureResult,
                            exportedEnvelope = exportedEnvelope,
                            isActionLoading = isActionLoading,
                            onCopy = onCopy
                        )
                    }
                }
            }

            // 3. Zona de Exclusão Segura no Hardware (Presente em todos os tipos)
            item {
                SecureHardwareDeletionCard(
                    onDeleteClick = { showDeleteConfirmDialog = true }
                )
            }

            item {
                Spacer(modifier = Modifier.height(24.dp))
            }
        }
    }

    // Diálogo de Confirmação de Exclusão
    if (showDeleteConfirmDialog) {
        AlertDialog(
            onDismissRequest = { showDeleteConfirmDialog = false },
            shape = RoundedCornerShape(18.dp),
            icon = {
                Icon(
                    imageVector = Icons.Filled.DeleteForever,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.error,
                    modifier = Modifier.size(32.dp)
                )
            },
            title = {
                Text(
                    text = stringResource(R.string.kd_delete_title),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
            },
            text = {
                Text(
                    text = stringResource(R.string.kd_delete_desc, entry.slotId),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        showDeleteConfirmDialog = false
                        onDeleteKey(entry.slotId)
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                        contentColor = MaterialTheme.colorScheme.onError
                    )
                ) {
                    Text(stringResource(R.string.kd_confirm_delete))
                }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteConfirmDialog = false }) {
                    Text(stringResource(R.string.vault_cancel_btn))
                }
            }
        )
    }
}

