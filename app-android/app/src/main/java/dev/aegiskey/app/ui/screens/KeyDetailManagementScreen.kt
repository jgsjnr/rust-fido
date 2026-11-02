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

// ---------------------------------------------------------
// Componentes Modulares de Seção
// ---------------------------------------------------------

@Composable
private fun KeyHeaderCard(
    entry: VaultKeyEntry,
    onCopy: (String) -> Unit
) {
    val typeTitle = when (entry.type) {
        AccessKeyType.PASSKEY_FIDO -> stringResource(R.string.kd_type_passkey)
        AccessKeyType.VENDOR_SIGNING_KEY -> stringResource(R.string.kd_type_vendor)
        AccessKeyType.CRYPTO_WALLET_BTC -> stringResource(R.string.kd_type_btc)
        AccessKeyType.CRYPTO_WALLET_ETH -> stringResource(R.string.kd_type_eth)
        AccessKeyType.CRYPTO_WALLET_SOL -> stringResource(R.string.kd_type_sol)
        AccessKeyType.CRYPTO_WALLET_DOT -> stringResource(R.string.kd_type_dot)
        AccessKeyType.PIV_SMARTCARD_SLOT -> stringResource(R.string.kd_type_piv)
        AccessKeyType.ENCRYPTED_AEGN_ENVELOPE -> stringResource(R.string.kd_type_aegn)
    }

    val typeIcon: ImageVector = when (entry.type) {
        AccessKeyType.PASSKEY_FIDO -> Icons.Filled.Fingerprint
        AccessKeyType.VENDOR_SIGNING_KEY -> Icons.Filled.Key
        AccessKeyType.CRYPTO_WALLET_BTC,
        AccessKeyType.CRYPTO_WALLET_ETH,
        AccessKeyType.CRYPTO_WALLET_SOL,
        AccessKeyType.CRYPTO_WALLET_DOT -> Icons.Filled.AccountBalanceWallet
        AccessKeyType.PIV_SMARTCARD_SLOT -> Icons.Filled.VpnKey
        AccessKeyType.ENCRYPTED_AEGN_ENVELOPE -> Icons.Filled.Lock
    }

    OutlinedCard(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.outlinedCardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.primaryContainer,
                    modifier = Modifier.size(44.dp)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(
                            imageVector = typeIcon,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onPrimaryContainer,
                            modifier = Modifier.size(24.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.width(12.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = entry.label,
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = typeTitle,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }

            // Badges informativas compactas
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.5f)
                ) {
                    Text(
                        text = stringResource(R.string.kd_slot, entry.slotId),
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                    )
                }

                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.5f)
                ) {
                    Text(
                        text = entry.algorithmOrCurve,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onTertiaryContainer,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                    )
                }

                if (entry.requiresPhysicalTouch) {
                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.4f)
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Filled.TouchApp,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(12.dp)
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(
                                text = stringResource(R.string.kd_touch),
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.primary
                            )
                        }
                    }
                }
            }

            // Exibição do Identificador / Chave Pública / Endereço com botão Copiar
            if (entry.publicSummary.isNotBlank()) {
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 10.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = entry.publicSummary,
                            style = AegisAddressMonospaceStyle,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        QuickActionPillButton(
                            text = stringResource(R.string.action_copy),
                            icon = Icons.Filled.ContentCopy,
                            onClick = { onCopy(entry.publicSummary) }
                        )
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------
// 1. PASSKEY_FIDO SECTION
// ---------------------------------------------------------
@Composable
private fun PasskeyFidoSection(
    entry: VaultKeyEntry,
    challengeInput: String,
    onChallengeChange: (String) -> Unit,
    onSignClick: () -> Unit,
    onExportEnvelopeClick: () -> Unit,
    signatureResult: String?,
    exportedEnvelope: String?,
    isActionLoading: Boolean,
    onCopy: (String) -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        // Painel de Propriedades FIDO2
        OutlinedCard(
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = stringResource(R.string.kd_pk_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                PropertyRow(label = stringResource(R.string.kd_pk_proto), value = stringResource(R.string.kd_pk_proto_val))
                PropertyRow(label = stringResource(R.string.kd_pk_curve), value = entry.algorithmOrCurve)
                PropertyRow(label = stringResource(R.string.kd_pk_store), value = stringResource(R.string.kd_pk_store_val))
                PropertyRow(label = stringResource(R.string.kd_pk_uv), value = stringResource(R.string.kd_pk_uv_val))
            }
        }

        // Card Interativo: Assinar Desafio FIDO2
        InteractiveSignCard(
            title = stringResource(R.string.kd_pk_sign_title),
            subtitle = stringResource(R.string.kd_pk_sign_desc),
            inputValue = challengeInput,
            onInputChange = onChallengeChange,
            buttonText = stringResource(R.string.kd_pk_sign_btn),
            onAction = onSignClick,
            isLoading = isActionLoading,
            resultText = signatureResult,
            onCopy = onCopy
        )

        // Card Interativo: Backup Criptografado AEGN
        InteractiveExportCard(
            title = stringResource(R.string.kd_pk_exp_title),
            subtitle = stringResource(R.string.kd_pk_exp_desc),
            buttonText = stringResource(R.string.kd_pk_exp_btn),
            onAction = onExportEnvelopeClick,
            isLoading = isActionLoading,
            exportedEnvelope = exportedEnvelope ?: entry.envelopeHex.takeIf { it.isNotBlank() },
            onCopy = onCopy
        )
    }
}

// ---------------------------------------------------------
// 2. CRYPTO_WALLET SECTION
// ---------------------------------------------------------
@Composable
private fun CryptoWalletSection(
    entry: VaultKeyEntry,
    txInput: String,
    onTxInputChange: (String) -> Unit,
    onSignClick: () -> Unit,
    onExportEnvelopeClick: () -> Unit,
    signatureResult: String?,
    exportedEnvelope: String?,
    isActionLoading: Boolean,
    onCopy: (String) -> Unit
) {
    val (networkName, standardFormat, defaultPath) = when (entry.type) {
        AccessKeyType.CRYPTO_WALLET_BTC -> Triple(stringResource(R.string.kd_net_btc), stringResource(R.string.kd_net_btc_fmt), "m/84'/0'/0'/0/0")
        AccessKeyType.CRYPTO_WALLET_ETH -> Triple(stringResource(R.string.kd_net_eth), stringResource(R.string.kd_net_eth_fmt), "m/44'/60'/0'/0/0")
        AccessKeyType.CRYPTO_WALLET_SOL -> Triple(stringResource(R.string.kd_net_sol), stringResource(R.string.kd_net_sol_fmt), "m/44'/501'/0'/0'")
        AccessKeyType.CRYPTO_WALLET_DOT -> Triple(stringResource(R.string.kd_net_dot), stringResource(R.string.kd_net_dot_fmt), "m/44'/354'/0'/0'/0'")
        else -> Triple(stringResource(R.string.kd_net_other), stringResource(R.string.kd_fmt_other), "")
    }

    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        // Painel Específico da Rede
        OutlinedCard(shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = stringResource(R.string.kd_w_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                PropertyRow(label = stringResource(R.string.kd_w_net), value = networkName)
                PropertyRow(label = stringResource(R.string.kd_w_fmt), value = standardFormat)
                PropertyRow(
                    label = stringResource(R.string.kd_w_path),
                    value = entry.derivationPathOrSlotCode.ifBlank { defaultPath }
                )
                PropertyRow(label = stringResource(R.string.kd_w_algo), value = entry.algorithmOrCurve)
            }
        }

        // Card de Endereço de Recebimento
        OutlinedCard(
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.outlinedCardColors(
                containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.2f)
            ),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Filled.AccountBalanceWallet,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = stringResource(R.string.kd_recv_title),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                }
                Text(
                    text = entry.publicSummary,
                    style = AegisAddressMonospaceStyle,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.fillMaxWidth()
                )
                Button(
                    onClick = { onCopy(entry.publicSummary) },
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(imageVector = Icons.Filled.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.kd_copy_full))
                }
            }
        }

        // Pré-visualização Desacoplada OLED 128x64 Clear Signing (OPP-06)
        ClearSigningPreviewMolecule(
            network = networkName,
            txPayload = txInput,
            modifier = Modifier.fillMaxWidth()
        )

        // Card Interativo: Assinar Transação ou Mensagem no Hardware (0x38)
        InteractiveSignCard(
            title = stringResource(R.string.kd_sign_tx_title),
            subtitle = stringResource(R.string.kd_sign_tx_desc),
            inputValue = txInput,
            onInputChange = onTxInputChange,
            buttonText = stringResource(R.string.kd_sign_tx_btn),
            onAction = onSignClick,
            isLoading = isActionLoading,
            resultText = signatureResult,
            onCopy = onCopy
        )

        // Card Backup Criptografado AEGN
        InteractiveExportCard(
            title = stringResource(R.string.kd_exp_title),
            subtitle = stringResource(R.string.kd_exp_desc),
            buttonText = stringResource(R.string.kd_exp_btn),
            onAction = onExportEnvelopeClick,
            isLoading = isActionLoading,
            exportedEnvelope = exportedEnvelope ?: entry.envelopeHex.takeIf { it.isNotBlank() },
            onCopy = onCopy
        )
    }
}

// ---------------------------------------------------------
// 3. VENDOR_SIGNING_KEY SECTION
// ---------------------------------------------------------
@Composable
private fun VendorSigningSection(
    entry: VaultKeyEntry,
    messageInput: String,
    onMessageChange: (String) -> Unit,
    onSignClick: () -> Unit,
    onExportEnvelopeClick: () -> Unit,
    signatureResult: String?,
    exportedEnvelope: String?,
    isActionLoading: Boolean,
    onCopy: (String) -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        // Painel de Capacidades Criptográficas
        OutlinedCard(shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = stringResource(R.string.kd_v_caps),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                PropertyRow(label = stringResource(R.string.kd_v_curve), value = entry.algorithmOrCurve)
                PropertyRow(label = stringResource(R.string.kd_v_usage), value = entry.usageDescription)
                PropertyRow(label = stringResource(R.string.kd_v_slot), value = stringResource(R.string.kd_v_slot_val))
                PropertyRow(label = stringResource(R.string.kd_v_compat), value = stringResource(R.string.kd_v_compat_val))
            }
        }

        // Card Interativo: Assinar Documento / Git / SSH
        InteractiveSignCard(
            title = stringResource(R.string.kd_v_sign_title),
            subtitle = stringResource(R.string.kd_v_sign_desc),
            inputValue = messageInput,
            onInputChange = onMessageChange,
            buttonText = stringResource(R.string.kd_v_sign_btn),
            onAction = onSignClick,
            isLoading = isActionLoading,
            resultText = signatureResult,
            onCopy = onCopy
        )

        // Card Interativo: Exportar Envelope Selado AEGN
        InteractiveExportCard(
            title = stringResource(R.string.kd_v_exp_title),
            subtitle = stringResource(R.string.kd_v_exp_desc),
            buttonText = stringResource(R.string.kd_v_exp_btn),
            onAction = onExportEnvelopeClick,
            isLoading = isActionLoading,
            exportedEnvelope = exportedEnvelope ?: entry.envelopeHex.takeIf { it.isNotBlank() },
            onCopy = onCopy
        )
    }
}

// ---------------------------------------------------------
// 4. PIV_SMARTCARD_SLOT SECTION
// ---------------------------------------------------------
@Composable
private fun PivSmartcardSection(
    entry: VaultKeyEntry,
    challengeInput: String,
    onChallengeChange: (String) -> Unit,
    newPin: String,
    onPinChange: (String) -> Unit,
    newPuk: String,
    onPukChange: (String) -> Unit,
    onEnrollPinClick: () -> Unit,
    onSignClick: () -> Unit,
    signatureResult: String?,
    isActionLoading: Boolean,
    onCopy: (String) -> Unit
) {
    val slotCode = entry.derivationPathOrSlotCode.ifBlank { "9A" }
    val slotDescription = when {
        slotCode.contains("9A") -> stringResource(R.string.kd_piv_9a)
        slotCode.contains("9C") -> stringResource(R.string.kd_piv_9c)
        slotCode.contains("9D") -> stringResource(R.string.kd_piv_9d)
        slotCode.contains("9E") -> stringResource(R.string.kd_piv_9e)
        else -> stringResource(R.string.kd_piv_other, slotCode)
    }

    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        // Painel do Slot PIV
        OutlinedCard(shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = stringResource(R.string.kd_piv_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                PropertyRow(label = stringResource(R.string.kd_piv_func), value = slotDescription)
                PropertyRow(label = stringResource(R.string.kd_piv_algo), value = entry.algorithmOrCurve)
                PropertyRow(label = stringResource(R.string.kd_piv_policy), value = stringResource(R.string.kd_piv_policy_val))
            }
        }

        // Card Interativo: Configurar / Alterar PIN e PUK (0x39)
        OutlinedCard(shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Filled.LockReset,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = stringResource(R.string.kd_pin_title),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                }

                Text(
                    text = stringResource(R.string.kd_pin_desc),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedTextField(
                        value = newPin,
                        onValueChange = onPinChange,
                        label = { Text(stringResource(R.string.kd_pin_new)) },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                        modifier = Modifier.weight(1f)
                    )
                    OutlinedTextField(
                        value = newPuk,
                        onValueChange = onPukChange,
                        label = { Text(stringResource(R.string.kd_puk_new)) },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                        modifier = Modifier.weight(1f)
                    )
                }

                Button(
                    onClick = onEnrollPinClick,
                    enabled = !isActionLoading && newPin.length in 6..8 && newPuk.length == 8,
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    if (isActionLoading) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    } else {
                        Icon(imageVector = Icons.Filled.CheckCircle, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(stringResource(R.string.kd_pin_save))
                    }
                }
            }
        }

        // Card Interativo: Testar Autenticação PIV
        InteractiveSignCard(
            title = stringResource(R.string.kd_test_title),
            subtitle = stringResource(R.string.kd_test_desc),
            inputValue = challengeInput,
            onInputChange = onChallengeChange,
            buttonText = stringResource(R.string.kd_test_btn),
            onAction = onSignClick,
            isLoading = isActionLoading,
            resultText = signatureResult,
            onCopy = onCopy
        )
    }
}

// ---------------------------------------------------------
// 5. ENCRYPTED_AEGN_ENVELOPE SECTION
// ---------------------------------------------------------
@Composable
private fun AegnEnvelopeSection(
    entry: VaultKeyEntry,
    challengeInput: String,
    onChallengeChange: (String) -> Unit,
    onExportEnvelopeClick: () -> Unit,
    onSignClick: () -> Unit,
    signatureResult: String?,
    exportedEnvelope: String?,
    isActionLoading: Boolean,
    onCopy: (String) -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        // Painel de Integridade do Envelope
        OutlinedCard(shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = stringResource(R.string.kd_a_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                PropertyRow(label = stringResource(R.string.kd_a_head), value = stringResource(R.string.kd_a_head_val))
                PropertyRow(label = stringResource(R.string.kd_a_crypto), value = stringResource(R.string.kd_a_crypto_val))
                PropertyRow(label = stringResource(R.string.kd_a_dkek), value = stringResource(R.string.kd_a_dkek_val))
            }
        }

        // Card Interativo: Inspecionar e Exportar Envelope
        InteractiveExportCard(
            title = stringResource(R.string.kd_a_insp_title),
            subtitle = stringResource(R.string.kd_a_insp_desc),
            buttonText = stringResource(R.string.kd_a_insp_btn),
            onAction = onExportEnvelopeClick,
            isLoading = isActionLoading,
            exportedEnvelope = exportedEnvelope ?: entry.envelopeHex.takeIf { it.isNotBlank() },
            onCopy = onCopy
        )

        // Card Interativo: Provar Posse / Assinar com Segredo
        InteractiveSignCard(
            title = stringResource(R.string.kd_a_prove_title),
            subtitle = stringResource(R.string.kd_a_prove_desc),
            inputValue = challengeInput,
            onInputChange = onChallengeChange,
            buttonText = stringResource(R.string.kd_a_prove_btn),
            onAction = onSignClick,
            isLoading = isActionLoading,
            resultText = signatureResult,
            onCopy = onCopy
        )
    }
}

// ---------------------------------------------------------
// 6. HARDWARE DELETION CARD
// ---------------------------------------------------------
@Composable
private fun SecureHardwareDeletionCard(
    onDeleteClick: () -> Unit
) {
    OutlinedCard(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.outlinedCardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.2f)
        ),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.error.copy(alpha = 0.5f)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Filled.WarningAmber,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.error,
                    modifier = Modifier.size(22.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = stringResource(R.string.kd_zone_title),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.error
                )
            }

            Text(
                text = stringResource(R.string.kd_zone_desc),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Button(
                onClick = onDeleteClick,
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error,
                    contentColor = MaterialTheme.colorScheme.onError
                ),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(imageVector = Icons.Filled.DeleteForever, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(stringResource(R.string.kd_zone_btn))
            }
        }
    }
}

// ---------------------------------------------------------
// Helpers de Linha & Cartões Interativos Reutilizáveis
// ---------------------------------------------------------
@Composable
private fun PropertyRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(0.45f).padding(end = 8.dp)
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.SemiBold,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(0.55f),
            textAlign = androidx.compose.ui.text.style.TextAlign.End
        )
    }
}

@Composable
private fun InteractiveSignCard(
    title: String,
    subtitle: String,
    inputValue: String,
    onInputChange: (String) -> Unit,
    buttonText: String,
    onAction: () -> Unit,
    isLoading: Boolean,
    resultText: String?,
    onCopy: (String) -> Unit
) {
    OutlinedCard(shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(text = title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            Text(text = subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)

            OutlinedTextField(
                value = inputValue,
                onValueChange = onInputChange,
                label = { Text(stringResource(R.string.kd_challenge_label)) },
                maxLines = 2,
                textStyle = AegisAddressMonospaceStyle.copy(fontSize = 12.sp),
                modifier = Modifier.fillMaxWidth()
            )

            Button(
                onClick = onAction,
                enabled = !isLoading && inputValue.isNotBlank(),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                if (isLoading) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                } else {
                    Icon(imageVector = Icons.Filled.Security, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(buttonText)
                }
            }

            AnimatedVisibility(visible = !resultText.isNullOrBlank()) {
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.4f),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = stringResource(R.string.kd_signed_label),
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.primary
                            )
                            QuickActionPillButton(
                                text = stringResource(R.string.action_copy),
                                icon = Icons.Filled.ContentCopy,
                                onClick = { onCopy(resultText ?: "") }
                            )
                        }
                        Text(
                            text = resultText ?: "",
                            style = AegisAddressMonospaceStyle.copy(fontSize = 11.sp),
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun InteractiveExportCard(
    title: String,
    subtitle: String,
    buttonText: String,
    onAction: () -> Unit,
    isLoading: Boolean,
    exportedEnvelope: String?,
    onCopy: (String) -> Unit
) {
    OutlinedCard(shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(text = title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            Text(text = subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)

            Button(
                onClick = onAction,
                enabled = !isLoading,
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                if (isLoading) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                } else {
                    Icon(imageVector = Icons.Filled.Lock, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(buttonText)
                }
            }

            AnimatedVisibility(visible = !exportedEnvelope.isNullOrBlank()) {
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = stringResource(R.string.kd_env_label),
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.primary
                            )
                            QuickActionPillButton(
                                text = stringResource(R.string.action_copy),
                                icon = Icons.Filled.ContentCopy,
                                onClick = { onCopy(exportedEnvelope ?: "") }
                            )
                        }
                        Text(
                            text = exportedEnvelope ?: "",
                            style = AegisAddressMonospaceStyle.copy(fontSize = 11.sp),
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                }
            }
        }
    }
}
