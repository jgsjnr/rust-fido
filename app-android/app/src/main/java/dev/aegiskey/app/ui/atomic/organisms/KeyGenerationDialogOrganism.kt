package dev.aegiskey.app.ui.atomic.organisms

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
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
import androidx.compose.material.icons.filled.AccountBalanceWallet
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.ui.atomic.atoms.PrimaryNextButton

data class KeyTypeOption(
    val type: AccessKeyType,
    val title: String,
    val description: String,
    val icon: ImageVector,
    val defaultCurve: String,
    val defaultExtra: String
)

val KEY_TYPE_OPTIONS = listOf(
    KeyTypeOption(
        type = AccessKeyType.PASSKEY_FIDO,
        title = "Passkey (FIDO2 / WebAuthn)",
        description = "Login sem senha para Google, Apple e GitHub",
        icon = Icons.Filled.Fingerprint,
        defaultCurve = "ES256 (P-256)",
        defaultExtra = ""
    ),
    KeyTypeOption(
        type = AccessKeyType.VENDOR_SIGNING_KEY,
        title = "Chave de Assinatura SSH / Git",
        description = "Assinatura digital de commits, código e SSH",
        icon = Icons.Filled.Key,
        defaultCurve = "Ed25519",
        defaultExtra = ""
    ),
    KeyTypeOption(
        type = AccessKeyType.CRYPTO_WALLET_BTC,
        title = "Carteira Bitcoin (BIP84)",
        description = "Segurança em hardware Native SegWit",
        icon = Icons.Filled.AccountBalanceWallet,
        defaultCurve = "secp256k1",
        defaultExtra = "m/84'/0'/0'/0/0"
    ),
    KeyTypeOption(
        type = AccessKeyType.CRYPTO_WALLET_ETH,
        title = "Carteira Ethereum / EVM",
        description = "Suporte para Ethereum, Polygon e EVM",
        icon = Icons.Filled.AccountBalanceWallet,
        defaultCurve = "secp256k1",
        defaultExtra = "m/44'/60'/0'/0/0"
    ),
    KeyTypeOption(
        type = AccessKeyType.CRYPTO_WALLET_SOL,
        title = "Carteira Solana",
        description = "Chave de alta velocidade Solana (Ed25519)",
        icon = Icons.Filled.AccountBalanceWallet,
        defaultCurve = "Ed25519",
        defaultExtra = "m/44'/501'/0'/0'"
    ),
    KeyTypeOption(
        type = AccessKeyType.CRYPTO_WALLET_DOT,
        title = "Carteira Polkadot",
        description = "Endereço Substrate SS58 (Ed25519)",
        icon = Icons.Filled.AccountBalanceWallet,
        defaultCurve = "Ed25519",
        defaultExtra = "m/44'/354'/0'/0'/0'"
    ),
    KeyTypeOption(
        type = AccessKeyType.PIV_SMARTCARD_SLOT,
        title = "Smartcard Corporativo PIV",
        description = "NIST SP 800-73-4 para logon e crachá",
        icon = Icons.Filled.VpnKey,
        defaultCurve = "ECCP256",
        defaultExtra = "9A"
    ),
    KeyTypeOption(
        type = AccessKeyType.ENCRYPTED_AEGN_ENVELOPE,
        title = "Envelope Criptografado AEGN",
        description = "Cofre de segredo selado com AES-256-GCM",
        icon = Icons.Filled.Lock,
        defaultCurve = "AES-256-GCM",
        defaultExtra = "aegn_secret_payload_seed"
    )
)

private val COSE_CURVES = listOf(
    "Ed25519 (-8)",
    "ES256 (P-256)",
    "ES384 (P-384)",
    "ES512 (P-521)",
    "ES256K (secp256k1)"
)

private val PIV_SLOTS = listOf(
    "9A" to "9A Autenticação",
    "9C" to "9C Assinatura",
    "9D" to "9D Cifragem",
    "9E" to "9E Crachá"
)

/**
 * Diálogo completo e responsivo para criar qualquer uma das 8 chaves físicas suportadas.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun KeyGenerationDialogOrganism(
    onDismissRequest: () -> Unit,
    onConfirm: (label: String, type: AccessKeyType, algorithmOrCurve: String, extraParam: String) -> Unit,
    isLoading: Boolean = false,
    modifier: Modifier = Modifier,
) {
    var accountName by remember { mutableStateOf("") }
    var selectedOption by remember { mutableStateOf(KEY_TYPE_OPTIONS.first()) }
    var chosenCurve by remember { mutableStateOf(selectedOption.defaultCurve) }
    var extraParam by remember { mutableStateOf(selectedOption.defaultExtra) }

    LaunchedEffect(selectedOption) {
        chosenCurve = selectedOption.defaultCurve
        extraParam = selectedOption.defaultExtra
    }

    val isFormValid = accountName.trim().isNotBlank()

    AlertDialog(
        onDismissRequest = { if (!isLoading) onDismissRequest() },
        shape = RoundedCornerShape(18.dp),
        title = {
            Text(
                text = "Criar Nova Chave no Hardware",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = "A nova chave criptográfica será gerada e gravada exclusivamente no chip AegisKey.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                OutlinedTextField(
                    value = accountName,
                    onValueChange = { accountName = it },
                    label = { Text("Nome da chave") },
                    placeholder = {
                        Text(
                            when (selectedOption.type) {
                                AccessKeyType.PASSKEY_FIDO -> "Ex: Google Login ou GitHub"
                                AccessKeyType.VENDOR_SIGNING_KEY -> "Ex: Chave SSH Notebook"
                                AccessKeyType.CRYPTO_WALLET_BTC -> "Ex: Cofre Bitcoin Poupança"
                                AccessKeyType.CRYPTO_WALLET_ETH -> "Ex: Carteira Ethereum DeFi"
                                AccessKeyType.CRYPTO_WALLET_SOL -> "Ex: Solana Mainnet"
                                AccessKeyType.CRYPTO_WALLET_DOT -> "Ex: Polkadot Staking"
                                AccessKeyType.PIV_SMARTCARD_SLOT -> "Ex: Crachá Corporativo PIV"
                                AccessKeyType.ENCRYPTED_AEGN_ENVELOPE -> "Ex: Semente Envelopada Mestre"
                            }
                        )
                    },
                    singleLine = true,
                    enabled = !isLoading,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth()
                )

                Text(
                    text = "Selecione o Tipo de Chave:",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.SemiBold
                )

                // Lista dos 8 tipos de chaves com visualização limpa
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    KEY_TYPE_OPTIONS.forEach { opt ->
                        val isSelected = opt.type == selectedOption.type
                        val borderColor = if (isSelected) {
                            MaterialTheme.colorScheme.primary
                        } else {
                            MaterialTheme.colorScheme.outlineVariant
                        }
                        val containerColor = if (isSelected) {
                            MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.22f)
                        } else {
                            MaterialTheme.colorScheme.surface
                        }

                        OutlinedCard(
                            shape = RoundedCornerShape(10.dp),
                            border = BorderStroke(if (isSelected) 1.5.dp else 1.dp, borderColor),
                            colors = CardDefaults.outlinedCardColors(containerColor = containerColor),
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(10.dp))
                                .clickable(enabled = !isLoading) { selectedOption = opt }
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 10.dp, vertical = 6.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Surface(
                                    shape = RoundedCornerShape(8.dp),
                                    color = if (isSelected) {
                                        MaterialTheme.colorScheme.primaryContainer
                                    } else {
                                        MaterialTheme.colorScheme.surfaceVariant
                                    },
                                    modifier = Modifier.size(30.dp)
                                ) {
                                    Box(contentAlignment = Alignment.Center) {
                                        Icon(
                                            imageVector = opt.icon,
                                            contentDescription = null,
                                            tint = if (isSelected) {
                                                MaterialTheme.colorScheme.primary
                                            } else {
                                                MaterialTheme.colorScheme.onSurfaceVariant
                                            },
                                            modifier = Modifier.size(16.dp)
                                        )
                                    }
                                }

                                Spacer(modifier = Modifier.width(8.dp))

                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = opt.title,
                                        style = MaterialTheme.typography.labelLarge,
                                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                    Text(
                                        text = opt.description,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                }
                            }
                        }
                    }
                }

                // Parâmetros Dinâmicos de Acordo com o Tipo Selecionado
                Spacer(modifier = Modifier.height(4.dp))
                when (selectedOption.type) {
                    AccessKeyType.PASSKEY_FIDO,
                    AccessKeyType.VENDOR_SIGNING_KEY -> {
                        Text(
                            text = "Algoritmo / Curva Criptográfica:",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold
                        )
                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            COSE_CURVES.forEach { curve ->
                                FilterChip(
                                    selected = chosenCurve == curve,
                                    onClick = { chosenCurve = curve },
                                    label = { Text(curve, style = MaterialTheme.typography.labelSmall) },
                                    colors = FilterChipDefaults.filterChipColors()
                                )
                            }
                        }
                    }
                    AccessKeyType.CRYPTO_WALLET_BTC,
                    AccessKeyType.CRYPTO_WALLET_ETH,
                    AccessKeyType.CRYPTO_WALLET_SOL,
                    AccessKeyType.CRYPTO_WALLET_DOT -> {
                        Text(
                            text = "Caminho de Derivação Hierárquica (HD Path):",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold
                        )
                        OutlinedTextField(
                            value = extraParam,
                            onValueChange = { extraParam = it },
                            label = { Text("Caminho HD (BIP32/44/84)") },
                            singleLine = true,
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.fillMaxWidth()
                        )
                        Surface(
                            shape = RoundedCornerShape(6.dp),
                            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
                        ) {
                            Text(
                                text = "Curva nativa: ${selectedOption.defaultCurve}",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                            )
                        }
                    }
                    AccessKeyType.PIV_SMARTCARD_SLOT -> {
                        Text(
                            text = "Selecione o Slot PIV (NIST SP 800-73-4):",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold
                        )
                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            PIV_SLOTS.forEach { (slotCode, slotLabel) ->
                                FilterChip(
                                    selected = extraParam == slotCode,
                                    onClick = { extraParam = slotCode },
                                    label = { Text(slotLabel, style = MaterialTheme.typography.labelSmall) }
                                )
                            }
                        }
                    }
                    AccessKeyType.ENCRYPTED_AEGN_ENVELOPE -> {
                        Text(
                            text = "Segredo a ser Selado com AES-256-GCM:",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold
                        )
                        OutlinedTextField(
                            value = extraParam,
                            onValueChange = { extraParam = it },
                            label = { Text("Segredo ou Semente") },
                            placeholder = { Text("Insira o segredo confidencial") },
                            singleLine = true,
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                }
            }
        },
        confirmButton = {
            PrimaryNextButton(
                text = "Gravar no Hardware",
                enabled = isFormValid && !isLoading,
                isLoading = isLoading,
                onClick = {
                    if (isFormValid) {
                        onConfirm(accountName.trim(), selectedOption.type, chosenCurve, extraParam)
                    }
                }
            )
        },
        dismissButton = {
            TextButton(
                onClick = onDismissRequest,
                enabled = !isLoading
            ) {
                Text(
                    text = "Cancelar",
                    style = MaterialTheme.typography.labelMedium,
                    maxLines = 1
                )
            }
        },
        modifier = modifier
    )
}
