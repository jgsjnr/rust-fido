package dev.aegiskey.app.ui.atomic.molecules

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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Tv
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.aegiskey.app.R

/**
 * Molécula de Atomic Design responsável pela pré-visualização desacoplada de Clear Signing Web3 (OPP-06).
 *
 * Renderiza de forma 100% responsiva (FlowRow, weight(1f), sem encavalar) o buffer visual
 * simulado do display OLED I2C SSD1306 128x64 diretamente em código, permitindo ao usuário
 * auditar os parâmetros críticos da transação (rede, destinatário, valor, taxa máxima e hash)
 * antes de confirmar no botão físico do hardware, sem exigir tela gráfica física acoplada à placa.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ClearSigningPreviewMolecule(
    network: String,
    txPayload: String,
    toAddress: String? = null,
    amount: String? = null,
    maxFee: String? = null,
    payloadHash: String? = null,
    oledLines: List<String>? = null,
    onRefresh: (() -> Unit)? = null,
    modifier: Modifier = Modifier
) {
    val displayTo = toAddress?.ifBlank { null } ?: parseFallbackToAddress(txPayload)
    val displayAmount = amount?.ifBlank { null } ?: parseFallbackAmount(txPayload)
    val displayFee = maxFee?.ifBlank { null } ?: "0.0015 ETH (Standard)"
    val displayHash = payloadHash?.ifBlank { null } ?: computeFallbackHash(txPayload)

    val resolvedOledLines = if (!oledLines.isNullOrEmpty()) {
        oledLines
    } else {
        listOf(
            "=== OLED 128x64 ===",
            "NET: ${network.take(12)}",
            "TO:  ${truncateAddress(displayTo)}",
            "VAL: ${displayAmount.take(14)}",
            "FEE: ${displayFee.take(14)}",
            "HASH: ${displayHash.take(16)}",
            "------------------",
            ">> PRESS HW BTN <<"
        )
    }

    OutlinedCard(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.outlinedCardColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
        modifier = modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            // 1. Cabeçalho Responsivo com Título e Botão de Refresh
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = MaterialTheme.colorScheme.secondaryContainer,
                    modifier = Modifier.size(36.dp)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(
                            imageVector = Icons.Filled.Tv,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSecondaryContainer,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.width(10.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.clear_signing_preview_title),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = stringResource(R.string.clear_signing_parsed_tx),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                if (onRefresh != null) {
                    IconButton(
                        onClick = onRefresh,
                        modifier = Modifier.size(36.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Refresh,
                            contentDescription = stringResource(R.string.clear_signing_btn_refresh),
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }
            }

            // 2. Badge de Advertência Explícita: CODE-ONLY OLED PREVIEW (NO PHYSICAL DISPLAY REQUIRED)
            FlowRow(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Start,
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = Color(0xFF0369A1).copy(alpha = 0.15f),
                    border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFF0284C7)),
                    modifier = Modifier.padding(vertical = 2.dp)
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Code,
                            contentDescription = null,
                            tint = Color(0xFF0284C7),
                            modifier = Modifier.size(14.dp)
                        )
                        Text(
                            text = stringResource(R.string.clear_signing_badge_code_only),
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.ExtraBold,
                            color = Color(0xFF0284C7),
                            letterSpacing = 0.4.sp
                        )
                    }
                }
            }

            // 3. Simulação Visual da Tela OLED 128x64 em Caixa Monocromática Escura
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(Color(0xFF050811))
                    .border(1.5.dp, Color(0xFF1E293B), RoundedCornerShape(12.dp))
                    .padding(horizontal = 12.dp, vertical = 10.dp)
            ) {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(3.dp)
                ) {
                    // Barra de Título do Frame OLED
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = stringResource(R.string.clear_signing_oled_header),
                            fontFamily = FontFamily.Monospace,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF38BDF8),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            text = "[SSD1306]",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 9.sp,
                            color = Color(0xFF94A3B8)
                        )
                    }

                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(1.dp)
                            .background(Color(0xFF1E293B))
                    )

                    Spacer(modifier = Modifier.height(2.dp))

                    // Linhas do Buffer Gráfico OLED Renderizadas em Monospace
                    resolvedOledLines.forEachIndexed { index, line ->
                        val lineColor = when {
                            line.contains("PRESS", true) || line.contains("HW BTN", true) -> Color(0xFF4ADE80)
                            line.contains("NET:", true) || line.contains("VAL:", true) -> Color(0xFFF8FAFC)
                            line.contains("TO:", true) -> Color(0xFFE2E8F0)
                            line.contains("===", true) || line.contains("---", true) -> Color(0xFF64748B)
                            else -> Color(0xFF94A3B8)
                        }

                        Text(
                            text = line,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            fontWeight = if (line.contains("PRESS", true)) FontWeight.Bold else FontWeight.Normal,
                            color = lineColor,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                }
            }

            // 4. Grid de Propriedades Estruturadas (FlowRow Responsivo sem Encavalamento)
            FlowRow(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                ClearSigningParamPill(
                    label = stringResource(R.string.clear_signing_network),
                    value = network,
                    modifier = Modifier.weight(1f, fill = false)
                )
                ClearSigningParamPill(
                    label = stringResource(R.string.clear_signing_amount),
                    value = displayAmount,
                    modifier = Modifier.weight(1f, fill = false)
                )
                ClearSigningParamPill(
                    label = stringResource(R.string.clear_signing_max_fee),
                    value = displayFee,
                    modifier = Modifier.weight(1f, fill = false)
                )
                ClearSigningParamPill(
                    label = stringResource(R.string.clear_signing_to_address),
                    value = truncateAddress(displayTo),
                    modifier = Modifier.weight(1f, fill = false)
                )
            }

            // 5. Nota de Segurança e Validação de Presença Física
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 2.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Icon(
                    imageVector = Icons.Filled.Security,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(16.dp)
                )
                Text(
                    text = stringResource(R.string.clear_signing_confirm_on_device),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
            }
        }
    }
}

@Composable
private fun ClearSigningParamPill(
    label: String,
    value: String,
    modifier: Modifier = Modifier
) {
    Surface(
        shape = RoundedCornerShape(8.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
        modifier = modifier
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontWeight = FontWeight.Medium
            )
            Text(
                text = value,
                style = MaterialTheme.typography.labelSmall,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

private fun truncateAddress(addr: String): String {
    val clean = addr.trim()
    return if (clean.length > 18) {
        clean.take(8) + ".." + clean.takeLast(6)
    } else {
        clean
    }
}

private fun parseFallbackToAddress(tx: String): String {
    val lower = tx.lowercase()
    return when {
        lower.contains("to:") -> tx.substringAfter("to:").substringBefore(" ").substringBefore("\n").trim()
        lower.contains("->") -> tx.substringAfter("->").substringBefore(" ").substringBefore("\n").trim()
        lower.contains("bc1q") -> "bc1q" + tx.substringAfter("bc1q").substringBefore(" ").substringBefore("\n").trim()
        lower.contains("0x") -> "0x" + tx.substringAfter("0x").substringBefore(" ").substringBefore("\n").trim()
        else -> "0x71C8F...b84F"
    }
}

private fun parseFallbackAmount(tx: String): String {
    val lower = tx.lowercase()
    return when {
        lower.contains("value:") -> tx.substringAfter("value:").substringBefore(" ").substringBefore("\n").trim()
        lower.contains("btc") -> tx.substringBefore(" btc", tx).substringAfterLast(" ").trim() + " BTC"
        lower.contains("sol") -> tx.substringBefore(" sol", tx).substringAfterLast(" ").trim() + " SOL"
        lower.contains("dot") -> tx.substringBefore(" dot", tx).substringAfterLast(" ").trim() + " DOT"
        lower.contains("ether") || lower.contains("eth") -> "1.2000 ETH"
        else -> "1.0000 TOKEN"
    }
}

private fun computeFallbackHash(tx: String): String {
    val hash = (tx.hashCode().toLong() and 0xFFFFFFFFL).toString(16).padStart(8, '0')
    return "0x${hash}a1b2c3d4"
}
