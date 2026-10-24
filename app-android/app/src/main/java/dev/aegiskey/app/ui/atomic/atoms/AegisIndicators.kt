package dev.aegiskey.app.ui.atomic.atoms

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ProgressIndicatorDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.aegiskey.app.ui.theme.AegisColors

/**
 * Indicador visual de progresso por passos (ex: Passo 2 de 4).
 * O passo ativo expande suavemente como uma pílula, enquanto os demais permanecem circulares.
 */
@Composable
fun StepProgressDotsAtom(
    currentStep: Int,
    totalSteps: Int,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        for (step in 1..totalSteps) {
            val isCurrent = step == currentStep
            val isPassed = step < currentStep

            val dotWidth by animateDpAsState(
                targetValue = if (isCurrent) 28.dp else 8.dp,
                label = "step_dot_width_$step",
            )
            val dotColor by animateColorAsState(
                targetValue = when {
                    isCurrent -> MaterialTheme.colorScheme.primary
                    isPassed -> MaterialTheme.colorScheme.primary.copy(alpha = 0.5f)
                    else -> MaterialTheme.colorScheme.surfaceVariant
                },
                label = "step_dot_color_$step",
            )

            Box(
                modifier = Modifier
                    .height(8.dp)
                    .width(dotWidth)
                    .clip(CircleShape)
                    .background(dotColor),
            )
        }
    }
}

/**
 * Anel circular de contagem regressiva para códigos temporários (TOTP).
 * Altera de cor dinamicamente:
 * - > 10s: Esmeralda / Segurança
 * - 6 a 10s: Âmbar / Atenção
 * - <= 5s: Vermelho / Renovando
 */
@Composable
fun TotpCountdownRingAtom(
    remainingSeconds: Int,
    totalSeconds: Int = 30,
    modifier: Modifier = Modifier,
) {
    val safeTotal = totalSeconds.coerceAtLeast(1)
    val safeRemaining = remainingSeconds.coerceIn(0, safeTotal)
    val targetProgress = safeRemaining.toFloat() / safeTotal.toFloat()

    val animatedProgress by animateFloatAsState(
        targetValue = targetProgress,
        animationSpec = ProgressIndicatorDefaults.ProgressAnimationSpec,
        label = "totp_ring_progress",
    )

    val ringColor = when {
        safeRemaining <= 5 -> MaterialTheme.colorScheme.error
        safeRemaining <= 10 -> MaterialTheme.colorScheme.tertiary
        else -> MaterialTheme.colorScheme.secondary
    }

    Box(
        modifier = modifier.size(44.dp),
        contentAlignment = Alignment.Center,
    ) {
        // Trilha de fundo translúcida
        CircularProgressIndicator(
            progress = { 1f },
            modifier = Modifier.size(44.dp),
            color = ringColor.copy(alpha = 0.15f),
            strokeWidth = 3.5.dp,
        )
        // Progresso ativo
        CircularProgressIndicator(
            progress = { animatedProgress },
            modifier = Modifier.size(44.dp),
            color = ringColor,
            strokeWidth = 3.5.dp,
        )
        Text(
            text = "$safeRemaining",
            style = MaterialTheme.typography.labelMedium.copy(
                fontWeight = FontWeight.Bold,
                fontSize = 12.sp,
            ),
            color = ringColor,
        )
    }
}

/**
 * Pílula informativa de status de conexão física (Bluetooth, USB ou Simulador).
 */
@Composable
fun ConnectionStatusBadgeAtom(
    isConnected: Boolean,
    transportLabel: String,
    modifier: Modifier = Modifier,
) {
    val isSimulated = transportLabel.contains("Simulador", ignoreCase = true)
    val badgeColor = when {
        !isConnected -> AegisColors.StatusDisconnected
        isSimulated -> AegisColors.StatusSimulated
        else -> AegisColors.StatusConnected
    }

    Surface(
        color = badgeColor.copy(alpha = 0.12f),
        shape = RoundedCornerShape(12.dp),
        modifier = modifier,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            // Ponto de status
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .clip(CircleShape)
                    .background(badgeColor),
            )
            val labelText = if (isConnected) {
                "$transportLabel · Conectada"
            } else {
                "$transportLabel · Desconectada"
            }
            Text(
                text = labelText,
                style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.SemiBold),
                color = badgeColor,
            )
        }
    }
}
