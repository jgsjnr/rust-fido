package dev.aegiskey.app.ui.atomic.atoms

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.aegiskey.app.R
import dev.aegiskey.app.ui.theme.AegisColors

/**
 * Step progress indicator.
 */
@Composable
fun StepProgressDotsAtom(
    currentStep: Int,
    totalSteps: Int,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        for (step in 1..totalSteps) {
            val isCurrent = step == currentStep
            val isPassed = step < currentStep

            val dotWidth by animateDpAsState(
                targetValue = if (isCurrent) 22.dp else 6.dp,
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
                    .height(6.dp)
                    .width(dotWidth)
                    .clip(CircleShape)
                    .background(dotColor),
            )
        }
    }
}

/**
 * Countdown ring for temporary codes (TOTP).
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
        modifier = modifier.size(40.dp),
        contentAlignment = Alignment.Center,
    ) {
        CircularProgressIndicator(
            progress = { 1f },
            modifier = Modifier.size(40.dp),
            color = ringColor.copy(alpha = 0.15f),
            strokeWidth = 3.dp,
        )
        CircularProgressIndicator(
            progress = { animatedProgress },
            modifier = Modifier.size(40.dp),
            color = ringColor,
            strokeWidth = 3.dp,
        )
        Text(
            text = "$safeRemaining",
            style = MaterialTheme.typography.labelSmall.copy(
                fontWeight = FontWeight.Bold,
                fontSize = 11.sp,
            ),
            color = ringColor,
            maxLines = 1,
        )
    }
}

/**
 * Compact connection status badge atom (Bluetooth, USB, or Virtual Simulator).
 */
@Composable
fun ConnectionStatusBadgeAtom(
    isConnected: Boolean,
    transportLabel: String,
    modifier: Modifier = Modifier,
) {
    val isSimulated = transportLabel.contains("Simulator", ignoreCase = true) || transportLabel.contains("Simulador", ignoreCase = true)
    val badgeColor = when {
        !isConnected -> AegisColors.StatusDisconnected
        isSimulated -> AegisColors.StatusSimulated
        else -> AegisColors.StatusConnected
    }

    Surface(
        color = badgeColor.copy(alpha = 0.12f),
        shape = RoundedCornerShape(10.dp),
        modifier = modifier,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(5.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(6.dp)
                    .clip(CircleShape)
                    .background(badgeColor),
            )
            val statusText = if (isConnected) {
                stringResource(R.string.status_connected)
            } else {
                stringResource(R.string.status_disconnected)
            }
            val labelText = "$transportLabel · $statusText"
            Text(
                text = labelText,
                style = MaterialTheme.typography.labelSmall.copy(
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 11.sp,
                ),
                color = badgeColor,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}
