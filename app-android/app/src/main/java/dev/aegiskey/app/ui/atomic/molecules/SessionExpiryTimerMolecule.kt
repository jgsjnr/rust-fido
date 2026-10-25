package dev.aegiskey.app.ui.atomic.molecules

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Molécula indicadora de contagem regressiva da sessão desbloqueada ativa (Unlocked).
 */
@Composable
fun SessionExpiryTimerMolecule(
    remainingMs: Long,
    modifier: Modifier = Modifier
) {
    val remainingSec = (remainingMs / 1000).coerceAtLeast(0)
    val mins = remainingSec / 60
    val secs = remainingSec % 60
    val timeFormatted = "%02d:%02d".format(mins, secs)

    Box(
        modifier = modifier
            .fillMaxWidth()
            .background(Color(0xFF064E3B).copy(alpha = 0.25f), RoundedCornerShape(12.dp))
            .padding(12.dp)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            CircularProgressIndicator(
                progress = { (remainingSec % 300) / 300f },
                modifier = Modifier.size(24.dp),
                color = Color(0xFF10B981),
                strokeWidth = 3.dp,
            )
            Column {
                Text(
                    text = "Sessão Desbloqueada",
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFFA7F3D0)
                )
                Text(
                    text = "Tempo restante de autorização: $timeFormatted",
                    fontSize = 12.sp,
                    color = Color(0xFFD1FAE5)
                )
            }
        }
    }
}
