package dev.aegiskey.app.ui.atomic.atoms

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.aegiskey.app.domain.model.SecureGuardStateEnum

/**
 * Pílula/Badge atômico para visualização instantânea do estado da FSM do Secure Guard.
 * Cores alinhadas com UX Seção 11.2 e Material 3 Design Tokens.
 */
@Composable
fun SecureGuardBadgeAtom(
    state: SecureGuardStateEnum,
    modifier: Modifier = Modifier
) {
    val (bgColor, textColor) = when (state) {
        SecureGuardStateEnum.UNPROVISIONED -> Color(0xFF64748B) to Color.White
        SecureGuardStateEnum.PROVISIONING -> Color(0xFF0284C7) to Color.White
        SecureGuardStateEnum.LOCKED -> Color(0xFFDC2626) to Color.White
        SecureGuardStateEnum.AUTHENTICATING -> Color(0xFFEAB308) to Color.Black
        SecureGuardStateEnum.UNLOCKED -> Color(0xFF16A34A) to Color.White
        SecureGuardStateEnum.RECOVERY_REQUIRED -> Color(0xFFEA580C) to Color.White
        SecureGuardStateEnum.RATE_LIMITED -> Color(0xFFD97706) to Color.White
        SecureGuardStateEnum.WIPE_PENDING -> Color(0xFF991B1B) to Color.White
        SecureGuardStateEnum.WIPE_IN_PROGRESS -> Color(0xFF7F1D1D) to Color.White
        SecureGuardStateEnum.ERROR_LOCKED -> Color(0xFF450A0A) to Color.White
        SecureGuardStateEnum.DEVICE_UNAVAILABLE -> Color(0xFF334155) to Color.White
    }

    Box(
        modifier = modifier
            .background(bgColor, RoundedCornerShape(12.dp))
            .padding(horizontal = 10.dp, vertical = 4.dp)
    ) {
        Text(
            text = state.displayName.uppercase(),
            color = textColor,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = 0.5.sp
        )
    }
}
