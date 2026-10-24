package dev.aegiskey.app.ui

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext
import dev.aegiskey.app.ui.theme.AegisDarkColorScheme
import dev.aegiskey.app.ui.theme.AegisLightColorScheme
import dev.aegiskey.app.ui.theme.AegisTypography
import dev.aegiskey.app.ui.theme.ThemeMode

/**
 * Tema oficial Material 3 do AegisKey.
 * Suporta modo Claro, modo Escuro e Cores Dinâmicas do Android 12+ (Material You).
 *
 * Mantém compatibilidade retroativa com chamadas existentes sem argumentos:
 * `AegisTheme { ... }`.
 */
@Composable
fun AegisTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit
) {
    val context = LocalContext.current
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> AegisDarkColorScheme
        else -> AegisLightColorScheme
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = AegisTypography,
        content = content
    )
}
