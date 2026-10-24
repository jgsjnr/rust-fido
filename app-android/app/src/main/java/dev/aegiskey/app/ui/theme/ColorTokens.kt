package dev.aegiskey.app.ui.theme

import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color

/**
 * Paleta de cores do AegisKey — Google Material 3 Design System.
 * Tons confiáveis de azul cobalto, esmeralda de segurança criptográfica
 * e âmbar para ações que exigem presença física.
 */
object AegisColors {
    // Azul Confiável (Primary)
    val PrimaryLight = Color(0xFF0061A4)
    val OnPrimaryLight = Color(0xFFFFFFFF)
    val PrimaryContainerLight = Color(0xFFD1E4FF)
    val OnPrimaryContainerLight = Color(0xFF001D36)

    val PrimaryDark = Color(0xFF9ECAFF)
    val OnPrimaryDark = Color(0xFF003258)
    val PrimaryContainerDark = Color(0xFF00497D)
    val OnPrimaryContainerDark = Color(0xFFD1E4FF)

    // Esmeralda Criptográfico (Secondary / Sucesso / Verificado)
    val SecondaryLight = Color(0xFF006A60)
    val OnSecondaryLight = Color(0xFFFFFFFF)
    val SecondaryContainerLight = Color(0xFF73F8E5)
    val OnSecondaryContainerLight = Color(0xFF00201C)

    val SecondaryDark = Color(0xFF53DBC9)
    val OnSecondaryDark = Color(0xFF003731)
    val SecondaryContainerDark = Color(0xFF005048)
    val OnSecondaryContainerDark = Color(0xFF73F8E5)

    // Âmbar / Presença Física (Tertiary / Atenção ao Botão)
    val TertiaryLight = Color(0xFF785900)
    val OnTertiaryLight = Color(0xFFFFFFFF)
    val TertiaryContainerLight = Color(0xFFFFDF9E)
    val OnTertiaryContainerLight = Color(0xFF261A00)

    val TertiaryDark = Color(0xFFF0BE3B)
    val OnTertiaryDark = Color(0xFF3F2E00)
    val TertiaryContainerDark = Color(0xFF5A4300)
    val OnTertiaryContainerDark = Color(0xFFFFDF9E)

    // Erro / Alerta
    val ErrorLight = Color(0xFFBA1A1A)
    val OnErrorLight = Color(0xFFFFFFFF)
    val ErrorContainerLight = Color(0xFFFFDAD6)
    val OnErrorContainerLight = Color(0xFF410002)

    val ErrorDark = Color(0xFFFFB4AB)
    val OnErrorDark = Color(0xFF690005)
    val ErrorContainerDark = Color(0xFF93000A)
    val OnErrorContainerDark = Color(0xFFFFDAD6)

    // Neutros e Superfícies — Tema Claro
    val BackgroundLight = Color(0xFFFDFCFF)
    val OnBackgroundLight = Color(0xFF1A1C1E)
    val SurfaceLight = Color(0xFFFDFCFF)
    val OnSurfaceLight = Color(0xFF1A1C1E)
    val SurfaceVariantLight = Color(0xFFDFE2EB)
    val OnSurfaceVariantLight = Color(0xFF43474E)
    val OutlineLight = Color(0xFF73777F)
    val OutlineVariantLight = Color(0xFFC3C7D0)

    // Neutros e Superfícies — Tema Escuro (OLED Friendly)
    val BackgroundDark = Color(0xFF101418)
    val OnBackgroundDark = Color(0xFFE2E2E6)
    val SurfaceDark = Color(0xFF101418)
    val OnSurfaceDark = Color(0xFFE2E2E6)
    val SurfaceVariantDark = Color(0xFF43474E)
    val OnSurfaceVariantDark = Color(0xFFC3C7D0)
    val OutlineDark = Color(0xFF8D9199)
    val OutlineVariantDark = Color(0xFF43474E)

    // Estados Específicos para Badges
    val StatusConnected = Color(0xFF1B8754)
    val StatusDisconnected = Color(0xFF8E9196)
    val StatusSimulated = Color(0xFFE67E22)
}

/** Esquema de Cores Claro Material 3 oficial do AegisKey. */
val AegisLightColorScheme = lightColorScheme(
    primary = AegisColors.PrimaryLight,
    onPrimary = AegisColors.OnPrimaryLight,
    primaryContainer = AegisColors.PrimaryContainerLight,
    onPrimaryContainer = AegisColors.OnPrimaryContainerLight,
    secondary = AegisColors.SecondaryLight,
    onSecondary = AegisColors.OnSecondaryLight,
    secondaryContainer = AegisColors.SecondaryContainerLight,
    onSecondaryContainer = AegisColors.OnSecondaryContainerLight,
    tertiary = AegisColors.TertiaryLight,
    onTertiary = AegisColors.OnTertiaryLight,
    tertiaryContainer = AegisColors.TertiaryContainerLight,
    onTertiaryContainer = AegisColors.OnTertiaryContainerLight,
    error = AegisColors.ErrorLight,
    onError = AegisColors.OnErrorLight,
    errorContainer = AegisColors.ErrorContainerLight,
    onErrorContainer = AegisColors.OnErrorContainerLight,
    background = AegisColors.BackgroundLight,
    onBackground = AegisColors.OnBackgroundLight,
    surface = AegisColors.SurfaceLight,
    onSurface = AegisColors.OnSurfaceLight,
    surfaceVariant = AegisColors.SurfaceVariantLight,
    onSurfaceVariant = AegisColors.OnSurfaceVariantLight,
    outline = AegisColors.OutlineLight,
    outlineVariant = AegisColors.OutlineVariantLight,
)

/** Esquema de Cores Escuro Material 3 oficial do AegisKey. */
val AegisDarkColorScheme = darkColorScheme(
    primary = AegisColors.PrimaryDark,
    onPrimary = AegisColors.OnPrimaryDark,
    primaryContainer = AegisColors.PrimaryContainerDark,
    onPrimaryContainer = AegisColors.OnPrimaryContainerDark,
    secondary = AegisColors.SecondaryDark,
    onSecondary = AegisColors.OnSecondaryDark,
    secondaryContainer = AegisColors.SecondaryContainerDark,
    onSecondaryContainer = AegisColors.OnSecondaryContainerDark,
    tertiary = AegisColors.TertiaryDark,
    onTertiary = AegisColors.OnTertiaryDark,
    tertiaryContainer = AegisColors.TertiaryContainerDark,
    onTertiaryContainer = AegisColors.OnTertiaryContainerDark,
    error = AegisColors.ErrorDark,
    onError = AegisColors.OnErrorDark,
    errorContainer = AegisColors.ErrorContainerDark,
    onErrorContainer = AegisColors.OnErrorContainerDark,
    background = AegisColors.BackgroundDark,
    onBackground = AegisColors.OnBackgroundDark,
    surface = AegisColors.SurfaceDark,
    onSurface = AegisColors.OnSurfaceDark,
    surfaceVariant = AegisColors.SurfaceVariantDark,
    onSurfaceVariant = AegisColors.OnSurfaceVariantDark,
    outline = AegisColors.OutlineDark,
    outlineVariant = AegisColors.OutlineVariantDark,
)

/** Modos de tema suportados pela aplicação. */
enum class ThemeMode {
    SYSTEM,
    LIGHT,
    DARK;

    fun getDisplayName(): String = when (this) {
        SYSTEM -> "Automático do Sistema"
        LIGHT -> "Tema Claro"
        DARK -> "Tema Escuro"
    }
}
