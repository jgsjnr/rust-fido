package dev.aegiskey.app.ui.atomic.organisms

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BrightnessAuto
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.LightMode
import androidx.compose.material.icons.filled.Palette
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.ui.atomic.molecules.SettingToggleRowMolecule
import dev.aegiskey.app.ui.theme.ThemeMode

@Composable
private fun ThemeModeOptionCard(
    label: String,
    icon: ImageVector,
    isSelected: Boolean,
    onSelect: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val borderColor = if (isSelected) {
        MaterialTheme.colorScheme.primary
    } else {
        MaterialTheme.colorScheme.outlineVariant
    }

    val containerColor = if (isSelected) {
        MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.25f)
    } else {
        MaterialTheme.colorScheme.surface
    }

    OutlinedCard(
        shape = RoundedCornerShape(12.dp),
        border = BorderStroke(if (isSelected) 1.5.dp else 1.dp, borderColor),
        colors = CardDefaults.outlinedCardColors(containerColor = containerColor),
        modifier = modifier
            .height(64.dp)
            .clip(RoundedCornerShape(12.dp))
            .clickable(onClick = onSelect),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 6.dp, horizontal = 4.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier.size(24.dp),
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = if (isSelected) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                    modifier = Modifier.size(20.dp),
                )
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium,
                color = if (isSelected) {
                    MaterialTheme.colorScheme.primary
                } else {
                    MaterialTheme.colorScheme.onSurface
                },
                textAlign = TextAlign.Center,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

/**
 * Theme and appearance selector organism.
 */
@Composable
fun ThemeSelectorOrganism(
    selectedThemeMode: ThemeMode,
    onThemeModeChange: (ThemeMode) -> Unit,
    dynamicColorEnabled: Boolean,
    onDynamicColorToggle: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = "Theme and Appearance",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            ThemeModeOptionCard(
                label = "System",
                icon = Icons.Filled.BrightnessAuto,
                isSelected = selectedThemeMode == ThemeMode.SYSTEM,
                onSelect = { onThemeModeChange(ThemeMode.SYSTEM) },
                modifier = Modifier.weight(1f),
            )

            ThemeModeOptionCard(
                label = "Light",
                icon = Icons.Filled.LightMode,
                isSelected = selectedThemeMode == ThemeMode.LIGHT,
                onSelect = { onThemeModeChange(ThemeMode.LIGHT) },
                modifier = Modifier.weight(1f),
            )

            ThemeModeOptionCard(
                label = "Dark",
                icon = Icons.Filled.DarkMode,
                isSelected = selectedThemeMode == ThemeMode.DARK,
                onSelect = { onThemeModeChange(ThemeMode.DARK) },
                modifier = Modifier.weight(1f),
            )
        }

        SettingToggleRowMolecule(
            title = "Dynamic Colors",
            description = "Apply Material You dynamic palette from system wallpaper.",
            icon = Icons.Filled.Palette,
            checked = dynamicColorEnabled,
            onCheckedChange = onDynamicColorToggle,
        )
    }
}
