package dev.aegiskey.app.ui.atomic.templates

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Palette
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.ui.atomic.atoms.ConnectionStatusBadgeAtom

/**
 * Main navigation destinations for AegisKey Hub.
 * ASD-STE100 standardized labels.
 */
enum class HubDestination(
    val route: String,
    val label: String,
    val icon: ImageVector,
) {
    VAULT(route = "vault", label = "Vault", icon = Icons.Filled.Lock),
    CODES(route = "codes", label = "TOTP", icon = Icons.Filled.Password),
    KEYS(route = "keys", label = "Devices", icon = Icons.Filled.VpnKey),
    SETTINGS(route = "settings", label = "Settings", icon = Icons.Filled.Settings),
}

/**
 * Global hub scaffold template with top bar and navigation bar.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainHubScaffoldTemplate(
    currentDestination: HubDestination,
    onNavigateToDestination: (HubDestination) -> Unit,
    activeKeyName: String,
    isConnected: Boolean,
    transportLabel: String,
    onSwitchKeyClick: () -> Unit,
    onToggleThemeClick: () -> Unit,
    modifier: Modifier = Modifier,
    snackbarHost: @Composable () -> Unit = {},
    content: @Composable (PaddingValues) -> Unit,
) {
    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = {
                    Surface(
                        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier
                            .widthIn(max = 190.dp)
                            .clip(RoundedCornerShape(10.dp))
                            .clickable(onClick = onSwitchKeyClick),
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                        ) {
                            Icon(
                                imageVector = Icons.Filled.VpnKey,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(16.dp),
                            )
                            Spacer(modifier = Modifier.width(5.dp))
                            Text(
                                text = activeKeyName.ifBlank { "Security Key" },
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                modifier = Modifier.weight(1f, fill = false),
                            )
                            Icon(
                                imageVector = Icons.Filled.ArrowDropDown,
                                contentDescription = "Switch security key",
                                modifier = Modifier.size(16.dp),
                            )
                        }
                    }
                },
                actions = {
                    ConnectionStatusBadgeAtom(
                        isConnected = isConnected,
                        transportLabel = transportLabel,
                    )
                    IconButton(
                        onClick = onToggleThemeClick,
                        modifier = Modifier.size(36.dp),
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Palette,
                            contentDescription = "Toggle theme mode",
                            tint = MaterialTheme.colorScheme.onSurface,
                            modifier = Modifier.size(20.dp),
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                ),
            )
        },
        bottomBar = {
            NavigationBar(
                containerColor = MaterialTheme.colorScheme.surface,
                tonalElevation = 2.dp,
            ) {
                HubDestination.entries.forEach { destination ->
                    val isSelected = destination == currentDestination
                    NavigationBarItem(
                        selected = isSelected,
                        onClick = { onNavigateToDestination(destination) },
                        icon = {
                            Icon(
                                imageVector = destination.icon,
                                contentDescription = destination.label,
                                modifier = Modifier.size(22.dp),
                            )
                        },
                        label = {
                            Text(
                                text = destination.label,
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        },
                    )
                }
            }
        },
        snackbarHost = snackbarHost,
        content = content,
    )
}
