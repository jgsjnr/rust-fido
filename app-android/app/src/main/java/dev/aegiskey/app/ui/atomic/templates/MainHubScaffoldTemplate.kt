package dev.aegiskey.app.ui.atomic.templates

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.R
import dev.aegiskey.app.domain.model.SecureGuardStateEnum
import dev.aegiskey.app.ui.atomic.organisms.ConnectedKeyHeaderOrganism

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
 * Global hub scaffold template with responsive ConnectedKeyHeaderOrganism top bar and navigation bar.
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
    guardState: SecureGuardStateEnum? = null,
    snackbarHost: @Composable () -> Unit = {},
    content: @Composable (PaddingValues) -> Unit,
) {
    Scaffold(
        modifier = modifier,
        topBar = {
            ConnectedKeyHeaderOrganism(
                activeKeyName = activeKeyName,
                isConnected = isConnected,
                transportLabel = transportLabel,
                onSwitchKeyClick = onSwitchKeyClick,
                onToggleThemeClick = onToggleThemeClick,
                guardState = guardState,
            )
        },
        bottomBar = {
            NavigationBar(
                containerColor = MaterialTheme.colorScheme.surface,
                tonalElevation = 2.dp,
            ) {
                HubDestination.entries.forEach { destination ->
                    val isSelected = destination == currentDestination
                    val labelText = when (destination) {
                        HubDestination.VAULT -> stringResource(R.string.nav_vault)
                        HubDestination.CODES -> stringResource(R.string.nav_totp)
                        HubDestination.KEYS -> stringResource(R.string.nav_devices)
                        HubDestination.SETTINGS -> stringResource(R.string.nav_settings)
                    }

                    NavigationBarItem(
                        selected = isSelected,
                        onClick = { onNavigateToDestination(destination) },
                        icon = {
                            Icon(
                                imageVector = destination.icon,
                                contentDescription = labelText,
                                modifier = Modifier.size(22.dp),
                            )
                        },
                        label = {
                            Text(
                                text = labelText,
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
