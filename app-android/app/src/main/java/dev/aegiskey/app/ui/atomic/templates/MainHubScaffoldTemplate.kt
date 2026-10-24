package dev.aegiskey.app.ui.atomic.templates

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
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
 * Destinos da navegação principal do AegisKey Hub.
 * 4 seções intuitivas e em português direto.
 */
enum class HubDestination(
    val route: String,
    val label: String,
    val icon: ImageVector,
) {
    VAULT(route = "vault", label = "Cofre", icon = Icons.Filled.Lock),
    CODES(route = "codes", label = "Códigos", icon = Icons.Filled.Password),
    KEYS(route = "keys", label = "Chaves", icon = Icons.Filled.VpnKey),
    SETTINGS(route = "settings", label = "Ajustes", icon = Icons.Filled.Settings),
}

/**
 * Template principal pós-pareamento para navegação diária no AegisKey.
 *
 * Oferece:
 * - TopAppBar informativa com a chave física ativa (com toque para troca de chave), badge de status e atalho de tema
 * - Barra inferior NavigationBar limpa com 4 destinos principais
 * - Suporte completo ao Scaffold PaddingValues para evitar qualquer sobreposição de telas
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
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier
                            .clip(RoundedCornerShape(14.dp))
                            .clickable(onClick = onSwitchKeyClick),
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                        ) {
                            Icon(
                                imageVector = Icons.Filled.VpnKey,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(18.dp),
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = activeKeyName.ifBlank { "Minha AegisKey" },
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Icon(
                                imageVector = Icons.Filled.ArrowDropDown,
                                contentDescription = "Trocar chave",
                                modifier = Modifier.size(18.dp),
                            )
                        }
                    }
                },
                actions = {
                    ConnectionStatusBadgeAtom(
                        isConnected = isConnected,
                        transportLabel = transportLabel,
                    )
                    IconButton(onClick = onToggleThemeClick) {
                        Icon(
                            imageVector = Icons.Filled.Palette,
                            contentDescription = "Alternar aparência",
                            tint = MaterialTheme.colorScheme.onSurface,
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
                tonalElevation = 3.dp,
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
                            )
                        },
                        label = {
                            Text(
                                text = destination.label,
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
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
