package dev.aegiskey.app.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForwardIos
import androidx.compose.material.icons.filled.Badge
import androidx.compose.material.icons.filled.Backup
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Medication
import androidx.compose.material.icons.filled.PhonelinkSetup
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.domain.model.AppThemeMode
import dev.aegiskey.app.ui.atomic.organisms.ThemeSelectorOrganism
import dev.aegiskey.app.ui.theme.ThemeMode
import dev.aegiskey.app.ui.viewmodel.AppThemeViewModel

@Composable
fun FriendlySettingsAndThemeScreen(
    themeViewModel: AppThemeViewModel,
    onNavigateToBackup: () -> Unit = {},
    onNavigateToTransfer: () -> Unit = {},
    onNavigateToOta: () -> Unit = {},
    onNavigateToRescue: () -> Unit = {},
    onNavigateToPiv: () -> Unit = {},
    onNavigateToLogs: () -> Unit = {},
    modifier: Modifier = Modifier,
) {
    val themePref by themeViewModel.themePreference.collectAsState()

    val currentUiThemeMode = when (themePref.mode) {
        AppThemeMode.SYSTEM -> ThemeMode.SYSTEM
        AppThemeMode.LIGHT -> ThemeMode.LIGHT
        AppThemeMode.DARK -> ThemeMode.DARK
    }

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        // Bloco de Tema e Cores
        item {
            ThemeSelectorOrganism(
                selectedThemeMode = currentUiThemeMode,
                onThemeModeChange = { uiMode ->
                    val domainMode = when (uiMode) {
                        ThemeMode.SYSTEM -> AppThemeMode.SYSTEM
                        ThemeMode.LIGHT -> AppThemeMode.LIGHT
                        ThemeMode.DARK -> AppThemeMode.DARK
                    }
                    themeViewModel.setThemeMode(domainMode)
                },
                dynamicColorEnabled = themePref.useDynamicColors,
                onDynamicColorToggle = { themeViewModel.setDynamicColors(it) },
            )
        }

        // Seção: Ferramentas de Manutenção e Segurança
        item {
            Text(
                text = "Segurança & Manutenção da Chave",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
        }

        item {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                SettingsNavigationItemCard(
                    title = "Backup e Recuperação",
                    description = "Crie uma cópia de segurança protegida para restabelecer seus acessos.",
                    icon = Icons.Filled.Backup,
                    onClick = onNavigateToBackup,
                )

                SettingsNavigationItemCard(
                    title = "Transferir Chave para Outro Celular",
                    description = "Passe o vínculo de dono da chave para um novo aparelho com segurança.",
                    icon = Icons.Filled.PhonelinkSetup,
                    onClick = onNavigateToTransfer,
                )

                SettingsNavigationItemCard(
                    title = "Atualização da Chave (OTA)",
                    description = "Instale novas melhorias e correções no software da sua AegisKey sem fio.",
                    icon = Icons.Filled.SystemUpdate,
                    onClick = onNavigateToOta,
                )

                SettingsNavigationItemCard(
                    title = "Diagnóstico de Emergência (Resgate)",
                    description = "Verifique os sensores, memória interna e teste a resposta da chave física.",
                    icon = Icons.Filled.Medication,
                    onClick = onNavigateToRescue,
                )

                SettingsNavigationItemCard(
                    title = "Cartão Inteligente (PIV / Certificados)",
                    description = "Certificados digitais para login corporativo e assinatura de documentos.",
                    icon = Icons.Filled.Badge,
                    onClick = onNavigateToPiv,
                )

                SettingsNavigationItemCard(
                    title = "Histórico de Atividades",
                    description = "Consulte os registros de conexões e eventos do dispositivo.",
                    icon = Icons.Filled.History,
                    onClick = onNavigateToLogs,
                )
            }
        }

        item {
            Surface(
                shape = RoundedCornerShape(16.dp),
                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text(
                        text = "AegisKey App · v0.1.0-wave5",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        text = "Segurança em hardware com transparência total e código aberto.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

@Composable
private fun SettingsNavigationItemCard(
    title: String,
    description: String,
    icon: ImageVector,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    OutlinedCard(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.outlinedCardColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .clickable(onClick = onClick),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Surface(
                shape = RoundedCornerShape(12.dp),
                color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.6f),
                modifier = Modifier.size(42.dp),
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        imageVector = icon,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(22.dp),
                    )
                }
            }

            Spacer(modifier = Modifier.width(14.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    text = description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            Spacer(modifier = Modifier.width(8.dp))

            Icon(
                imageVector = Icons.AutoMirrored.Filled.ArrowForwardIos,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
                modifier = Modifier.size(16.dp),
            )
        }
    }
}
