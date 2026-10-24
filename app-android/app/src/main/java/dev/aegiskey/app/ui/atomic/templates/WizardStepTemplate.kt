package dev.aegiskey.app.ui.atomic.templates

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.ui.atomic.atoms.PrimaryNextButton
import dev.aegiskey.app.ui.atomic.atoms.SecondaryBackButton
import dev.aegiskey.app.ui.atomic.atoms.StepProgressDotsAtom

/**
 * Template padronizado para fluxos lineares e acolhedores no estilo "Próximo → Próximo → Concluir"
 * (Onboarding, Pareamento Guiado, Recuperação e Troca de Dono).
 *
 * Estrutura:
 * 1. Topo: Indicador de passos em pílula + Título acolhedor + Subtítulo amigável
 * 2. Centro: Área rolável para o conteúdo customizado do passo
 * 3. Base: Barra fixa de ações com botão Voltar e botão Próximo/Concluir em destaque
 */
@Composable
fun WizardStepTemplate(
    currentStep: Int,
    totalSteps: Int,
    title: String,
    onNextClick: () -> Unit,
    subtitle: String? = null,
    nextButtonText: String = if (currentStep >= totalSteps) "Concluir" else "Próximo",
    isNextEnabled: Boolean = true,
    isNextLoading: Boolean = false,
    onBackClick: (() -> Unit)? = null,
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    val scrollState = rememberScrollState()

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .statusBarsPadding(),
    ) {
        // Cabeçalho Fixo do Passo
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp, vertical = 16.dp),
        ) {
            StepProgressDotsAtom(
                currentStep = currentStep,
                totalSteps = totalSteps,
            )

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = title,
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onBackground,
            )

            if (!subtitle.isNullOrBlank()) {
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        // Conteúdo Central Rolável
        Box(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth(),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(scrollState)
                    .padding(horizontal = 24.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
                content = content,
            )
        }

        // Barra Inferior Fixa de Navegação
        Surface(
            tonalElevation = 3.dp,
            shadowElevation = 4.dp,
            color = MaterialTheme.colorScheme.surface,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .navigationBarsPadding()
                    .padding(horizontal = 20.dp, vertical = 16.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (currentStep > 1 && onBackClick != null) {
                    SecondaryBackButton(
                        onClick = onBackClick,
                        enabled = !isNextLoading,
                        modifier = Modifier.weight(1f),
                    )
                }

                PrimaryNextButton(
                    text = nextButtonText,
                    onClick = onNextClick,
                    enabled = isNextEnabled,
                    isLoading = isNextLoading,
                    modifier = Modifier.weight(if (currentStep > 1 && onBackClick != null) 1.6f else 1f),
                )
            }
        }
    }
}
