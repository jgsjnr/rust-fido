package dev.aegiskey.app.ui.screens

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import dev.aegiskey.app.ui.viewmodel.OnboardingWizardViewModel

/**
 * Onboarding wizard screen delegating to [FriendlyOnboardingWizardScreen].
 */
@Composable
fun OnboardingWizardScreen(
    viewModel: OnboardingWizardViewModel,
    onFinished: () -> Unit,
    modifier: Modifier = Modifier,
) {
    FriendlyOnboardingWizardScreen(
        viewModel = viewModel,
        onFinished = onFinished,
        modifier = modifier
    )
}
