package dev.aegiskey.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow

/**
 * Componentes explicativos para usuario nao-tecnico (licao priorizada):
 * toda opcao mostra TITULO + texto simples do que significa.
 * Reusa FriendlyText/AegisSpacing de UiCommon. Sem Log aqui (so UI).
 */

/** Opcao de dropdown com explicacao em linguagem simples. */
data class ExplainedOption<T>(val value: T, val title: String, val explanation: String)

/** Checkbox com titulo + explicacao (ex.: usos Assinar/Autenticar). */
@Composable
fun LabeledCheckbox(
    checked: Boolean,
    title: String,
    explanation: String,
    onCheckedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .clickable(enabled = enabled) { onCheckedChange(!checked) },
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(AegisSpacing.Tight),
    ) {
        Checkbox(checked = checked, onCheckedChange = null, enabled = enabled)
        Column(Modifier.weight(1f)) {
            FriendlyText(text = title, maxLines = 1)
            FriendlyText(
                text = explanation,
                style = MaterialTheme.typography.bodySmall,
                maxLines = 2,
            )
        }
    }
}

/** Interruptor com titulo + explicacao (ex.: TOTP/HOTP). */
@Composable
fun LabeledToggle(
    checked: Boolean,
    title: String,
    explanation: String,
    onCheckedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .clickable(enabled = enabled) { onCheckedChange(!checked) },
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(AegisSpacing.Tight),
    ) {
        Column(Modifier.weight(1f)) {
            FriendlyText(text = title, maxLines = 1)
            FriendlyText(
                text = explanation,
                style = MaterialTheme.typography.bodySmall,
                maxLines = 2,
            )
        }
        Switch(checked = checked, onCheckedChange = null, enabled = enabled)
    }
}

/** Radio com titulo + explicacao (ex.: origem Hardware vs App). */
@Composable
fun LabeledRadio(
    selected: Boolean,
    title: String,
    explanation: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .clickable(enabled = enabled) { onClick() },
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(AegisSpacing.Tight),
    ) {
        RadioButton(selected = selected, onClick = null, enabled = enabled)
        Column(Modifier.weight(1f)) {
            FriendlyText(text = title, maxLines = 1)
            FriendlyText(
                text = explanation,
                style = MaterialTheme.typography.bodySmall,
                maxLines = 3,
            )
        }
    }
}

/**
 * Dropdown que explica a opcao escolhida (supportingText) e cada
 * alternativa (duas linhas no menu). Mesmo padrao ExposedDropdownMenuBox
 * ja usado em Accounts/Vault.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun <T> ExplainedDropdown(
    label: String,
    options: List<ExplainedOption<T>>,
    selected: ExplainedOption<T>,
    onSelected: (ExplainedOption<T>) -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { if (enabled) expanded = !expanded },
    ) {
        OutlinedTextField(
            value = selected.title,
            onValueChange = {},
            readOnly = true,
            enabled = enabled,
            label = { Text(label) },
            supportingText = { Text(selected.explanation) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = modifier.menuAnchor().fillMaxWidth(),
        )
        ExposedDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
        ) {
            for (option in options) {
                DropdownMenuItem(
                    text = {
                        Column {
                            Text(option.title, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(
                                option.explanation,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    },
                    onClick = {
                        onSelected(option)
                        expanded = false
                    },
                )
            }
        }
    }
}

/** Confirmacao destrutiva (EXCLUIR/REGENERAR): sem PII alem do rotulo. */
@Composable
fun ConfirmActionDialog(
    title: String,
    body: String,
    confirmLabel: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title, maxLines = 2, overflow = TextOverflow.Ellipsis) },
        text = {
            Text(
                body,
                style = MaterialTheme.typography.bodyMedium,
                overflow = TextOverflow.Ellipsis,
            )
        },
        confirmButton = { TextButton(onClick = onConfirm) { Text(confirmLabel) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancelar") } },
    )
}