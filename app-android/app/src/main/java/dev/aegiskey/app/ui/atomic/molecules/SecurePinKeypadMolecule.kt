package dev.aegiskey.app.ui.atomic.molecules

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Molécula segura de digitação de PIN mascarado (4 a 16 caracteres).
 * Nunca vaza o PIN e limpa a memória após submissão.
 */
@Composable
fun SecurePinKeypadMolecule(
    label: String = "PIN do Cofre",
    buttonText: String = "Confirmar",
    enabled: Boolean = true,
    errorMessage: String? = null,
    onSubmit: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    var pinText by remember { mutableStateOf("") }
    val isValid = pinText.length in 4..16

    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        OutlinedTextField(
            value = pinText,
            onValueChange = {
                if (it.length <= 16) {
                    pinText = it
                }
            },
            label = { Text(label) },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.NumberPassword,
                imeAction = if (isValid) ImeAction.Done else ImeAction.None
            ),
            keyboardActions = KeyboardActions(
                onDone = {
                    if (isValid && enabled) {
                        val p = pinText
                        pinText = ""
                        onSubmit(p)
                    }
                }
            ),
            singleLine = true,
            isError = errorMessage != null,
            supportingText = {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = errorMessage ?: "Mínimo 4 dígitos",
                        fontSize = 11.sp
                    )
                    Text(
                        text = "${pinText.length}/16",
                        fontSize = 11.sp
                    )
                }
            },
            enabled = enabled,
            modifier = Modifier.fillMaxWidth()
        )

        Button(
            onClick = {
                if (isValid && enabled) {
                    val p = pinText
                    pinText = ""
                    onSubmit(p)
                }
            },
            enabled = isValid && enabled,
            modifier = Modifier.align(Alignment.End)
        ) {
            Text(buttonText)
        }
    }
}
