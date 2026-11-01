package dev.aegiskey.app.ui.atomic.molecules

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.aegiskey.app.R

/**
 * Responsive masked PIN keypad molecule (4 to 16 digits) with 3-column touch-adaptive keypad.
 * Complies with ASD-STE100 and guarantees uniform width and height (44.dp - 48.dp) on any screen size.
 */
@Composable
fun SecurePinKeypadMolecule(
    label: String = stringResource(R.string.pin_label_default),
    buttonText: String = stringResource(R.string.pin_btn_confirm),
    enabled: Boolean = true,
    errorMessage: String? = null,
    onSubmit: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    var pinText by remember { mutableStateOf("") }
    val isValid = pinText.length in 4..16

    val onAppendDigit: (String) -> Unit = { digit ->
        if (enabled && pinText.length < 16) {
            pinText += digit
        }
    }

    val onBackspace: () -> Unit = {
        if (enabled && pinText.isNotEmpty()) {
            pinText = pinText.dropLast(1)
        }
    }

    val onClear: () -> Unit = {
        if (enabled) {
            pinText = ""
        }
    }

    val handleSubmit: () -> Unit = {
        if (isValid && enabled) {
            val p = pinText
            pinText = ""
            onSubmit(p)
        }
    }

    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedTextField(
            value = pinText,
            onValueChange = {
                if (it.length <= 16 && it.all { ch -> ch.isDigit() }) {
                    pinText = it
                }
            },
            label = { Text(label) },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.NumberPassword,
                imeAction = if (isValid) ImeAction.Done else ImeAction.None,
            ),
            keyboardActions = KeyboardActions(
                onDone = { handleSubmit() },
            ),
            singleLine = true,
            isError = errorMessage != null,
            supportingText = {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = errorMessage ?: stringResource(R.string.pin_min_digits),
                        fontSize = 11.sp,
                        color = if (errorMessage != null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.weight(1f, fill = false),
                    )
                    Text(
                        text = "${pinText.length}/16",
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            },
            enabled = enabled,
            modifier = Modifier.fillMaxWidth(),
        )

        // 3-Column Adaptive Keypad Grid (buttons height: 46.dp, weight: 1f per column)
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            // Row 1: 1, 2, 3
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                KeypadDigitButton(digit = "1", enabled = enabled, onClick = { onAppendDigit("1") }, modifier = Modifier.weight(1f))
                KeypadDigitButton(digit = "2", enabled = enabled, onClick = { onAppendDigit("2") }, modifier = Modifier.weight(1f))
                KeypadDigitButton(digit = "3", enabled = enabled, onClick = { onAppendDigit("3") }, modifier = Modifier.weight(1f))
            }

            // Row 2: 4, 5, 6
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                KeypadDigitButton(digit = "4", enabled = enabled, onClick = { onAppendDigit("4") }, modifier = Modifier.weight(1f))
                KeypadDigitButton(digit = "5", enabled = enabled, onClick = { onAppendDigit("5") }, modifier = Modifier.weight(1f))
                KeypadDigitButton(digit = "6", enabled = enabled, onClick = { onAppendDigit("6") }, modifier = Modifier.weight(1f))
            }

            // Row 3: 7, 8, 9
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                KeypadDigitButton(digit = "7", enabled = enabled, onClick = { onAppendDigit("7") }, modifier = Modifier.weight(1f))
                KeypadDigitButton(digit = "8", enabled = enabled, onClick = { onAppendDigit("8") }, modifier = Modifier.weight(1f))
                KeypadDigitButton(digit = "9", enabled = enabled, onClick = { onAppendDigit("9") }, modifier = Modifier.weight(1f))
            }

            // Row 4: Clear (C), 0, Backspace (⌫)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                FilledTonalButton(
                    onClick = onClear,
                    enabled = enabled && pinText.isNotEmpty(),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier
                        .weight(1f)
                        .height(46.dp),
                ) {
                    Text(
                        text = stringResource(R.string.pin_keypad_clear),
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Bold,
                    )
                }

                KeypadDigitButton(digit = "0", enabled = enabled, onClick = { onAppendDigit("0") }, modifier = Modifier.weight(1f))

                FilledTonalButton(
                    onClick = onBackspace,
                    enabled = enabled && pinText.isNotEmpty(),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier
                        .weight(1f)
                        .height(46.dp),
                ) {
                    Text(
                        text = stringResource(R.string.pin_keypad_backspace),
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Bold,
                    )
                }
            }
        }

        // Action Submit Button
        Button(
            onClick = handleSubmit,
            enabled = isValid && enabled,
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier
                .fillMaxWidth()
                .height(46.dp),
        ) {
            Text(
                text = buttonText,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
        }
    }
}

@Composable
private fun KeypadDigitButton(
    digit: String,
    enabled: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    FilledTonalButton(
        onClick = onClick,
        enabled = enabled,
        shape = RoundedCornerShape(10.dp),
        colors = ButtonDefaults.filledTonalButtonColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.7f),
            contentColor = MaterialTheme.colorScheme.onSurface,
        ),
        modifier = modifier.height(46.dp),
    ) {
        Text(
            text = digit,
            fontSize = 17.sp,
            fontWeight = FontWeight.SemiBold,
        )
    }
}
