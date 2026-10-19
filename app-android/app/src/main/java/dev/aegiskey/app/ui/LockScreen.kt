package dev.aegiskey.app.ui

import android.app.Activity
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.security.AppLock
import dev.aegiskey.app.security.BiometricGate
import dev.aegiskey.app.security.MIN_APP_PASSWORD_LEN

/**
 * Wave7 app lock gate (behind FeatureFlags.ENABLE_APP_LOCK, default OFF).
 * First run enrolls the password (bridge PBKDF2 verifier + salt stored
 * encrypted); later runs verify. The biometric button appears only when
 * BiometricGate has a real CryptoObject (stub today, so hidden).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LockScreen(appLock: AppLock, onUnlocked: () -> Unit) {
    val context = LocalContext.current
    val enrolled = remember { appLock.isEnrolled() }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    val biometricReady = remember { BiometricGate.available(context) }

    fun submit() {
        error = null
        try {
            if (!enrolled) {
                require(password.length >= MIN_APP_PASSWORD_LEN) { "password too short" }
                require(password == confirm) { "passwords do not match" }
                appLock.enroll(password.toCharArray())
                onUnlocked()
            } else {
                if (appLock.verify(password.toCharArray())) {
                    onUnlocked()
                } else {
                    error = "wrong password"
                }
            }
        } catch (e: Exception) {
            error = (e.message ?: "lock failed").take(48)
        } finally {
            password = ""
            confirm = ""
        }
    }

    Scaffold(topBar = { TopAppBar(title = { Text(if (enrolled) "Unlock" else "Set lock password") }) }) { inner ->
        Column(
            Modifier.padding(inner).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text(if (enrolled) "Password" else "New password (min $MIN_APP_PASSWORD_LEN)") },
                visualTransformation = PasswordVisualTransformation()
            )
            if (!enrolled) {
                OutlinedTextField(
                    value = confirm,
                    onValueChange = { confirm = it },
                    label = { Text("Confirm password") },
                    visualTransformation = PasswordVisualTransformation()
                )
            }
            Button(onClick = ::submit, enabled = password.isNotEmpty()) {
                Text(if (enrolled) "Unlock" else "Set password")
            }
            if (biometricReady) {
                val activity = context as? Activity
                OutlinedButton(
                    onClick = {
                        val crypto = BiometricGate.stubCryptoObject() ?: return@OutlinedButton
                        if (activity == null) return@OutlinedButton
                        BiometricGate.authenticate(activity, crypto) { result ->
                            if (result is BiometricGate.Result.Success) onUnlocked()
                        }
                    }
                ) { Text("Unlock with biometrics") }
            }
            error?.let { Text("Error: $it", color = MaterialTheme.colorScheme.error) }
            Text(
                "Local gate only: device auth (UP + PIN) still happens on the authenticator.",
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}
