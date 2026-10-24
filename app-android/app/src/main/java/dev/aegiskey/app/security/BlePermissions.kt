package dev.aegiskey.app.security

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat

/**
 * Matriz e helpers de permissões BLE (API 31+; minSdk 31 => sem ramos pré-31).
 *
 * - S+ (único caminho real): BLUETOOTH_SCAN (neverForLocation, Manifest) +
 *   BLUETOOTH_CONNECT, pedidas em runtime na tela Pair e no Onboarding.
 * - SCAN com neverForLocation não usa localização; o app nunca deriva posição.
 * - LOCATION (FINE/COARSE): nunca pedida — implicaria uso que o app não faz.
 */
object BlePermissions {
    val REQUIRED: Array<String> = arrayOf(
        Manifest.permission.BLUETOOTH_SCAN,
        Manifest.permission.BLUETOOTH_CONNECT,
    )

    fun requiredFor(sdkInt: Int = Build.VERSION_CODES.S): Array<String> =
        if (sdkInt >= Build.VERSION_CODES.S) REQUIRED else emptyArray()

    fun hasPermissions(context: Context): Boolean =
        REQUIRED.all { perm ->
            ContextCompat.checkSelfPermission(context, perm) == PackageManager.PERMISSION_GRANTED
        }

    fun shouldShowRationale(activity: Activity?): Boolean {
        if (activity == null) return false
        return REQUIRED.any { activity.shouldShowRequestPermissionRationale(it) }
    }

    /** Token fixo p/ log/diagnostico (nomes apenas, sem estado). */
    fun names(): String = "BLUETOOTH_SCAN(neverForLocation)+BLUETOOTH_CONNECT"
}

/**
 * Efeito Composable para solicitar permissões de Bluetooth Runtime no Android 12+ (API 31+).
 * Dispara automaticamente a solicitação do sistema operacional caso ainda não estejam concedidas,
 * chamando [onPermissionsResult] com o resultado da resposta do usuário.
 */
@Composable
fun RequestBlePermissionsEffect(
    onPermissionsResult: (Boolean) -> Unit = {}
) {
    val context = LocalContext.current
    val alreadyGranted = remember(context) { BlePermissions.hasPermissions(context) }

    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { grants ->
        val allGranted = grants.values.all { it }
        onPermissionsResult(allGranted)
    }

    LaunchedEffect(alreadyGranted) {
        if (!alreadyGranted) {
            launcher.launch(BlePermissions.REQUIRED)
        } else {
            onPermissionsResult(true)
        }
    }
}

/**
 * Helper Composable para obter uma ação invocável que pede as permissões de Bluetooth ao usuário.
 */
@Composable
fun rememberBlePermissionLauncher(
    onResult: (Boolean) -> Unit = {}
): () -> Unit {
    val context = LocalContext.current
    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { grants ->
        onResult(grants.values.all { it })
    }

    return {
        if (BlePermissions.hasPermissions(context)) {
            onResult(true)
        } else {
            launcher.launch(BlePermissions.REQUIRED)
        }
    }
}
