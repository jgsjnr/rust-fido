package dev.aegiskey.app.security

import android.Manifest
import android.os.Build

/**
 * Matriz de permissoes BLE (API 31+; minSdk 31 => sem ramos pre-31).
 *
 * - S+ (único caminho real): BLUETOOTH_SCAN (neverForLocation, Manifest) +
 *   BLUETOOTH_CONNECT, pedidas em runtime na tela Pair. SCAN com
 *   neverForLocation nao usa localizacao; o app nunca deriva posicao.
 * - LOCATION (FINE/COARSE): nunca pedida — implicaria uso que o app nao faz.
 * - BLUETOOTH_ADVERTISE: nunca pedida — central only, sem anuncio periferico.
 * - POST_NOTIFICATIONS: nunca pedida — sem foreground service, sem aviso.
 * - NEARBY_WIFI_DEVICES: nunca pedida — WiFi e HttpURLConnection direto ao
 *   IP do AP, sem WifiManager scan.
 *
 * Pura e JVM-testavel ([requiredFor] recebe o SDK; producao usa o default
 * [Build.VERSION.SDK_INT]). Fail-closed: SDK < S (inalcancavel c/ minSdk 31)
 * rende conjunto vazio = negar, nunca liberar.
 */
object BlePermissions {
    val REQUIRED: Array<String> = arrayOf(
        Manifest.permission.BLUETOOTH_SCAN,
        Manifest.permission.BLUETOOTH_CONNECT,
    )

    fun requiredFor(sdkInt: Int = Build.VERSION.SDK_INT): Array<String> =
        if (sdkInt >= Build.VERSION_CODES.S) REQUIRED else emptyArray()

    /** Token fixo p/ log/diagnostico (nomes apenas, sem estado). */
    fun names(): String = "BLUETOOTH_SCAN(neverForLocation)+BLUETOOTH_CONNECT"
}
