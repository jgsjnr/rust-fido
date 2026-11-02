package dev.aegiskey.app

import android.app.Application
import dev.aegiskey.app.ota2.Ota2Keys

/**
 * Application init: wires the offline OTA release pubkey (OTA_HOOK.md line 1).
 * The [BuildConfig.OTA_RELEASE_PUBKEY_HEX] field currently carries the denied
 * all-zeros placeholder (fail-closed): every ota2 verify path denies until a
 * real release key is provisioned. Never ship a nonzero dev key here.
 */
class AegisApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        runCatching { Ota2Keys.configureReleaseKey(BuildConfig.OTA_RELEASE_PUBKEY_HEX) }
    }
}
