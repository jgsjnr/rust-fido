package dev.aegiskey.app

import android.app.Application
import dev.aegiskey.app.ota2.Ota2Keys

/**
 * Application init: wires the offline OTA pubkeys (OTA_HOOK.md).
 *
 * - PROD path (fail-closed): [BuildConfig.OTA_RELEASE_PUBKEY_HEX] carries the
 *   denied all-zeros placeholder until the owner-held release key is
 *   provisioned at signing time; every ota2 verify denies until then.
 * - Lab path (test-only, default-off): [BuildConfig.OTA_LAB_PUBKEY_HEX] is
 *   honored only in debug builds (zeros = off, fail-closed); release builds
 *   clear it. Do NOT invent keys: the lab value comes from the key holder.
 */
class AegisApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        runCatching { Ota2Keys.configureReleaseKey(BuildConfig.OTA_RELEASE_PUBKEY_HEX) }
        if (BuildConfig.DEBUG) {
            runCatching { Ota2Keys.configureLabKey(BuildConfig.OTA_LAB_PUBKEY_HEX) }
        } else {
            Ota2Keys.clearLabKey()
        }
    }
}
