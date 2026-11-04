package dev.aegiskey.app.ui.navigation

/**
 * Single source of truth for in-app navigation routes (click-through F2).
 *
 * The PIV settings card used to be dead: `MainActivity` never passed
 * `onNavigateToPiv` and `NavHost` had no `"piv"` destination. Every route
 * used by [dev.aegiskey.app.AegisApp] / tests lives here so a missing
 * destination fails a unit test instead of silently no-oping on tap.
 */
object AppRoutes {
    const val VAULT = "vault"
    const val CODES = "codes"
    const val KEYS = "keys"
    const val SETTINGS = "settings"
    const val OTA2 = "ota2"
    const val CAPS = "caps"

    /** Smart-card (PIV / certificates) destination. Must exist in NavHost. */
    const val PIV = "piv"

    /** Password vault viewer (F-PM2 blind transport, zero persistence). */
    const val PM = "pm"

    const val ONBOARDING_WIZARD = "onboarding-wizard"

    /** Every destination the NavHost must register. */
    val ALL: Set<String> = setOf(VAULT, CODES, KEYS, SETTINGS, OTA2, CAPS, PIV, PM, ONBOARDING_WIZARD)
}
