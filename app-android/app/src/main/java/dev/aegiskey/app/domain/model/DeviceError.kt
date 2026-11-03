package dev.aegiskey.app.domain.model

/**
 * Typed device failure that resolves to `strings.xml` (click-through F1).
 *
 * Repositories throw [DeviceError] with a string resource instead of a
 * hardcoded Portuguese literal. ViewModels catch it and expose [resId] so
 * Compose screens render `stringResource(resId)` in the active locale
 * (EN default + values-pt). [detail] carries the device-supplied fragment
 * (e.g. status label) for `%1$s` templates; it is never invented telemetry.
 */
open class DeviceError(
    val resId: Int,
    detail: String? = null,
) : Exception(detail)
