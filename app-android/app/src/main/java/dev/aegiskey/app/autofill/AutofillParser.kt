package dev.aegiskey.app.autofill

/**
 * Pure login-form locator for the Android Autofill Framework path.
 *
 * The service walks an [android.app.assist.AssistStructure] and flattens
 * every fillable node into an [InputField] (framework-free: the adapter in
 * [AegisAutofillService] maps real `ViewNode`s to these). [parse] then
 * locates the username + password pair to fill.
 *
 * Authority rule: this object only locates *fields*. Values always come
 * from punctual PM-vault releases (device-attested username + secret);
 * nothing here invents telemetry, state, labels, or prose.
 *
 * Fail-closed: no password-class field -> null (the service answers the
 * framework with a null response, never a guess).
 */
object AutofillParser {

    // Framework value mirrors (android.view.View / android.text.InputType).
    // Literals on purpose: this file must stay free of android imports so
    // host-side unit tests can exercise it on the JVM.
    const val HINT_USERNAME = "username"
    const val HINT_PASSWORD = "password"
    const val HINT_EMAIL = "emailAddress"

    const val TYPE_MASK_CLASS = 0x0000000f
    const val TYPE_MASK_VARIATION = 0x00000ff0
    const val TYPE_CLASS_TEXT = 0x00000001
    const val TYPE_CLASS_NUMBER = 0x00000002
    const val TYPE_TEXT_VARIATION_PASSWORD = 0x00000080
    const val TYPE_TEXT_VARIATION_VISIBLE_PASSWORD = 0x00000090
    const val TYPE_TEXT_VARIATION_WEB_PASSWORD = 0x00000070
    const val TYPE_NUMBER_VARIATION_PASSWORD = 0x00000010

    /**
     * One fillable node, flattened in AssistStructure traversal order.
     * [index] is the adapter position; the service maps it back to the
     * framework `AutofillId`.
     */
    data class InputField(
        val index: Int,
        val hints: Set<String> = emptySet(),
        val inputType: Int = 0,
        val hint: String? = null,
        val focused: Boolean = false,
    )

    /** Located login pair. [usernameIndex] may be null (password-only form). */
    data class ParsedForm(
        val usernameIndex: Int,
        val passwordIndex: Int,
        val hasUsername: Boolean,
    )

    private fun isPasswordField(f: InputField): Boolean {
        if (HINT_PASSWORD in f.hints) return true
        val cls = f.inputType and TYPE_MASK_CLASS
        val variation = f.inputType and TYPE_MASK_VARIATION
        return (cls == TYPE_CLASS_TEXT && variation in setOf(
            TYPE_TEXT_VARIATION_PASSWORD,
            TYPE_TEXT_VARIATION_VISIBLE_PASSWORD,
            TYPE_TEXT_VARIATION_WEB_PASSWORD,
        )) || (cls == TYPE_CLASS_NUMBER && variation == TYPE_NUMBER_VARIATION_PASSWORD)
    }

    private fun looksLikeUsername(f: InputField): Boolean {
        if (HINT_USERNAME in f.hints || HINT_EMAIL in f.hints) return true
        val text = ((f.hint ?: "") + " " + f.hints.joinToString(" ")).lowercase()
        return text.contains("user") ||
            text.contains("email") ||
            text.contains("login") ||
            text.contains("usuár") ||
            text.contains("usuar")
    }

    /**
     * Locates the login pair. Deterministic: first password-class field
     * wins (a focused one wins ties); username is the nearest
     * username-like field before it, else the nearest text field before
     * it. Returns null when no password field exists.
     */
    fun parse(fields: List<InputField>): ParsedForm? {
        val passwords = fields.filter(::isPasswordField)
        if (passwords.isEmpty()) return null
        val password = passwords.firstOrNull { it.focused } ?: passwords.first()
        val before = fields.filter { it.index < password.index && !isPasswordField(it) }
        val username = before.lastOrNull(::looksLikeUsername)
            ?: before.lastOrNull()
        return ParsedForm(
            usernameIndex = username?.index ?: password.index,
            passwordIndex = password.index,
            hasUsername = username != null,
        )
    }
}
