package dev.aegiskey.app

import dev.aegiskey.app.autofill.AutofillGate
import dev.aegiskey.app.autofill.AutofillMatcher
import dev.aegiskey.app.autofill.AutofillParser
import dev.aegiskey.app.autofill.AutofillPrefs
import dev.aegiskey.app.autofill.AutofillSecrets
import dev.aegiskey.app.pm.PmCbor
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Host-only autofill tests (no hardware, no framework):
 * - parse: username+password pair located in traversal order;
 * - match: package/web-domain ranking over authority candidates only;
 * - fail-closed: gate denies without switch or without session;
 * - wipe: transient releases and working copies zeroize after fill.
 */
class AutofillServiceTest {

    private fun textField(
        index: Int,
        hints: Set<String> = emptySet(),
        inputType: Int = AutofillParser.TYPE_CLASS_TEXT,
        hint: String? = null,
        focused: Boolean = false,
    ) = AutofillParser.InputField(
        index = index,
        hints = hints,
        inputType = inputType,
        hint = hint,
        focused = focused,
    )

    private fun passwordType(): Int =
        AutofillParser.TYPE_CLASS_TEXT or AutofillParser.TYPE_TEXT_VARIATION_PASSWORD

    // --- parse ---

    @Test
    fun parse_locates_username_before_password() {
        val fields = listOf(
            textField(0, hint = "Email"),
            textField(1, inputType = passwordType()),
            textField(2, hint = "Notes"),
        )
        val form = AutofillParser.parse(fields)
        assertNotNull(form)
        assertEquals(0, form!!.usernameIndex)
        assertEquals(1, form.passwordIndex)
        assertTrue(form.hasUsername)
    }

    @Test
    fun parse_prefers_hinted_username_over_plain_text() {
        val fields = listOf(
            textField(0, hint = "Search"),
            textField(1, hints = setOf(AutofillParser.HINT_USERNAME)),
            textField(2, inputType = passwordType()),
        )
        val form = AutofillParser.parse(fields)
        assertNotNull(form)
        assertEquals(1, form!!.usernameIndex)
        assertEquals(2, form.passwordIndex)
    }

    @Test
    fun parse_password_only_form_has_no_username() {
        val fields = listOf(textField(0, inputType = passwordType()))
        val form = AutofillParser.parse(fields)
        assertNotNull(form)
        assertFalse(form!!.hasUsername)
        assertEquals(0, form.passwordIndex)
    }

    @Test
    fun parse_returns_null_without_password_field() {
        val fields = listOf(
            textField(0, hint = "Username"),
            textField(1, hint = "Notes"),
        )
        assertNull(AutofillParser.parse(fields))
        assertNull(AutofillParser.parse(emptyList()))
    }

    @Test
    fun parse_detects_hinted_password_without_input_type() {
        val fields = listOf(
            textField(0, hints = setOf(AutofillParser.HINT_USERNAME)),
            textField(1, hints = setOf(AutofillParser.HINT_PASSWORD)),
        )
        val form = AutofillParser.parse(fields)
        assertNotNull(form)
        assertEquals(1, form!!.passwordIndex)
        assertTrue(form.hasUsername)
    }

    // --- match ---

    @Test
    fun match_ranks_web_domain_first_and_keeps_rest() {
        val a = AutofillMatcher.VaultCandidate(ByteArray(4) { 0x01 }, "alice", "https://bank.example/login")
        val b = AutofillMatcher.VaultCandidate(ByteArray(4) { 0x02 }, "bob", null)
        val c = AutofillMatcher.VaultCandidate(ByteArray(4) { 0x03 }, "carol", "https://other.example")
        val ranked = AutofillMatcher.rank(listOf(b, c, a), "com.example.app", "bank.example")
        assertEquals("alice", ranked[0].username)
        // Ties keep device order.
        assertEquals(listOf("alice", "bob", "carol"), ranked.map { it.username })
    }

    @Test
    fun match_all_null_urls_preserves_device_order() {
        val candidates = listOf(
            AutofillMatcher.VaultCandidate(ByteArray(4) { 0x01 }, "alice", null),
            AutofillMatcher.VaultCandidate(ByteArray(4) { 0x02 }, "bob", null),
        )
        val ranked = AutofillMatcher.rank(candidates, "com.any.app", null)
        assertEquals(listOf("alice", "bob"), ranked.map { it.username })
    }

    @Test
    fun match_never_drops_candidates() {
        val candidates = listOf(
            AutofillMatcher.VaultCandidate(ByteArray(4) { 0x01 }, "alice", "https://unrelated.example"),
        )
        val ranked = AutofillMatcher.rank(candidates, "com.other.app", "other.domain")
        assertEquals(1, ranked.size)
        assertEquals("alice", ranked[0].username)
    }

    @Test
    fun hostOf_strips_scheme_www_port_and_path() {
        assertEquals("bank.example", AutofillMatcher.hostOf("https://www.bank.example/login?q=1"))
        assertEquals("bank.example", AutofillMatcher.hostOf("bank.example:8443/a"))
        assertEquals("com.example.app", AutofillMatcher.hostOf("com.example.app"))
    }

    // --- fail-closed gate ---

    @Test
    fun gate_denies_without_switch_or_session() {
        assertFalse(AutofillGate.canFill(autofillEnabled = false, sessionUnlocked = true))
        assertFalse(AutofillGate.canFill(autofillEnabled = true, sessionUnlocked = false))
        assertFalse(AutofillGate.canFill(autofillEnabled = false, sessionUnlocked = false))
        assertTrue(AutofillGate.canFill(autofillEnabled = true, sessionUnlocked = true))
    }

    @Test
    fun prefs_default_is_off_fail_closed() {
        assertFalse(AutofillPrefs.DEFAULT_ENABLED)
    }

    @Test
    fun gate_reports_locked_when_no_session_pin() {
        // Host JVM: no Android session exists, probe must read locked.
        assertFalse(AutofillGate.isSessionUnlocked())
    }

    // --- wipe after fill ---

    @Test
    fun release_wipes_after_fill() {
        val rel = PmCbor.PmRelease(
            id = ByteArray(16) { 0x0A },
            username = "alice",
            secret = ByteArray(24) { 0x5A },
        )
        // Simulate dataset build consuming the release, then wipe.
        assertTrue(rel.secret.any { it != 0.toByte() })
        rel.wipe()
        assertTrue(rel.secret.all { it == 0.toByte() })
        assertTrue(rel.id.all { it == 0.toByte() })
    }

    @Test
    fun working_copies_wipe_after_fill() {
        val secret = ByteArray(16) { 0x3C }
        val chars = charArrayOf('s', '3', 'c', 'r', 'e', 't')
        AutofillSecrets.wipe(secret)
        AutofillSecrets.wipe(chars)
        assertTrue(AutofillSecrets.isWiped(secret))
        assertTrue(AutofillSecrets.isWiped(chars))
    }
}
