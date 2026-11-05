package dev.aegiskey.app.autofill

/**
 * Package/app-scoped ranking of vault candidates for an autofill request.
 *
 * Authority rule: candidates carry device-attested data only (opaque id,
 * released username, and an optional device-disclosed url). Ranking never
 * invents an app↔credential association: when no candidate url matches
 * the requesting package / web domain, order is preserved (device order)
 * and the *user* picks — the framework shows every dataset scoped to the
 * requesting app's fields only, so nothing ever fills cross-app.
 *
 * Today the firmware GET release discloses `{id, username, secret}` (no
 * label/url), so [VaultCandidate.url] is normally null and every entry is
 * offered for user choice. The url hook exists for a future
 * device-disclosed url without changing this contract.
 */
object AutofillMatcher {

    /** One punctual release, transient (caller wipes after dataset build). */
    data class VaultCandidate(
        val id: ByteArray,
        val username: String,
        val url: String? = null,
    )

    /**
     * Stable rank: url host matching [webDomain] (www-tolerant) or the
     * requesting [packageName] first; everything else keeps device order.
     * Never drops candidates.
     */
    fun rank(
        candidates: List<VaultCandidate>,
        packageName: String,
        webDomain: String? = null,
    ): List<VaultCandidate> {
        if (candidates.isEmpty()) return candidates
        val pkg = packageName.lowercase()
        val domain = webDomain?.lowercase()?.removePrefix("www.")?.takeIf { it.isNotBlank() }
        return candidates.sortedByDescending { score(it, pkg, domain) }
            .let { ranked ->
                // sortedByDescending is stable: ties keep device order.
                ranked
            }
    }

    private fun score(c: VaultCandidate, pkg: String, domain: String?): Int {
        val host = c.url?.let(::hostOf) ?: return 0
        if (domain != null && (host == domain || host == "www.$domain")) return 2
        if (host == pkg) return 2
        if (pkg.contains(host) || host.contains(pkg.substringAfterLast('.'))) return 1
        return 0
    }

    /** Lowercases, strips scheme/userinfo/port/path; never throws. */
    fun hostOf(rawUrl: String): String {
        var s = rawUrl.trim().lowercase()
        s = s.substringAfter("://", s)
        s = s.substringBefore('/')
        s = s.substringBefore('?')
        if ('@' in s) s = s.substringAfterLast('@')
        s = s.substringBefore(':')
        return s.removePrefix("www.")
    }
}
