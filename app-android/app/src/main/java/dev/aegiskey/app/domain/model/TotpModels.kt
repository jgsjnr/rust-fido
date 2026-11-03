package dev.aegiskey.app.domain.model

data class TotpAccountItem(
    val id: String,
    val issuer: String,
    val accountName: String,
    val currentCode: String,
    val formattedCode: String,
    val remainingSeconds: Int,
    val periodSeconds: Int = 30,
    val digits: Int = 6,
    val requiresTouchToRefresh: Boolean = false,
    val isHotp: Boolean = false,
    val counter: Long = 0L,
    val algorithm: String = "SHA1",
    /**
     * Finding A3: true only when [currentCode] was just returned by the
     * device (OP_OATH_CODE). False (fail-safe default, including all cached
     * items of unknown provenance) means the code was computed locally or is
     * stale: the UI must label it honestly instead of implying device origin.
     */
    val isOnDeviceBacked: Boolean = false
)
