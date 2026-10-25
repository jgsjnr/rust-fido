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
    val algorithm: String = "SHA1"
)
