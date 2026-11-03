package dev.aegiskey.app.ui.viewmodel

/**
 * Finding A3: outstanding device User Presence (UP) request.
 *
 * The device denied an op with NEED_UP (0x01): the originating sheet must
 * stay open and show the existing "touch the key" prompt instead of closing
 * or succeeding silently. [op] names the denied operation (e.g. "key-gen",
 * "oath-list", "oath-code", "oath-put") so the UI can resolve localized
 * text; [status] carries the raw wire byte (always 0x01 today).
 */
data class PresenceRequest(
    val op: String,
    val status: Int = 0x01,
)
