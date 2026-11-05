package dev.aegiskey.app.domain.usecase

import dev.aegiskey.app.domain.repository.PasswordManagerRepository
import dev.aegiskey.app.pm.PmCbor

/** Pages over opaque device record ids (blind transport, no labels). */
class GetPmListUseCase(private val repo: PasswordManagerRepository) {
    suspend operator fun invoke(cursor: Long = 0L, limit: Int = PmCbor.PM_LIST_DEFAULT_LIMIT) =
        repo.listPage(cursor, limit)
}

/** Fetches the punctual gated release (transient: display + zeroize). */
class GetPmReleaseUseCase(private val repo: PasswordManagerRepository) {
    suspend operator fun invoke(id: ByteArray) = repo.getRelease(id)
}

/** Entry-count / quota telemetry (no secrets). */
class GetPmStatusUseCase(private val repo: PasswordManagerRepository) {
    suspend operator fun invoke() = repo.getStatus()
}

/** Stores (or replaces) one login record on the device (`0x43`). */
class PutPmEntryUseCase(private val repo: PasswordManagerRepository) {
    suspend operator fun invoke(
        label: String,
        username: String,
        secret: ByteArray,
        url: String? = null,
    ) = repo.putEntry(label, username, secret, url)
}

/** Removes one record by opaque id (`0x46`, scoped per-item delete). */
class DeletePmEntryUseCase(private val repo: PasswordManagerRepository) {
    suspend operator fun invoke(id: ByteArray) = repo.deleteEntry(id)
}
