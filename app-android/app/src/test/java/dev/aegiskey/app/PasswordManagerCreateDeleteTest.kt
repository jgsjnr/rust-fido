package dev.aegiskey.app

import dev.aegiskey.app.data.cbor.SecureGuardCbor
import dev.aegiskey.app.domain.repository.PasswordManagerRepository
import dev.aegiskey.app.domain.repository.PmGateError
import dev.aegiskey.app.domain.repository.PmListResult
import dev.aegiskey.app.domain.usecase.DeletePmEntryUseCase
import dev.aegiskey.app.domain.usecase.GetPmListUseCase
import dev.aegiskey.app.domain.usecase.GetPmReleaseUseCase
import dev.aegiskey.app.domain.usecase.GetPmStatusUseCase
import dev.aegiskey.app.domain.usecase.PutPmEntryUseCase
import dev.aegiskey.app.pm.PmCbor
import dev.aegiskey.app.ui.viewmodel.PasswordManagerViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * Host-only create/delete tests (F-PM1 wiring on the F-PM2 viewer).
 *
 * No hardware, no persistence: the fake repository below is plain RAM,
 * opcodes/frames follow [PmCbor] (PUT `0x43`, DELETE `0x46`), and secrets
 * only ever appear as opaque fixtures that are wiped after each test.
 * Covers: put codec round-trip + fail-closed caps, delete codec, the
 * create→list→delete flow through the use-cases, fail-closed invalid
 * input (never reaches the transport), and ViewModel state updates.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class PasswordManagerCreateDeleteTest {

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    /** In-RAM fake: deterministic opaque ids, transport-call accounting. */
    private class FakePasswordManagerRepository : PasswordManagerRepository {
        private data class Record(
            val id: ByteArray,
            val label: String,
            val username: String,
            val secret: ByteArray,
            val url: String?,
        )

        private val records = LinkedHashMap<String, Record>()
        var transportCalls = 0
        private var nextId = 1

        private fun denied() = PmGateError(
            PmGateError.Kind.DENIED, 0x04, "Denied",
            "Password vault denied: Denied",
        )

        override suspend fun listPage(cursor: Long, limit: Int): Result<PmListResult> {
            transportCalls++
            val page = PmCbor.PmPage(records.values.map { it.id.copyOf() }, 0L, false)
            return Result.success(PmListResult(page, 0))
        }

        override suspend fun getRelease(id: ByteArray): Result<PmCbor.PmRelease> {
            transportCalls++
            val rec = records[PmCbor.opaqueIdHex(id)] ?: return Result.failure(denied())
            return Result.success(PmCbor.PmRelease(rec.id.copyOf(), rec.username, rec.secret.copyOf()))
        }

        override suspend fun getStatus(): Result<PmCbor.PmStatus> {
            transportCalls++
            return Result.success(PmCbor.PmStatus(records.size.toLong(), 50L))
        }

        override suspend fun putEntry(
            label: String,
            username: String,
            secret: ByteArray,
            url: String?,
        ): Result<Unit> = runCatching {
            // Fail-closed edge first: invalid input throws before any
            // transport byte (mirrors PasswordManagerRepositoryImpl).
            PmCbor.encodePutRequest(label, username, secret, url).fill(0)
            transportCalls++
            val id = ByteArray(16).also { it[15] = (nextId++).toByte() }
            records[PmCbor.opaqueIdHex(id)] = Record(id, label, username, secret.copyOf(), url)
        }

        override suspend fun deleteEntry(id: ByteArray): Result<Unit> = runCatching {
            PmCbor.encodeDeleteRequest(id.copyOf())
            transportCalls++
            val hex = PmCbor.opaqueIdHex(id)
            if (!records.containsKey(hex)) throw denied()
            records.remove(hex)
        }
    }

    private fun viewModelOf(fake: FakePasswordManagerRepository) = PasswordManagerViewModel(
        getList = GetPmListUseCase(fake),
        getRelease = GetPmReleaseUseCase(fake),
        getStatus = GetPmStatusUseCase(fake),
        putUseCase = PutPmEntryUseCase(fake),
        deleteUseCase = DeletePmEntryUseCase(fake),
    )

    @Test
    fun put_codec_roundtrip_with_and_without_url() {
        val noUrl = PmCbor.PmPutBody("bank", "alice", ByteArray(24) { 0x5A }, null)
        val noUrlBytes = PmCbor.encodePutRequest(noUrl.label, noUrl.username, noUrl.secret, noUrl.url)
        val decodedNoUrl = PmCbor.decodePutRequest(noUrlBytes)
        assertEquals("bank", decodedNoUrl.label)
        assertEquals("alice", decodedNoUrl.username)
        assertTrue(decodedNoUrl.secret.contentEquals(noUrl.secret))
        assertEquals(null, decodedNoUrl.url)
        decodedNoUrl.wipe()
        assertTrue(decodedNoUrl.secret.all { it == 0.toByte() })

        val withUrl = PmCbor.PmPutBody("mail", "bob", ByteArray(16) { 0x0B }, "https://m.example")
        val withUrlBytes = PmCbor.encodePutRequest(withUrl.label, withUrl.username, withUrl.secret, withUrl.url)
        val decodedWithUrl = PmCbor.decodePutRequest(withUrlBytes)
        assertEquals(withUrl.label, decodedWithUrl.label)
        assertEquals(withUrl.username, decodedWithUrl.username)
        assertTrue(decodedWithUrl.secret.contentEquals(withUrl.secret))
        assertEquals(withUrl.url, decodedWithUrl.url)
    }

    @Test
    fun put_codec_rejects_empty_secret_and_overcaps_fail_closed() {
        val okSecret = ByteArray(8) { 0x01 }
        try {
            PmCbor.encodePutRequest("bank", "alice", ByteArray(0))
            fail("empty secret must fail closed")
        } catch (_: IllegalArgumentException) {
        }
        try {
            PmCbor.encodePutRequest("bank", "alice", ByteArray(PmCbor.PM_SECRET_MAX_BYTES + 1) { 0x01 })
            fail("oversize secret must fail closed")
        } catch (_: IllegalArgumentException) {
        }
        try {
            PmCbor.encodePutRequest("l".repeat(PmCbor.PM_LABEL_MAX_BYTES + 1), "alice", okSecret)
            fail("oversize label must fail closed")
        } catch (_: IllegalArgumentException) {
        }
        try {
            PmCbor.encodePutRequest("bank", "u".repeat(PmCbor.PM_USERNAME_MAX_BYTES + 1), okSecret)
            fail("oversize username must fail closed")
        } catch (_: IllegalArgumentException) {
        }
        try {
            PmCbor.encodePutRequest("bank", "alice", okSecret, "u".repeat(PmCbor.PM_URL_MAX_BYTES + 1))
            fail("oversize url must fail closed")
        } catch (_: IllegalArgumentException) {
        }
        // Caps are byte-based (UTF-8), not char-based.
        try {
            PmCbor.encodePutRequest("é".repeat(65), "alice", okSecret)
            fail("multibyte label over the byte cap must fail closed")
        } catch (_: IllegalArgumentException) {
        }
        try {
            PmCbor.decodePutRequest(ByteArray(4) { 0x00 })
            fail("junk put body must fail closed")
        } catch (_: Exception) {
        }
    }

    @Test
    fun delete_codec_roundtrip_and_rejects_fail_closed() {
        val id = ByteArray(16) { 0x0C }
        val body = PmCbor.encodeDeleteRequest(id)
        val decoded = SecureGuardCbor.decode(body)
        assertTrue("delete body must decode to a map", decoded is Map<*, *>)
        val idBytes = (decoded as Map<*, *>)["id"] as? ByteArray
        assertTrue(idBytes != null && idBytes.contentEquals(id))
        try {
            PmCbor.encodeDeleteRequest(ByteArray(0))
            fail("empty id must fail closed")
        } catch (_: IllegalArgumentException) {
        }
        try {
            PmCbor.encodeDeleteRequest(ByteArray(PmCbor.PM_ID_MAX_BYTES + 1) { 0x01 })
            fail("oversize id must fail closed")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun create_list_delete_flow_through_use_cases() = runTest(testDispatcher) {
        val fake = FakePasswordManagerRepository()
        val put = PutPmEntryUseCase(fake)
        val list = GetPmListUseCase(fake)
        val release = GetPmReleaseUseCase(fake)
        val delete = DeletePmEntryUseCase(fake)

        // Create (PUT 0x43 edge).
        val secret = ByteArray(24) { 0x5A }
        assertTrue(put("bank", "alice", secret).isSuccess)

        // List shows the new opaque id (no labels cross the edge).
        val page = list(0L, PmCbor.PM_LIST_DEFAULT_LIMIT).getOrThrow().page
        assertEquals(1, page.ids.size)
        val id = page.ids.single()

        // Release discloses the punctual fields (transient: wipe after use).
        val rel = release(id).getOrThrow()
        assertEquals("alice", rel.username)
        assertTrue(rel.secret.contentEquals(secret))
        rel.wipe()

        // Scoped per-item delete (0x46): only this record goes.
        assertTrue(delete(id).isSuccess)
        assertTrue(list(0L, PmCbor.PM_LIST_DEFAULT_LIMIT).getOrThrow().page.ids.isEmpty())

        // Deleting again fails closed (unknown id, no silent success).
        assertTrue(delete(id).isFailure)
    }

    @Test
    fun put_invalid_never_reaches_transport() = runTest(testDispatcher) {
        val fake = FakePasswordManagerRepository()
        val put = PutPmEntryUseCase(fake)
        val before = fake.transportCalls
        // Empty secret is structurally invalid: the encode edge throws
        // before any transport byte (fail-closed, SDK parity).
        assertTrue(put("bank", "alice", ByteArray(0)).isFailure)
        assertEquals("invalid input must not emit transport bytes", before, fake.transportCalls)
    }

    @Test
    fun viewModel_create_list_delete_updates_state() = runTest(testDispatcher) {
        val fake = FakePasswordManagerRepository()
        val vm = viewModelOf(fake)
        testScheduler.advanceUntilIdle()
        assertTrue(vm.uiState.value.ids.isEmpty())
        assertEquals(0L, vm.uiState.value.entryCount)

        // Create → list refreshes, nonce ticks, census follows device data.
        vm.putEntry("bank", "alice", ByteArray(24) { 0x5A })
        testScheduler.advanceUntilIdle()
        assertEquals(1, vm.uiState.value.ids.size)
        assertEquals(1L, vm.uiState.value.putOkNonce)
        assertEquals(1L, vm.uiState.value.entryCount)
        assertEquals(50L, vm.uiState.value.maxEntries)

        // Blank service never reaches the transport (fail-closed at the edge).
        val callsBefore = fake.transportCalls
        val nonceBefore = vm.uiState.value.putOkNonce
        vm.putEntry("  ", "alice", ByteArray(8) { 0x01 })
        testScheduler.advanceUntilIdle()
        assertEquals(callsBefore, fake.transportCalls)
        assertEquals(nonceBefore, vm.uiState.value.putOkNonce)

        // Scoped delete → list refreshes, nonce ticks.
        vm.deleteEntry(vm.uiState.value.ids.single())
        testScheduler.advanceUntilIdle()
        assertTrue(vm.uiState.value.ids.isEmpty())
        assertEquals(1L, vm.uiState.value.deleteOkNonce)
        assertEquals(0L, vm.uiState.value.entryCount)
    }
}
