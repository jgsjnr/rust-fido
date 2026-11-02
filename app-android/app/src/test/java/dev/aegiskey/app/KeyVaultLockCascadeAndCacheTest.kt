package dev.aegiskey.app

import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.repository.ConnectedKeysRepositoryImpl
import dev.aegiskey.app.data.repository.KeyVaultRepositoryImpl
import dev.aegiskey.app.data.repository.SecureGuardRepositoryImpl
import dev.aegiskey.app.data.transport.HostUsbUartBridgeClient
import dev.aegiskey.app.data.transport.SimulatedRenodeTransport
import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.SecureGuardPolicy
import dev.aegiskey.app.domain.model.SecureGuardStateEnum
import dev.aegiskey.app.domain.model.SecureGuardStatus
import dev.aegiskey.app.domain.model.VaultKeyEntry
import dev.aegiskey.app.domain.repository.SecureGuardRepository
import dev.aegiskey.app.usb.UsbCtaphid
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class KeyVaultLockCascadeAndCacheTest {

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        dev.aegiskey.app.data.debug.DebugHardwareChipMock.IS_MOCK_ENABLED = false
        SecureGuardRepositoryImpl.clearSessionPin()
    }

    @After
    fun tearDown() {
        dev.aegiskey.app.data.debug.DebugHardwareChipMock.IS_MOCK_ENABLED = false
        SecureGuardRepositoryImpl.clearSessionPin()
        Dispatchers.resetMain()
    }

    @Test
    fun encryptedKeysStore_envelopeSeal_roundtrip_with_hardwareBinding() {
        val store = EncryptedKeysStore(null)
        val keyId = "test-key-01"
        val bindingId = "AEGIS_HW_BINDING_ABC123"

        val entry = VaultKeyEntry(
            slotId = 0,
            label = "GitHub Passkey",
            type = AccessKeyType.PASSKEY_FIDO,
            publicSummary = "Secured on slot 0",
            createdAtEpochMs = 123456789L,
            algorithmOrCurve = "ES256 (P-256)",
            usageDescription = "WebAuthn",
            derivationPathOrSlotCode = "fido2/0",
            envelopeHex = "4145474E",
            requiresPhysicalTouch = true
        )

        // Salva com hardware binding
        store.saveVaultEntries(keyId, listOf(entry), bindingId)

        // Carrega com o mesmo hardware binding -> sucesso
        val loaded = store.loadVaultEntries(keyId, bindingId)
        assertEquals(1, loaded.size)
        assertEquals("GitHub Passkey", loaded[0].label)
        assertEquals(AccessKeyType.PASSKEY_FIDO, loaded[0].type)

        // Carrega com hardware binding incorreto -> falha fechada, retorna lista vazia
        val wrongBinding = store.loadVaultEntries(keyId, "INCORRECT_BINDING_XYZ")
        assertTrue("Deve falhar fechado com binding incorreto", wrongBinding.isEmpty())
    }

    @Test
    fun encryptedKeysStore_backwardCompatibility_with_plainJson() {
        val store = EncryptedKeysStore(null)
        val keyId = "test-legacy-key"

        val entry = VaultKeyEntry(
            slotId = 1,
            label = "Legacy BTC Wallet",
            type = AccessKeyType.CRYPTO_WALLET_BTC,
            publicSummary = "bc1qtest123",
            createdAtEpochMs = 111111111L
        )

        // Salva sem hardware binding (fallback compatível)
        store.saveVaultEntries(keyId, listOf(entry), null)

        val loaded = store.loadVaultEntries(keyId, null)
        assertEquals(1, loaded.size)
        assertEquals("Legacy BTC Wallet", loaded[0].label)
        assertEquals(AccessKeyType.CRYPTO_WALLET_BTC, loaded[0].type)
    }

    private class MockSecureGuardRepository(
        initialStatus: SecureGuardStatus = SecureGuardStatus(
            state = SecureGuardStateEnum.LOCKED,
            isUnlocked = false
        )
    ) : SecureGuardRepository {
        val _flow = MutableStateFlow(initialStatus)
        override val statusFlow: StateFlow<SecureGuardStatus> = _flow

        override suspend fun getStatus() = Result.success(_flow.value)
        override suspend fun provision(pin: String, recoveryCode: String?, policy: SecureGuardPolicy?) = Result.success("RC")
        override suspend fun unlock(pin: String): Result<SecureGuardStatus> {
            SecureGuardRepositoryImpl.lastVerifiedSessionPin = pin
            val unlocked = _flow.value.copy(
                state = SecureGuardStateEnum.UNLOCKED,
                isUnlocked = true,
                sessionRemainingMs = 300_000L
            )
            _flow.value = unlocked
            return Result.success(unlocked)
        }
        override suspend fun lock(): Result<Unit> {
            SecureGuardRepositoryImpl.lastVerifiedSessionPin = null
            _flow.value = _flow.value.copy(
                state = SecureGuardStateEnum.LOCKED,
                isUnlocked = false,
                sessionRemainingMs = 0L
            )
            return Result.success(Unit)
        }
        override suspend fun changePin(currentPin: String, newPin: String) = Result.success(Unit)
        override suspend fun recover(recoveryCode: String, newPin: String) = Result.success(null)
        override suspend fun updatePolicy(policy: SecureGuardPolicy) = Result.success(policy)
        override suspend fun wipeSelective(scope: Int, confirmationToken: String) = Result.success(false)
        override fun onHardwareDetached() {
            SecureGuardRepositoryImpl.lastVerifiedSessionPin = null
            _flow.value = _flow.value.copy(
                state = SecureGuardStateEnum.LOCKED,
                isUnlocked = false,
                sessionRemainingMs = 0L
            )
        }
    }

    @Test
    fun keyVaultRepository_memory_empty_when_secureGuard_locked() = runTest(testDispatcher) {
        val store = EncryptedKeysStore(null)
        val keyId = "device-key-1"
        val bindingId = "BINDING-1"

        val entry = VaultKeyEntry(
            slotId = 0,
            label = "Passkey Google",
            type = AccessKeyType.PASSKEY_FIDO,
            publicSummary = "Google passkey",
            createdAtEpochMs = 12345L
        )
        store.saveVaultEntries(keyId, listOf(entry), bindingId)

        val connectedKeysRepo = ConnectedKeysRepositoryImpl(store, null, null)
        val dev = ConnectedKeyDevice(
            id = keyId,
            displayName = "AegisKey Dev",
            hardwareAddressOrId = "usb:1",
            bindingIdHex = bindingId,
            transportType = ConnectionTransportType.USB,
            isCurrentlyConnected = true
        )
        connectedKeysRepo.addOrUpdateKey(dev)

        val sgRepo = MockSecureGuardRepository(
            SecureGuardStatus(state = SecureGuardStateEnum.LOCKED, isUnlocked = false)
        )

        val standaloneScope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val vaultRepo = KeyVaultRepositoryImpl(
            keysStore = store,
            usbKeyTransport = null,
            bleKeyTransport = null,
            simulatedRenodeTransport = SimulatedRenodeTransport(),
            connectedKeysRepository = connectedKeysRepo,
            secureGuardRepository = sgRepo,
            scope = standaloneScope
        )

        // Enquanto o Secure Guard estiver bloqueado, as chaves NÃO devem estar em memória
        assertTrue("Chaves em memória devem estar vazias enquanto bloqueado", vaultRepo.vaultEntries.value.isEmpty())
    }

    @Test
    fun keyVaultRepository_unlock_loads_cache_and_lock_wipes_memory() = runTest(testDispatcher) {
        val store = EncryptedKeysStore(null)
        val keyId = "device-key-2"
        val bindingId = "BINDING-2"

        val entry = VaultKeyEntry(
            slotId = 0,
            label = "AWS Root Key",
            type = AccessKeyType.PASSKEY_FIDO,
            publicSummary = "AWS key",
            createdAtEpochMs = 12345L
        )
        store.saveVaultEntries(keyId, listOf(entry), bindingId)

        val connectedKeysRepo = ConnectedKeysRepositoryImpl(store, null, null)
        val dev = ConnectedKeyDevice(
            id = keyId,
            displayName = "AegisKey Pro",
            hardwareAddressOrId = "usb:2",
            bindingIdHex = bindingId,
            transportType = ConnectionTransportType.USB,
            isCurrentlyConnected = true
        )
        connectedKeysRepo.addOrUpdateKey(dev)

        val sgRepo = MockSecureGuardRepository(
            SecureGuardStatus(state = SecureGuardStateEnum.LOCKED, isUnlocked = false)
        )

        val standaloneScope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val vaultRepo = KeyVaultRepositoryImpl(
            keysStore = store,
            usbKeyTransport = null,
            bleKeyTransport = null,
            simulatedRenodeTransport = SimulatedRenodeTransport(),
            connectedKeysRepository = connectedKeysRepo,
            secureGuardRepository = sgRepo,
            scope = standaloneScope
        )

        assertTrue("Inicialmente bloqueado e vazio", vaultRepo.vaultEntries.value.isEmpty())

        // 1. Desbloqueia com PIN
        sgRepo.unlock("1234")

        assertEquals("Após desbloqueio, deve carregar chaves do cache selado", 1, vaultRepo.vaultEntries.value.size)
        assertEquals("AWS Root Key", vaultRepo.vaultEntries.value[0].label)

        // 2. Bloqueia novamente
        sgRepo.lock()

        assertTrue("Após bloqueio, memória deve ser imediatamente apagada", vaultRepo.vaultEntries.value.isEmpty())
    }

    @Test
    fun keyVaultRepository_refreshVault_transientFailure_preservesMemory_whenUnlocked() = runTest(testDispatcher) {
        val store = EncryptedKeysStore(null)
        val keyId = "device-key-3"
        val bindingId = "BINDING-3"

        val entry = VaultKeyEntry(
            slotId = 0,
            label = "GitHub Signer",
            type = AccessKeyType.PASSKEY_FIDO,
            publicSummary = "GitHub key",
            createdAtEpochMs = 12345L
        )
        store.saveVaultEntries(keyId, listOf(entry), bindingId)

        val connectedKeysRepo = ConnectedKeysRepositoryImpl(store, null, null)
        val dev = ConnectedKeyDevice(
            id = keyId,
            displayName = "AegisKey Enterprise",
            hardwareAddressOrId = "usb:3",
            bindingIdHex = bindingId,
            transportType = ConnectionTransportType.USB,
            isCurrentlyConnected = true
        )
        connectedKeysRepo.addOrUpdateKey(dev)

        val sgRepo = MockSecureGuardRepository()

        val standaloneScope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val vaultRepo = KeyVaultRepositoryImpl(
            keysStore = store,
            usbKeyTransport = null,
            bleKeyTransport = null,
            simulatedRenodeTransport = SimulatedRenodeTransport(),
            connectedKeysRepository = connectedKeysRepo,
            secureGuardRepository = sgRepo,
            scope = standaloneScope
        )

        // Desbloqueia a sessão
        sgRepo.unlock("1234")
        assertEquals(1, vaultRepo.vaultEntries.value.size)

        // refreshVault falha (não há hardware conectado neste teste unitário)
        val res = vaultRepo.refreshVault(keyId)

        // Requisito 1: Enquanto Secure Guard estiver UNLOCKED, erro transitório de leitura da chave física NÃO ZERA as chaves em memória
        assertTrue("refreshVault deve retornar sucesso preservando as chaves em memória", res.isSuccess)
        assertEquals("Chaves em memória devem ser preservadas durante a sessão ativa", 1, vaultRepo.vaultEntries.value.size)
        assertEquals("GitHub Signer", vaultRepo.vaultEntries.value[0].label)
    }

    @Test
    fun keyVaultRepository_refreshVault_wipesMemory_whenLocked() = runTest(testDispatcher) {
        val store = EncryptedKeysStore(null)
        val keyId = "device-key-4"
        val bindingId = "BINDING-4"

        val connectedKeysRepo = ConnectedKeysRepositoryImpl(store, null, null)
        val dev = ConnectedKeyDevice(
            id = keyId,
            displayName = "AegisKey 4",
            hardwareAddressOrId = "usb:4",
            bindingIdHex = bindingId,
            transportType = ConnectionTransportType.USB,
            isCurrentlyConnected = true
        )
        connectedKeysRepo.addOrUpdateKey(dev)

        val sgRepo = MockSecureGuardRepository(
            SecureGuardStatus(state = SecureGuardStateEnum.LOCKED, isUnlocked = false)
        )

        val standaloneScope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val vaultRepo = KeyVaultRepositoryImpl(
            keysStore = store,
            usbKeyTransport = null,
            bleKeyTransport = null,
            simulatedRenodeTransport = SimulatedRenodeTransport(),
            connectedKeysRepository = connectedKeysRepo,
            secureGuardRepository = sgRepo,
            scope = standaloneScope
        )

        // Executa refreshVault enquanto bloqueado
        val res = vaultRepo.refreshVault(keyId)

        assertTrue(vaultRepo.vaultEntries.value.isEmpty())
        assertTrue(res.getOrThrow().isEmpty())
    }

    @Test
    fun secureGuardRepository_onHardwareDetached_locksImmediately_andClearsSessionPin() {
        val bridge = HostUsbUartBridgeClient()
        val sgRepo = SecureGuardRepositoryImpl(bridge, null, null)

        SecureGuardRepositoryImpl.lastVerifiedSessionPin = "4927"
        sgRepo.onHardwareDetached()

        assertNull("PIN da sessão ativa deve ser zerado imediatamente", SecureGuardRepositoryImpl.lastVerifiedSessionPin)
        assertEquals(SecureGuardStateEnum.LOCKED, sgRepo.statusFlow.value.state)
        assertFalse(sgRepo.statusFlow.value.isUnlocked)
        assertEquals(0L, sgRepo.statusFlow.value.sessionRemainingMs)
    }

    @Test
    fun secureGuardRepository_getStatus_forcesLocked_whenUsbDetachedAndBleNotReady() = runTest(testDispatcher) {
        val bridge = HostUsbUartBridgeClient()
        val dummyUsb = UsbCtaphid(null)
        val sgRepo = SecureGuardRepositoryImpl(bridge, dummyUsb, null)

        val res = sgRepo.getStatus()
        assertTrue(res.isSuccess)
        val status = res.getOrThrow()
        assertEquals("Deve forçar LOCKED imediatamente quando USB desconectado", SecureGuardStateEnum.LOCKED, status.state)
        assertFalse("Não deve estar desbloqueado", status.isUnlocked)
        assertEquals(0L, status.sessionRemainingMs)
    }

    @Test
    fun usbCtaphid_detached_triggers_cascadeNotification() {
        val usb = UsbCtaphid(null)

        var listenerFired = false
        usb.onHardwareDetachedListener = {
            listenerFired = true
        }

        var secondaryListenerFired = false
        usb.addOnHardwareDetachedListener {
            secondaryListenerFired = true
        }

        usb.notifyHardwareDetached()

        assertTrue("onHardwareDetachedListener deve ser invocado", listenerFired)
        assertTrue("Listener registrado via addOnHardwareDetachedListener deve ser invocado", secondaryListenerFired)
    }
}
