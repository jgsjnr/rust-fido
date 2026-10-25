package dev.aegiskey.app

import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.local.ThemePreferencesStore
import dev.aegiskey.app.data.repository.ConnectedKeysRepositoryImpl
import dev.aegiskey.app.data.repository.KeyVaultRepositoryImpl
import dev.aegiskey.app.data.repository.PairingWizardRepositoryImpl
import dev.aegiskey.app.data.repository.ThemeRepositoryImpl
import dev.aegiskey.app.data.repository.TotpRepositoryImpl
import dev.aegiskey.app.data.system.SystemSecurityService
import dev.aegiskey.app.data.transport.SimulatedRenodeTransport
import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.domain.model.AppThemeMode
import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.DiscoveredKeyCandidate
import dev.aegiskey.app.domain.model.SecurityToggles
import dev.aegiskey.app.domain.usecase.GetAppStartDestinationUseCase
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.UUID

@OptIn(ExperimentalCoroutinesApi::class)
class CleanJourneyArchitectureTest {

    private lateinit var keysStore: EncryptedKeysStore
    private lateinit var themeStore: ThemePreferencesStore
    private lateinit var securityService: SystemSecurityService
    private lateinit var simulatedTransport: SimulatedRenodeTransport

    private lateinit var connectedKeysRepo: ConnectedKeysRepositoryImpl
    private lateinit var themeRepo: ThemeRepositoryImpl
    private lateinit var getStartDestinationUseCase: GetAppStartDestinationUseCase

    @Before
    fun setUp() {
        // Inicializa com null context para ativar armazenamento determinístico em memória
        keysStore = EncryptedKeysStore(context = null)
        keysStore.clearAll()

        themeStore = ThemePreferencesStore(context = null)
        securityService = SystemSecurityService(context = null)
        simulatedTransport = SimulatedRenodeTransport()

        // Usamos Dispatchers.Unconfined para reatividade síncrona nos StateFlows de teste
        connectedKeysRepo = ConnectedKeysRepositoryImpl(
            keysStore = keysStore,
            scope = CoroutineScope(Dispatchers.Unconfined)
        )
        themeRepo = ThemeRepositoryImpl(themeStore)
        getStartDestinationUseCase = GetAppStartDestinationUseCase(connectedKeysRepo)
    }

    @Test
    fun testEmptyKeys_startDestinationIsOnboardingWizard() = runTest {
        // 1. Quando o repositório está vazio (0 chaves conectadas)
        assertEquals(0, connectedKeysRepo.connectedKeys.value.size)
        assertFalse("Não deve ter nenhuma chave conectada inicialmente", connectedKeysRepo.hasAnyConnectedKey.value)

        // 2. O destino inicial da navegação deve ser o Onboarding Wizard
        val startDestination = getStartDestinationUseCase().first()
        assertEquals(GetAppStartDestinationUseCase.StartDestination.OnboardingWizard, startDestination)
    }

    @Test
    fun testCompleteFiveStepPairingWizardFlow_addsKeyAndRedirectsToMainHub() = runTest {
        dev.aegiskey.app.data.debug.DebugHardwareChipMock.IS_MOCK_ENABLED = true
        val wizardRepo = PairingWizardRepositoryImpl(
            bleClient = null,
            usbCtaphid = null,
            simulatedRenodeTransport = simulatedTransport,
            securityService = securityService,
            connectedKeysRepository = connectedKeysRepo,
            scope = CoroutineScope(Dispatchers.Unconfined)
        )

        // Passo 1: Solicita e simula pressionar o botão físico por 5 segundos
        assertFalse(wizardRepo.buttonHoldSimulatedOrDetected.value)
        val holdResult = wizardRepo.simulatePhysicalButtonHold5s()
        assertTrue("Simulação do botão por 5s deve ter sucesso", holdResult.isSuccess)
        assertTrue("Estado de botão físico ativado", wizardRepo.buttonHoldSimulatedOrDetected.value)

        // Passo 2: Inicia varredura/descoberta de chaves no modo SIMULATOR
        wizardRepo.startDiscovery(ConnectionTransportType.SIMULATOR)
        assertTrue(wizardRepo.isScanning.value)
        val candidates = wizardRepo.discoveredCandidates.value
        assertFalse("Deve encontrar candidato Renode Simulator", candidates.isEmpty())
        val candidate = candidates.first()
        assertEquals(ConnectionTransportType.SIMULATOR, candidate.transportType)

        // Passo 3: Conecta ao candidato encontrado
        val connectResult = wizardRepo.connectToCandidate(candidate)
        assertTrue("Conexão ao candidato deve ter sucesso", connectResult.isSuccess)

        // Passo 4: Simula confirmação por toque único no botão físico (User Presence)
        val touchResult = wizardRepo.simulatePhysicalButtonSingleTouch()
        assertTrue("Toque único de confirmação física deve ter sucesso", touchResult.isSuccess)

        // Passo 5: Executa o vínculo criptográfico seguro (Biometric Binding)
        val bindingResult = wizardRepo.performBiometricBinding(
            keyAliasName = "Minha AegisKey Primária",
            recoveryPin = null
        )
        assertTrue("Vínculo biométrico deve ter sucesso", bindingResult.isSuccess)
        val boundDevice = bindingResult.getOrThrow()
        assertEquals("Minha AegisKey Primária", boundDevice.displayName)
        assertEquals(ConnectionTransportType.SIMULATOR, boundDevice.transportType)

        // Verificações pós-vinculação no repositório de chaves conectadas
        assertEquals(1, connectedKeysRepo.connectedKeys.value.size)
        assertTrue("hasAnyConnectedKey deve mudar para true", connectedKeysRepo.hasAnyConnectedKey.value)
        assertEquals(boundDevice.id, connectedKeysRepo.activeKey.value?.id)

        // O destino inicial agora deve ser o Hub Principal
        val nextDestination = getStartDestinationUseCase().first()
        assertEquals(GetAppStartDestinationUseCase.StartDestination.MainHub, nextDestination)
    }

    @Test
    fun testMultiKeyLifecycle_activeSwitch_togglesUpdate_andEmptyRedirectsToWizard() = runTest {
        // Cria primeira chave
        val key1 = ConnectedKeyDevice(
            id = UUID.randomUUID().toString(),
            displayName = "Chave Titular",
            hardwareAddressOrId = "ble:11:22:33:44:55:66",
            bindingIdHex = "A1B2C3D4E5F60718",
            transportType = ConnectionTransportType.BLE,
            isCurrentlyConnected = true,
            firmwareRevision = 1,
            lastConnectedEpochMs = System.currentTimeMillis()
        )
        connectedKeysRepo.addOrUpdateKey(key1)

        assertEquals(1, connectedKeysRepo.connectedKeys.value.size)
        assertEquals(key1.id, connectedKeysRepo.activeKey.value?.id)
        assertTrue(connectedKeysRepo.hasAnyConnectedKey.value)

        // Adiciona uma 2ª chave
        val key2 = ConnectedKeyDevice(
            id = UUID.randomUUID().toString(),
            displayName = "Chave Backup",
            hardwareAddressOrId = "usb:303a:ae61",
            bindingIdHex = "B2C3D4E5F60718A1",
            transportType = ConnectionTransportType.USB,
            isCurrentlyConnected = false,
            firmwareRevision = 1,
            lastConnectedEpochMs = System.currentTimeMillis()
        )
        connectedKeysRepo.addOrUpdateKey(key2)

        assertEquals(2, connectedKeysRepo.connectedKeys.value.size)

        // Troca a chave ativa para a 2ª chave
        connectedKeysRepo.selectActiveKey(key2.id)
        assertEquals(key2.id, connectedKeysRepo.activeKey.value?.id)

        // Atualiza as opções de segurança da chave ativa
        val newToggles = SecurityToggles(
            lockOnWalkAway = false,
            requireBiometricsOnOpen = true,
            requireTouchForEveryCode = true
        )
        connectedKeysRepo.updateKeyToggles(key2.id, newToggles)

        val updatedKey2 = connectedKeysRepo.activeKey.value
        assertNotNull(updatedKey2)
        assertEquals(false, updatedKey2?.toggles?.lockOnWalkAway)
        assertEquals(true, updatedKey2?.toggles?.requireBiometricsOnOpen)
        assertEquals(true, updatedKey2?.toggles?.requireTouchForEveryCode)

        // Remove a 2ª chave -> chave ativa volta automaticamente para a primeira
        connectedKeysRepo.removeKey(key2.id)
        assertEquals(1, connectedKeysRepo.connectedKeys.value.size)
        assertEquals(key1.id, connectedKeysRepo.activeKey.value?.id)
        assertTrue(connectedKeysRepo.hasAnyConnectedKey.value)

        // Remove a última chave restante -> repositório fica com 0 chaves
        connectedKeysRepo.removeKey(key1.id)
        assertEquals(0, connectedKeysRepo.connectedKeys.value.size)
        assertFalse("hasAnyConnectedKey deve retornar imediatamente a false", connectedKeysRepo.hasAnyConnectedKey.value)

        // Verifica redirecionamento imediato para o Onboarding Wizard
        val destination = getStartDestinationUseCase().first()
        assertEquals(GetAppStartDestinationUseCase.StartDestination.OnboardingWizard, destination)
    }

    @Test
    fun testKeyVaultGenerationAndTotpCountdownFlow() = runTest {
        // Prepara uma chave conectada no modo simulador
        val simKey = ConnectedKeyDevice(
            id = "sim-key-001",
            displayName = "Chave Vault Test",
            hardwareAddressOrId = "tcp:10.0.2.2:5678",
            bindingIdHex = "0011223344556677",
            transportType = ConnectionTransportType.SIMULATOR,
            isCurrentlyConnected = true,
            firmwareRevision = 1,
            lastConnectedEpochMs = System.currentTimeMillis()
        )
        connectedKeysRepo.addOrUpdateKey(simKey)

        val vaultRepo = KeyVaultRepositoryImpl(
            keysStore = keysStore,
            bleClient = null,
            simulatedRenodeTransport = simulatedTransport,
            connectedKeysRepository = connectedKeysRepo
        )

        // Geração de Passkey FIDO
        val passkeyResult = vaultRepo.generateNewAccessKey("sim-key-001", "Google Account", AccessKeyType.PASSKEY_FIDO)
        assertTrue("Criação de Passkey FIDO deve ter sucesso", passkeyResult.isSuccess)
        val passkey = passkeyResult.getOrThrow()
        assertEquals(AccessKeyType.PASSKEY_FIDO, passkey.type)
        assertEquals("Google Account", passkey.label)

        // Geração de Chave de Assinatura de Hardware do Vendor (Vendor Signing Key)
        val vendorKeyResult = vaultRepo.generateNewAccessKey("sim-key-001", "Vendor Master Signer", AccessKeyType.VENDOR_SIGNING_KEY, algorithmOrCurve = "Ed25519 (moderna)")
        assertTrue("Criação de Vendor Signing Key deve ter sucesso", vendorKeyResult.isSuccess)
        val vendorKey = vendorKeyResult.getOrThrow()
        assertEquals(AccessKeyType.VENDOR_SIGNING_KEY, vendorKey.type)
        assertEquals("Vendor Master Signer", vendorKey.label)

        // Geração de Carteiras Cripto BTC, ETH, SOL e DOT
        val btcResult = vaultRepo.generateNewAccessKey("sim-key-001", "Cold Wallet BTC", AccessKeyType.CRYPTO_WALLET_BTC)
        assertTrue(btcResult.isSuccess)
        val ethResult = vaultRepo.generateNewAccessKey("sim-key-001", "DeFi Wallet ETH", AccessKeyType.CRYPTO_WALLET_ETH)
        assertTrue(ethResult.isSuccess)
        val solResult = vaultRepo.generateNewAccessKey("sim-key-001", "Vault Solana", AccessKeyType.CRYPTO_WALLET_SOL)
        assertTrue(solResult.isSuccess)
        val dotResult = vaultRepo.generateNewAccessKey("sim-key-001", "Polkadot Staking", AccessKeyType.CRYPTO_WALLET_DOT)
        assertTrue(dotResult.isSuccess)

        // Geração de Slot Smartcard PIV (NIST SP 800-73-4)
        val pivResult = vaultRepo.generateNewAccessKey("sim-key-001", "PIV Smartcard 9A", AccessKeyType.PIV_SMARTCARD_SLOT, extraParam = "9A")
        assertTrue(pivResult.isSuccess)
        val pivKey = pivResult.getOrThrow()
        assertEquals(AccessKeyType.PIV_SMARTCARD_SLOT, pivKey.type)

        // Geração / Importação de Envelope AEGN v1 Selado
        val aegnResult = vaultRepo.generateNewAccessKey("sim-key-001", "Vault Envelope Key", AccessKeyType.ENCRYPTED_AEGN_ENVELOPE)
        assertTrue(aegnResult.isSuccess)
        val aegnKey = aegnResult.getOrThrow()
        assertEquals(AccessKeyType.ENCRYPTED_AEGN_ENVELOPE, aegnKey.type)

        // Verifica lista total de credenciais do cofre (todas as 8 categorias cobertas)
        val allEntries = vaultRepo.vaultEntries.value
        assertEquals(8, allEntries.size)

        // Teste de assinatura de desafio / transação criptográfica
        val signResult = vaultRepo.signChallengeOrTransaction("sim-key-001", passkey.slotId, "CHALLENGE_NONCE_ABC123")
        assertTrue("Assinatura com chave do cofre deve ter sucesso", signResult.isSuccess)
        assertNotNull(signResult.getOrThrow())

        // Teste de exportação de envelope AEGN
        val exportResult = vaultRepo.exportKeyEnvelopeAegn("sim-key-001", aegnKey.slotId)
        assertTrue("Exportação de envelope AEGN deve ter sucesso", exportResult.isSuccess)
        assertTrue(exportResult.getOrThrow().isNotBlank())

        // Teste de configuração de PIN/PUK PIV
        val pivPinResult = vaultRepo.enrollOrUpdatePivPin("sim-key-001", "9A", "123456", "12345678")
        assertTrue("Configuração de PIN/PUK PIV deve ter sucesso", pivPinResult.isSuccess)

        // Teste de diagnóstico completo do hardware
        val diagResult = vaultRepo.fetchHardwareDiagnostics("sim-key-001")
        assertTrue("Diagnóstico de hardware deve ter sucesso", diagResult.isSuccess)
        val diagnostics = diagResult.getOrThrow()
        assertEquals(8, diagnostics.totalVaultItems)
        assertEquals(24, diagnostics.freeSlotsRemaining)
        assertEquals(5, diagnostics.fido2SupportedCurves.size)
        assertEquals(4, diagnostics.pivSlotsAvailable.size)
        assertTrue(diagnostics.healthStatusText.contains("Hardware Conectado"))

        // Executa teste rápido de integridade do hardware
        val healthResult = vaultRepo.runQuickHealthCheck("sim-key-001")
        assertTrue(healthResult.isSuccess)
        val healthMessage = healthResult.getOrThrow()
        assertTrue("Mensagem deve conter indicação de conexão do hardware", healthMessage.contains("Hardware Conectado"))

        // --- Teste do Repositório TOTP ---
        val totpRepo = TotpRepositoryImpl(
            keysStore = keysStore,
            bleClient = null,
            simulatedRenodeTransport = simulatedTransport,
            connectedKeysRepository = connectedKeysRepo
        )

        // Adiciona conta TOTP válida (SHA1, 6 dígitos)
        val addTotpResult = totpRepo.addAccount(
            keyId = "sim-key-001",
            issuer = "GitHub",
            accountName = "octocat",
            secretOrUri = "JBSWY3DPEHPK3PXP", // Base32 padronizado RFC 4648
            digits = 6
        )
        assertTrue("Cadastro TOTP deve ter sucesso", addTotpResult.isSuccess)
        val totpItem = addTotpResult.getOrThrow()
        assertEquals("GitHub", totpItem.issuer)
        assertEquals("octocat", totpItem.accountName)
        assertEquals(6, totpItem.currentCode.length)
        assertTrue("Código formatado deve conter espaço central", totpItem.formattedCode.contains(" "))

        // Adiciona conta HOTP baseada em evento / contador
        val addHotpResult = totpRepo.addAccount(
            keyId = "sim-key-001",
            issuer = "InternalVPN",
            accountName = "admin",
            secretOrUri = "JBSWY3DPEHPK3PXP",
            digits = 8,
            isHotp = true
        )
        assertTrue("Cadastro HOTP deve ter sucesso", addHotpResult.isSuccess)
        val hotpItem = addHotpResult.getOrThrow()
        assertTrue(hotpItem.isHotp)
        assertEquals(0L, hotpItem.counter)
        assertEquals(8, hotpItem.currentCode.length)

        // Incrementa contador do HOTP
        val incrementResult = totpRepo.incrementHotpCounter("sim-key-001", hotpItem.id)
        assertTrue("Incremento de contador HOTP deve ter sucesso", incrementResult.isSuccess)
        val updatedHotp = incrementResult.getOrThrow()
        assertEquals(1L, updatedHotp.counter)
        assertEquals(8, updatedHotp.currentCode.length)

        // Verifica listagem
        val accounts = totpRepo.accounts.value
        assertEquals(2, accounts.size)

        // Testa contagem regressiva e atualização do timer de 30s
        totpRepo.tickTimer(1700000000L)
        val remaining = totpRepo.remainingSeconds.value
        assertTrue("Segundos restantes devem estar no intervalo [1, 30]", remaining in 1..30)
    }

    @Test
    fun testThemeRepositoryModesAndDynamicColors() = runTest {
        // Estado padrão inicial
        assertEquals(AppThemeMode.SYSTEM, themeRepo.themePreference.value.mode)
        assertTrue(themeRepo.themePreference.value.useDynamicColors)

        // Altera para Tema Claro
        themeRepo.setThemeMode(AppThemeMode.LIGHT)
        assertEquals(AppThemeMode.LIGHT, themeRepo.themePreference.value.mode)

        // Altera para Tema Escuro
        themeRepo.setThemeMode(AppThemeMode.DARK)
        assertEquals(AppThemeMode.DARK, themeRepo.themePreference.value.mode)

        // Retorna para Padrão do Sistema
        themeRepo.setThemeMode(AppThemeMode.SYSTEM)
        assertEquals(AppThemeMode.SYSTEM, themeRepo.themePreference.value.mode)

        // Desativa cores dinâmicas do Material You
        themeRepo.setDynamicColors(false)
        assertFalse(themeRepo.themePreference.value.useDynamicColors)

        // Reativa cores dinâmicas
        themeRepo.setDynamicColors(true)
        assertTrue(themeRepo.themePreference.value.useDynamicColors)
    }

    @Test
    fun testRealHardware_failsClosedWhenUnreachable() = runTest {
        val wizardRepo = PairingWizardRepositoryImpl(
            bleClient = null,
            usbCtaphid = null,
            simulatedRenodeTransport = simulatedTransport,
            securityService = securityService,
            connectedKeysRepository = connectedKeysRepo,
            scope = CoroutineScope(Dispatchers.Unconfined)
        )

        // Candidato real Bluetooth que não existe/está inacessível
        val realCandidate = DiscoveredKeyCandidate(
            id = "C4:D3:E2:F1:00:11",
            name = "AegisKey FIDO2 Real Hardware",
            signalRssi = -60,
            transportType = ConnectionTransportType.BLE
        )

        // Conectar deve falhar de forma honesta e fechada (fail-closed)
        val connectResult = wizardRepo.connectToCandidate(realCandidate)
        assertTrue("Conexão com hardware real ausente deve falhar de modo honesto", connectResult.isFailure)

        // Vínculo biométrico deve falhar imediatamente sem respostas falsas
        val bindResult = wizardRepo.performBiometricBinding("Chave Real Ausente", null)
        assertTrue("Vínculo biométrico sem resposta do hardware deve falhar (fail-closed)", bindResult.isFailure)
    }

    @Test
    fun testTotpAndVault_failClosedWhenHardwareOffline() = runTest {
        // Chave real desconectada
        val offlineKey = ConnectedKeyDevice(
            id = "offline-key-001",
            displayName = "Chave Offline",
            hardwareAddressOrId = "ble:C4:D3:E2:F1:00:11",
            bindingIdHex = "1122334455667788",
            transportType = ConnectionTransportType.BLE,
            isCurrentlyConnected = false,
            firmwareRevision = 1,
            lastConnectedEpochMs = System.currentTimeMillis()
        )
        connectedKeysRepo.addOrUpdateKey(offlineKey)

        val vaultRepo = KeyVaultRepositoryImpl(
            keysStore = keysStore,
            bleClient = null, // offline
            simulatedRenodeTransport = simulatedTransport,
            connectedKeysRepository = connectedKeysRepo
        )

        // Health check de chave desconectada deve falhar honestamente
        val healthResult = vaultRepo.runQuickHealthCheck("offline-key-001")
        assertTrue("Health check em hardware offline deve falhar (fail-closed)", healthResult.isFailure)

        val totpRepo = TotpRepositoryImpl(
            keysStore = keysStore,
            bleClient = null, // offline
            simulatedRenodeTransport = simulatedTransport,
            connectedKeysRepository = connectedKeysRepo
        )

        // Cadastro TOTP com chave offline deve falhar
        val addResult = totpRepo.addAccount(
            keyId = "offline-key-001",
            issuer = "Service",
            accountName = "user",
            secretOrUri = "JBSWY3DPEHPK3PXP",
            digits = 6
        )
        assertTrue("Cadastro TOTP em hardware offline deve falhar (fail-closed)", addResult.isFailure)
    }

    @Test
    fun testBridgeDiscovery_zeroMocksWhenBridgeOffline() = runTest {
        dev.aegiskey.app.data.debug.DebugHardwareChipMock.IS_MOCK_ENABLED = false
        val wizardRepo = PairingWizardRepositoryImpl(
            bleClient = null,
            usbCtaphid = null,
            hostBridgeClient = dev.aegiskey.app.data.transport.HostUsbUartBridgeClient(),
            simulatedRenodeTransport = simulatedTransport,
            securityService = securityService,
            connectedKeysRepository = connectedKeysRepo,
            scope = CoroutineScope(Dispatchers.Unconfined)
        )

        wizardRepo.startDiscovery(ConnectionTransportType.USB)
        val candidates = wizardRepo.discoveredCandidates.value
        // Com mocks desligados e sem hardware na ponte, não deve inventar dispositivos
        assertTrue("Não deve conter mock fake quando desabilitado", candidates.none { it.id == "USB:303A:AE61:01" })
    }
}
