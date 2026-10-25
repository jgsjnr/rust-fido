package dev.aegiskey.app

import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.local.ThemePreferencesStore
import dev.aegiskey.app.data.repository.ConnectedKeysRepositoryImpl
import dev.aegiskey.app.data.repository.KeyVaultRepositoryImpl
import dev.aegiskey.app.data.repository.PairingWizardRepositoryImpl
import dev.aegiskey.app.data.repository.ThemeRepositoryImpl
import dev.aegiskey.app.data.repository.TotpRepositoryImpl
import dev.aegiskey.app.data.system.SystemSecurityService
import dev.aegiskey.app.data.transport.HostUsbUartBridgeClient
import dev.aegiskey.app.data.transport.SimulatedRenodeTransport
import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.domain.model.AppThemeMode
import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.DiscoveredKeyCandidate
import dev.aegiskey.app.domain.model.OnboardingStep
import dev.aegiskey.app.domain.model.SecurityToggles
import dev.aegiskey.app.domain.usecase.ConnectCandidateUseCase
import dev.aegiskey.app.domain.usecase.GetAppStartDestinationUseCase
import dev.aegiskey.app.domain.usecase.PerformBiometricBindingUseCase
import dev.aegiskey.app.domain.usecase.SimulateButtonHoldUseCase
import dev.aegiskey.app.domain.usecase.SimulateButtonSingleTouchUseCase
import dev.aegiskey.app.domain.usecase.StartDiscoveryUseCase
import dev.aegiskey.app.domain.usecase.StopDiscoveryUseCase
import dev.aegiskey.app.ui.viewmodel.OnboardingWizardViewModel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
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
        Dispatchers.setMain(UnconfinedTestDispatcher())

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

    @After
    fun tearDown() {
        Dispatchers.resetMain()
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

    @Test
    fun testPairingAndKeyCreation_viaBleTransport() = runTest {
        dev.aegiskey.app.data.debug.DebugHardwareChipMock.IS_MOCK_ENABLED = true
        val wizardRepo = PairingWizardRepositoryImpl(
            bleClient = null,
            usbCtaphid = null,
            simulatedRenodeTransport = simulatedTransport,
            securityService = securityService,
            connectedKeysRepository = connectedKeysRepo,
            scope = CoroutineScope(Dispatchers.Unconfined)
        )

        // 1. Inicia busca BLE
        wizardRepo.startDiscovery(ConnectionTransportType.BLE)
        val candidates = wizardRepo.discoveredCandidates.value
        val bleCandidate = candidates.firstOrNull { it.transportType == ConnectionTransportType.BLE }
        assertNotNull("Deve encontrar candidato BLE", bleCandidate)

        // 2. Conecta ao candidato BLE
        val connectResult = wizardRepo.connectToCandidate(bleCandidate!!)
        assertTrue("Conexão ao BLE deve ter sucesso", connectResult.isSuccess)

        // 3. Toque físico
        wizardRepo.simulatePhysicalButtonSingleTouch()

        // 4. Vínculo biométrico
        val bindingResult = wizardRepo.performBiometricBinding(
            keyAliasName = "Chave BLE Corporativa",
            recoveryPin = null
        )
        assertTrue("Pareamento BLE deve ter sucesso", bindingResult.isSuccess)
        val device = bindingResult.getOrThrow()
        assertEquals(ConnectionTransportType.BLE, device.transportType)
        assertEquals("Chave BLE Corporativa", device.displayName)

        // 5. Criação de chaves no cofre via BLE
        val vaultRepo = KeyVaultRepositoryImpl(
            keysStore = keysStore,
            usbKeyTransport = null,
            bleKeyTransport = null,
            simulatedRenodeTransport = simulatedTransport,
            connectedKeysRepository = connectedKeysRepo
        )

        val passkeyResult = vaultRepo.generateNewAccessKey(
            keyId = device.id,
            label = "GitHub Passkey",
            type = AccessKeyType.PASSKEY_FIDO,
            algorithmOrCurve = "ES256 (P-256)"
        )
        assertTrue("Criação de Passkey via BLE deve ter sucesso", passkeyResult.isSuccess)
        val entry = passkeyResult.getOrThrow()
        assertEquals(AccessKeyType.PASSKEY_FIDO, entry.type)
        assertEquals("GitHub Passkey", entry.label)
    }

    @Test
    fun testPairingAndKeyCreation_viaWifiTransport() = runTest {
        dev.aegiskey.app.data.debug.DebugHardwareChipMock.IS_MOCK_ENABLED = true
        val wizardRepo = PairingWizardRepositoryImpl(
            bleClient = null,
            usbCtaphid = null,
            simulatedRenodeTransport = simulatedTransport,
            securityService = securityService,
            connectedKeysRepository = connectedKeysRepo,
            scope = CoroutineScope(Dispatchers.Unconfined)
        )

        // 1. Inicia busca Wi-Fi
        wizardRepo.startDiscovery(ConnectionTransportType.WIFI)
        val candidates = wizardRepo.discoveredCandidates.value
        val wifiCandidate = candidates.firstOrNull { it.transportType == ConnectionTransportType.WIFI }
        assertNotNull("Deve encontrar candidato Wi-Fi", wifiCandidate)

        // 2. Conecta ao candidato Wi-Fi
        val connectResult = wizardRepo.connectToCandidate(wifiCandidate!!)
        assertTrue("Conexão ao Wi-Fi deve ter sucesso", connectResult.isSuccess)

        // 3. Toque físico
        wizardRepo.simulatePhysicalButtonSingleTouch()

        // 4. Vínculo biométrico
        val bindingResult = wizardRepo.performBiometricBinding(
            keyAliasName = "AegisKey Wi-Fi AP",
            recoveryPin = null
        )
        assertTrue("Pareamento Wi-Fi deve ter sucesso", bindingResult.isSuccess)
        val device = bindingResult.getOrThrow()
        assertEquals(ConnectionTransportType.WIFI, device.transportType)

        // 5. Criação de carteira de criptomoedas no cofre via Wi-Fi
        val vaultRepo = KeyVaultRepositoryImpl(
            keysStore = keysStore,
            usbKeyTransport = null,
            bleKeyTransport = null,
            simulatedRenodeTransport = simulatedTransport,
            connectedKeysRepository = connectedKeysRepo
        )

        val walletResult = vaultRepo.generateNewAccessKey(
            keyId = device.id,
            label = "Carteira Ethereum",
            type = AccessKeyType.CRYPTO_WALLET_ETH,
            algorithmOrCurve = "secp256k1"
        )
        assertTrue("Criação de carteira via Wi-Fi deve ter sucesso", walletResult.isSuccess)
        val entry = walletResult.getOrThrow()
        assertEquals(AccessKeyType.CRYPTO_WALLET_ETH, entry.type)
        assertEquals("Carteira Ethereum", entry.label)
    }

    @Test
    fun testOnboardingWizard_persistsSteps1To4_andOnlyMutatesConnectedKeysAtStep5() = runTest {
        dev.aegiskey.app.data.debug.DebugHardwareChipMock.IS_MOCK_ENABLED = true
        val wizardRepo = PairingWizardRepositoryImpl(
            bleClient = null,
            usbCtaphid = null,
            simulatedRenodeTransport = simulatedTransport,
            securityService = securityService,
            connectedKeysRepository = connectedKeysRepo,
            keysStore = keysStore,
            scope = CoroutineScope(Dispatchers.Unconfined)
        )

        val wizardVm = OnboardingWizardViewModel(
            pairingWizardRepository = wizardRepo,
            startDiscoveryUseCase = StartDiscoveryUseCase(wizardRepo),
            stopDiscoveryUseCase = StopDiscoveryUseCase(wizardRepo),
            connectCandidateUseCase = ConnectCandidateUseCase(wizardRepo),
            simulateButtonHoldUseCase = SimulateButtonHoldUseCase(wizardRepo),
            simulateButtonSingleTouchUseCase = SimulateButtonSingleTouchUseCase(wizardRepo),
            performBiometricBindingUseCase = PerformBiometricBindingUseCase(wizardRepo),
        )

        // Inicial: Passo 1, nenhuma chave cadastrada
        assertEquals(OnboardingStep.WELCOME_TRANSPORT, wizardVm.uiState.value.currentStep)
        assertFalse("Nenhuma chave deve estar conectada inicialmente", connectedKeysRepo.hasAnyConnectedKey.value)

        // Passo 1 -> Passo 2: Seleciona USB e avança
        wizardVm.selectTransport(ConnectionTransportType.USB)
        wizardVm.nextStep()
        testScheduler.advanceUntilIdle()
        assertEquals(OnboardingStep.HOLD_PHYSICAL_BUTTON, wizardVm.uiState.value.currentStep)
        assertFalse("Chave ainda NÃO pode ser cadastrada no Passo 2", connectedKeysRepo.hasAnyConnectedKey.value)

        // Passo 2 -> Passo 3: Avança para descoberta
        wizardVm.nextStep()
        testScheduler.advanceUntilIdle()
        assertEquals(OnboardingStep.DISCOVER_AND_CONNECT, wizardVm.uiState.value.currentStep)
        assertFalse("Chave ainda NÃO pode ser cadastrada no Passo 3", connectedKeysRepo.hasAnyConnectedKey.value)

        // Passo 3 -> Passo 4: Conecta ao candidato USB
        val mockUsb = dev.aegiskey.app.data.debug.DebugHardwareChipMock.MOCK_USB_CANDIDATE
        assertNotNull(mockUsb)
        wizardVm.selectCandidateAndConnect(mockUsb)
        testScheduler.advanceUntilIdle()
        wizardVm.nextStep()
        testScheduler.advanceUntilIdle()
        var attempts = 0
        while (wizardVm.uiState.value.currentStep != OnboardingStep.TOUCH_AND_BIOMETRIC_BIND && attempts < 20) {
            Thread.sleep(50)
            testScheduler.advanceUntilIdle()
            attempts++
        }
        assertEquals(OnboardingStep.TOUCH_AND_BIOMETRIC_BIND, wizardVm.uiState.value.currentStep)
        assertFalse("Chave ainda NÃO pode ser cadastrada no Passo 4", connectedKeysRepo.hasAnyConnectedKey.value)

        // Passo 4 -> Passo 5: Confirma toque físico
        wizardVm.nextStep()
        testScheduler.advanceUntilIdle()
        attempts = 0
        while (wizardVm.uiState.value.currentStep != OnboardingStep.NAME_AND_FINISH && attempts < 20) {
            Thread.sleep(50)
            testScheduler.advanceUntilIdle()
            attempts++
        }
        assertEquals(OnboardingStep.NAME_AND_FINISH, wizardVm.uiState.value.currentStep)
        assertFalse("Chave ainda NÃO pode ser cadastrada antes de concluir o Passo 5", connectedKeysRepo.hasAnyConnectedKey.value)

        // Passo 5: Conclui com nome personalizado e abre cofre
        var onCompletedCalled = false
        wizardVm.completeWizardWithCustomName("Minha Chave USB Corporativa") {
            onCompletedCalled = true
        }
        testScheduler.advanceUntilIdle()
        attempts = 0
        while (!connectedKeysRepo.hasAnyConnectedKey.value && attempts < 20) {
            Thread.sleep(50)
            testScheduler.advanceUntilIdle()
            attempts++
        }

        assertTrue("Callback de conclusão deve ser chamado", onCompletedCalled)
        assertTrue("hasAnyConnectedKey DEVE mudar para true apenas no Passo 5", connectedKeysRepo.hasAnyConnectedKey.value)
        assertEquals("Minha Chave USB Corporativa", connectedKeysRepo.activeKey.value?.displayName)
        assertTrue(wizardVm.uiState.value.isCompleted)
    }

    @Test
    fun testProximityAndDynamicLock_nearAwayLockedTransitionAndUnlock() = runTest {
        val bridgeClient = HostUsbUartBridgeClient()

        // 1. Configura a política de Dynamic Lock (limiar -75 dBm, 6 segundos, histerese 5 dB)
        val configOk = bridgeClient.configureProximityLock(
            enabled = true,
            thresholdDbm = -75,
            lockSeconds = 6,
            enforceWindowsLock = false
        )
        assertTrue(configOk)

        // 2. Consulta estado inicial
        val initialStatus = bridgeClient.fetchProximityStatus()
        assertTrue(initialStatus.enabled)
        assertEquals(-75, initialStatus.thresholdDbm)
        assertEquals(6.0, initialStatus.lockSeconds, 0.01)

        // 3. Celular próximo (-32 dBm) -> Estado NEAR, locked=false
        val nearStatus = bridgeClient.sendPhoneRssiAndEvaluate(rssiDbm = -32, elapsedSeconds = 2.0)
        assertEquals("NEAR", nearStatus.state)
        assertFalse(nearStatus.locked)
        assertEquals(0.0, nearStatus.awaySeconds, 0.01)

        // 4. Sinal na banda de histerese (-72 dBm entre -75 e -70 dBm) -> Mantém NEAR sem travar
        val hystStatus = bridgeClient.sendPhoneRssiAndEvaluate(rssiDbm = -72, elapsedSeconds = 1.0)
        assertFalse(hystStatus.locked)

        // 5. Usuário se afasta com o celular (-84 dBm) por 2 segundos -> Estado AWAY (não travado ainda)
        val awayStep1 = bridgeClient.sendPhoneRssiAndEvaluate(rssiDbm = -84, elapsedSeconds = 2.0)
        assertEquals("AWAY", awayStep1.state)
        assertFalse(awayStep1.locked)
        assertEquals(2.0, awayStep1.awaySeconds, 0.01)

        // 6. Usuário continua afastado (-90 dBm) por mais 5 segundos (total 7s > 6s) -> Transição para LOCKED!
        val lockedStatus = bridgeClient.sendPhoneRssiAndEvaluate(rssiDbm = -90, elapsedSeconds = 5.0)
        assertEquals("LOCKED", lockedStatus.state)
        assertTrue("Dynamic Lock deve estar ATIVO (locked=true)", lockedStatus.locked)

        // 7. Mesmo com novas amostras fracas, trava é mantida (latch)
        val latchStatus = bridgeClient.sendPhoneRssiAndEvaluate(rssiDbm = -95, elapsedSeconds = 2.0)
        assertTrue(latchStatus.locked)
        assertEquals("LOCKED", latchStatus.state)

        // 8. Retorno e destravamento com Toque UP + PIN
        val unlockOk = bridgeClient.unlockProximitySession("12345678")
        assertTrue("Destravamento de proximidade deve ter sucesso", unlockOk)

        val restoredStatus = bridgeClient.fetchProximityStatus()
        assertFalse("locked deve voltar a false", restoredStatus.locked)
        assertEquals("NEAR", restoredStatus.state)
        assertEquals(0.0, restoredStatus.awaySeconds, 0.01)
    }
}
