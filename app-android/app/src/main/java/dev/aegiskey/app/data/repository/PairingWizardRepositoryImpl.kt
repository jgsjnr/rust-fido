package dev.aegiskey.app.data.repository

import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.data.debug.DebugHardwareChipMock
import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.system.SystemSecurityService
import dev.aegiskey.app.data.transport.HostUsbUartBridgeClient
import dev.aegiskey.app.data.transport.SimulatedRenodeTransport
import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.DiscoveredKeyCandidate
import dev.aegiskey.app.domain.model.TotpAccountItem
import dev.aegiskey.app.domain.model.VaultKeyEntry
import dev.aegiskey.app.domain.repository.ConnectedKeysRepository
import dev.aegiskey.app.domain.repository.PairingWizardRepository
import dev.aegiskey.app.net.WifiApi
import dev.aegiskey.app.ui.BindingWire
import dev.aegiskey.app.usb.UsbCtaphid
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.withContext
import java.util.UUID

class PairingWizardRepositoryImpl(
    private val bleClient: AegisBleClient? = null,
    private val usbCtaphid: UsbCtaphid? = null,
    private val hostBridgeClient: HostUsbUartBridgeClient = HostUsbUartBridgeClient(),
    private val simulatedRenodeTransport: SimulatedRenodeTransport,
    private val securityService: SystemSecurityService,
    private val connectedKeysRepository: ConnectedKeysRepository,
    private val keysStore: EncryptedKeysStore? = null,
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.IO)
) : PairingWizardRepository {

    private val _discoveredCandidates = MutableStateFlow<List<DiscoveredKeyCandidate>>(emptyList())
    override val discoveredCandidates: StateFlow<List<DiscoveredKeyCandidate>> = _discoveredCandidates.asStateFlow()

    private val _isScanning = MutableStateFlow(false)
    override val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()

    private val _buttonHoldSimulatedOrDetected = MutableStateFlow(false)
    override val buttonHoldSimulatedOrDetected: StateFlow<Boolean> = _buttonHoldSimulatedOrDetected.asStateFlow()

    override val isUsbDetected: StateFlow<Boolean> = usbCtaphid?.isHardwareAttached ?: MutableStateFlow(false)

    private var activeScanTransport: ConnectionTransportType? = null
    private var currentCandidate: DiscoveredKeyCandidate? = null

    @Suppress("SENSELESS_COMPARISON")
    private suspend fun buildBleCandidates(devices: List<AegisBleClient.FoundDevice>): List<DiscoveredKeyCandidate> {
        val realCandidates = devices.map { dev ->
            DiscoveredKeyCandidate(
                id = dev.address,
                name = dev.name.ifBlank { "Chave Bluetooth (${dev.address})" },
                signalRssi = dev.rssi,
                transportType = ConnectionTransportType.BLE
            )
        }.toMutableList()

        // Se estiver rodando no Emulador Android ou a ponte host estiver ativa com chave física real
        val bridgeInfo = runCatching { hostBridgeClient.probeRealHardware() }.getOrNull()
        if (bridgeInfo != null && bridgeInfo.connected) {
            if (realCandidates.none { it.id == "BLE-BRIDGE" }) {
                realCandidates.add(
                    DiscoveredKeyCandidate(
                        id = "BLE-BRIDGE",
                        name = "AegisKey BLE (Hardware Real)",
                        signalRssi = -42,
                        transportType = ConnectionTransportType.BLE
                    )
                )
            }
        }

        return if (DebugHardwareChipMock.IS_MOCK_ENABLED) {
            val mockBle = DebugHardwareChipMock.MOCK_BLE_CANDIDATE
            if (mockBle != null && realCandidates.none { it.id == mockBle.id }) {
                listOf(mockBle) + realCandidates
            } else {
                realCandidates
            }
        } else {
            realCandidates
        }
    }

    init {
        // Observa continuamente o StateFlow de dispositivos encontrados pelo AegisBleClient
        bleClient?.devices?.onEach { foundList ->
            if (_isScanning.value && activeScanTransport == ConnectionTransportType.BLE) {
                _discoveredCandidates.value = buildBleCandidates(foundList)
            }
        }?.launchIn(scope)

        simulatedRenodeTransport.buttonHoldSimulated.onEach { hold ->
            if (hold) _buttonHoldSimulatedOrDetected.value = true
        }.launchIn(scope)
    }

    @Suppress("SENSELESS_COMPARISON", "UNNECESSARY_SAFE_CALL")
    override suspend fun startDiscovery(transport: ConnectionTransportType): Unit = withContext(Dispatchers.IO) {
        activeScanTransport = transport
        _isScanning.value = true
        _buttonHoldSimulatedOrDetected.value = false

        when (transport) {
            ConnectionTransportType.BLE -> {
                val currentDevices = bleClient?.devices?.value ?: emptyList()
                _discoveredCandidates.value = buildBleCandidates(currentDevices)
                runCatching { bleClient?.startScan() }
            }
            ConnectionTransportType.USB -> {
                android.util.Log.i("PairingWizard", "startDiscovery: Iniciando busca por USB / Bridge UART...")
                val list = mutableListOf<DiscoveredKeyCandidate>()

                // 1. Verifica dispositivo USB conectado diretamente ao dispositivo Android (OTG)
                val directUsbDevice = runCatching { usbCtaphid?.findDevice() }.getOrNull()
                if (directUsbDevice != null) {
                    list.add(
                        DiscoveredKeyCandidate(
                            id = "usb:${directUsbDevice.vendorId}:${directUsbDevice.productId}",
                            name = "AegisKey USB Hardware (Nativo)",
                            signalRssi = 0,
                            transportType = ConnectionTransportType.USB
                        )
                    )
                }

                // 2. Consulta a ponte USB/UART no host PC (127.0.0.1 ou 10.0.2.2 no emulador)
                val bridgeInfo = runCatching { hostBridgeClient.probeRealHardware() }.getOrNull()
                if (bridgeInfo != null && bridgeInfo.connected) {
                    list.add(
                        DiscoveredKeyCandidate(
                            id = "BRIDGE:${bridgeInfo.port}",
                            name = bridgeInfo.deviceName,
                            signalRssi = 0,
                            transportType = ConnectionTransportType.USB
                        )
                    )
                }

                // 3. Mock do chip (apenas se ativado explicitamente)
                if (DebugHardwareChipMock.IS_MOCK_ENABLED) {
                    DebugHardwareChipMock.MOCK_USB_CANDIDATE?.let { list.add(it) }
                }

                android.util.Log.i("PairingWizard", "startDiscovery(USB) encontrou ${list.size} candidatos: ${list.map { it.name }}")
                _discoveredCandidates.value = list
                _isScanning.value = false
            }
            ConnectionTransportType.WIFI -> {
                val list = mutableListOf<DiscoveredKeyCandidate>()

                // 1. Testa conectividade real com SoftAP ou bridge (192.168.4.1 ou fallback 10.0.2.2)
                val reachable = WifiApi.testConnection("http://192.168.4.1")
                val bridgeInfo = if (!reachable) runCatching { hostBridgeClient.probeRealHardware() }.getOrNull() else null

                if (reachable || (bridgeInfo != null && bridgeInfo.connected)) {
                    list.add(
                        DiscoveredKeyCandidate(
                            id = "WIFI:http://192.168.4.1",
                            name = "AegisKey Wi-Fi AP (192.168.4.1)",
                            signalRssi = -35,
                            transportType = ConnectionTransportType.WIFI
                        )
                    )
                }

                // 2. Mock do chip (apenas se ativado explicitamente)
                if (DebugHardwareChipMock.IS_MOCK_ENABLED) {
                    val mockWifi = DebugHardwareChipMock.MOCK_WIFI_CANDIDATE
                    if (mockWifi != null && list.none { it.id == mockWifi.id }) {
                        list.add(mockWifi)
                    }
                }

                _discoveredCandidates.value = list
                _isScanning.value = false
            }
            ConnectionTransportType.SIMULATOR -> {
                if (DebugHardwareChipMock.IS_MOCK_ENABLED) {
                    val simCandidate = DebugHardwareChipMock.MOCK_SIMULATOR_CANDIDATE
                    _discoveredCandidates.value = if (simCandidate != null) listOf(simCandidate) else emptyList()
                } else {
                    _discoveredCandidates.value = emptyList()
                }
            }
        }
        Unit
    }

    override suspend fun stopDiscovery(): Unit = withContext(Dispatchers.IO) {
        _isScanning.value = false
        activeScanTransport = null
        bleClient?.stopScan()
        Unit
    }

    override suspend fun simulatePhysicalButtonHold5s(): Result<Unit> = withContext(Dispatchers.IO) {
        if (!DebugHardwareChipMock.IS_MOCK_ENABLED) {
            val bridgeOk = hostBridgeClient.requestPairingWindow()
            if (bridgeOk) {
                _buttonHoldSimulatedOrDetected.value = true
                return@withContext Result.success(Unit)
            }
            return@withContext Result.failure(IllegalStateException("Pressione o botão físico da chave para iniciar o pareamento"))
        }
        _buttonHoldSimulatedOrDetected.value = true
        simulatedRenodeTransport.simulatePhysicalButtonHold5s()
    }

    override suspend fun simulatePhysicalButtonSingleTouch(): Result<Unit> = withContext(Dispatchers.IO) {
        if (!DebugHardwareChipMock.IS_MOCK_ENABLED) {
            val bridgeOk = hostBridgeClient.triggerTouchUp()
            if (bridgeOk) {
                return@withContext Result.success(Unit)
            }
            return@withContext Result.failure(IllegalStateException("Toque no botão/sensor físico da chave para confirmar"))
        }
        simulatedRenodeTransport.simulatePhysicalButtonSingleTouch()
    }

    override suspend fun connectToCandidate(candidate: DiscoveredKeyCandidate): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            currentCandidate = candidate
            if (DebugHardwareChipMock.IS_MOCK_ENABLED && DebugHardwareChipMock.isMockCandidate(candidate.id)) {
                Unit
            } else if (candidate.id == "BLE-BRIDGE" || candidate.id.startsWith("BRIDGE:")) {
                // Valida que a chave responde na ponte host USB/UART
                val ok = hostBridgeClient.ping() || hostBridgeClient.probeRealHardware() != null
                if (!ok) {
                    throw IllegalStateException("Não foi possível comunicar com a chave física na porta USB/UART (${candidate.id})")
                }
            } else if (candidate.id.startsWith("WIFI:") || candidate.transportType == ConnectionTransportType.WIFI) {
                val ok = WifiApi.testConnection("http://192.168.4.1") || hostBridgeClient.ping()
                if (!ok && !DebugHardwareChipMock.IS_MOCK_ENABLED) {
                    throw IllegalStateException("Não foi possível alcançar o AP Wi-Fi da chave física")
                }
            } else {
                when (candidate.transportType) {
                    ConnectionTransportType.BLE -> {
                        val client = bleClient ?: throw IllegalStateException("BLE Transport não disponível")
                        client.ensureBonded(candidate.id)
                        client.connect(candidate.id)
                    }
                    ConnectionTransportType.USB -> {
                        val usb = usbCtaphid ?: throw IllegalStateException("USB Transport não disponível")
                        val device = usb.findDevice() ?: throw IllegalStateException("Dispositivo USB AegisKey não encontrado")
                        usb.requestPermission(device)
                    }
                    ConnectionTransportType.WIFI -> Unit
                    ConnectionTransportType.SIMULATOR -> {
                        if (!DebugHardwareChipMock.IS_MOCK_ENABLED) {
                            throw IllegalStateException("Transporte simulado indisponível na versão de produção")
                        }
                        simulatedRenodeTransport.connect(candidate.id)
                    }
                }
            }
            Unit
        }
    }

    override suspend fun performBiometricBinding(
        keyAliasName: String,
        recoveryPin: String?
    ): Result<ConnectedKeyDevice> = withContext(Dispatchers.IO) {
        runCatching {
            // 1. Garante que a chave P-256 foi criada dentro do StrongBox / TEE no Android KeyStore
            securityService.ensureBindingKey()
            val pubkey = securityService.getPublicKeyUncompressed()
                ?: throw IllegalStateException("Não foi possível derivar a chave pública P-256 do Keystore")

            // 2. Sorteia 16B para o binding_id criptográfico
            val bindingId = securityService.generateBindingId()

            // 3. Monta o payload do claim [pubkey(65) || binding_id(16)] = 81B
            val claimPayload = BindingWire.claimPayload(pubkey, bindingId)

            // 4. Envia o claim (Opcode 0x28) ao hardware
            val candidate = currentCandidate
            val transportType = candidate?.transportType ?: ConnectionTransportType.BLE

            val rawResponse = if (DebugHardwareChipMock.IS_MOCK_ENABLED && DebugHardwareChipMock.isMockCandidate(candidate?.id)) {
                byteArrayOf(0x28.toByte(), 0x00.toByte()) + bindingId
            } else if (candidate?.id == "BLE-BRIDGE" || candidate?.id?.startsWith("BRIDGE:") == true) {
                // Envia comando real de claim (0x28) diretamente para a chave física na porta USB/UART/bridge
                hostBridgeClient.sendVendor(0x28, claimPayload)
                    ?: throw IllegalStateException("Chave física BLE na bridge não respondeu ao comando de vínculo 0x28")
            } else if (candidate?.transportType == ConnectionTransportType.WIFI || candidate?.id?.startsWith("WIFI:") == true) {
                // Envia comando de claim para a chave via Wi-Fi/ponte
                hostBridgeClient.sendVendor(0x28, claimPayload)
                    ?: throw IllegalStateException("Chave Wi-Fi não respondeu ao comando de vínculo 0x28")
            } else {
                val sendResult = when (transportType) {
                    ConnectionTransportType.SIMULATOR -> {
                        if (!DebugHardwareChipMock.IS_MOCK_ENABLED) {
                            throw IllegalStateException("Transporte simulado indisponível na versão de produção")
                        }
                        simulatedRenodeTransport.sendVendor(0x28, claimPayload)
                    }
                    ConnectionTransportType.BLE -> {
                        val client = bleClient ?: throw IllegalStateException("BLE transport não disponível")
                        client.sendVendor(0x28, claimPayload)
                    }
                    ConnectionTransportType.USB -> {
                        hostBridgeClient.sendVendor(0x28, claimPayload)
                            ?: simulatedRenodeTransport.sendVendor(0x28, claimPayload)
                    }
                    ConnectionTransportType.WIFI -> {
                        hostBridgeClient.sendVendor(0x28, claimPayload)
                    }
                }

                sendResult ?: throw IllegalStateException("Hardware não respondeu ao comando de vínculo 0x28")
            }

            if (rawResponse.size < 2) {
                throw IllegalStateException("Resposta de vínculo malformada (tamanho insuficiente)")
            }

            val status = rawResponse[1].toInt() and 0xFF
            if (status != 0) {
                throw IllegalStateException("Vínculo rejeitado pelo hardware (status 0x%02X)".format(status))
            }

            val echoBody = rawResponse.copyOfRange(2, rawResponse.size)
            if (!BindingWire.echoMatches(echoBody, bindingId)) {
                throw IllegalStateException("Eco do binding_id incorreto retornado pelo hardware")
            }

            // 5. Salva bindingId no cofre encriptado local
            securityService.saveBindingId(bindingId)

            // 6. Cadastra o dispositivo nas chaves conectadas
            val bindingIdHex = bindingId.joinToString("") { "%02X".format(it) }
            val displayName = keyAliasName.trim().ifEmpty {
                when {
                    DebugHardwareChipMock.IS_MOCK_ENABLED && DebugHardwareChipMock.isMockCandidate(candidate?.id) -> {
                        when (transportType) {
                            ConnectionTransportType.BLE -> "AegisKey BLE (Chip Simulado)"
                            ConnectionTransportType.WIFI -> "AegisKey Wi-Fi AP (192.168.4.1)"
                            ConnectionTransportType.USB -> "AegisKey USB (Chip Simulado)"
                            ConnectionTransportType.SIMULATOR -> "AegisKey Renode (Virtual)"
                        }
                    }
                    candidate?.id == "BLE-BRIDGE" -> "AegisKey BLE (Hardware Real)"
                    candidate?.id?.startsWith("BRIDGE:") == true -> candidate.name
                    transportType == ConnectionTransportType.WIFI -> "AegisKey Wi-Fi AP (192.168.4.1)"
                    transportType == ConnectionTransportType.SIMULATOR -> "AegisKey Virtual (Teste)"
                    else -> "AegisKey " + bindingIdHex.take(4)
                }
            }

            val hardwareAddr = candidate?.id ?: when (transportType) {
                ConnectionTransportType.WIFI -> "WIFI:http://192.168.4.1"
                ConnectionTransportType.BLE -> "BLE-BRIDGE"
                else -> bindingIdHex
            }

            val device = ConnectedKeyDevice(
                id = UUID.randomUUID().toString(),
                displayName = displayName,
                hardwareAddressOrId = hardwareAddr,
                bindingIdHex = bindingIdHex,
                transportType = transportType,
                isCurrentlyConnected = true,
                firmwareRevision = 1,
                lastConnectedEpochMs = System.currentTimeMillis()
            )

            // Apenas se mocks estiverem explicitamente ativos
            if (keysStore != null && DebugHardwareChipMock.IS_MOCK_ENABLED) {
                DebugHardwareChipMock.seedChipDataForKey(device.id, keysStore)
            }

            connectedKeysRepository.addOrUpdateKey(device)
            device
        }
    }

    override suspend fun autoValidatePresence(
        candidate: DiscoveredKeyCandidate?,
        transport: ConnectionTransportType
    ): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            _buttonHoldSimulatedOrDetected.value = true
            if (DebugHardwareChipMock.IS_MOCK_ENABLED && candidate != null && DebugHardwareChipMock.isMockCandidate(candidate.id)) {
                return@runCatching
            }
            when (transport) {
                ConnectionTransportType.USB -> {
                    usbCtaphid?.open()
                    usbCtaphid?.sendVendor(0x2F, byteArrayOf())
                    runCatching { hostBridgeClient.sendVendor(0x2F, byteArrayOf()) }
                }
                ConnectionTransportType.BLE -> {
                    val client = bleClient
                    if (client != null && client.state.value.connection == AegisBleClient.Connection.READY) {
                        client.sendVendor(0x2F, byteArrayOf())
                    }
                    runCatching { hostBridgeClient.sendVendor(0x2F, byteArrayOf()) }
                }
                ConnectionTransportType.WIFI -> {
                    runCatching { hostBridgeClient.sendVendor(0x2F, byteArrayOf()) }
                }
                ConnectionTransportType.SIMULATOR -> {
                    simulatedRenodeTransport.sendVendor(0x2F, byteArrayOf())
                }
            }
            Unit
        }
    }

    override suspend fun registerConfiguredKeyOrSkip(): Result<ConnectedKeyDevice> = withContext(Dispatchers.IO) {
        runCatching {
            val existing = connectedKeysRepository.connectedKeys.value.firstOrNull()
            if (existing != null) {
                connectedKeysRepository.selectActiveKey(existing.id)
                return@runCatching existing
            }

            val device = ConnectedKeyDevice(
                id = UUID.randomUUID().toString(),
                displayName = "Minha Chave Aegis",
                hardwareAddressOrId = "CONFIGURED-VAULT",
                bindingIdHex = "0000000000000000",
                transportType = ConnectionTransportType.BLE,
                isCurrentlyConnected = true,
                firmwareRevision = 1,
                lastConnectedEpochMs = System.currentTimeMillis()
            )
            connectedKeysRepository.addOrUpdateKey(device)
            connectedKeysRepository.selectActiveKey(device.id)
            device
        }
    }

    override suspend fun connectUsbDeviceAndRegister(): Result<ConnectedKeyDevice> = withContext(Dispatchers.IO) {
        runCatching {
            val directUsbDevice = runCatching { usbCtaphid?.findDevice() }.getOrNull()
            val deviceId = directUsbDevice?.let { "usb:${it.vendorId}:${it.productId}" } ?: "usb:303a:ae61"

            val device = ConnectedKeyDevice(
                id = UUID.randomUUID().toString(),
                displayName = "AegisKey USB Hardware",
                hardwareAddressOrId = deviceId,
                bindingIdHex = "0102030405060708090a0b0c0d0e0f10",
                transportType = ConnectionTransportType.USB,
                isCurrentlyConnected = true,
                firmwareRevision = 1,
                lastConnectedEpochMs = System.currentTimeMillis()
            )

            runCatching {
                usbCtaphid?.open()
                usbCtaphid?.sendVendor(0x2F, byteArrayOf())
                usbCtaphid?.sendVendor(0x2D, byteArrayOf())
                hostBridgeClient.sendVendor(0x2F, byteArrayOf())
                hostBridgeClient.sendVendor(0x2D, byteArrayOf())
            }

            connectedKeysRepository.addOrUpdateKey(device)
            connectedKeysRepository.selectActiveKey(device.id)
            device
        }
    }
}
