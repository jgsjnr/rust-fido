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

    private var activeScanTransport: ConnectionTransportType? = null
    private var currentCandidate: DiscoveredKeyCandidate? = null

    private fun buildBleCandidates(devices: List<AegisBleClient.FoundDevice>): List<DiscoveredKeyCandidate> {
        val realCandidates = devices.map { dev ->
            DiscoveredKeyCandidate(
                id = dev.address,
                name = dev.name.ifBlank { "Chave Bluetooth (${dev.address})" },
                signalRssi = dev.rssi,
                transportType = ConnectionTransportType.BLE
            )
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

                // Ponto de acesso direto ou rede Wi-Fi da AegisKey
                list.add(
                    DiscoveredKeyCandidate(
                        id = "WIFI:http://192.168.4.1",
                        name = "AegisKey Wi-Fi (192.168.4.1)",
                        signalRssi = -35,
                        transportType = ConnectionTransportType.WIFI
                    )
                )

                _discoveredCandidates.value = list
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
            // Em ambiente com chave real na ponte, tenta solicitar janela de pareamento na UART
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
            // Em ambiente de bancada, avisa a ponte ou requer toque no sensor físico
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
            } else if (candidate.id.startsWith("BRIDGE:")) {
                // Valida que a chave responde na ponte host USB/UART
                val ok = hostBridgeClient.ping() || hostBridgeClient.probeRealHardware() != null
                if (!ok) {
                    throw IllegalStateException("Não foi possível comunicar com a chave física na porta USB/UART (${candidate.id})")
                }
            } else if (candidate.id.startsWith("WIFI:") || candidate.transportType == ConnectionTransportType.WIFI) {
                // Tenta verificar disponibilidade do AP Wi-Fi
                runCatching { WifiApi.getWifiNets("http://192.168.4.1") }
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
            } else if (candidate?.id?.startsWith("BRIDGE:") == true) {
                // Envia comando real de claim (0x28) diretamente para a chave física na porta USB/UART
                hostBridgeClient.sendVendor(0x28, claimPayload)
                    ?: throw IllegalStateException("Chave física no USB/UART não respondeu ao comando de vínculo 0x28")
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
                    DebugHardwareChipMock.IS_MOCK_ENABLED && DebugHardwareChipMock.isMockCandidate(candidate?.id) -> "AegisKey FIDO2 (Chip Debug)"
                    candidate?.id?.startsWith("BRIDGE:") == true -> candidate.name
                    transportType == ConnectionTransportType.WIFI -> "AegisKey Wi-Fi (192.168.4.1)"
                    transportType == ConnectionTransportType.SIMULATOR -> "AegisKey Virtual (Teste)"
                    else -> "AegisKey " + bindingIdHex.take(4)
                }
            }

            val hardwareAddr = candidate?.id ?: (if (transportType == ConnectionTransportType.WIFI) "WIFI:http://192.168.4.1" else bindingIdHex)

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
}
