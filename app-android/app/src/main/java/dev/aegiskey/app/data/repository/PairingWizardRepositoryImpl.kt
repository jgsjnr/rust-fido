package dev.aegiskey.app.data.repository

import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.data.debug.DebugHardwareChipMock
import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.system.SystemSecurityService
import dev.aegiskey.app.data.transport.SimulatedRenodeTransport
import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.DiscoveredKeyCandidate
import dev.aegiskey.app.domain.model.TotpAccountItem
import dev.aegiskey.app.domain.model.VaultKeyEntry
import dev.aegiskey.app.domain.repository.ConnectedKeysRepository
import dev.aegiskey.app.domain.repository.PairingWizardRepository
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
        return if (DebugHardwareChipMock.isDebugMode) {
            val mockBle = DebugHardwareChipMock.MOCK_BLE_CANDIDATE
            if (realCandidates.none { it.id == mockBle.id }) {
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
                // Emite imediatamente candidatos conhecidos (bonded + mock) sem tela vazia
                val currentDevices = bleClient?.devices?.value ?: emptyList()
                _discoveredCandidates.value = buildBleCandidates(currentDevices)
                runCatching { bleClient?.startScan() }
            }
            ConnectionTransportType.USB -> {
                val device = runCatching { usbCtaphid?.findDevice() }.getOrNull()
                val list = mutableListOf<DiscoveredKeyCandidate>()
                if (device != null) {
                    list.add(
                        DiscoveredKeyCandidate(
                            id = "usb:${device.vendorId}:${device.productId}",
                            name = "AegisKey USB Hardware",
                            signalRssi = 0,
                            transportType = ConnectionTransportType.USB
                        )
                    )
                }
                if (DebugHardwareChipMock.isDebugMode) {
                    list.add(DebugHardwareChipMock.MOCK_USB_CANDIDATE)
                }
                _discoveredCandidates.value = list
            }
            ConnectionTransportType.SIMULATOR -> {
                _discoveredCandidates.value = listOf(
                    if (DebugHardwareChipMock.isDebugMode) DebugHardwareChipMock.MOCK_SIMULATOR_CANDIDATE
                    else DiscoveredKeyCandidate(
                        id = "tcp:10.0.2.2:5678",
                        name = "AegisKey Renode Simulator",
                        signalRssi = -25,
                        transportType = ConnectionTransportType.SIMULATOR
                    )
                )
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
        _buttonHoldSimulatedOrDetected.value = true
        simulatedRenodeTransport.simulatePhysicalButtonHold5s()
    }

    override suspend fun simulatePhysicalButtonSingleTouch(): Result<Unit> = withContext(Dispatchers.IO) {
        simulatedRenodeTransport.simulatePhysicalButtonSingleTouch()
    }

    override suspend fun connectToCandidate(candidate: DiscoveredKeyCandidate): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            currentCandidate = candidate
            if (DebugHardwareChipMock.isMockCandidate(candidate.id)) {
                // Candidato Mock do Chip ESP32: conexão simulada instantânea
                Unit
            } else {
                when (candidate.transportType) {
                    ConnectionTransportType.BLE -> {
                        runCatching {
                            bleClient?.ensureBonded(candidate.id)
                            bleClient?.connect(candidate.id)
                        }
                    }
                    ConnectionTransportType.USB -> {
                        runCatching {
                            val device = usbCtaphid?.findDevice()
                            if (device != null) {
                                usbCtaphid?.requestPermission(device)
                            }
                        }
                    }
                    ConnectionTransportType.SIMULATOR -> {
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

            val rawResponse = if (DebugHardwareChipMock.isMockCandidate(candidate?.id)) {
                // Eco imediato determinístico do chip físico simulado
                byteArrayOf(0x28.toByte(), 0x00.toByte()) + bindingId
            } else {
                val sendResult = runCatching {
                    when (transportType) {
                        ConnectionTransportType.SIMULATOR -> simulatedRenodeTransport.sendVendor(0x28, claimPayload)
                        ConnectionTransportType.BLE -> bleClient?.sendVendor(0x28, claimPayload)
                        ConnectionTransportType.USB -> simulatedRenodeTransport.sendVendor(0x28, claimPayload)
                    }
                }.getOrNull()

                sendResult ?: if (DebugHardwareChipMock.isDebugMode) {
                    byteArrayOf(0x28.toByte(), 0x00.toByte()) + bindingId
                } else {
                    throw IllegalStateException("Hardware não respondeu ao comando de vínculo 0x28")
                }
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
                    DebugHardwareChipMock.isMockCandidate(candidate?.id) -> "AegisKey FIDO2 (Chip Debug)"
                    transportType == ConnectionTransportType.SIMULATOR -> "AegisKey Virtual (Teste)"
                    else -> "AegisKey " + bindingIdHex.take(4)
                }
            }

            val device = ConnectedKeyDevice(
                id = UUID.randomUUID().toString(),
                displayName = displayName,
                hardwareAddressOrId = candidate?.id ?: (if (transportType == ConnectionTransportType.SIMULATOR) "tcp:10.0.2.2:5678" else bindingIdHex),
                bindingIdHex = bindingIdHex,
                transportType = transportType,
                isCurrentlyConnected = true,
                firmwareRevision = 1,
                lastConnectedEpochMs = System.currentTimeMillis()
            )

            // Em modo debug (ou simulador), injeta dados ricos e realistas simulando a NVS do chip
            if (keysStore != null && (DebugHardwareChipMock.isDebugMode || transportType == ConnectionTransportType.SIMULATOR)) {
                DebugHardwareChipMock.seedChipDataForKey(device.id, keysStore)
            }

            connectedKeysRepository.addOrUpdateKey(device)
            device
        }
    }
}
