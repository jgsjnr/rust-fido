package dev.aegiskey.app.data.repository

import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.data.system.SystemSecurityService
import dev.aegiskey.app.data.transport.SimulatedRenodeTransport
import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.DiscoveredKeyCandidate
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
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.IO)
) : PairingWizardRepository {

    private val _discoveredCandidates = MutableStateFlow<List<DiscoveredKeyCandidate>>(emptyList())
    override val discoveredCandidates: StateFlow<List<DiscoveredKeyCandidate>> = _discoveredCandidates.asStateFlow()

    private val _isScanning = MutableStateFlow(false)
    override val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()

    private val _buttonHoldSimulatedOrDetected = MutableStateFlow(false)
    override val buttonHoldSimulatedOrDetected: StateFlow<Boolean> = _buttonHoldSimulatedOrDetected.asStateFlow()

    private var currentCandidate: DiscoveredKeyCandidate? = null

    init {
        // Observa dispositivos encontrados pelo AegisBleClient se disponível
        bleClient?.state?.onEach { uiState ->
            if (_isScanning.value && currentCandidate?.transportType != ConnectionTransportType.SIMULATOR) {
                val bleCandidates = uiState.devices.map {
                    DiscoveredKeyCandidate(
                        id = it.address,
                        name = it.name.ifBlank { "AegisKey BLE" },
                        signalRssi = -55,
                        transportType = ConnectionTransportType.BLE
                    )
                }
                _discoveredCandidates.value = bleCandidates
            }
        }?.launchIn(scope)

        simulatedRenodeTransport.buttonHoldSimulated.onEach { hold ->
            if (hold) _buttonHoldSimulatedOrDetected.value = true
        }.launchIn(scope)
    }

    override suspend fun startDiscovery(transport: ConnectionTransportType): Unit = withContext(Dispatchers.IO) {
        _isScanning.value = true
        _buttonHoldSimulatedOrDetected.value = false
        _discoveredCandidates.value = emptyList()

        when (transport) {
            ConnectionTransportType.BLE -> {
                bleClient?.startScan()
            }
            ConnectionTransportType.USB -> {
                val device = usbCtaphid?.findDevice()
                if (device != null) {
                    _discoveredCandidates.value = listOf(
                        DiscoveredKeyCandidate(
                            id = "usb:${device.vendorId}:${device.productId}",
                            name = "AegisKey USB Hardware",
                            signalRssi = 0,
                            transportType = ConnectionTransportType.USB
                        )
                    )
                }
            }
            ConnectionTransportType.SIMULATOR -> {
                _discoveredCandidates.value = listOf(
                    DiscoveredKeyCandidate(
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
            when (candidate.transportType) {
                ConnectionTransportType.BLE -> {
                    bleClient?.ensureBonded(candidate.id)
                    bleClient?.connect(candidate.id)
                }
                ConnectionTransportType.USB -> {
                    val device = usbCtaphid?.findDevice()
                    if (device != null) {
                        usbCtaphid?.requestPermission(device)
                    }
                }
                ConnectionTransportType.SIMULATOR -> {
                    simulatedRenodeTransport.connect(candidate.id)
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

            val rawResponse = when (transportType) {
                ConnectionTransportType.SIMULATOR -> {
                    simulatedRenodeTransport.sendVendor(0x28, claimPayload)
                }
                ConnectionTransportType.BLE -> {
                    bleClient?.sendVendor(0x28, claimPayload)
                }
                ConnectionTransportType.USB -> {
                    simulatedRenodeTransport.sendVendor(0x28, claimPayload)
                }
            } ?: throw IllegalStateException("Hardware não respondeu ao comando de vínculo 0x28")

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
            val displayName = keyAliasName.trim().ifEmpty { "AegisKey " + bindingIdHex.take(4) }

            val device = ConnectedKeyDevice(
                id = UUID.randomUUID().toString(),
                displayName = displayName,
                hardwareAddressOrId = candidate?.id ?: bindingIdHex,
                bindingIdHex = bindingIdHex,
                transportType = transportType,
                isCurrentlyConnected = true,
                firmwareRevision = 1,
                lastConnectedEpochMs = System.currentTimeMillis()
            )

            connectedKeysRepository.addOrUpdateKey(device)
            device
        }
    }
}
