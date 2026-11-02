package dev.aegiskey.app.di

import android.content.Context
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.local.ThemePreferencesStore
import dev.aegiskey.app.data.repository.ConnectedKeysRepositoryImpl
import dev.aegiskey.app.data.repository.KeyVaultRepositoryImpl
import dev.aegiskey.app.data.repository.PairingWizardRepositoryImpl
import dev.aegiskey.app.data.repository.SecureGuardRepositoryImpl
import dev.aegiskey.app.data.repository.ThemeRepositoryImpl
import dev.aegiskey.app.domain.repository.SecureGuardRepository
import dev.aegiskey.app.domain.usecase.ChangeSecureGuardPinUseCase
import dev.aegiskey.app.domain.usecase.GetSecureGuardStatusUseCase
import dev.aegiskey.app.domain.usecase.LockSecureGuardUseCase
import dev.aegiskey.app.domain.usecase.ProvisionSecureGuardUseCase
import dev.aegiskey.app.domain.usecase.RecoverSecureGuardUseCase
import dev.aegiskey.app.domain.usecase.TriggerSelectiveWipeTestUseCase
import dev.aegiskey.app.domain.usecase.UnlockSecureGuardUseCase
import dev.aegiskey.app.domain.usecase.UpdateSecureGuardPolicyUseCase
import dev.aegiskey.app.ui.viewmodel.SecureGuardViewModel
import dev.aegiskey.app.data.repository.TotpRepositoryImpl
import dev.aegiskey.app.data.system.SystemSecurityService
import dev.aegiskey.app.data.transport.BleKeyTransport
import dev.aegiskey.app.data.transport.HostUsbUartBridgeClient
import dev.aegiskey.app.data.transport.SimulatedRenodeTransport
import dev.aegiskey.app.data.transport.UsbKeyTransport
import dev.aegiskey.app.domain.repository.ConnectedKeysRepository
import dev.aegiskey.app.domain.repository.KeyVaultRepository
import dev.aegiskey.app.domain.repository.PairingWizardRepository
import dev.aegiskey.app.domain.repository.ThemeRepository
import dev.aegiskey.app.domain.repository.TotpRepository
import dev.aegiskey.app.domain.usecase.AddTotpAccountUseCase
import dev.aegiskey.app.domain.usecase.ConnectCandidateUseCase
import dev.aegiskey.app.domain.usecase.DeleteTotpAccountUseCase
import dev.aegiskey.app.domain.usecase.DeleteVaultEntryUseCase
import dev.aegiskey.app.domain.usecase.EnrollOrUpdatePivPinUseCase
import dev.aegiskey.app.domain.usecase.ExportKeyEnvelopeAegnUseCase
import dev.aegiskey.app.domain.usecase.FetchHardwareDiagnosticsUseCase
import dev.aegiskey.app.domain.usecase.GenerateAccessKeyUseCase
import dev.aegiskey.app.domain.usecase.GetActiveKeyUseCase
import dev.aegiskey.app.domain.usecase.GetAppStartDestinationUseCase
import dev.aegiskey.app.domain.usecase.GetConnectedKeysUseCase
import dev.aegiskey.app.domain.usecase.GetThemePreferenceUseCase
import dev.aegiskey.app.domain.usecase.GetTotpAccountsUseCase
import dev.aegiskey.app.domain.usecase.GetVaultEntriesUseCase
import dev.aegiskey.app.domain.usecase.IncrementHotpCounterUseCase
import dev.aegiskey.app.domain.usecase.PerformBiometricBindingUseCase
import dev.aegiskey.app.domain.usecase.RefreshTotpCodesUseCase
import dev.aegiskey.app.domain.usecase.RefreshVaultUseCase
import dev.aegiskey.app.domain.usecase.RemoveKeyUseCase
import dev.aegiskey.app.domain.usecase.RenameKeyUseCase
import dev.aegiskey.app.domain.usecase.ResetHardwareVaultUseCase
import dev.aegiskey.app.domain.usecase.RunHealthCheckUseCase
import dev.aegiskey.app.domain.usecase.SelectActiveKeyUseCase
import dev.aegiskey.app.domain.usecase.SetDynamicColorsUseCase
import dev.aegiskey.app.domain.usecase.SetThemeModeUseCase
import dev.aegiskey.app.domain.usecase.SignChallengeOrTransactionUseCase
import dev.aegiskey.app.domain.usecase.SimulateButtonHoldUseCase
import dev.aegiskey.app.domain.usecase.SimulateButtonSingleTouchUseCase
import dev.aegiskey.app.domain.usecase.StartDiscoveryUseCase
import dev.aegiskey.app.domain.usecase.StopDiscoveryUseCase
import dev.aegiskey.app.domain.usecase.TickTotpTimerUseCase
import dev.aegiskey.app.domain.usecase.UpdateKeySecurityTogglesUseCase
import dev.aegiskey.app.ui.viewmodel.AppThemeViewModel
import dev.aegiskey.app.ui.viewmodel.ConnectedKeysViewModel
import dev.aegiskey.app.ui.viewmodel.KeyVaultViewModel
import dev.aegiskey.app.ui.viewmodel.OnboardingWizardViewModel
import dev.aegiskey.app.ui.viewmodel.TotpAuthenticatorViewModel
import dev.aegiskey.app.usb.UsbCtaphid

/**
 * Container de Injeção de Dependências manual limpo e desacoplado.
 * Provê instâncias singleton de fontes locais, segurança do sistema,
 * transportes de hardware, repositórios de domínio e casos de uso da aplicação.
 */
class AppContainer(val context: Context) {

    // --- Fontes Locais & Segurança ---
    val keysStore: EncryptedKeysStore by lazy { EncryptedKeysStore(context) }
    val themeStore: ThemePreferencesStore by lazy { ThemePreferencesStore(context) }
    val securityService: SystemSecurityService by lazy { SystemSecurityService(context) }

    // --- Transportes de Hardware & Simulação ---
    val bleClient: AegisBleClient by lazy { AegisBleClient(context) }
    val usbCtaphid: UsbCtaphid by lazy {
        UsbCtaphid(context).apply {
            onHardwareDetachedListener = {
                (secureGuardRepository as? SecureGuardRepositoryImpl)?.onHardwareDetached()
                keyVaultRepository.clearMemoryVault()
            }
        }
    }
    val simulatedRenodeTransport: SimulatedRenodeTransport by lazy { SimulatedRenodeTransport() }
    val hostUsbUartBridgeClient: HostUsbUartBridgeClient by lazy { HostUsbUartBridgeClient() }

    val bleTransport: BleKeyTransport by lazy { BleKeyTransport(bleClient, hostUsbUartBridgeClient) }
    val usbTransport: UsbKeyTransport by lazy { UsbKeyTransport(usbCtaphid, hostUsbUartBridgeClient) }

    // --- Repositórios ---
    val connectedKeysRepository: ConnectedKeysRepository by lazy {
        ConnectedKeysRepositoryImpl(
            keysStore = keysStore,
            usbKeyTransport = usbTransport,
            bleKeyTransport = bleTransport
        )
    }

    val pairingWizardRepository: PairingWizardRepository by lazy {
        PairingWizardRepositoryImpl(
            bleClient = bleClient,
            usbCtaphid = usbCtaphid,
            hostBridgeClient = hostUsbUartBridgeClient,
            simulatedRenodeTransport = simulatedRenodeTransport,
            securityService = securityService,
            connectedKeysRepository = connectedKeysRepository,
            keysStore = keysStore
        )
    }

    val secureGuardRepository: SecureGuardRepository by lazy {
        SecureGuardRepositoryImpl(
            hostBridgeClient = hostUsbUartBridgeClient,
            usbCtaphid = usbCtaphid,
            bleKeyTransport = bleTransport,
            connectedKeysRepository = connectedKeysRepository
        ).also { repo ->
            usbCtaphid.addOnHardwareDetachedListener {
                repo.onHardwareDetached()
            }
        }
    }

    val keyVaultRepository: KeyVaultRepository by lazy {
        KeyVaultRepositoryImpl(
            keysStore = keysStore,
            usbKeyTransport = usbTransport,
            bleKeyTransport = bleTransport,
            simulatedRenodeTransport = simulatedRenodeTransport,
            connectedKeysRepository = connectedKeysRepository,
            secureGuardRepository = secureGuardRepository
        ).also { repo ->
            usbCtaphid.addOnHardwareDetachedListener {
                repo.clearMemoryVault()
            }
        }
    }

    val totpRepository: TotpRepository by lazy {
        TotpRepositoryImpl(
            keysStore = keysStore,
            usbKeyTransport = usbTransport,
            bleKeyTransport = bleTransport,
            simulatedRenodeTransport = simulatedRenodeTransport,
            connectedKeysRepository = connectedKeysRepository
        )
    }

    val themeRepository: ThemeRepository by lazy {
        ThemeRepositoryImpl(themeStore)
    }

    // --- Casos de Uso: Secure Guard (Zero-Trust On-Device Authority) ---
    val getSecureGuardStatusUseCase: GetSecureGuardStatusUseCase by lazy {
        GetSecureGuardStatusUseCase(secureGuardRepository)
    }
    val provisionSecureGuardUseCase: ProvisionSecureGuardUseCase by lazy {
        ProvisionSecureGuardUseCase(secureGuardRepository)
    }
    val unlockSecureGuardUseCase: UnlockSecureGuardUseCase by lazy {
        UnlockSecureGuardUseCase(secureGuardRepository)
    }
    val lockSecureGuardUseCase: LockSecureGuardUseCase by lazy {
        LockSecureGuardUseCase(secureGuardRepository)
    }
    val changeSecureGuardPinUseCase: ChangeSecureGuardPinUseCase by lazy {
        ChangeSecureGuardPinUseCase(secureGuardRepository)
    }
    val recoverSecureGuardUseCase: RecoverSecureGuardUseCase by lazy {
        RecoverSecureGuardUseCase(secureGuardRepository)
    }
    val updateSecureGuardPolicyUseCase: UpdateSecureGuardPolicyUseCase by lazy {
        UpdateSecureGuardPolicyUseCase(secureGuardRepository)
    }
    val triggerSelectiveWipeTestUseCase: TriggerSelectiveWipeTestUseCase by lazy {
        TriggerSelectiveWipeTestUseCase(secureGuardRepository)
    }

    // --- Casos de Uso: Inicialização e Navegação ---
    val getAppStartDestinationUseCase: GetAppStartDestinationUseCase by lazy {
        GetAppStartDestinationUseCase(connectedKeysRepository)
    }

    // --- Casos de Uso: Pareamento & Wizard ---
    val startDiscoveryUseCase: StartDiscoveryUseCase by lazy {
        StartDiscoveryUseCase(pairingWizardRepository)
    }
    val stopDiscoveryUseCase: StopDiscoveryUseCase by lazy {
        StopDiscoveryUseCase(pairingWizardRepository)
    }
    val connectCandidateUseCase: ConnectCandidateUseCase by lazy {
        ConnectCandidateUseCase(pairingWizardRepository)
    }
    val simulateButtonHoldUseCase: SimulateButtonHoldUseCase by lazy {
        SimulateButtonHoldUseCase(pairingWizardRepository)
    }
    val simulateButtonSingleTouchUseCase: SimulateButtonSingleTouchUseCase by lazy {
        SimulateButtonSingleTouchUseCase(pairingWizardRepository)
    }
    val performBiometricBindingUseCase: PerformBiometricBindingUseCase by lazy {
        PerformBiometricBindingUseCase(pairingWizardRepository)
    }

    // --- Casos de Uso: Dispositivos Pareados ---
    val getConnectedKeysUseCase: GetConnectedKeysUseCase by lazy {
        GetConnectedKeysUseCase(connectedKeysRepository)
    }
    val getActiveKeyUseCase: GetActiveKeyUseCase by lazy {
        GetActiveKeyUseCase(connectedKeysRepository)
    }
    val selectActiveKeyUseCase: SelectActiveKeyUseCase by lazy {
        SelectActiveKeyUseCase(connectedKeysRepository)
    }
    val updateKeySecurityTogglesUseCase: UpdateKeySecurityTogglesUseCase by lazy {
        UpdateKeySecurityTogglesUseCase(connectedKeysRepository)
    }
    val renameKeyUseCase: RenameKeyUseCase by lazy {
        RenameKeyUseCase(connectedKeysRepository)
    }
    val removeKeyUseCase: RemoveKeyUseCase by lazy {
        RemoveKeyUseCase(connectedKeysRepository)
    }

    // --- Casos de Uso: Cofre de Chaves ---
    val getVaultEntriesUseCase: GetVaultEntriesUseCase by lazy {
        GetVaultEntriesUseCase(keyVaultRepository)
    }
    val refreshVaultUseCase: RefreshVaultUseCase by lazy {
        RefreshVaultUseCase(keyVaultRepository)
    }
    val generateAccessKeyUseCase: GenerateAccessKeyUseCase by lazy {
        GenerateAccessKeyUseCase(keyVaultRepository)
    }
    val deleteVaultEntryUseCase: DeleteVaultEntryUseCase by lazy {
        DeleteVaultEntryUseCase(keyVaultRepository)
    }
    val resetHardwareVaultUseCase: ResetHardwareVaultUseCase by lazy {
        ResetHardwareVaultUseCase(keyVaultRepository)
    }
    val runHealthCheckUseCase: RunHealthCheckUseCase by lazy {
        RunHealthCheckUseCase(keyVaultRepository)
    }
    val signChallengeOrTransactionUseCase: SignChallengeOrTransactionUseCase by lazy {
        SignChallengeOrTransactionUseCase(keyVaultRepository)
    }
    val exportKeyEnvelopeAegnUseCase: ExportKeyEnvelopeAegnUseCase by lazy {
        ExportKeyEnvelopeAegnUseCase(keyVaultRepository)
    }
    val enrollOrUpdatePivPinUseCase: EnrollOrUpdatePivPinUseCase by lazy {
        EnrollOrUpdatePivPinUseCase(keyVaultRepository)
    }
    val fetchHardwareDiagnosticsUseCase: FetchHardwareDiagnosticsUseCase by lazy {
        FetchHardwareDiagnosticsUseCase(keyVaultRepository)
    }

    // --- Casos de Uso: TOTP & Contas ---
    val getTotpAccountsUseCase: GetTotpAccountsUseCase by lazy {
        GetTotpAccountsUseCase(totpRepository)
    }
    val refreshTotpCodesUseCase: RefreshTotpCodesUseCase by lazy {
        RefreshTotpCodesUseCase(totpRepository)
    }
    val addTotpAccountUseCase: AddTotpAccountUseCase by lazy {
        AddTotpAccountUseCase(totpRepository)
    }
    val deleteTotpAccountUseCase: DeleteTotpAccountUseCase by lazy {
        DeleteTotpAccountUseCase(totpRepository)
    }
    val incrementHotpCounterUseCase: IncrementHotpCounterUseCase by lazy {
        IncrementHotpCounterUseCase(totpRepository)
    }
    val tickTotpTimerUseCase: TickTotpTimerUseCase by lazy {
        TickTotpTimerUseCase(totpRepository)
    }

    // --- Casos de Uso: Tema & Preferências ---
    val getThemePreferenceUseCase: GetThemePreferenceUseCase by lazy {
        GetThemePreferenceUseCase(themeRepository)
    }
    val setThemeModeUseCase: SetThemeModeUseCase by lazy {
        SetThemeModeUseCase(themeRepository)
    }
    val setDynamicColorsUseCase: SetDynamicColorsUseCase by lazy {
        SetDynamicColorsUseCase(themeRepository)
    }

    // --- ViewModels Retidos (Persistem contra recriações da Activity e diálogos USB) ---
    val appThemeViewModel: AppThemeViewModel by lazy {
        AppThemeViewModel(
            getThemePreferenceUseCase = getThemePreferenceUseCase,
            setThemeModeUseCase = setThemeModeUseCase,
            setDynamicColorsUseCase = setDynamicColorsUseCase,
        )
    }

    val onboardingWizardViewModel: OnboardingWizardViewModel by lazy {
        OnboardingWizardViewModel(
            pairingWizardRepository = pairingWizardRepository,
            startDiscoveryUseCase = startDiscoveryUseCase,
            stopDiscoveryUseCase = stopDiscoveryUseCase,
            connectCandidateUseCase = connectCandidateUseCase,
            simulateButtonHoldUseCase = simulateButtonHoldUseCase,
            simulateButtonSingleTouchUseCase = simulateButtonSingleTouchUseCase,
            performBiometricBindingUseCase = performBiometricBindingUseCase,
        )
    }

    val connectedKeysViewModel: ConnectedKeysViewModel by lazy {
        ConnectedKeysViewModel(
            getConnectedKeysUseCase = getConnectedKeysUseCase,
            getActiveKeyUseCase = getActiveKeyUseCase,
            selectActiveKeyUseCase = selectActiveKeyUseCase,
            updateKeySecurityTogglesUseCase = updateKeySecurityTogglesUseCase,
            renameKeyUseCase = renameKeyUseCase,
            removeKeyUseCase = removeKeyUseCase,
            connectedKeysRepository = connectedKeysRepository,
        )
    }

    val keyVaultViewModel: KeyVaultViewModel by lazy {
        KeyVaultViewModel(
            getActiveKeyUseCase = getActiveKeyUseCase,
            getVaultEntriesUseCase = getVaultEntriesUseCase,
            refreshVaultUseCase = refreshVaultUseCase,
            generateAccessKeyUseCase = generateAccessKeyUseCase,
            deleteVaultEntryUseCase = deleteVaultEntryUseCase,
            runHealthCheckUseCase = runHealthCheckUseCase,
            updateKeySecurityTogglesUseCase = updateKeySecurityTogglesUseCase,
            simulateButtonSingleTouchUseCase = simulateButtonSingleTouchUseCase,
            securityService = securityService,
            signChallengeOrTransactionUseCase = signChallengeOrTransactionUseCase,
            exportKeyEnvelopeAegnUseCase = exportKeyEnvelopeAegnUseCase,
            enrollOrUpdatePivPinUseCase = enrollOrUpdatePivPinUseCase,
            fetchHardwareDiagnosticsUseCase = fetchHardwareDiagnosticsUseCase,
            resetHardwareVaultUseCase = resetHardwareVaultUseCase,
            keysStore = keysStore,
            secureGuardRepository = secureGuardRepository,
        )
    }

    val totpAuthenticatorViewModel: TotpAuthenticatorViewModel by lazy {
        TotpAuthenticatorViewModel(
            getActiveKeyUseCase = getActiveKeyUseCase,
            getTotpAccountsUseCase = getTotpAccountsUseCase,
            refreshTotpCodesUseCase = refreshTotpCodesUseCase,
            addTotpAccountUseCase = addTotpAccountUseCase,
            deleteTotpAccountUseCase = deleteTotpAccountUseCase,
            tickTotpTimerUseCase = tickTotpTimerUseCase,
            securityService = securityService,
            incrementHotpCounterUseCase = incrementHotpCounterUseCase,
            keysStore = keysStore,
        )
    }

    val secureGuardViewModel: SecureGuardViewModel by lazy {
        SecureGuardViewModel(
            getSecureGuardStatusUseCase = getSecureGuardStatusUseCase,
            provisionSecureGuardUseCase = provisionSecureGuardUseCase,
            unlockSecureGuardUseCase = unlockSecureGuardUseCase,
            lockSecureGuardUseCase = lockSecureGuardUseCase,
            changeSecureGuardPinUseCase = changeSecureGuardPinUseCase,
            recoverSecureGuardUseCase = recoverSecureGuardUseCase,
            updateSecureGuardPolicyUseCase = updateSecureGuardPolicyUseCase,
            triggerSelectiveWipeTestUseCase = triggerSelectiveWipeTestUseCase,
            repository = secureGuardRepository
        )
    }

    companion object {
        @Volatile
        private var instance: AppContainer? = null

        fun getInstance(context: Context): AppContainer =
            instance ?: synchronized(this) {
                instance ?: AppContainer(context.applicationContext).also { instance = it }
            }
    }
}
