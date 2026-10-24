package dev.aegiskey.app.di

import android.content.Context
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.data.local.EncryptedKeysStore
import dev.aegiskey.app.data.local.ThemePreferencesStore
import dev.aegiskey.app.data.repository.ConnectedKeysRepositoryImpl
import dev.aegiskey.app.data.repository.KeyVaultRepositoryImpl
import dev.aegiskey.app.data.repository.PairingWizardRepositoryImpl
import dev.aegiskey.app.data.repository.ThemeRepositoryImpl
import dev.aegiskey.app.data.repository.TotpRepositoryImpl
import dev.aegiskey.app.data.system.SystemSecurityService
import dev.aegiskey.app.data.transport.BleKeyTransport
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
import dev.aegiskey.app.domain.usecase.GenerateAccessKeyUseCase
import dev.aegiskey.app.domain.usecase.GetActiveKeyUseCase
import dev.aegiskey.app.domain.usecase.GetAppStartDestinationUseCase
import dev.aegiskey.app.domain.usecase.GetConnectedKeysUseCase
import dev.aegiskey.app.domain.usecase.GetThemePreferenceUseCase
import dev.aegiskey.app.domain.usecase.GetTotpAccountsUseCase
import dev.aegiskey.app.domain.usecase.GetVaultEntriesUseCase
import dev.aegiskey.app.domain.usecase.PerformBiometricBindingUseCase
import dev.aegiskey.app.domain.usecase.RefreshTotpCodesUseCase
import dev.aegiskey.app.domain.usecase.RefreshVaultUseCase
import dev.aegiskey.app.domain.usecase.RemoveKeyUseCase
import dev.aegiskey.app.domain.usecase.RenameKeyUseCase
import dev.aegiskey.app.domain.usecase.RunHealthCheckUseCase
import dev.aegiskey.app.domain.usecase.SelectActiveKeyUseCase
import dev.aegiskey.app.domain.usecase.SetDynamicColorsUseCase
import dev.aegiskey.app.domain.usecase.SetThemeModeUseCase
import dev.aegiskey.app.domain.usecase.SimulateButtonHoldUseCase
import dev.aegiskey.app.domain.usecase.SimulateButtonSingleTouchUseCase
import dev.aegiskey.app.domain.usecase.StartDiscoveryUseCase
import dev.aegiskey.app.domain.usecase.StopDiscoveryUseCase
import dev.aegiskey.app.domain.usecase.TickTotpTimerUseCase
import dev.aegiskey.app.domain.usecase.UpdateKeySecurityTogglesUseCase
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
    val usbCtaphid: UsbCtaphid by lazy { UsbCtaphid(context) }
    val simulatedRenodeTransport: SimulatedRenodeTransport by lazy { SimulatedRenodeTransport() }

    val bleTransport: BleKeyTransport by lazy { BleKeyTransport(bleClient) }
    val usbTransport: UsbKeyTransport by lazy { UsbKeyTransport(usbCtaphid) }

    // --- Repositórios ---
    val connectedKeysRepository: ConnectedKeysRepository by lazy {
        ConnectedKeysRepositoryImpl(keysStore)
    }

    val pairingWizardRepository: PairingWizardRepository by lazy {
        PairingWizardRepositoryImpl(
            bleClient = bleClient,
            usbCtaphid = usbCtaphid,
            simulatedRenodeTransport = simulatedRenodeTransport,
            securityService = securityService,
            connectedKeysRepository = connectedKeysRepository
        )
    }

    val keyVaultRepository: KeyVaultRepository by lazy {
        KeyVaultRepositoryImpl(
            keysStore = keysStore,
            bleClient = bleClient,
            simulatedRenodeTransport = simulatedRenodeTransport,
            connectedKeysRepository = connectedKeysRepository
        )
    }

    val totpRepository: TotpRepository by lazy {
        TotpRepositoryImpl(
            keysStore = keysStore,
            bleClient = bleClient,
            simulatedRenodeTransport = simulatedRenodeTransport,
            connectedKeysRepository = connectedKeysRepository
        )
    }

    val themeRepository: ThemeRepository by lazy {
        ThemeRepositoryImpl(themeStore)
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
    val runHealthCheckUseCase: RunHealthCheckUseCase by lazy {
        RunHealthCheckUseCase(keyVaultRepository)
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

    companion object {
        @Volatile
        private var instance: AppContainer? = null

        fun getInstance(context: Context): AppContainer =
            instance ?: synchronized(this) {
                instance ?: AppContainer(context.applicationContext).also { instance = it }
            }
    }
}
