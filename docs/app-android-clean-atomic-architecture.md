# Arquitetura Clean Architecture + SOLID + Atomic Design do App Android AegisKey

> **Documento Técnico de Engenharia de Software e Segurança Mobile**  
> **Escopo:** Aplicativo Android (`app-android/`) & Ponte Nativa Rust UniFFI (`crates/uniffi-bridge/`)  
> **Padrões:** Clean Architecture, SOLID, Atomic Design (Material 3), Fail-Closed Security, Zeroize Cryptography  
> **Status:** Implementado e Validado

---

## 1. Visão Geral e Princípios Arquiteturais

O aplicativo móvel **AegisKey Android** foi reestruturado para unir o mais alto nível de rigor criptográfico e segurança de hardware com uma experiência de usuário (UX) fluida, moderna e não intimidadora. A arquitetura adota a **Clean Architecture** em camadas estritas combinada com os princípios **SOLID** e a metodologia **Atomic Design** sobre o **Google Material 3 (Material You)**.

Toda a lógica sensível, empacotamento de protocolos criptográficos (`AEGN` v1), derivação de chaves e fragmentação BLE reside na camada nativa em Rust (`crates/uniffi-bridge`), exposta ao Kotlin por meio de bindings seguros gerados pelo **Mozilla UniFFI**.

```
+--------------------------------------------------------------------------+
|                        CAMADA DE APRESENTAÇÃO UI                         |
|   Screens (Compose) -> Templates -> Organisms -> Molecules -> Atoms      |
+--------------------------------------------------------------------------+
                                    | (StateFlow / Eventos)
                                    v
+--------------------------------------------------------------------------+
|                          CAMADA DE VIEWMODELS                            |
|     StateFlows reativos, orquestração de UI State, lifecycle aware       |
+--------------------------------------------------------------------------+
                                    | (Invocação de Casos de Uso)
                                    v
+--------------------------------------------------------------------------+
|                            CAMADA DE DOMÍNIO                             |
|    UseCases especializados (SRP) + Interfaces de Repositório + Modelos    |
+--------------------------------------------------------------------------+
                                    | (Inversão de Dependência - DIP)
                                    v
+--------------------------------------------------------------------------+
|                            CAMADA DE DADOS                               |
|   Implementações de Repositório + Armazenamento Seguro + Transportes     |
|   (EncryptedSharedPreferences, AndroidKeyStore, BLE, USB, Simulador)     |
+--------------------------------------------------------------------------+
                                    | (JNI via UniFFI)
                                    v
+--------------------------------------------------------------------------+
|                         CAMADA NATIVA (RUST)                             |
|      libaegis_bridge.so: Envelopes AEGN v1, Fragmentador BLE, TOTP      |
+--------------------------------------------------------------------------+
```

---

## 2. Diagrama de Arquitetura em Camadas (Mermaid)

O diagrama abaixo detalha o fluxo de controle, dados e dependências entre os módulos Kotlin e a biblioteca nativa em Rust. Observe que a seta de dependência sempre aponta para o centro (Domínio), respeitando a Regra de Dependência da Clean Architecture.

```mermaid
flowchart TD
    subgraph PresentationLayer["1. Camada de Apresentação (Atomic UI)"]
        direction TB
        subgraph AtomicUI["Atomic Design (Material 3)"]
            Atoms["Átomos\n(PrimaryNextButton, StepProgressDotsAtom,\nTotpCountdownRingAtom, AegisSwitchAtom)"]
            Molecules["Moléculas\n(ConnectedKeyCardMolecule,\nPhysicalButtonPromptCardMolecule,\nTotpCodeCardMolecule, SettingToggleRowMolecule)"]
            Organisms["Organismos\n(AddTotpAccountDialogOrganism,\nKeyGenerationDialogOrganism, ThemeSelectorOrganism)"]
            Templates["Templates\n(WizardStepTemplate, MainHubScaffoldTemplate)"]
            Screens["Telas (Screens)\n(OnboardingScreen, ScanPairScreen,\nVaultScreen, AccountsScreen, SettingsScreen)"]
            
            Atoms --> Molecules
            Molecules --> Organisms
            Organisms --> Templates
            Templates --> Screens
        end
        VM["ViewModels & UI States\n(PairingWizardViewModel, TotpViewModel,\nVaultViewModel, ConnectedKeysViewModel)"]
        Screens --> VM
    end

    subgraph DomainLayer["2. Camada de Domínio (Negócio Puro)"]
        direction TB
        UseCases["Casos de Uso (UseCases)\n- GetAppStartDestinationUseCase\n- GetConnectedKeysUseCase / SelectActiveKeyUseCase\n- StartDiscoveryUseCase / PerformBiometricBindingUseCase\n- RefreshTotpCodesUseCase / AddTotpAccountUseCase\n- GenerateAccessKeyUseCase / RefreshVaultUseCase\n- GetThemePreferenceUseCase / SetThemeModeUseCase"]
        
        RepoInterfaces["Interfaces de Repositório (Contratos)\n- ConnectedKeysRepository\n- PairingWizardRepository\n- KeyVaultRepository\n- TotpRepository\n- ThemeRepository"]
        
        DomainModels["Modelos de Domínio\n- ConnectedKeyDevice & SecurityToggles\n- TotpAccountItem & VaultKeyEntry\n- DiscoveredKeyCandidate\n- AppThemePreference & AppThemeMode"]
        
        UseCases --> RepoInterfaces
        UseCases --> DomainModels
    end

    subgraph DataLayer["3. Camada de Dados & Infraestrutura"]
        direction TB
        RepoImpl["Implementações de Repositório\n- ConnectedKeysRepositoryImpl\n- PairingWizardRepositoryImpl\n- KeyVaultRepositoryImpl\n- TotpRepositoryImpl\n- ThemeRepositoryImpl"]
        
        subgraph SystemAndSecurity["Segurança & APIs Android"]
            SecService["SystemSecurityService\n(SecureRandom, Clipboard Sensitive,\nBiometricManager checks)"]
            KeyStore["BindingKey (AndroidKeyStore)\nEC P-256 StrongBox / TEE\nBiometricPrompt integration"]
            Prefs["EncryptedKeysStore\n(EncryptedSharedPreferences AES256_GCM)\nThemePreferencesStore"]
        end
        
        subgraph Transports["Transportes de Hardware"]
            KeyTrans["<<interface>> KeyTransport"]
            BleTrans["BleKeyTransport\n(AegisBleClient - 0xFFFD / 0xFFFE)"]
            UsbTrans["UsbKeyTransport\n(UsbCtaphid - VID 0x303A PID 0xAE61)"]
            SimTrans["SimulatedRenodeTransport\n(TCP 10.0.2.2:5678 / Deterministic)"]
            
            KeyTrans <|.. BleTrans
            KeyTrans <|.. UsbTrans
            KeyTrans <|.. SimTrans
        end
        
        RepoImpl --> SecService
        RepoImpl --> KeyStore
        RepoImpl --> Prefs
        RepoImpl --> KeyTrans
    end

    subgraph NativeRustLayer["4. Camada Nativa Rust (UniFFI Bridge)"]
        direction TB
        BridgeFacade["AegisBridge.kt (Fachada Kotlin com Fallback Seguro)"]
        UniFFIJni["libaegis_bridge.so (JNI bindings C/Rust)"]
        RustLib["crates/uniffi-bridge/src/lib.rs\n- ble_split_fragments (0x28..0x2D, 0x30..0x34)\n- envelope_seal / envelope_open (AEGN v1 AES-256-GCM)\n- totp_format_display & otpauth_extract_label_and_secret\n- wallet_address (Bitcoin P2WPKH, EVM, Solana)\n- Zeroize mem clearing & Fail-Closed Errors"]
        
        BridgeFacade --> UniFFIJni
        UniFFIJni --> RustLib
    end

    %% Ligações entre as camadas
    VM --> UseCases
    RepoImpl -- implements --> RepoInterfaces
    RepoImpl --> BridgeFacade
    PresentationLayer -.-> DomainModels
```

---

## 3. Aplicação Rigorosa dos Princípios SOLID

A base de código segue as 5 regras de design orientado a objetos e arquitetura limpa:

### 3.1. Single Responsibility Principle (SRP) — Princípio da Responsabilidade Única
- **Casos de Uso Granulares:** Cada caso de uso executa exatamente uma operação de negócio. Por exemplo:
  - `GetAppStartDestinationUseCase`: exclusiva responsabilidade de observar o repositório de chaves e emitir se o app deve abrir no Wizard ou no Hub Principal.
  - `PerformBiometricBindingUseCase`: exclusiva responsabilidade de coordenar o handshake de claim P-256 entre o KeyStore e o hardware.
  - `TickTotpTimerUseCase`: gerencia exclusivamente a passagem do tempo para o anel de contagem regressiva de 30 segundos.
- **Componentes Atômicos:** Cada composable de UI possui um único foco. `TotpCountdownRingAtom` apenas renderiza o indicador circular de tempo restante; não gerencia requisições de rede, cópia para o clipboard ou exclusão de contas.

### 3.2. Open/Closed Principle (OCP) — Princípio Aberto/Fechado
- **Transportes Extensíveis (`KeyTransport`):** O contrato de comunicação de baixo nível é modelado pela interface `KeyTransport`. Novos meios físicos de transmissão (ex: NFC, Wi-Fi Direct ou WebSockets) podem ser adicionados implementando `KeyTransport`, sem alterar uma única linha de código nos repositórios de negócio ou nas telas.
- **Provedores de Algoritmos Criptográficos:** O cofre de chaves (`KeyVaultRepositoryImpl`) mapeia novos tipos de credenciais (`AccessKeyType.PASSKEY_FIDO`, `CRYPTO_WALLET_BTC`, `CRYPTO_WALLET_ETH`, `CRYPTO_WALLET_SOL`) com parâmetros COSE correspondentes sem necessidade de modificar a estrutura de persistência.

### 3.3. Liskov Substitution Principle (LSP) — Princípio da Substituição de Liskov
- Os três transportes de hardware implementam fielmente o contrato `KeyTransport`:
  - `BleKeyTransport`: opera via Bluetooth Low Energy real com características GATT `0xFFFD`.
  - `UsbKeyTransport`: opera via USB HID CTAPHID nativo do Android.
  - `SimulatedRenodeTransport`: opera via socket TCP local ou simulação determinística em memória.
- Qualquer repositório que dependa de `KeyTransport` opera de forma indistinta se estiver conversando com um hardware real por BLE ou com um emulador Renode conectado ao socket TCP. Os invariantes de envio, cancelamento e timeout são mantidos em todas as implementações.

### 3.4. Interface Segregation Principle (ISP) — Princípio da Segregação de Interfaces
- Em vez de uma interface monolítica de repositório (`AegisRepository`), o domínio divide os contratos por responsabilidades de contexto:
  - `ConnectedKeysRepository`: gerencia a lista de chaves pareadas, chave ativa e toggles.
  - `PairingWizardRepository`: gerencia busca, escaneamento, holding do botão e binding.
  - `KeyVaultRepository`: gerencia slots de passkeys e carteiras cripto.
  - `TotpRepository`: gerencia contas OATH, refresh de códigos e sincronização com o hardware.
  - `ThemeRepository`: gerencia exclusivamente as preferências visuais de tema.
- Telas que lidam apenas com TOTP nunca dependem de métodos de pareamento ou de geração de carteira Bitcoin.

### 3.5. Dependency Inversion Principle (DIP) — Princípio da Inversão de Dependência
- Módulos de alto nível (Casos de Uso no pacote `domain/usecase/`) dependem exclusivamente de abstrações (interfaces no pacote `domain/repository/`), e nunca de implementações concretas (`data/repository/`).
- O contêiner manual de injeção de dependências (`dev.aegiskey.app.di.AppContainer`) instancia as implementações (`ConnectedKeysRepositoryImpl`, `EncryptedKeysStore`, `AegisBleClient`) e as injeta nos casos de uso e ViewModels, desacoplando o código de frameworks específicos e viabilizando testes unitários sem mocks complexos.

---

## 4. Catálogo Completo de Componentes Atomic Design (Material 3)

A interface gráfica adota o **Atomic Design**, garantindo consistência visual, escalabilidade, suporte acessível a leitores de tela e desacoplamento total da lógica de apresentação.

### 4.1. Átomos (Atoms)
Componentes indivisíveis construídos sobre primitivas do Material 3:

| Componente | Arquivo | Responsabilidade |
|---|---|---|
| `PrimaryNextButton` | `AegisButtons.kt` | Botão principal de avanço ("Próximo", "Concluir"). Destaque visual elevado, shape arredondado (16dp), área de toque mínima de 50dp e indicador de carregamento embutido. |
| `SecondaryBackButton` | `AegisButtons.kt` | Botão secundário de contorno ("Voltar") com ícone de seta, permitindo retrocesso suave em qualquer fluxo. |
| `QuickActionPillButton` | `AegisButtons.kt` | Botão em formato de pílula compacta (36dp de altura) para ações de 1 toque: "Copiar", "Renomear", "Testar Presença". |
| `StepProgressDotsAtom` | `AegisIndicators.kt` | Indicador de etapas lineares. O passo ativo expande suavemente como uma pílula (28dp de largura) com cor primária, enquanto os demais permanecem circulares (8dp). |
| `TotpCountdownRingAtom` | `AegisIndicators.kt` | Anel circular de 44dp que exibe a contagem regressiva de 30 segundos. Possui transição de cores trifásica: Esmeralda (> 10s), Âmbar (6 a 10s) e Vermelho de alerta (≤ 5s). |
| `ConnectionStatusBadgeAtom` | `AegisIndicators.kt` | Pílula com ponto luminoso que indica o estado da conexão física: Verde (Conectado), Laranja (Simulador/Renode) ou Cinza (Desconectado). |
| `AegisSwitchAtom` | `AegisToggles.kt` | Switch Material 3 com suporte a feedback tátil e cores adaptativas para alternar flags de segurança. |
| `ThemeOptionChipAtom` | `AegisToggles.kt` | Chip de seleção visual para alternância entre temas (Claro, Escuro, Automático). |

### 4.2. Moléculas (Molecules)
Combinações de átomos que formam pequenas unidades funcionais reutilizáveis:

| Componente | Arquivo | Descrição e Comportamento |
|---|---|---|
| `ConnectedKeyCardMolecule` | `ConnectedKeyCardMolecule.kt` | Cartão de identificação da chave AegisKey. Exibe nome, badge de transporte, status ativo e botões de ação rápida (renomear, selecionar ativa, remover). |
| `PhysicalButtonPromptCardMolecule` | `PhysicalButtonPromptCardMolecule.kt` | Cartão instrucional que atrai a atenção do usuário para a ação física na chave. Apresenta ícone pulsante suave e instruções claras ("Segure por 5 segundos" ou "Toque rápido"). No modo emulador/Renode, embute o botão "Simular Toque na Chave". |
| `SettingToggleRowMolecule` | `SettingToggleRowMolecule.kt` | Linha completa de configuração com título, descrição explicativa e `AegisSwitchAtom`. Usada nos toggles de Proximidade (Walkaway), Biometria Obrigatória e Presença Física (UP). |
| `TotpCodeCardMolecule` | `TotpCodeCardMolecule.kt` | Cartão completo de conta TOTP: exibe ícone do serviço, emissor, conta, código em fonte monoespaçada grande (agrupado em 3+3 dígitos), anel regressivo animado e botão de cópia de 1 toque. |
| `VaultEntryCardMolecule` | `VaultEntryCardMolecule.kt` | Cartão de credencial do cofre (Passkey FIDO2 ou Carteira de Criptomoeda). Exibe tipo de chave, slot do hardware, resumo público e botão de exclusão protegida. |

### 4.3. Organismos (Organisms)
Componentes complexos que combinam moléculas e átomos para orquestrar fluxos modais:

| Componente | Arquivo | Comportamento |
|---|---|---|
| `AddTotpAccountDialogOrganism` | `AddTotpAccountDialogOrganism.kt` | Diálogo modal com validação em tempo real para cadastro de novo fator 2FA. Aceita URI completa `otpauth://totp/...` ou segredo Base32 digitado, com sanitização de caracteres e suporte a 6 ou 8 dígitos. |
| `KeyGenerationDialogOrganism` | `KeyGenerationDialogOrganism.kt` | Diálogo modal para criação de novas credenciais no hardware. Permite escolher entre Passkey FIDO2 (P-256), Carteira Bitcoin SegWit (secp256k1), Carteira Ethereum (secp256k1) ou Carteira Solana (Ed25519). |
| `ThemeSelectorOrganism` | `ThemeSelectorOrganism.kt` | Seletor de modo de tema com preview imediato e opção para ativar ou desativar as Cores Dinâmicas (Material You). |

### 4.4. Templates
Esqueletos estruturais de página que recebem conteúdos variáveis e gerenciam o layout:

- **`WizardStepTemplate`:** Template para jornadas passo a passo lineares ("Próximo → Próximo → Concluir"). Organiza:
  1. Topo fixo com `StepProgressDotsAtom`, título acolhedor e subtítulo;
  2. Área central rolável para o conteúdo customizado do passo;
  3. Barra de rodapé fixa com os botões `SecondaryBackButton` e `PrimaryNextButton`.
- **`MainHubScaffoldTemplate`:** Template principal do dashboard pós-pareamento:
  1. TopAppBar com atalho da chave ativa, badge de status de conexão e botão de tema;
  2. Área de conteúdo protegida contra sobreposição de barras (`innerPadding`);
  3. NavigationBar inferior com os 4 destinos: **Cofre**, **Códigos (TOTP)**, **Chaves** e **Ajustes**.

### 4.5. Telas (Screens)
As telas orquestram os Templates com os ViewModels correspondentes:
- `OnboardingScreen`: tela inicial acolhedora com detecção de estado de vínculo;
- `ScanPairScreen`: escaneamento BLE `0xFFFD` com validação de permissões;
- `VaultScreen`: listagem e geração de Passkeys e carteiras criptográficas;
- `AccountsScreen` / `TotpScreen`: central de códigos de autenticação temporários;
- `SettingsScreen`: controle de toggles de segurança e seleção de tema visual.

---

## 5. Sistema de Temas Material 3 e Cores Dinâmicas

O sistema visual do AegisKey foi construído com base nas especificações do **Google Material 3**:

```
+--------------------------------------------------------------------------+
|                        SISTEMA DE TEMAS AEGISKEY                         |
+--------------------------------------------------------------------------+
  |-- Tema Claro (AegisLightColorScheme):
  |   * Primary: Azul Cobalto Confiável (#0061A4)
  |   * Secondary: Esmeralda de Segurança Criptográfica (#006A60)
  |   * Tertiary: Âmbar de Presença Física / Toque no Botão (#785900)
  |   * Background / Surface: Tons limpos e nítidos (#FDFCFF)
  |
  |-- Tema Escuro (AegisDarkColorScheme):
  |   * Primary: Azul Claro Suave (#9ECAFF)
  |   * Secondary: Esmeralda Claro (#53DBC9)
  |   * Tertiary: Âmbar Claro (#F0BE3B)
  |   * Background / Surface: Preto Profundo OLED-friendly (#101418)
  |
  |-- Modo Automático do Sistema:
  |   * Sincroniza dinamicamente com as preferências do SO (Dia/Noite).
  |
  |-- Cores Dinâmicas (Material You - Android 12+):
  |   * Utiliza dynamicLightColorScheme() e dynamicDarkColorScheme().
  |   * Extrai a paleta harmônica do papel de parede do usuário.
+--------------------------------------------------------------------------+
```

### Tipografia Monospace para Códigos de Segurança
O arquivo `TypographyTokens.kt` define o estilo `AegisCodeMonospaceStyle`, projetado especificamente para códigos de verificação:
- Família `FontFamily.Monospace` com tracking largo (`letterSpacing = 3.sp`);
- Numerais com largura fixa, prevenindo deslocamentos visuais conforme os números alternam a cada 30 segundos.

---

## 6. Integração com APIs Nativas do Sistema Android

O AegisKey aproveita as mais robustas primitivas de segurança do Android SDK:

### 6.1. AndroidKeyStore EC P-256 (StrongBox / TEE)
Implementado em `BindingKey.kt` e abstraído por `SystemSecurityService.kt`:
- **Chave Não-Exportável:** O par de chaves EC P-256 (`secp256r1`) é gerado diretamente no hardware de segurança:
  - Tenta primeiro o **StrongBox Keymaster** (chip de segurança dedicado, HSM isolado no hardware);
  - Caso o dispositivo não possua StrongBox (`StrongBoxUnavailableException`), efetua fallback gracioso para o **TEE (Trusted Execution Environment)** do processador principal.
- **Biometria Obrigatória por Operação:** A especificação exige autenticação de usuário sem tolerância de tempo:
  ```kotlin
  val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
      .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
      .setDigests(KeyProperties.DIGEST_SHA256)
      .setUserAuthenticationRequired(true)
      .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
      .setIsStrongBoxBacked(strongBox)
      .build()
  ```
- **Assinatura do Handshake de Vínculo:** A chave privada do celular assina a mensagem `challenge(32B) || op(1B) || payload_hash(32B)` via `Signature.getInstance("SHA256withECDSA")`. A chave privada **nunca** sai do chip criptográfico do Android.

### 6.2. BiometricPrompt com CryptoObject
- A invocação biométrica utiliza `BiometricPrompt` amarrado ao `BiometricPrompt.CryptoObject(signature)`. A assinatura só pode ser finalizada após a leitura positiva da digital biométrica nível 3 (Class 3 / Strong), impedindo qualquer disparo acidental ou em segundo plano.

### 6.3. EncryptedSharedPreferences com MasterKey AES256_GCM
Implementado em `EncryptedKeysStore.kt`:
- Todos os metadados de chaves conectadas, apelidos, identificadores de vínculo (`bindingId`) e entradas do cofre são persistidos com criptografia authenticated em repouso:
  - Esquema de chave: `MasterKey.KeyScheme.AES256_GCM` gerenciado pelo KeyStore do Android;
  - Esquema de chaves de preferência: `AES256_SIV`;
  - Esquema de valores: `AES256_GCM`.

### 6.4. Área de Transferência Protegida (Android 13+ Sensitive Clipboard)
Ao copiar códigos TOTP ou chaves sensíveis com `copySensitiveCode`:
```kotlin
val clip = ClipData.newPlainText(label, sensitiveCode)
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
    val extras = PersistableBundle().apply {
        putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
    }
    clip.description.extras = extras
}
clipboard.setPrimaryClip(clip)
```
Essa flag impede que o Android 13+ (API 33+) exiba o código aberto no balão de pré-visualização de área de transferência, prevenindo shoulder surfing e vazamento em capturas de tela.

### 6.5. Permissões de Bluetooth no Android 12+ (API 31+)
No Android 12 ou superior, o aplicativo solicita estritamente:
- `Manifest.permission.BLUETOOTH_SCAN` com a diretiva `neverForLocation` declarada no Manifesto;
- `Manifest.permission.BLUETOOTH_CONNECT`.
- **Privacidade Radical:** As permissões de localização geográfica (`ACCESS_FINE_LOCATION` ou `ACCESS_COARSE_LOCATION`) **nunca** são requisitadas, pois o escaneamento do serviço de hardware `0xFFFD` não utiliza dados geográficos.

### 6.6. Receptores de Broadcast Seguros (`RECEIVER_NOT_EXPORTED`)
Todos os `BroadcastReceiver` registrados dinamicamente (como o monitor de status de bonding BLE e o monitor de conexão USB CTAPHID) utilizam explicitamente a flag:
```kotlin
ContextCompat.registerReceiver(
    context,
    receiver,
    filter,
    ContextCompat.RECEIVER_NOT_EXPORTED
)
```
Isso impede que outros aplicativos instalados no mesmo dispositivo enviem intents forjados para simular desconexão ou autorização USB.

---

## 7. Ponte Rust + Kotlin (UniFFI Bridge)

A comunicação de alto desempenho e segurança entre a interface Kotlin e o núcleo do protocolo do AegisKey é realizada pelo **UniFFI Bridge**:

```
crates/uniffi-bridge/
├── src/
│   ├── aegis_bridge.udl  (Interface Definition Language do UniFFI)
│   └── lib.rs            (Implementação segura em Rust puro com Zeroize)
└── target/
    └── libaegis_bridge.so (Compilado para arm64-v8a e x86_64)
          |
          v
app-android/.../AegisBridge.kt (Fachada Kotlin com fallbacks puros)
```

### 7.1. Funções Expostas e Garantias de Segurança

#### 1. Fragmentação e Montagem BLE (`ble_split_fragments`)
- Converte payloads de até 512 bytes (`CONTROL_POINT_LENGTH`) em fragmentos MTU-safe de no máximo 244 bytes para escrita na característica GATT `0xFFF1`.
- Suporta nativamente:
  - Mensagens padrão CTAP-BLE: `0x81` (PING) e `0x83` (MSG);
  - **Opcodes de Gerenciamento de Vínculo:** `0x28` a `0x2D` (`0x28 CLAIM`, `0x29 CHALLENGE`, `0x2A VERIFY`, `0x2B RELEASE`, `0x2C RECOVERY_SET`, `0x2D RECOVERY_UNLOCK`);
  - **Opcodes de Atualização OTA:** `0x30` a `0x34`.
- Rejeita opcodes inválidos com `BridgeError.InvalidOpcode` e aborta com `BridgeError.Overflow` caso o payload exceda o limite.

#### 2. Envelopes Criptográficos `AEGN` v1
- `envelope_validate(envelope)`: Validação formal de framing (Magic `0x41 0x45 0x47 0x4E`, Versão `0x01`, comprimento mínimo de 33B e verificação fail-closed contra nonces zerados).
- `envelope_seal(key, plaintext, aad, nonce)`: Encripta o plaintext usando **AES-256-GCM**. As chaves e nonces são buffers transitórios fornecidos pelo chamador e são **zerados em memória (`zeroize()`)** imediatamente após a operação.
- `envelope_open(key, envelope, aad)`: Decripta e valida a autenticidade do envelope. Rejeita nonces nulos e envelopes adulterados.

#### 3. Parse e Formatação OATH/TOTP
- `totp_format_display(code)`: Formata códigos numéricos de 6 a 8 dígitos para exibição legível com espaçamento central (ex: `"123456"` vira `"123 456"`).
- `otpauth_extract_label_and_secret(input)`: Efetua parse seguro tanto de strings URI complexas (`otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub`) quanto de chaves Base32 puras digitadas pelo usuário. Limpa automaticamente espaços em branco, hífens e converte para maiúsculas sem expor o segredo a logs.

#### 4. Derivação de Endereços de Carteira (`wallet_address`)
- Computação local e pública a partir de chaves públicas já expostas, sem nunca solicitar ao hardware ou expor chaves privadas:
  - **Bitcoin (`btc`):** Deriva endereço nativo Bech32 SegWit P2WPKH (`bc1q...`) a partir de chave pública secp256k1 comprimida de 33 bytes.
  - **Ethereum (`eth` / `evm`):** Deriva endereço hexadecimal checksummed (`0x...`) a partir de chave secp256k1 não comprimida de 64 bytes (`x || y`).
  - **Solana (`sol`):** Deriva endereço Base58 a partir de chave Ed25519 de 32 bytes.

---

## 8. Resumo da Conformidade Arquitetural

| Camada / Princípio | Elemento Chave | Garantia de Engenharia |
|---|---|---|
| **Clean Architecture** | Isolamento de Camadas | Domínio puro sem dependências de framework Android; regras de negócio imutáveis. |
| **SOLID** | SRP, OCP, LSP, ISP, DIP | UseCases granulares, interface `KeyTransport` polimórfica e inversão via `AppContainer`. |
| **Atomic Design** | Atoms -> Molecules -> Organisms -> Templates | 100% de reuso de componentes Material 3 e padronização visual entre Claro, Escuro e Dinâmico. |
| **Android Security** | KeyStore StrongBox & Sensitive Clipboard | Chave EC P-256 protegida em hardware, autenticação biométrica classe 3 e proteção contra vazamento em clipboard. |
| **Rust UniFFI** | `libaegis_bridge.so` + `Zeroize` | Desacoplamento da criptografia de baixo nível; zeramento ativo de buffers sensíveis na RAM. |
