# Modelagem de Ameaças e Análise de Segurança (STRIDE) — AegisKey Secure Guard

> **Projeto:** AegisKey FIDO2 & Multi-Protocol Hardware Authenticator  
> **Subsistema:** Secure Guard (Cofre Local de Autoridade e Defesa Ativa)  
> **Status:** Documento Normativo de Análise de Segurança e Vetores de Ameaça  
> **Data:** 25 de Outubro de 2026  
> **Referência Metodológica:** Microsoft STRIDE / NIST SP 800-63B / FIPS 140-3 Nível 3  

---

## 1. Superfície de Ataque e Escopo do Sistema

O modelo de ameaças do **AegisKey Secure Guard** considera um atacante com capacidades multifacetadas: desde malwares operando no sistema operacional do smartphone (Android) ou computador hospedeiro (Windows/Linux/macOS), até agentes maliciosos com posse física temporária ou permanente do dispositivo microcontrolador (ESP32-S3).

```
+-------------------------------------------------------------------------------------------------------------------+
|                                       SUPERFÍCIE DE ATAQUE E FRONTEIRAS DE CONFIANÇA                              |
+-------------------------------------------------------------------------------------------------------------------+
|                                                                                                                   |
|  [ HOSPEDEIRO / ATACANTE REMOTO NÃO CONFIÁVEL ]                                                                    |
|  +-------------------------------------------------------------------------------------------------------------+  |
|  | Malware em Host Android / PC | App Malicioso sem Permissão | Man-in-the-Middle USB/BLE | Script Automatizado|  |
|  +-------------------------------------------------------------------------------------------------------------+  |
|                                       |                             |                             |               |
|                      (Injeção de Pacotes USB)              (Sniffing BLE)          (Comandos via UART COM7)       |
|                                       v                             v                             v               |
|  ===================================[ FRONTEIRA FÍSICA E LÓGICA DE CONFIANÇA ]=================================== |
|                                       |                             |                             |               |
|  [ SILÍCIO DO DISPOSITIVO - ESP32-S3 (ZONA DE ALTA CONFIANÇA) ]                                                   |
|  +-------------------------------------------------------------------------------------------------------------+  |
|  |  +-------------------------------------------------------------------------------------------------------+  |  |
|  |  | Camada de Transporte: USB Native / BLE NimBLE / UART0                                                 |  |  |
|  |  +-------------------------------------------------------------------------------------------------------+  |  |
|  |                                                |                                                            |  |
|  |                                                v                                                            |  |
|  |  +-------------------------------------------------------------------------------------------------------+  |  |
|  |  | BARREIRA DE AUTORIZAÇÃO (authorize_vendor_opcode): Intercepta e Bloqueia Opcodes 0x20..0x37           |  |  |
|  |  +-------------------------------------------------------------------------------------------------------+  |  |
|  |                                                |                                                            |  |
|  |                                                v                                                            |  |
|  |  +-------------------------------------------------------------------------------------------------------+  |  |
|  |  | SECURE GUARD ENGINE (FSM de 10 Estados, KDF PBKDF2, Backoff Progressivo, Limite 5 Erros)             |  |  |
|  |  +-------------------------------------------------------------------------------------------------------+  |  |
|  |                           |                                                    |                            |  |
|  |            (Gravação Atômica Pré-Resposta)                         (Zeroize de buffers efêmeros)            |  |
|  |                           v                                                    v                            |  |
|  |  +--------------------------------------------------+   +------------------------------------------------+  |  |
|  |  | Armazenamento Flash NVS Cifrado AES-256           |   | Memória RAM SRAM (512 KiB)                     |  |  |
|  |  | Record de 256 bytes (Magic AEGSG001 + CRC32)     |   | Limpeza estrita de verifiers e segredos        |  |  |
|  |  +--------------------------------------------------+   +------------------------------------------------+  |  |
|  |                                                                                                             |  |
|  |  +-------------------------------------------------------------------------------------------------------+  |  |
|  |  | COFRE DE ATIVOS PROTEGIDOS: Carteiras Web3 (BTC/ETH/SOL) e Chaves On-Device [ISOLADO DE PASSKEYS FIDO2] |  |  |
|  |  +-------------------------------------------------------------------------------------------------------+  |  |
|  +-------------------------------------------------------------------------------------------------------------+  |
+-------------------------------------------------------------------------------------------------------------------+
```

---

## 2. Matriz Geral STRIDE

A taxonomia STRIDE categoriza os riscos contra as propriedades fundamentais de segurança:

| Categoria STRIDE | Propriedade Ameaçada | Vetor Primário no Sistema AegisKey | Mecanismo de Mitigação Implementado |
|---|---|---|---|
| **S**poofing (Falsificação) | Autenticidade | Bypass da interface do Android enviando comandos brutos de desbloqueio ou geração de chaves. | Barreira mandatória no firmware (`authorize_vendor_opcode`). A chave só atende comandos autorizados pelo seu próprio estado local. |
| **T**ampering (Adulteração) | Integridade | Injeção de falhas (glitching) ou alteração física da memória flash para forçar contador de erros para zero. | Registro binário de 256 bytes com cabeçalho Magic `AEGSG001`, versão e CRC32 IEEE 802.3. Transição *fail-closed* imediata para `ErrorLocked`. |
| **R**epudiation (Repúdio) | Irretratabilidade | O usuário ou atacante nega ter tentado adivinhar o PIN ou executado limpeza da chave. | `AuditRingBuffer` com capacidade para 32 eventos cronológicos em timestamp monotônico de hardware (Zero Secrets in Logs). |
| **I**nformation Disclosure | Confidencialidade | Análise de consumo/tempo (Timing Attacks) na validação de PIN ou extração de senhas em logs e dumps de RAM. | Algoritmo `constant_time_eq_32` com trait `subtle::ConstantTimeEq`; limpeza obrigatória de memória via `zeroize::Zeroize`. |
| **D**enial of Service | Disponibilidade | Bloqueio malicioso permanente das credenciais FIDO2 do usuário após esgotar tentativas do Secure Guard. | Isolamento de namespaces: Wipe do Secure Guard afeta exclusivamente carteiras Web3 e chaves protegidas, preservando 100% das passkeys WebAuthn. |
| **E**levation of Privilege | Autorização | Envio direto de opcodes privilegiados (`OP_WALLET_GEN 0x35`) sem prévia autenticação de PIN. | Barreira centralizada em `freertos_route.rs`. Estado `Unlocked` verificado autonomamente no silício com expiração de sessão monotônica. |

---

## 3. Análise Detalhada das 7 Ameaças Principais e Mitigações

### Ameaça 1: Bypass da UI Android via Comandos Vendor Diretos

- **Descrição do Ataque:** Um invasor obtém acesso ao sistema operacional hospedeiro (via malware Android com permissão USB/BLE ou através de script direto em Python via `COM7`) e ignora deliberadamente as telas de autenticação da interface gráfica do app. O invasor envia diretamente pacotes CTAPHID estruturados com opcodes sensíveis, tais como `0x35 OP_WALLET_GEN` ou `0x20 OP_KEY_GEN_ONDEVICE`.
- **Risco:** Comprometimento de credenciais, geração de novas chaves sem consentimento ou extração de endereços de carteiras privadas.
- **Severidade:** **Crítica (CVSS 9.1)**.
- **Mecanismo de Mitigação (`authorize_vendor_opcode`):**
  - O firmware implementa o princípio de **Zero-Trust On-Device**. O microcontrolador ESP32-S3 não confia em nenhuma declaração de autorização fornecida pelo aplicativo Android ou host.
  - No ponto de entrada único de mensagens vendor em `crates/aegis-fido-firmware/src/freertos_route.rs`, cada opcode passa pela inspeção mandatória:
    ```rust
    // Interposição mandatória no roteador FreeRTOS
    guard.authorize_vendor_opcode(opcode, now_ms)?;
    ```
  - Em `crates/aegis-fido-core/src/secure_guard/engine.rs`:
    ```rust
    pub fn authorize_vendor_opcode(&mut self, opcode: u8, now_ms: u64) -> Result<(), SecureGuardError> {
        let resource = ProtectedResourceClass::from_vendor_opcode(opcode);
        let _ = self.check_and_touch_session(now_ms);

        if resource.requires_unlock(&self.policy) && self.state != SecureGuardState::Unlocked {
            return Err(SecureGuardError::AccessDeniedLocked {
                state: self.state,
                opcode,
            });
        }
        Ok(())
    }
    ```
  - Se o estado não for estritamente `SecureGuardState::Unlocked`, a operação é imediatamente rejeitada e abortada antes de qualquer acesso à partição `storage`, retornando código de erro CTAP2 `0x27 CTAP2_ERR_PIN_REQUIRED`.

---

### Ameaça 2: Ataque de Força Bruta contra o PIN do Usuário

- **Descrição do Ataque:** O atacante com posse da chave física submete sequências contínuas de PINs (ex: de `0000` a `9999`) em alta velocidade através de conexões USB ou serial com o intuito de adivinhar a senha por enumeração exaustiva.
- **Risco:** Acesso total não autorizado ao cofre de chaves privadas e carteiras Web3.
- **Severidade:** **Crítica (CVSS 8.9)**.
- **Mecanismos de Mitigação Combinados:**
  1. **Derivação de Alta Resistência (PBKDF2-HMAC-SHA256):**
     - O PIN do usuário nunca é armazenado em formato plano nem com hash trivial de iteração única.
     - É aplicado PBKDF2-HMAC-SHA256 (RFC 8018) com um salt de alta entropia de 16 bytes gerado pelo HRNG de silício do ESP32-S3 (`TRNG`), calibrado para 2.000 iterações em produção (`PBKDF2_DEFAULT_ITERATIONS`).
     - Cada tentativa de validação impõe uma sobrecarga computacional de processamento na CPU Xtensa LX7, tornando inviável o envio em rajadas.
  2. **Backoff Progressivo e Penalidade Temporal (`RateLimited`):**
     - O subsistema monitora o número de tentativas consecutivas incorretas (`failed_attempts`) e calcula dinamicamente o retardo mínimo exigido antes da próxima tentativa:
       $$\text{Delay}(n) = \begin{cases} 0\text{ ms}, & n = 1 \\ 2.000\text{ ms}, & n = 2 \\ 5.000\text{ ms}, & n = 3 \\ 15.000\text{ ms}, & n = 4 \end{cases}$$
     - Durante a janela de penalidade temporal, o motor transita para o estado `SecureGuardState::RateLimited`. Qualquer tentativa de envio de PIN recebida antes de `rate_limit_until_ms` é sumariamente rejeitada com `SecureGuardError::RateLimited`, sem sequer invocar o KDF nem consumir ciclos de CPU.
  3. **Limite Estrito de 5 Tentativas e Bloqueio Definitivo:**
     - A constante `MAX_ATTEMPTS = 5` é inegociável.
     - Na 5ª falha consecutiva, o dispositivo bloqueia permanentemente a autenticação por PIN, transitando irreversivelmente para `SecureGuardState::RecoveryRequired` (exigindo o segredo de recuperação de 16 bytes) ou `SecureGuardState::WipePending` (acionando o wipe automático de ativos).

---

### Ameaça 3: Power-Cycling / Reboot para Evasão do Contador de Falhas

- **Descrição do Ataque:** O atacante envia uma tentativa de PIN incorreta. Imediatamente após a falha (ou antes que o firmware complete o processamento), o invasor corta bruscamente a alimentação elétrica da porta USB (ciclo de power-cycle / reboot forçado), na tentativa de fazer o microcontrolador reiniciar sem persistir o incremento do contador de erros na memória flash. Dessa forma, o atacante tentaria manter o dispositivo perpetuamente com 0 ou 1 erro registrado.
- **Risco:** Evasão do limite de 5 tentativas e execução de força bruta indefinida.
- **Severidade:** **Alta (CVSS 7.8)**.
- **Mecanismo de Mitigação (Persistência Atômica Pré-Resposta):**
  - O firmware implementa o paradigma de **Persistência Pré-Resposta**: a atualização do contador de erros na partição Flash NVS é concluída e commitada de forma atômica **antes** de qualquer pacote de resposta ser montado ou transmitido ao host.
  - Fluxo atômico implementado no firmware:
    1. A comparação de hash do PIN falha;
    2. O contador interno `failed_attempts` é incrementado em memória;
    3. O registro completo de 256 bytes `SecureGuardPersistentRecord` é serializado e seu CRC32 é recalculado;
    4. O blob é gravado via `nvs_set_blob("sg_state", bytes)` seguido obrigatoriamente de `nvs_commit()`;
    5. Somente após a confirmação de sincronização física da Flash, a mensagem de erro é transmitida pela interface USB/BLE.
  - Ao ser reiniciado após corte de energia, o método `SecureGuardEngine::from_persisted_record` reconstrói o estado a partir da Flash. Se o registro gravava 4 tentativas falhas, o dispositivo reinicia diretamente no estado `RateLimited` ou `Locked` com 4 tentativas consumidas. Se o corte ocorreu durante a 5ª tentativa, ele reinicia em `RecoveryRequired` ou `WipePending`.
  - **Invariante de Reinicialização de Sessão:** Mesmo que o dispositivo tenha sido desligado no estado `Unlocked`, o método `from_persisted_record` **jamais restaura a sessão como desbloqueada**. Toda reinicialização do chip força o retorno para o estado `Locked`.

---

### Ameaça 4: Ataques de Canal Lateral por Tempo (Timing Attacks)

- **Descrição do Ataque:** Durante a verificação do PIN ou do código de recuperação, uma comparação tradicional byte a byte (como `memcmp` ou operadores `==` convencionais com parada prematura no primeiro byte divergente) responde mais rápido caso o primeiro byte esteja incorreto, e demora frações de microssegundos a mais se o primeiro byte coincidir. Um atacante conectado à serial de depuração com analisador lógico de alta resolução poderia decodificar os bytes da senha medindo o tempo de resposta da chave.
- **Risco:** Revelação da chave ou PIN em poucas centenas de amostras.
- **Severidade:** **Alta (CVSS 7.4)**.
- **Mecanismo de Mitigação (`constant_time_eq_32`):**
  - Todas as validações criptográficas de credenciais (PIN e Recovery Code) são processadas através da função `constant_time_eq_32`, construída sobre o trait `subtle::ConstantTimeEq`:
    ```rust
    #[inline]
    pub fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
        a.ct_eq(b).into()
    }
    ```
  - Essa operação executa um ciclo invariante de operações lógicas XOR cumulativas em todos os 32 bytes do hash derivado, garantindo tempo de execução estritamente constante, independentemente de onde ocorra a divergência de bits.
  - Não há branches condicionais dependentes de dados secretos durante a comparação.

---

### Ameaça 5: Corrupção de Flash e Injeção de Falhas (Fault Injection)

- **Descrição do Ataque:** O atacante induz variações bruscas de tensão (voltage glitching), pulsos eletromagnéticos (EMFI) ou manipula diretamente o conteúdo dos blocos de flash SPI com um programador externo para alterar os flags de bloqueio, corromper o verificador de PIN ou colocar o firmware em estado indefinido.
- **Risco:** Bypass do estado `Locked` ou execução de código com estado corrompido.
- **Severidade:** **Alta (CVSS 7.5)**.
- **Mecanismo de Mitigação (Integridade Binária e Transição Fail-Closed):**
  - O registro persistente possui layout estrito e canônico de 256 bytes (`PERSISTENT_RECORD_SIZE`):
    - **Bytes 0..7:** Magic Header fixo `AEGSG001`;
    - **Bytes 8..9:** Versão de formato `0x0001` (Big-Endian);
    - **Bytes 252..255:** Checksum CRC32 IEEE 802.3 (polinômio `0xEDB88320`) calculado sobre os bytes 0 a 251.
  - Ao carregar os dados em `from_persisted_bytes`:
    ```rust
    pub fn from_persisted_bytes(bytes: &[u8; PERSISTENT_RECORD_SIZE], now_ms: u64) -> Self {
        match SecureGuardPersistentRecord::from_bytes(bytes) {
            Ok(record) => Self::from_persisted_record(&record, now_ms),
            Err(_) => {
                let mut engine = Self::new(SecureGuardPolicy::default());
                engine.is_provisioned = true;
                engine.state = SecureGuardState::ErrorLocked;
                engine.audit_log.push(now_ms, SecureGuardAuditEventType::IntegrityFailure { detail_code: 0x01 });
                engine
            }
        }
    }
    ```
  - Se um único bit do registro for alterado, o CRC32 falhará. O motor entra instantaneamente em **`SecureGuardState::ErrorLocked`**. Nesse estado fail-closed, todas as operações de autorização são negadas permanentemente, impedindo qualquer acesso a chaves privadas.

---

### Ameaça 6: Perda Destrutiva de Passkeys FIDO2 em Caso de Wipe do Secure Guard

- **Descrição do Ataque (Negação de Serviço / Dano ao Usuário):** Um atacante propositalmente erra o PIN do Secure Guard 5 vezes para acionar a rotina de wipe automático, com o objetivo de destruir todas as credenciais FIDO2/WebAuthn de trabalho e serviços pessoais do usuário (e-mail, bancos, portais governamentais).
- **Risco:** Dano irreparável ao usuário final por perda de acesso permanente às suas contas de autenticação de dois fatores.
- **Severidade:** **Crítica (CVSS 8.5)**.
- **Mecanismo de Mitigação (Isolamento Estrito de Escopo de Wipe):**
  - O subsistema impõe **segregação física e lógica de namespaces** na partição de armazenamento Flash.
  - O enum `SecureGuardWipeScope::ProtectedResourcesOnly` rege a ação de limpeza:
    ```rust
    pub enum SecureGuardWipeScope {
        ProtectedResourcesOnly, // Apaga exclusivamente carteiras Web3 e chaves protegidas
        AllCredentials,         // Limpeza total (apenas comando explícito de fábrica)
    }
    ```
  - A rotina de wipe acionada pelo esgotamento das 5 tentativas do Secure Guard apaga **apenas** o cofre de carteiras Web3 (`wallet_*`) e chaves privadas on-device associadas ao Secure Guard.
  - **Preservação Sagrada das Passkeys FIDO2:** As credenciais residentes FIDO2/CTAP2 (`fido_cred_*`, `credProtect`, contadores de uso WebAuthn e PIN FIDO) residem sob namespaces e chaves NVS completamente isolados. Elas **nunca são apagadas por ações do Secure Guard**, garantindo que o usuário mantenha o acesso aos seus serviços WebAuthn intacto mesmo se a carteira for apagada.
  - **Modo de Teste Não-Destrutivo (`test_mode_non_destructive_wipe`):** Em bancadas de validação ou testes automatizados HIL, a flag de política permite simular todo o rito de wipe (registrando `last_wipe_simulated = true` e gerando telemetria completa) sem destruir as chaves do desenvolvedor em silício.

---

### Ameaça 7: Vazamento de Segredos em Memória RAM ou Logs de Diagnóstico

- **Descrição do Ataque:** Extração de restos de memória RAM após o processamento criptográfico (via dump de core, cold-boot attack ou buffer over-read) ou exposição de senhas e chaves privadas em mensagens de log de depuração do firmware transmitidas via porta serial UART0.
- **Risco:** Comprometimento da confidencialidade de chaves criptográficas mestras e PINs.
- **Severidade:** **Alta (CVSS 7.9)**.
- **Mecanismos de Mitigação Combinados:**
  1. **Scrubbing de Memória Obrigatório com `Zeroize`:**
     - Todas as estruturas transitórias contendo senhas, chaves intermediárias ou blocos KDF implementam o trait `zeroize::Zeroize`.
     - Ao concluir a execução de `pbkdf2_hmac_sha256`, os vetores $U$ e $T$ alocados na pilha são ativamente sobrescritos com bytes zero:
       ```rust
       out.copy_from_slice(&t);
       u.zeroize();
       t.zeroize();
       ```
     - Os métodos de verificação limpam candidatos e segredos de memória imediatamente após o uso.
  2. **AuditRingBuffer Estritamente Numérico (Zero Secrets in Logs):**
     - O ring buffer de auditoria (`AuditRingBuffer` em `audit.rs`) armazena até 32 eventos de segurança exclusivamente como tipos enum fortemente tipados com metadados puramente numéricos (timestamp em ms, contadores de falhas restantes, códigos de estado e motivos de expiração).
     - **Proibição Absoluta de Strings e Segredos:** Nenhum campo do enum `SecureGuardAuditEventType` contém ponteiros para buffers de senha, hashes de credenciais ou chaves privadas. As saídas de depuração e logs do comando `0x38 OP_FW_LOG` são matematicamente incapazes de vazar credenciais.

---

## 4. Matriz de Resumo de Riscos Residuais

| Identificador | Ameaça Analisada | Severidade Inicial | Nível de Risco Residual | Justificativa do Risco Residual |
|---|---|---|---|---|
| **THREAT-01** | Bypass da UI Android chamando Opcodes Vendor | Crítica | **Baixo** | Barreira de firmware atua no ponto de entrada único do silício; impossível de ser evadida por software de host. |
| **THREAT-02** | Força Bruta de PIN via USB/Serial | Crítica | **Baixo** | Limitado a estritamente 5 tentativas totais com KDF iterativo e penalidades de backoff progressivo. |
| **THREAT-03** | Reboot forçado entre tentativas incorretas | Alta | **Insignificante** | Contador persistido de forma síncrona na Flash NVS antes da emissão da resposta de erro. |
| **THREAT-04** | Ataques de canal lateral por tempo (Timing) | Alta | **Insignificante** | Comparação estritamente invariante em tempo constante via `subtle::ConstantTimeEq`. |
| **THREAT-05** | Corrupção de memória flash ou injeção de falhas | Alta | **Baixo** | Checksum CRC32 e cabeçalho Magic de 256 bytes colocam o chip em fail-closed `ErrorLocked`. |
| **THREAT-06** | Destruição de passkeys FIDO2 em wipe | Crítica | **Insignificante** | Isolamento estrito de namespaces: passkeys FIDO2 são imunes a wipes do Secure Guard. |
| **THREAT-07** | Vazamento de senhas em RAM ou logs | Alta | **Insignificante** | Limpeza de memória com `zeroize` e ring buffer de auditoria estritamente numérico. |
