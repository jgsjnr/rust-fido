# Especificação de Protocolo e Formato de Dados — AegisKey Secure Guard

> **Projeto:** AegisKey FIDO2 & Multi-Protocol Hardware Authenticator  
> **Subsistema:** Secure Guard (Protocolo de Transporte Wire e Persistência Binária)  
> **Status:** Especificação Técnica Normativa e Congelada (Protocol Freeze)  
> **Data:** 25 de Outubro de 2026  
> **Transporte Primário:** USB CTAPHID (`CMD_MSG 0x83`) / BLE GATT (`0xFFFD/0xFFF1`) / Serial UART (`COM7`)  
> **Codificação de Mensagens:** CBOR (RFC 8949) Canonical + Binário Puro de 256 bytes para Flash NVS  

---

## 1. Visão Geral do Transporte Wire

O protocolo de comunicação do Secure Guard opera encapsulado nas mensagens de vendor do padrão **CTAPHID** através do comando canônico **`CMD_MSG (0x83)`**. Toda transação consiste em um pacote de requisição enviado pelo host (Android App, SDK ou Desktop) e um pacote de resposta emitido pelo firmware ESP32-S3.

```
+-------------------------------------------------------------------------------------------------+
|                                ENCAPSULAMENTO CTAPHID DAS MENSAGENS VENDOR                      |
+-------------------------------------------------------------------------------------------------+
|                                                                                                 |
|   +-------------------+--------------------+------------------------------------------------+   |
|   | CTAPHID CMD (1B)  | Payload Length (2B)| Payload Data (N Bytes)                         |   |
|   | 0x83 (CMD_MSG)    | Big-Endian (Len)   | Opcode Vendor (1B) + Argumentos CBOR (N-1 B)   |   |
|   +-------------------+--------------------+------------------------------------------------+   |
|                                            |                                                    |
|                                            v                                                    |
|                   +------------------------+------------------------+                           |
|                   | Vendor Opcode (1 Byte) | CBOR Payload (Map)     |                           |
|                   | 0x3A .. 0x3E           | { 0x01: ..., 0x02: ...}|                           |
|                   +------------------------+------------------------+                           |
+-------------------------------------------------------------------------------------------------+
```

### 1.1. Códigos de Retorno de Transporte (Status Codes)

As respostas de comandos do Secure Guard retornam o primeiro byte com o código de status:

| Código (Hex) | Nome do Status | Significado Operacional |
|---|---|---|
| **`0x00`** | `STATUS_SUCCESS` | Operação executada e confirmada com êxito. Seguido do payload CBOR de resposta. |
| **`0x21`** | `CTAP2_ERR_INVALID_PARAMETER` | Parâmetros CBOR malformados, chave ausente ou tipo inválido. |
| **`0x25`** | `CTAP2_ERR_OPERATION_DENIED` | Operação rejeitada por política interna ou transição de estado proibida. |
| **`0x27`** | `CTAP2_ERR_PIN_REQUIRED` | Acesso negado: o recurso exige que o Secure Guard esteja no estado `Unlocked`. |
| **`0x28`** | `CTAP2_ERR_PIN_INVALID` | PIN ou segredo de recuperação fornecido está incorreto. |
| **`0x29`** | `CTAP2_ERR_PIN_BLOCKED` | Limite de 5 tentativas atingido. Dispositivo em `RecoveryRequired` ou wipe acionado. |
| **`0x33`** | `CTAP2_ERR_PIN_POLICY_VIOLATION`| PIN submetido é muito curto, muito longo ou trivial (ex: "1111", "1234"). |
| **`0x34`** | `CTAP2_ERR_PIN_TOKEN_EXPIRED` | Sessão ativa expirou por inatividade ou timeout absoluto. |
| **`0x3A`** | `CTAP2_ERR_TOO_MANY_PIN_ATTEMPTS` | Tentativa rejeitada devido a penalidade de backoff progressivo ativa (`RateLimited`). |

---

## 2. Especificação Detalhada dos Opcodes Vendor (0x3A..0x3E)

```
+-------------------------------------------------------------------------------------------------+
|                                 MAPA DE OPCODES SECURE GUARD (CMD_MSG 0x83)                     |
+-------------------------------------------------------------------------------------------------+
|   Opcode  | Mnemônico Formal              | Finalidade Operacional                              |
|   --------+-------------------------------+--------------------------------------------------   |
|   0x3A    | OP_SECURE_GUARD_STATUS        | Consulta estado da FSM, contadores e políticas      |
|   0x3B    | OP_SECURE_GUARD_UNLOCK        | Ações de provisionamento, desbloqueio e recuperação |
|   0x3C    | OP_SECURE_GUARD_LOCK          | Encerramento imediato da sessão ativa               |
|   0x3D    | OP_SECURE_GUARD_CONFIG        | Atualização autenticada de políticas de segurança   |
|   0x3E    | OP_SECURE_GUARD_WIPE_SELECTIVE| Acionamento controlado / teste de wipe seletivo     |
+-------------------------------------------------------------------------------------------------+
```

---

### 2.1. Opcode `0x3A`: `OP_SECURE_GUARD_STATUS` (Consulta de Estado e Telemetria)

Permite ao aplicativo Android ou cliente de host inspecionar o estado atual do cofre de autoridade sem necessidade de autenticação prévia.

- **Requisição:**
  - Opcode: `0x3A`
  - Payload CBOR: Opcional / Vazio (Map `{}`) ou `{ 0x01: bool (include_audit_tail) }`.

- **Resposta de Sucesso (`0x00` + Map CBOR):**

| Chave CBOR | Nome do Campo | Tipo de Dado | Descrição Técnica |
|---|---|---|---|
| **`0x01`** | `state` | `unsigned int` | Código wire do estado canônico (`0x00` a `0x09`). |
| **`0x02`** | `is_provisioned` | `bool` | `true` se um PIN e chave de recuperação já foram provisionados. |
| **`0x03`** | `failed_attempts` | `unsigned int` | Número de falhas consecutivas registradas (`0` a `5`). |
| **`0x04`** | `remaining_attempts` | `unsigned int` | Tentativas restantes antes de bloqueio/wipe (`5 - failed_attempts`). |
| **`0x05`** | `rate_limit_remaining_ms` | `unsigned int` | Milissegundos restantes de penalidade de backoff (0 se inativo). |
| **`0x06`** | `session_active` | `bool` | `true` se existe uma sessão válida destravada no firmware. |
| **`0x07`** | `session_remaining_ms` | `unsigned int` | Tempo restante de vida da sessão atual em ms. |
| **`0x08`** | `policy` | `Map` | Mapa com os parâmetros de política ativos (ver Seção 2.4). |
| **`0x09`** | `last_wipe_simulated`| `bool` | `true` se o último wipe foi realizado em modo de teste não destrutivo. |
| **`0x0A`** | `audit_event_count` | `unsigned int` | Quantidade de eventos gravados no ring buffer interno. |

---

### 2.2. Opcode `0x3B`: `OP_SECURE_GUARD_UNLOCK` (Provisionamento, Desbloqueio e Recuperação)

Multiplexador de operações com credenciais criptográficas. O campo `0x01: "action"` define a operação a ser executada.

#### Ação 1: `"provision"` (Definição do Primeiro PIN)
- **Requisição CBOR:**
  ```cbor
  {
    0x01: "provision",
    0x02: h'34393237',            // pin (Byte string do PIN candidato, ex: "4927")
    0x03: h'1010101010101010...',  // recovery_code (16 bytes gerados pelo host ou vazio para geração local)
    0x04: h'aabbccddeeff...'       // host_nonce (opcional, 16B de entropia adicional)
  }
  ```
- **Resposta de Sucesso (`0x00` + Map CBOR):**
  ```cbor
  {
    0x01: "provisioned",
    0x02: h'f0e1d2c3b4a5...',     // recovery_code (16 bytes gerados em silício para exibição ao usuário)
    0x03: 0x02                   // new_state (0x02 = Locked)
  }
  ```

#### Ação 2: `"unlock"` (Desbloqueio de Sessão)
- **Requisição CBOR:**
  ```cbor
  {
    0x01: "unlock",
    0x02: h'34393237'             // pin (Byte string do PIN, ex: "4927")
  }
  ```
- **Resposta de Sucesso (`0x00` + Map CBOR):**
  ```cbor
  {
    0x01: "unlocked",
    0x02: 0x04,                   // state (0x04 = Unlocked)
    0x03: 300000                  // session_duration_ms
  }
  ```
- **Respostas de Erro:**
  - `0x28 CTAP2_ERR_PIN_INVALID`: PIN errado. Retorna `{ 0x01: remaining_attempts, 0x02: backoff_ms }`.
  - `0x3A CTAP2_ERR_TOO_MANY_PIN_ATTEMPTS`: Rejeitado por rate limit. Retorna `{ 0x01: rate_limit_remaining_ms }`.
  - `0x29 CTAP2_ERR_PIN_BLOCKED`: 5 erros atingidos. Transição para `RecoveryRequired` ou `WipePending`.

#### Ação 3: `"change_pin"` (Alteração Transacional de PIN)
- **Requisição CBOR:**
  ```cbor
  {
    0x01: "change_pin",
    0x02: h'34393237',            // current_pin
    0x03: h'39313832'             // new_pin (ex: "9182")
  }
  ```
- **Resposta de Sucesso (`0x00` + Map CBOR):**
  ```cbor
  {
    0x01: "pin_changed",
    0x02: 0x02                   // state (Locked)
  }
  ```

#### Ação 4: `"recover"` (Recuperação de Emergência de Acesso)
- **Requisição CBOR:**
  ```cbor
  {
    0x01: "recover",
    0x02: h'f0e1d2c3b4a5...',     // recovery_code (16 bytes do segredo de uso único)
    0x03: h'37343132'             // new_pin (novo PIN a ser cadastrado)
  }
  ```
- **Resposta de Sucesso (`0x00` + Map CBOR):**
  ```cbor
  {
    0x01: "recovered",
    0x02: h'998877665544...',     // new_rotated_recovery_code (novo segredo de uso único rotacionado)
    0x03: 0x02                   // state (Locked)
  }
  ```

---

### 2.3. Opcode `0x3C`: `OP_SECURE_GUARD_LOCK` (Bloqueio Imediato de Sessão)

Permite ao aplicativo revogar a sessão ativa instantaneamente (ao sair da tela de cofre, fechar o app ou solicitar bloqueio manual).

- **Requisição:**
  - Opcode: `0x3C`
  - Payload CBOR: Vazio `{}`.
- **Resposta de Sucesso (`0x00` + Map CBOR):**
  ```cbor
  {
    0x01: "locked",
    0x02: 0x02                   // state (0x02 = Locked)
  }
  ```

---

### 2.4. Opcode `0x3D`: `OP_SECURE_GUARD_CONFIG` (Configuração de Políticas)

Atualiza a política de segurança no silício. **Requer obrigatoriamente que a sessão esteja no estado `Unlocked`**.

- **Requisição CBOR:**
  ```cbor
  {
    0x01: bool,                   // wipe_on_5_failures (true = wipe, false = recovery code)
    0x02: unsigned int,           // session_duration_ms (ex: 300000 = 5 min)
    0x03: unsigned int,           // inactivity_timeout_ms (ex: 120000 = 2 min)
    0x04: bool,                   // protect_keys_and_aegn (default: true)
    0x05: bool,                   // protect_oath (default: false)
    0x06: bool                    // test_mode_non_destructive_wipe (default: false)
  }
  ```
- **Resposta de Sucesso (`0x00` + Map CBOR):**
  ```cbor
  {
    0x01: "config_updated",
    0x02: true                    // persisted_to_nvs
  }
  ```
- **Resposta se Bloqueado:**
  - Código `0x27 CTAP2_ERR_PIN_REQUIRED`.

---

### 2.5. Opcode `0x3E`: `OP_SECURE_GUARD_WIPE_SELECTIVE` (Acionamento de Wipe Seletivo)

Comando administrativo para resetar o cofre de ativos protegidos do Secure Guard. **Exige estado `Unlocked` ou presença física prolongada**.

- **Requisição CBOR:**
  ```cbor
  {
    0x01: 0x01,                   // scope: 0x01 = ProtectedResourcesOnly, 0x02 = AllCredentials
    0x02: "CONFIRM_WIPE"          // confirmation_token
  }
  ```
- **Resposta de Sucesso (`0x00` + Map CBOR):**
  ```cbor
  {
    0x01: "wiped",
    0x02: 0x00,                   // state (0x00 = Unprovisioned)
    0x03: bool                    // simulated (true se test_mode ativo)
  }
  ```

---

## 3. Especificação Binária do `SecureGuardPersistentRecord` (256 Bytes)

Para garantir máxima velocidade, ausência de fragmentação de heap e integridade absoluta na partição Flash NVS do ESP32-S3, os dados vitais do Secure Guard são serializados em uma estrutura binária estritamente alinhada de exatamente **256 bytes**.

```
+-------------------------------------------------------------------------------------------------+
|                         LAYOUT DE MEMÓRIA DO RECORD DE 256 BYTES (NVS BLOB)                     |
+-------------------------------------------------------------------------------------------------+
| Offset (Dec)  | Tamanho | Campo no Código Rust             | Descrição Técnica                  |
|---------------+---------+----------------------------------+----------------------------------- |
| [000..007]    | 8 B     | PERSISTENCE_MAGIC                | ASCII "AEGSG001" (0x41 0x45 ...)   |
| [008..009]    | 2 B     | PERSISTENCE_VERSION              | uint16 Big-Endian (0x0001)         |
| [010]         | 1 B     | is_provisioned                   | 0x01 se provisionado, 0x00 senão   |
| [011]         | 1 B     | state_wire                       | Código wire do estado (0x00..0x09) |
| [012]         | 1 B     | failed_attempts                  | Contador de falhas (0..=5)         |
| [013]         | 1 B     | last_wipe_simulated              | 0x01 se wipe em modo de teste      |
| [014..021]    | 8 B     | rate_limit_until_ms              | uint64 Big-Endian (Timestamp ms)   |
| [022..037]    | 16 B    | pin_salt                         | Salt TRNG aleatório do PIN         |
| [038..069]    | 32 B    | pin_verifier                     | Verificador PBKDF2-HMAC-SHA256     |
| [070..085]    | 16 B    | recovery_salt                    | Salt TRNG do Segredo de Recuperação|
| [086..117]    | 32 B    | recovery_verifier                | Verificador PBKDF2 da Recuperação  |
| [118]         | 1 B     | policy.wipe_on_5_failures        | Booleano (0x00 ou 0x01)            |
| [119]         | 1 B     | policy.protect_keys_and_aegn     | Booleano (0x00 ou 0x01)            |
| [120]         | 1 B     | policy.protect_oath              | Booleano (0x00 ou 0x01)            |
| [121]         | 1 B     | policy.test_mode_non_destructive | Booleano (0x00 ou 0x01)            |
| [122]         | 1 B     | policy.min_pin_len               | Tamanho mínimo de PIN (ex: 4)      |
| [123]         | 1 B     | policy.max_pin_len               | Tamanho máximo de PIN (ex: 16)     |
| [124]         | 1 B     | policy.reject_trivial_pins       | Booleano (0x00 ou 0x01)            |
| [125]         | 1 B     | reserved_byte                    | Byte reservado de alinhamento (0)  |
| [126..133]    | 8 B     | policy.session_duration_ms       | uint64 Big-Endian (ex: 300.000 ms) |
| [134..141]    | 8 B     | policy.inactivity_timeout_ms     | uint64 Big-Endian (ex: 120.000 ms) |
| [142..145]    | 4 B     | policy.pbkdf2_iterations         | uint32 Big-Endian (ex: 2.000)      |
| [146..251]    | 106 B   | reserved_padding                 | Preenchimento com zeros (0x00)     |
| [252..255]    | 4 B     | crc32                            | uint32 Big-Endian CRC32 IEEE 802.3 |
+-------------------------------------------------------------------------------------------------+
```

### 3.1. Algoritmo de Integridade CRC32

O cálculo de verificação de integridade cobre exatamente os **252 primeiros bytes** do registro (offset `0` ao `251` inclusive):

$$\text{CRC32}_{\text{computed}} = \text{CRC-32}_{\text{IEEE 802.3}}(\text{bytes}[0..251])$$

- Polinômio padrão: `0xEDB88320` (inverso / refletido).
- Valor inicial: `0xFFFFFFFF`.
- XOR de saída: `0xFFFFFFFF`.
- Vetor canônico de teste: a sequência ASCII `"123456789"` produz estritamente `0xCBF43926`.

Se o valor armazenado nos bytes `252..255` diferir de $\text{CRC32}_{\text{computed}}$ durante a inicialização, o parser retorna `SecureGuardError::PersistenceCorrupted("CRC32 mismatch")` e aciona o bloqueio de segurança `ErrorLocked`.
