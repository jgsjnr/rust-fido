# Manual Completo de Conexão, Botão Físico e Operação da Chave AegisKey (ESP32-S3)

Este guia explica de forma direta **como funcionam as portas da placa**, **os 4 modos de conexão**, **o que o botão físico realmente faz no código** e **o ciclo de PIN, Desbloqueio e Wipe Full**.

---

## 1. Entendendo as Duas Portas USB da Placa ESP32-S3 N16R8

A sua placa `ESP32-S3-DevKitC-1 (N16R8)` possui **duas portas USB-C físicas**, e cada uma tem um papel diferente no hardware:

| Porta na Placa | Chip / Pinos | Para que serve | Quando usar |
| :--- | :--- | :--- | :--- |
| **Porta `UART` (`COM`)** | Conversor USB-Serial (CP2102 / CH343) ligado à `UART0` | Gravação de firmware (`esptool`), logs de boot e comunicação com a **Bridge no PC (`COM7`)** | Quando a placa estiver ligada no **PC** junto com o programa `Start-AegisKey.bat` / `AegisKeyTray.exe` |
| **Porta `USB` (`OTG Nativo`)** | Pinos nativos `GPIO 19 (D-)` e `GPIO 20 (D+)` (`TinyUSB`) | Funciona como **Chave FIDO2 / CTAPHID / KeePassXC / Teclado OTP nativa** (`VID 0x303A : PID 0xAE61`) | Quando ligar a placa **direto no celular via cabo OTG** ou quando usar WebAuthn / KeePassXC direto no navegador/PC sem Bridge |

---

## 2. Os 4 Modos de Conexão da Chave

### Modo A — Cabo USB OTG Direto no Celular (Recomendado no Android)
1. Conecte o cabo USB-C na porta **`USB` (Nativa)** da placa e na entrada USB-C do celular (com adaptador OTG ou cabo C-para-C).
2. O Android exibirá um popup nativo: *"Permitir que o app AegisKey acesse AegisKey Security Key?"* -> Toque em **OK**.
3. No app Android, clique em **"Já tenho uma chave — Ir para o Cofre"** (ou selecione **USB-C Direto**).
4. **Não é necessário segurar o botão por 5 segundos no USB!** O próprio app envia o comando `0x2F` via cabo USB para abrir a janela de sessão.

### Modo B — Bluetooth Low Energy (BLE GATT `0xFFFD`) no Celular
1. Ligue a placa em qualquer fonte de energia USB (PC, carregador ou powerbank).
2. **Para que serve o botão no Bluetooth**: Se a chave ainda não estiver pareada ou estiver com a janela fechada, **segure o botão `BOOT (GPIO 0)` por 5 segundos** (isso abre a janela `PairingManager` por **60 segundos** no firmware).
3. No app Android, selecione **Bluetooth (BLE)** -> toque em **Buscar Chaves** -> selecione `AegisKey`.
   - *Nota*: Com a correção aplicada no `AndroidManifest.xml` e no Wizard, se o Android abrir a janela de confirmação de pareamento Bluetooth do sistema, ao confirmar e voltar para o app você **continua exatamente na etapa onde estava** (sem reiniciar o Wizard).

### Modo C — PC Windows / Linux via Bridge (`COM7` + App C# Flutuante)
1. Conecte a porta **`UART`** da placa no PC (`COM7`).
2. Abra o [Start-AegisKey.bat](file:///e:/projetos/fido/dist/Start-AegisKey.bat) (ou `AegisKeyTray.exe`).
3. O gerenciador flutuante (`380 × 660 px`) conecta automaticamente na `COM7` via `http://127.0.0.1:5678`, exibe o status do **Secure Guard**, **KeePassXC (`Slots 0x30/0x38`)**, **Proximidade Bluetooth** e abre o popup de PIN automaticamente quando o Windows/SSH/KeePassXC solicita a chave.

### Modo D — Wi-Fi Local / Rede (Bridge HTTP/TCP)
- Quando a placa está conectada ao PC com a Bridge (`porta 5678`), o celular na mesma rede Wi-Fi (ou via `adb reverse tcp:5678 tcp:5678`) também consegue conversar com a placa física através da Bridge.

---

## 3. O que o Botão Físico (`BOOT / GPIO 0`) Realmente Faz no Código?

Mapeamento exato do código-fonte ([button.rs](file:///e:/projetos/fido/crates/aegis-fido-firmware/src/button.rs), [pairing.rs](file:///e:/projetos/fido/crates/aegis-fido-firmware/src/pairing.rs) e [freertos_route.rs](file:///e:/projetos/fido/crates/aegis-fido-firmware/src/freertos_route.rs)):

1. **Pressionar e Segurar por 5 segundos (`Hold 5s`)**:
   - Dispara `PairingManager::on_button_hold_5s(now_ms)` no firmware.
   - Abre a janela `pairing_open = true` por **60 segundos**, permitindo que um novo celular faça o vínculo (`0x28 OP_BIND_CLAIM`) via Bluetooth.
   - **Importante**: Quando conectado por **cabo USB**, você **não precisa** segurar o botão por 5 segundos, pois o firmware aceita o comando de software `0x2F` (`OP_TRIGGER_PAIRING_OPEN`) enviado automaticamente pelo app!
2. **Toque Rápido de 1 segundo (`Short Press / User Presence - UP`)**:
   - Ativa o latch físico `up_latched = true` (com janela de confirmação para operações FIDO2 `MakeCredential` / `GetAssertion` no navegador ou assinaturas críticas).
   - Durante uma sessão ativa recém-desbloqueada pelo PIN do **Secure Guard**, o próprio desbloqueio (`0x3B`) já arma `pairing_open = true`, `pin_verified = true` e `arm_up = true` para que você possa criar chaves no Cofre sem precisar apertar o botão duas vezes!
3. **Botão `RST` (`EN`)**:
   - Apenas reinicia a CPU do ESP32-S3 (mantendo todas as chaves salvas na Flash NVS).

---

## 4. Ciclo de Senha (PIN), Desbloqueio e Garantia Contra Bloqueio Permanente

1. **Chave Limpa (`Unprovisioned` — LED Ciano)**:
   - Quando a chave está limpa de fábrica ou após um **Wipe Full**, ela não possui senha cadastrada.
   - Na primeira vez que você clicar em **Desbloquear Cofre** e digitar qualquer PIN de **4 a 16 caracteres** (ex.: `000000`, `123456`, `849201`), o app **cria essa senha na chave e já desbloqueia a sessão automaticamente**, fechando o popup e liberando o Cofre, Carteiras, TOTP e KeePassXC ao mesmo tempo.
2. **Chave Configurada e Bloqueada (`Locked` — LED Âmbar)**:
   - Sempre que a chave é reconectada ou o tempo da sessão expira (5 minutos), ela entra em `Locked`.
   - Basta clicar em **Desbloquear Sessão**, digitar seu PIN no popup -> o popup fecha sozinho e o LED passa para **Verde Esmeralda (`Unlocked`)**.
3. **Proteção Anti-Bloqueio Permanente (`Never Lock Forever`)**:
   - Se você errar o PIN 5 vezes seguidas, a chave **não bloqueia para sempre**: ela aplica apenas uma pausa temporária de segurança (`RateLimited` por 15 segundos) e depois permite tentar novamente.
   - Além disso, o botão **Wipe Full (Restaurar de Fábrica)** pode ser acionado a qualquer momento para zerar a chave de volta ao estado `Unprovisioned` e cadastrar um novo PIN do zero.
