# Especificação de Design Industrial, Mecânico e Ergonômico — AegisKey Secure Guard

> **Projeto:** AegisKey Hardware Security Key & Web3 Hardwallet  
> **Módulo:** Chave Física Criptográfica Portátil  
> **SoC / Módulo Base:** Espressif ESP32-S3-WROOM-1-N16R8 (16MB Flash Quad SPI, 8MB Octal PSRAM)  
> **Data:** 25 de Outubro de 2026  
> **Status:** Documento Normativo e de Engenharia Industrial (Seção 13)  

---

## 1. Visão Geral e Filosofia do Produto

A **AegisKey Secure Guard** é concebida para atuar como o elo físico e tangível de segurança do usuário, combinando os requisitos de um autenticador FIDO2/WebAuthn de uso diário com o rigor de segurança de uma carteira de hardware (Hardwallet) Web3.

O design industrial é guiado por três pilares essenciais:
1. **Portabilidade Extrema e Resistência para Chaveiro (Everyday Carry - EDC):** A chave deve resistir aos rigores de transporte diário junto a chaves metálicas, quedas acidentais, vibração, poeira e umidade moderada.
2. **Ergonomia Tátil sem Falsos Positivos:** O botão físico deve ser intuitivo e confortável de acionar intencionalmente com o polegar ou indicador quando conectado, mas protegido contra pressões involuntárias enquanto guardado no bolso.
3. **Comunicação Visual Semântica e Não Intrusiva:** O LED RGB deve comunicar com clareza imediata o estado de segurança do dispositivo (bloqueado, aguardando toque, autenticado, rate limit ou wipe) através de uma janela difusora suave, sem ofuscamento visual.

---

## 2. Fator de Forma, Dimensões e Ergonomia de Chaveiro

```
+-------------------------------------------------------------------------------------------------+
|                                 VISTA SUPERIOR E DIMENSIONAL (mm)                               |
+-------------------------------------------------------------------------------------------------+
|                                                                                                 |
|   <--- 12.0 mm ---> <------------------------- 40.0 mm ------------------------->              |
|                     +---------------------------------------+                 |                 |
|   +---------------+ |   [ ] Botão Táctil Rebaixado (GPIO 0) |                 |                 |
|   |               | |       (Relevo côncavo anti-acidental) |    +-------+    |                 |
|   | Conector      | |                                       |    | ( O ) |    | 20.0 mm         |
|   | USB-C Macho   | |   (*) Janela Difusora WS2812 (GPIO 48)|    |       |    | (Largura)       |
|   | Integrado     | |       (Lente de policarbonato leitoso)|    +-------+    |                 |
|   +---------------+ +---------------------------------------+    Furo Chaveiro|                 |
|                                                                  Reforçado    |                 |
|                     <----------------- 52.0 mm Comprimento Total ------------>                  |
|                                                                                                 |
|   Espessura Total: 7.8 mm                                                                       |
|   Peso Estimado: 12.5 gramas                                                                    |
+-------------------------------------------------------------------------------------------------+
```

### 2.1. Especificações Dimensionais e Peso
- **Comprimento Total:** 52,0 mm (incluindo 12,0 mm de projeção do conector USB-C).
- **Largura do Corpo:** 20,0 mm (largura padrão confortável para empunhadura e compatível com portas USB adjacentes em notebooks finos sem obstruir portas vizinhas).
- **Espessura Máxima:** 7,8 mm (perfil ultrafino com bordas arredondadas com raio de 1,5 mm para evitar que a chave prenda nas costuras do bolso).
- **Peso Líquido:** 12,5 g $\pm$ 0,5 g (leve o suficiente para não sobrecarregar chaveiros convencionais).

### 2.2. Conector USB-C / USB-A Integrado
- **Interface Primária:** Plugue macho USB Tipo-C nativo Full-Speed (reversível), montado com reforço de ancoragem passante (Through-Hole Retention Tabs) soldadas diretamente à placa de circuito impresso (PCB) em 4 pontos estruturais.
- **Resistência Mecânica do Conector:** Projetado para suportar ciclos mínimos de 10.000 inserções/remoções (conforme padrão USB-IF) e esforço de flexão perpendicular de até 50 N.
- **Opção de Compatibilidade:** Tampa de proteção em silicone de alta densidade acoplada por cabo de aço trançado flexível ou versão de conector retrátil para proteção dos pinos de contato elétrico contra resíduos e fiapos.

### 2.3. Furo Reforçado para Argola de Chaveiro
- **Diâmetro Interno:** 4,5 mm (compatível com argolas metálicas espirais convencionais de até 3,0 mm de espessura de arame).
- **Construção Estrutural:** O furo para argola não é uma simples perfuração plástica na carcaça. Ele incorpora um **anel metálico interno em aço inoxidável 304** (Stainless Steel Eyelet Ring) prensado entre as duas conchas do invólucro plástico.
- **Resistência à Tração:** O conjunto suporta esforço de tração estática superior a **15 kgf (147 N)** sem deformação ou ruptura, impedindo o desprendimento acidental do chaveiro em situações de puxão ou queda.

---

## 3. Botão Físico de Confirmação e Presença do Usuário (GPIO 0)

O acionamento físico é o fundamento inegociável da segurança FIDO2 e do módulo Secure Guard, provando consentimento humano contra ataques remotos:

```
+-------------------------------------------------------------------------------------------------+
|                                 PERFIL DE REBAIXO DO BOTÃO BOOT                                 |
+-------------------------------------------------------------------------------------------------+
|                                                                                                 |
|      Superfície Externa da Carcaça Plástica                                                     |
|      =========================\                           /==========================           |
|                                \  Depressão Côncava de   /                                      |
|                                 \ 1.2 mm de profundidade/                                       |
|                                  +---------------------+                                        |
|                                  |   [ Atuador Tátil ] | (Altura nivelada a -0.4 mm)            |
|                                  +---------------------+                                        |
|                                  |   Domo Metálico     | (Curso: 0.25 mm / Força: 1.8 N)        |
|                                  +---------------------+                                        |
|      ----------------------------+---------------------+-----------------------------           |
|      Placa de Circuito Impresso (PCB)                                                           |
+-------------------------------------------------------------------------------------------------+
```

### 3.1. Rebaixo Ergonômico Anti-Acidental
- **Problema Crítico de Chaveiros:** Botões salientes são pressionados continuamente quando pressionados contra moedas, chaves ou ao sentar-se sobre o chaveiro no bolso.
- **Solução de Engenharia:** O botão conectado ao `GPIO 0` (Active-LOW com pull-up interno) é posicionado dentro de um **nicho côncavo elíptico** com 1,2 mm de profundidade em relação à superfície superior do gabinete. O topo do atuador fica posicionado a **0,4 mm abaixo do plano externo**.
- **Ativação Intencional:** Para acionar o botão, o usuário deve posicionar a ponta do dedo intencionalmente sobre o nicho. Objetos planos ou impactos difusos não conseguem alcançar o atuador mecânico.

### 3.2. Características Mecânicas do Switch Tátil
- **Tecnologia:** Interruptor micro-táctil de montagem em superfície (SMD) com domo de liga metálica níquel-ouro (Metal Dome Tact Switch).
- **Força de Atuação (Operating Force):** Calibrada em **$1,8\text{ N} \pm 0,3\text{ N}$** (180 gramas-força). Essa carga exige pressão deliberada, eliminando acionamentos por vibração ou toque superficial.
- **Curso de Atuação (Travel Distance):** $0,25\text{ mm} \pm 0,05\text{ mm}$, fornecendo um "clique" mecânico sonoro e tátil perfeitamente perceptível pelo usuário mesmo em ambientes ruidosos.
- **Ciclo de Vida:** Testado para mais de 500.000 ciclos de acionamento sem fadiga de mola ou perda de condutividade.

### 3.3. Papel no Subsistema Secure Guard
1. **Confirmação de Presença Física (User Presence - UP):** Toque rápido (< 1s) para autorizar transações Web3, assinaturas de chaves privadas e asserções WebAuthn.
2. **Consentimento de Operações Críticas:** Abertura da janela de pareamento de 60s (hold físico contínuo por 5 segundos com feedback luminoso em âmbar).
3. **Confirmação de Ações Irreversíveis:** Exigência de toque físico duplo durante rotinas de desbloqueio de emergência ou autorização de reset.

---

## 4. Janela Difusora e Tabela de Estados Visuais do LED RGB WS2812 (GPIO 48)

O LED RGB endereçável WS2812 (GPIO 48) opera a uma taxa de sinalização de 800 kHz, fornecendo feedback de segurança rico e inequívoco.

### 4.1. Construção da Janela Difusora
- **Material:** Lente moldada em **Policarbonato de Grau Óptico com Aditivo Difusor Leitoso** (Milky White Light-Diffusing Polycarbonate).
- **Tratamento Superficial:** Texturização fosca acetinada (VDI 3400 Ref. 24) na face externa.
- **Benefícios Técnicos:**
  - Elimina completamente o "hotspot" (ponto de luz brilhante e pontual característico do chip LED SMD);
  - Mistura perfeitamente os três canais vermelho, verde e azul na fonte, evitando franjas coloridas em tons mistos (ex: Ciano, Âmbar e Magenta);
  - Ângulo de dispersão luminosa superior a **160°**, garantindo que o usuário identifique o status do dispositivo independentemente da orientação em que a porta USB estiver plugada.

### 4.2. Tabela Completa de Estados Luminosos do Secure Guard

A tabela a seguir padroniza o comportamento cromático e semântico do LED RGB para a experiência unificada entre o firmware e as interfaces visuais:

| # | Estado Semântico do Sistema | Cor Hex / RGB | Padrão de Animação e Temporização | Significado e Contexto de Segurança |
|---|---|---|---|---|
| **1** | **Desconectado / Suspenso** | Desligado (`#000000`) | Apagado estático | Chave fora da porta USB, em repouso profundo ou desligada por corte de alimentação. |
| **2** | **Conectado / Pronto (Standby)** | Ciano Suave (`#00FFFF`) | *Breathing Cyan* (Pulso senoidal lento de 2.000 ms) | Alimentação estabelecida, autoteste aprovado, firmware operacional em modo de repouso seguro. |
| **3** | **Aguardando Toque Físico (UP)** | Âmbar / Laranja (`#FF8C00`) | *PromptTouch* (Pisca pulsante em ciclo de 800 ms) | Operação pendente (WebAuthn ou Secure Guard) exigindo toque físico no botão `BOOT`. |
| **4** | **Secure Guard Bloqueado** | Vermelho Alerta (`#FF0000`) | Estático contínuo com 60% de brilho | Cofre do Secure Guard bloqueado. Acesso restrito a passkeys públicas; carteiras Web3 trancadas. |
| **5** | **Secure Guard Desbloqueado** | Verde Esmeralda (`#00FF00`) | Verde contínuo sólido | Sessão de autoridade ativa no firmware. Recursos protegidos (Wallets e chaves) liberados. |
| **6** | **Sucesso Criptográfico** | Verde Brilhante (`#00FF00`) | Pulso único rápido de 500 ms com fade-out | Operação de assinatura, KDF ou autenticação FIDO2 concluída com êxito. |
| **7** | **Rate Limited / Alerta de Erro** | Âmbar / Vermelho Alternado | Strobe rápido (100 ms Âmbar / 100 ms Vermelho) | Tentativa incorreta de PIN do Secure Guard. Backoff temporal e penalidade de espera ativados. |
| **8** | **Bloqueio Iminente (4/5 Falhas)** | Magenta Intenso (`#FF00FF`) | Pisca duplo rápido a cada 1.000 ms | **Alerta Crítico:** 4 tentativas consecutivas incorretas. Próxima falha provocará o wipe seletivo. |
| **9** | **Wipe Acionado / Bloqueio Total** | Vermelho Estroboscópico | 5 flashes ultrarrápidos (50 ms on / off) $\rightarrow$ Desligado | Esgotamento das 5 tentativas. Execução do apagamento seguro de carteiras e desligamento do LED. |
| **10**| **Janela de Pareamento Aberta** | Azul Real (`#0000FF`) | *Breathing Blue* (Pulso senoidal suave por 60s) | Botão mantido por 5s ou comando 0x2F. Chave visível para pareamento mútuo via BLE/USB. |
| **11**| **Localizador Visual (Wink)** | Branco Puro (`#FFFFFF`) | 5 estrobos rápidos (80 ms on / 80 ms off) | Disparado pelo comando CTAPHID `CMD_WINK (0x88)` para identificação física da chave. |

---

## 5. Proteção Mecânica, Térmica, Blindagem ESD e Área de Antena RF

```
+-------------------------------------------------------------------------------------------------+
|                                 ARQUITETURA DE CAMADAS E BLINDAGEM                              |
+-------------------------------------------------------------------------------------------------+
|                                                                                                 |
|   +-----------------------------------------------------------------------------------------+   |
|   | Concha Superior: Policarbonato/ABS UL 94 V-0 (Resistente a Impacto)                    |   |
|   +-----------------------------------------------------------------------------------------+   |
|                                                                                                 |
|   +-------------------+  +-------------------------+  +-----------------------------------+   |
|   | Conector USB-C    |  | Módulo ESP32-S3-WROOM-1 |  | Antena PCB 2.4 GHz (BLE / Wi-Fi)  |   |
|   | Pinos VBUS/D-/D+/G|  | Blindagem Metálica RF   |  | ZONA DE EXCLUSÃO (KEEP-OUT)       |   |
|   |                   |  | (Thermal Pad para dissip|  | Sem cobre, sem planos de terra,   |   |
|   | Proteção ESD:     |  |  ação de 240 MHz)       |  | sem parafusos ou metal externo!   |   |
|   | Matriz TVS 4ch    |  +-------------------------+  +-----------------------------------+   |
|   | (+-15kV ar / 8kV) |                                                                         |
|   +-------------------+                                                                         |
|                                                                                                 |
|   +-----------------------------------------------------------------------------------------+   |
|   | Placa de Circuito Impresso de 4 Camadas (FR-4 TG-150, 1.2 mm de espessura)              |   |
|   +-----------------------------------------------------------------------------------------+   |
|                                                                                                 |
|   +-----------------------------------------------------------------------------------------+   |
|   | Concha Inferior: Soldagem Ultrassônica ou Encaixe por Interferência com Selagem IP54    |   |
|   +-----------------------------------------------------------------------------------------+   |
+-------------------------------------------------------------------------------------------------+
```

### 5.1. Proteção Mecânica e Gabinete (Enclosure)
- **Material do Gabinete:** Blenda de **Policarbonato e ABS (PC/ABS)** de alto impacto ou liga metálica injetada de zinco **Zamak-5** com pintura eletrostática a pó fosca texturizada.
- **Classificação de Flamabilidade:** Certificação **UL 94 V-0** (auto-extinguível em menos de 10 segundos em caso de fogo, sem gotejamento inflamável).
- **Fechamento e Vedação:** As metades do gabinete são unidas por **soldagem por ultrassom (Ultrasonic Welding)** ou adesivo estrutural de poliuretano com canaleta labiríntica perimetral, atingindo classificação de proteção **IP54** (resistência total a poeira e respingos d'água laterais).
- **Resistência a Quedas:** Suporta impactos repetidos de quedas de **1,5 metro de altura** sobre piso de concreto sem estilhaçamento ou desconexão interna de componentes.

### 5.2. Dissipação Térmica em 240 MHz
- **Desafio:** O processador Xtensa dual-core de 240 MHz e os rádios integrados de 2.4 GHz dissipam até 0,8 W em pico de atividade (ex: derivação intensiva de KDF PBKDF2 ou negociações simultâneas USB e BLE).
- **Solução Térmica:**
  - Aplicação de um elastômero condutivo térmico (**Thermal Interface Material - TIM**) com condutividade mínima de $3,0\text{ W/m}\cdot\text{K}$ entre a tampa metálica de blindagem do módulo ESP32-S3 e a concha plástica interna;
  - Utilização de plano contínuo de cobre interno na PCB de 4 camadas (camadas 2 e 3 de terra sólido) funcionando como espalhador térmico (Heat Spreader);
  - A temperatura superficial do gabinete mantém-se estritamente abaixo de **$42^\circ\text{C}$** em operação contínua a uma temperatura ambiente de $25^\circ\text{C}$, atendendo aos limites de conforto térmico humano (IEC 62368-1).

### 5.3. Blindagem Contra Descargas Eletrostáticas (ESD Protection)
- **Vulnerabilidade:** A inserção manual de periféricos USB expõe as linhas de dados a arcos de eletricidade estática acumulados no corpo humano ou roupas de lã/sintéticos.
- **Arranjo de Proteção:**
  - Inclusão mandatória de uma matriz de diodos supressores de transientes de baixíssima capacitância (**TVS Array**, ex: `USBLC6-2SC6` ou `TPD4E02B04`) diretamente adjacente aos terminais do conector USB-C;
  - Capacitância parasita por linha inferior a **0,5 pF**, preservando a integridade de sinal Full-Speed (12 Mbps);
  - **Classificação de Imunidade:** Atendimento integral à norma **IEC 61000-4-2 Nível 4**:
    - Descarga por contato: **$\pm 8\text{ kV}$**;
    - Descarga pelo ar: **$\pm 15\text{ kV}$**.
  - O chassi do conector USB é aterrado através de um circuito RC paralelo ($1\text{ M}\Omega \parallel 4,7\text{ nF} / 1\text{ kV}$) para desacoplar ruídos de alta frequência sem criar laços de terra (ground loops).

### 5.4. Zona de Exclusão (Keep-Out Zone) da Antena PCB 2.4 GHz
- **Posicionamento:** A antena PCB meandrada (MIFA) integrada no módulo ESP32-S3-WROOM-1 fica localizada na extremidade oposta ao conector USB (próxima à argola do chaveiro).
- **Regras Estritas de Layout:**
  - **Zona Livre de Cobre:** Em um raio de **mínimo 6,0 mm** ao redor de toda a geometria da antena, todas as 4 camadas da PCB devem ter o cobre completamente removido (sem planos de alimentação, terra ou trilhas de sinal);
  - **Zona Livre de Metal na Carcaça:** Nenhum componente metálico (incluindo o anel de reforço do chaveiro, parafusos ou clipes) pode sobrepor o cone de irradiação da antena;
  - **Desempenho Assegurado:** O ganho da antena é mantido em $\sim +2\text{ dBi}$, assegurando alcance livre de linha de visada de **pelo menos 15 metros** para o protocolo BLE GATT e alcance de estabilidade de sinal para o monitor RSSI de proximidade sem atenuações espúrias.

---

## 6. Diretrizes de Fabricabilidade e Testes em Linha de Produção (DFM / DFT)

1. **Pontos de Teste (Test Points - TP):**
   - Disponibilização de test pads acessíveis na face inferior da placa para pinos `GPIO 0` (BOOT), `GPIO 48` (LED), `TXD0`, `RXD0`, `USB_D-`, `USB_D+`, `3V3` e `GND`.
   - Compatibilidade com fixação em berço de agulhas (**Pogo-pin Bed of Nails**) para programação automatizada em bancada sem necessidade de montagem final.
2. **Gravação e Provisionamento em Linha:**
   - Queima segura de eFuses OTP: gravação da chave primária em `BLOCK7`, salt do dispositivo em `BLOCK8` e travamento de leitura/escrita conforme especificado em `crates/aegis-fido-firmware/src/efuse.rs`.
   - Verificação óptica automatizada (AOI) da difusão luminosa do LED WS2812 através da lente leitosa.
3. **Sustentabilidade e Conformidade Regulatória:**
   - Atendimento pleno às diretrizes **RoHS** (restrição de substâncias perigosas) e **REACH**;
   - Carcaça plástica marcada com código de reciclagem (SPI 7 - Other PC/ABS).
