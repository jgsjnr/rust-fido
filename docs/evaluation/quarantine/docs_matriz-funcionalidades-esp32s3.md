# Matriz de funcionalidades implementáveis em Rust + ESP-IDF no ESP32-S3

## Objetivo e escopo

Este documento organiza as funcionalidades de uma chave criptográfica própria baseada no **ESP32-S3 N16R8**, usando **Rust como linguagem principal** e **ESP-IDF como camada de suporte ao hardware**.

Classificação usada:

- **Implementável:** tecnicamente viável com Rust, ESP-IDF e bibliotecas compatíveis.
- **Com ressalvas:** exige desenvolvimento próprio, integração com componentes C, validação de interoperabilidade ou armazenamento protegido.
- **Não garantido:** pode ser reproduzido funcionalmente, mas não oferece garantia equivalente à de um secure element dedicado.

> Implementar um algoritmo não equivale a implementar um autenticador compatível com uma especificação nem garante resistência a ataques físicos.

---

## 1. Funcionalidades criptográficas

| Funcionalidade | Viabilidade | Observações |
|---|---|---|
| Geração de chaves ECC | Implementável | Depende das curvas suportadas pela biblioteca |
| SECP256R1 / P-256 | Implementável | Prioridade para FIDO2 e WebAuthn |
| SECP384R1 / P-384 | Implementável | Maior custo de processamento |
| SECP521R1 / P-521 | Com ressalvas | Validar suporte e desempenho |
| SECP256K1 | Com ressalvas | Não presumir suporte nativo |
| Brainpool | Com ressalvas | Depende da biblioteca criptográfica |
| Curvas Koblitz | Com ressalvas | Validar implementação e interoperabilidade |
| Curve25519 / X25519 | Implementável | Troca de chaves |
| Curve448 / X448 | Com ressalvas | Maior custo de memória e processamento |
| Ed25519 | Implementável | Assinaturas digitais |
| Ed448 | Com ressalvas | Depende de implementação compatível |
| ECDSA | Implementável | Assinatura e verificação |
| ECDSA raw e prehashed | Implementável | Definir formato e semântica do hash |
| EdDSA puro, context e prehashed | Com ressalvas | Respeitar as variantes da especificação |
| RSA 1024, 2048, 3072 e 4096 | Implementável | RSA-1024 não é recomendado para novas aplicações seguras |
| RSA com tamanhos arbitrários | Com ressalvas | Limitado por memória, biblioteca e protocolo |
| RSA-PKCS#1 v1.5 | Implementável | Assinatura e verificação |
| RSA-PSS | Implementável | Preferível para novos sistemas que o aceitem |
| Raw RSA | Com ressalvas | Operação de baixo nível; requer tratamento seguro de padding |
| SHA-1, SHA-224, SHA-256, SHA-384 e SHA-512 | Implementável | SHA-1 apenas para compatibilidade legada |
| ECDH | Implementável | Derivação de segredo compartilhado |
| Derivação de chaves privadas EC | Com ressalvas | Definir construção e compatibilidade com a curva |
| RSA-OAEP | Implementável com biblioteca compatível | Cifração e decifração |
| RSA-X.509 | Com ressalvas | Operação RSA legada sem padding moderno |
| AES-128, AES-192 e AES-256 | Implementável | Geração e gestão de chaves |
| AES-CBC, ECB, CFB, OFB, CTR e XTS | Com ressalvas | Disponibilidade depende da biblioteca; ECB/CBC não autenticam dados |
| AES-GCM e AES-CCM | Implementável | Cifração autenticada |
| AES-CMAC | Implementável | Autenticação de mensagens |
| ChaCha20-Poly1305 | Implementável | Cifração autenticada |
| HKDF, PBKDF2 e X9.63-KDF | Implementável | Derivação de chaves |
| HMAC-SHA-2 | Implementável | Inclui variantes SHA-256, SHA-384 e SHA-512 |
| AES Key Derivation | Com ressalvas | Especificar a construção exata |
| RNG de hardware (HRNG) | Implementável | Usar API documentada e garantir condições adequadas de entropia |

**Recomendação:** exponha uma interface criptográfica em Rust e implemente cada algoritmo por uma biblioteca com suporte verificado a `no_std` ou por integração controlada com ESP-IDF. Não presuma que todos os algoritmos sejam acelerados por hardware.

---

## 2. FIDO2, CTAP e WebAuthn

| Funcionalidade | Viabilidade | Condições |
|---|---|---|
| CTAP 2.3 | Com ressalvas | Comandos, estados, erros, extensões e transporte da versão-alvo |
| CTAP 1.2 / U2F | Com ressalvas | Compatibilidade com clientes legados |
| USB HID para FIDO | Implementável | Transporte e máquina de estados CTAP |
| WebAuthn | Implementável como autenticador | O navegador fornece a API; o dispositivo implementa o protocolo do autenticador |
| Registro de credenciais | Implementável | Criação, persistência e associação ao relying party |
| Login/autenticação por passkey | Implementável | Assinatura do desafio e validação dos parâmetros |
| Credenciais discoverable/resident | Implementável | Armazenamento protegido, limites e gerenciamento |
| Gerenciamento de credenciais | Implementável | Listagem, exclusão e atualização conforme CTAP |
| Attestation básica e self-attestation | Implementável | Formatos e certificados compatíveis |
| Enterprise attestation | Com ressalvas | Política, provisionamento e requisitos do cliente |
| ECDSA e EdDSA na autenticação | Com ressalvas | Usar apenas algoritmos aceitos pelo protocolo e cliente |
| User Presence (UP) por botão | Implementável | Vincular evento físico à operação pendente |
| User Verification (UV) por PIN | Implementável | Protocolo PIN/UV, limites de tentativas e proteção contra replay |
| HMAC-Secret | Com ressalvas | Segredo por credencial, derivação e interoperabilidade |
| minPinLength | Implementável | Política de tamanho mínimo e respostas CTAP |
| CredProtect | Implementável | Níveis de proteção e política de descoberta |
| CredBlob | Implementável | Dados associados à credencial |
| LargeBlob, até 2048 bytes | Com ressalvas | Espaço, integridade e operações de leitura/escrita |
| UVM | Com ressalvas | Declarar apenas métodos de verificação realmente implementados |
| Extensões para pagamentos de terceiros | Com ressalvas | Implementar a extensão exata e validar interoperabilidade |
| Política de complexidade do PIN | Com ressalvas | Definir e aplicar regras da versão suportada |
| Authenticator Configuration | Implementável | Controles de configuração autorizados pelo protocolo |
| Permissões MC, GA, CM, ACFG e LBW | Com ressalvas | Mapear permissões a operações e validar autorização |
| Seleção de dispositivo | Implementável | Interface própria; não confundir com seleção de credenciais |
| Registro/login por aplicação | Implementável | Cliente precisa ser compatível com WebAuthn/FIDO |
| Botão configurável pelo fabricante | Implementável | Configuração autenticada e protegida contra alterações não autorizadas |

**Atenção:** CTAP 2.3 não é apenas uma lista de extensões. A conformidade exige comportamento normativo, códigos de erro, limites de mensagens, estados PIN/UV, transporte e testes aplicáveis.

---

## 3. OTP, OATH e autenticação por desafio

| Funcionalidade | Viabilidade | Condições |
|---|---|---|
| TOTP | Implementável | Segredo protegido, relógio confiável e algoritmo compatível |
| HOTP | Implementável | Contador persistente e atualização atômica |
| OATH | Implementável | Implementar mecanismos e formatos desejados |
| Desafio-resposta | Implementável | Definir protocolo, derivação de segredo e verificação |
| Teclado USB HID | Implementável | Emulação compatível com o sistema operacional |
| OTP digitado após pressionar botão | Implementável | Gerar/selecionar OTP e exigir ação física |
| Seleção de conta/serviço | Implementável | Menu e armazenamento de configurações |
| Contador de uso de chaves | Com ressalvas | Persistência, resistência a rollback e desgaste da flash |

O USB HID de teclado é diferente do USB HID para FIDO. São funções separadas e devem ter controles distintos. Para reduzir vazamentos, o teclado não deve digitar segredos sem ação física deliberada.

---

## 4. Armazenamento, backup e gestão de segredos

| Funcionalidade | Viabilidade | Condições |
|---|---|---|
| Chaves privadas residentes | Com ressalvas | Cifração em repouso, autenticação e isolamento lógico |
| Sementes OTP | Com ressalvas | Proteção equivalente à das chaves privadas |
| Dados arbitrários cifrados até 4 KB | Implementável | Cifração autenticada e controle de tamanho |
| Backup e restauração de credenciais | Implementável | Formato autenticado, integridade e proteção contra replay |
| Frase de recuperação de 24 palavras | Implementável | Definir padrão, entropia, checksum e codificação |
| Exportação/importação autenticada de passkeys | Com ressalvas | Protocolo próprio ou padrão compatível |
| Derivação HD | Implementável | BIP32 e SLIP-0010 conforme curvas suportadas |
| Assinaturas HD e cifração derivada | Implementável | Caminhos, separação de domínios e política de uso |
| DKEK (Device Key Encryption Key) | Implementável como estratégia de chaves | Proteção depende do armazenamento da chave raiz |
| DKEK n-de-m | Implementável | Distribuição, recomposição e recuperação dos compartilhamentos |
| Até 16 domínios de chaves | Implementável | Isolamento lógico, autorização e quotas |
| DEK para armazenamento interno | Implementável | Cifração autenticada e gestão de chaves |
| PIN de transporte | Implementável | Política de sessão e proteção contra tentativas |
| PIN de sessão | Implementável | Autorização com expiração e escopo definidos |
| PKA sem PIN | Com ressalvas | Política própria; não equivale a proteção física |
| RTC | Com ressalvas | Considerar perda de energia e adulteração temporal |
| Certificados de titular | Implementável | Formatos e cadeias compatíveis |

Uma frase de recuperação de 24 palavras não protege automaticamente o dispositivo. Defina a fonte de entropia, o esquema de derivação e o procedimento de recuperação antes de implementá-la.

---

## 5. PIV, OpenPGP e cartão inteligente

| Funcionalidade | Viabilidade | Condições |
|---|---|---|
| OpenPGP Card 3.4.1 | Com ressalvas | Comandos e estruturas da versão específica |
| PIV | Com ressalvas | Objetos, comandos, políticas e algoritmos exigidos |
| PKCS#11 | Implementável como interface | Normalmente requer módulo/middleware no computador host |
| USB CCID | Com ressalvas | Implementar a classe CCID e os comandos de cartão inteligente |
| Extended APDU | Implementável | Parser, limites, fragmentação e tratamento de erros |
| RSA/ECC para cartão | Implementável | Limitado às primitivas efetivamente implementadas |
| ECDH para cartão | Implementável | Formatos e parâmetros compatíveis |
| Autorização por PIN | Implementável | Política de bloqueio, tentativas e sessão |
| KDF para PIN | Implementável | Escolher KDF e parâmetros adequados à especificação |
| Manage Security Environment (MSE) | Com ressalvas | Comandos e estados conforme o perfil |
| Ciclo de vida do cartão | Implementável | Transições e bloqueio de operações em estados inválidos |
| User Interaction Flag (UIF) | Implementável | Configurar exigência de confirmação física |
| Certificados de titular | Implementável | Importação, armazenamento e validação |
| CVC certificates | Com ressalvas | Perfil CVC e algoritmos exigidos |
| PKI attestation por chave | Com ressalvas | Autoridade ou identidade de atestação confiável |
| Emissão remota PKI CVCert | Com ressalvas | Protocolo de emissão, autoridade e validação |
| Secure messaging | Com ressalvas | Implementar protocolo completo de canal seguro |
| PKA por chave pública | Implementável como mecanismo próprio | Interoperabilidade depende do protocolo |

**PKCS#11 não é um protocolo USB que o dispositivo implementa isoladamente.** Uma implementação prática oferece comandos criptográficos por CCID e um módulo PKCS#11 no computador, que traduz as operações para aplicações como OpenSC e OpenSSL.

O suporte USB, endpoints e coexistência de interfaces deve ser validado no hardware e na versão do ESP-IDF escolhidos.

---

## 6. Segurança do firmware e proteção física

| Funcionalidade | Viabilidade | Limitações |
|---|---|---|
| Secure Boot v2 | Implementável nativamente | Verificação de firmware assinado |
| Flash Encryption | Implementável nativamente | Criptografa conteúdo da flash externa |
| NVS Encryption | Implementável | Requer configuração correta de chaves e partições |
| Chaves protegidas por eFuse | Com ressalvas | Depende do propósito e da configuração da eFuse |
| OTP por eFuse | Com ressalvas | Operação irreversível; planejar antes da gravação |
| Secure Lock | Implementável parcialmente | Política própria combinada com proteções do hardware |
| Dificultar dumps da flash | Implementável parcialmente | Secure Boot, Flash Encryption, interfaces e eFuses |
| Desabilitação de JTAG | Implementável | Pode ser irreversível conforme a eFuse |
| Restrição do download mode | Com ressalvas | Configuração de eFuses e modo de produção |
| Proteção contra downgrade | Com ressalvas | Controle de versão confiável e estratégia anti-rollback |
| Rescue interface | Implementável | Recuperação autenticada e de escopo limitado |
| Recuperação após falha de firmware | Implementável | Bootloader e imagem assinada de recuperação |
| Confirmação física antes de assinar | Implementável | Vincular a confirmação ao pedido específico |
| Contador de operações criptográficas | Com ressalvas | Resistência a rollback depende da persistência |
| Proteção de chaves em RAM | Parcialmente | Limpeza de buffers, redução de cópias e controle de exposição |
| Resistência a canal lateral | Parcial | Requer análise de tempo, consumo e comportamento físico |
| Resistência a fault injection | Não garantida | Não equivale a secure element certificado |
| Resistência a ataques invasivos | Não garantida | Não há garantia equivalente à de elemento seguro dedicado |

É possível dificultar substancialmente a extração de segredos usando Flash Encryption em modo de produção, chaves protegidas em eFuse e Secure Boot. Isso **não garante que uma chave privada jamais possa ser extraída**: as chaves são utilizadas durante operações e a proteção depende do modelo de ameaça e da implementação.

Secure Boot e Flash Encryption podem restringir atualização e recuperação via USB. Projete e teste o fluxo de rescue antes de ativar eFuses definitivas.

---

## 7. Botões, LEDs e configuração

| Funcionalidade | Viabilidade |
|---|---|
| Leitura do botão físico | Implementável |
| Confirmação de presença por botão | Implementável |
| Confirmação de assinatura por botão | Implementável |
| Configuração do comportamento do botão | Implementável |
| Bloqueio após tentativas inválidas | Implementável |
| Configuração via USB | Implementável |
| Indicadores LED de estado | Implementável |
| Personalização de padrões de LED | Implementável |
| Menu local de contas e credenciais | Implementável, conforme os recursos de tela |
| Modo de recuperação | Implementável |
| Configuração de PIN | Implementável |
| Configuração de OTP/OATH | Implementável |
| Seleção de interfaces USB | Implementável |
| Registro de eventos sem segredos | Implementável |

Implemente um protocolo próprio de configuração dos LEDs, com autenticação e validação dos comandos.

---

## 8. Ordem recomendada de implementação

### Fase 1 — Base segura

- [ ] Projeto Rust + ESP-IDF reproduzível
- [ ] RNG e primitivas criptográficas essenciais
- [ ] Armazenamento autenticado de credenciais
- [ ] Botão físico e máquina de estados
- [ ] Planejamento de Secure Boot e Flash Encryption

### Fase 2 — Autenticador FIDO

- [ ] USB HID para FIDO
- [ ] CTAP e U2F
- [ ] P-256 e ECDSA
- [ ] Registro, login e credenciais discoverable
- [ ] PIN/UV e confirmação física

### Fase 3 — Extensões e gerenciamento

- [ ] HMAC-Secret, minPinLength e CredProtect
- [ ] CredBlob e LargeBlob
- [ ] Gerenciamento de credenciais
- [ ] Attestation e configuração do autenticador

### Fase 4 — Funcionalidades adicionais

- [ ] TOTP, HOTP e OATH
- [ ] USB HID de teclado
- [ ] OpenPGP e PIV
- [ ] RSA, Brainpool, EdDSA e outras curvas compatíveis

### Fase 5 — Recursos avançados

- [ ] CCID, APDU estendido e PKCS#11 no host
- [ ] HD, BIP32 e SLIP-0010
- [ ] Backup e recuperação autenticados
- [ ] DKEK, múltiplos domínios e política anti-rollback
- [ ] Testes de interoperabilidade e avaliação de segurança

---

## 9. Critérios mínimos de validação

Antes de considerar uma funcionalidade concluída:

- [ ] Testar primitivas criptográficas com vetores de referência.
- [ ] Testar entradas inválidas, truncadas e malformadas.
- [ ] Verificar limites de memória, tamanho de mensagens e concorrência.
- [ ] Validar PIN, bloqueio, tentativas e estados de autorização.
- [ ] Confirmar que presença física está vinculada à operação correta.
- [ ] Testar persistência após desligamento inesperado.
- [ ] Testar recuperação, atualização e comportamento após falhas.
- [ ] Testar interoperabilidade com clientes e sistemas-alvo.
- [ ] Não registrar PINs, sementes, chaves privadas ou OTPs em logs.
- [ ] Documentar quais algoritmos e extensões foram realmente implementados.
- [ ] Não declarar conformidade FIDO sem executar os testes de conformidade aplicáveis.
- [ ] Fazer revisão de segurança antes de uso com credenciais reais.

---

## Conclusão

O ESP32-S3 N16R8 é uma plataforma viável para desenvolver um autenticador USB próprio com FIDO2, OTP, operações criptográficas, armazenamento cifrado e funcionalidades de cartão inteligente. O maior esforço não está apenas em implementar AES, RSA ou ECDSA, mas em construir um **autenticador interoperável, com gerenciamento correto de credenciais e um modelo de segurança consistente**.

Prioridade sugerida:

1. FIDO2/CTAP, P-256, ECDSA, PIN/UV, botão físico e armazenamento protegido.
2. Extensões FIDO e gerenciamento de credenciais.
3. OTP/OATH e interface de teclado.
4. OpenPGP, PIV, CCID e RSA avançado.
5. Curvas adicionais, HD, backup e mecanismos avançados de gestão de chaves.

A lista descreve viabilidade técnica, não uma certificação de conformidade ou garantia de resistência a ataques físicos. Verifique a compatibilidade real de cada algoritmo com a versão do ESP-IDF, a biblioteca criptográfica e os limites de RAM/flash do dispositivo.
