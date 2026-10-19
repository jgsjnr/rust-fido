# PIV + Proximidade BLE — Parte 1 (Wave 1)

> **Carimbo LAB-ONLY:** isto é código de laboratório. Sem secure boot
> (trava que só deixa rodar firmware assinado). Não usar em produção.

## 1. O que foi feito na Wave 1

**`crates/aegis-fido-usb/src/piv.rs` — cartão PIV mínimo (MVP slots 9A/9E):**
- `SELECT` por AID (código que escolhe o aplicativo PIV no cartão) só aceita
  o AID do PIV. Se acertar, volta o FCI de laboratório (cartão de visita do app).
- `GET DATA` (leitura de um objeto do cartão) só funciona depois do `SELECT`.
  Sem `SELECT`, responde `69 85` (condição não satisfeita).
- Objetos lidos: CHUID e CCC (crachá e mapa do cartão, valores falsos de lab).
  Tudo atrás da trava `lab-mocks`: sem ela, responde `6A 82` (não encontrado).
- Erros cobertos: AID desconhecido `6A 82`, sem `SELECT` `69 85`,
  pedido malformado `6A 82`, instrução desconhecida `6D 00`, P1 errado no `SELECT`.
- Onde ver os testes: `piv.rs` módulo `mod tests` (8 testes `should_*`).
- Ainda sem PIN (senha do cartão). Só seleciona e lê. Trava, não autentica.

**`crates/aegis-fido-firmware/src/proximity.rs` — vigia de proximidade por RSSI:**
- RSSI é a força do sinal Bluetooth, em dBm (número negativo; quanto mais
  perto de zero, mais forte. Ex.: -60 é forte, -85 é fraco).
- Regra padrão: sinal abaixo de -75 dBm por 10 segundos = `Away` (longe).
- Histerese de 5 dB (margem anti-pisca-pisca): só volta a `Near` (perto)
  acima de -70 dBm. Entre -75 e -70, congela tudo.
- `Locked` (travado) nunca é automático: só via `confirm_lock()` a partir de `Away`.
- Sair de `Locked` exige presença física + PIN válido via `unlock()`.
- Sem leitura (`None`) conta como sinal fraco. Tempo por chamada limitado a 60 s.
- Funciona sem sistema operacional (`no_std`), com relógio injetado (testável no PC).
- Onde ver os testes: `proximity.rs` módulo `mod tests` (9 testes `should_*`).

## 2. O que você precisa ter

- [ ] Windows 10/11 com Bluetooth ligado (MVP é Windows primeiro).
- [ ] Celular ou chave BLE (fob) como presença para teste de proximidade.
- [ ] Portas COM livres para a placa (ver no Gerenciador de Dispositivos).
- [ ] Opcional: AD de laboratório (Active Directory de teste) para logon com PIV.
- [ ] Não usar emulador Android para USB: emulador não tem USB host
  (não enxerga a chave física). Teste USB só em hardware real.

## 3. Como testar na worktree

Passo 0 — volte para um estado conhecido (obrigatório antes de tudo):

```powershell
git status
git stash list
```

Se houver sujeira, pare e limpe antes de testar.

Passo 1 — testes unitários (dentro da worktree `fido-piv-ble-proximity-1`):

```powershell
cargo test -p aegis-fido-usb piv::
cargo test -p aegis-fido-firmware proximity::
```

Passo 2 — qualidade (zero avisos):

```powershell
cargo clippy --all-targets -- -D warnings
```

Passo 3 — Windows com firmware PIV gravado (só quando existir):

```powershell
certutil -scinfo
```

- `certutil -scinfo` lista cartões PIV visíveis no Windows. Deve mostrar
  o cartão de laboratório. Se não aparecer, o firmware PIV ainda não está gravado.

## 4. Avisos + o que fica para a fase 2

**LAB-ONLY e lock-only:**
- Sem secure boot: qualquer um pode gravar firmware. Só em bancada isolada.
- Proximidade só sugere travar; RSSI nunca libera acesso sozinho.
- PIV atual só lê CHUID/CCC falsos dos slots 9A/9E (autenticação e assinatura).
  Nenhum certificado real sai do dispositivo.

**Fase 2 (não mexer agora):**
- Slots 9C/9D (assinatura de código e gerência de chave).
- Linux e macOS (hoje só Windows).
- GATT real (perfil Bluetooth de troca de dados) e RFC associada.
- Máquina de estados do VERIFY (conferência do PIN com tentativas e bloqueio).
