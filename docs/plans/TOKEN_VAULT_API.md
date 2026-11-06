# Token Vault API — Cofre de senhas via USB CTAPHID e BLE

Documento de integracao para sistemas externos. Como guardar, ler, listar,
apagar e auditar segredos de login no dispositivo usando os opcodes
`0x43` a `0x47`, acessiveis por USB CTAPHID (fio e funis seriais) e por BLE.

Convenacao deste documento: todos os valores hexadecimais de segredos,
usuarios e identificadores sao FICTICIOS e servem so como exemplo de
formato. Nenhum segredo real consta aqui.

## 1. Visao geral

O cofre (password manager embarcado) guarda registros de login selados no
dispositivo. O sistema externo (aplicativo, ponte HTTP, script) e um
transporte cego: ele carrega o CBOR, mas nunca decide politica, nunca
persiste segredo e nunca registra dado sensivel em log.

| Op | Nome | Codigo | Resposta de sucesso |
|----|------|--------|--------------------|
| PUT | Gravar (cria ou substitui) | `0x43` | `0x00` + `{id}` opaco |
| GET | Ler um registro | `0x44` | `0x00` + `{id, username, secret}` |
| LIST | Paginar identificadores | `0x45` | `0x00` + `{ids, next_cursor, has_more}` |
| DELETE | Apagar um registro | `0x46` | `0x00`, sem corpo |
| STATUS | Censo do cofre | `0x47` | `0x00` + `{entry_count, max_entries}` |

Regras que valem para as cinco operacoes:

- Resposta sempre no formato `[status, corpo...]`: o primeiro byte e o
  estado do fio; o restante e CBOR.
- GET e PUT/DELETE que tocam segredo exigem PIN estrito sempre, sem
  excecao e sem atalho de modo de teste nos funis seriais.
- LIST devolve so identificadores opacos (bytes aleatorios gerados pelo
  dispositivo). Rotulos e usuarios NUNCA cruzam esse limite.
- GET devolve usuario e segredo de forma pontual: exibir e zerar da
  memoria em seguida; nunca persistir, nunca registrar em log.
- Falhas de formato ou de cofre negam fail-closed (`0x03`/`0x04`).

## 2. Modelo de ameacas

Considere estes atacantes ao integrar:

1. **Proximidade fisica (USB/serial).** Quem tem o cabo tem o canal em
   texto claro por construcao (igual a USB HID). A defesa e a presenca
   fisica: janela de pareamento aberta por acao no botao do dispositivo
   (cerca de 60 s) mais toque de confirmacao por operacao (latch de
   presenca de uso unico, consumido a cada operacao).
2. **Proximidade de radio (BLE).** O vinculo criptografico (bonding)
   identifica o telefone pareado. Sem vinculo valido, toda operacao do
   cofre nega `0x05` antes de qualquer outro gate, sem tocar no cofre.
3. **Programa malicioso no hospedeiro.** Pode observar e repetir quadros.
   Defesas em camadas: sem sessao PIN valida nao ha leitura nem escrita
   (`0x02`); sem presenca fresca nao ha nada (`0x01`); identificadores
   opacos nao revelam nada (LIST nao vaza rotulos); e o backoff trava
   martelamento (secao 7).
4. **Repeticao (replay).** Quadros CTAPHID/BLE repetidos caem nos mesmos
   gates da primeira tentativa: fora da janela de 60 s (pareamento ou
   vinculo) a resposta e negacao, nao execucao. Operacoes de leitura
   repetidas dentro da janela devolvem o mesmo registro — por isso o
   hospedeiro deve zerar segredos apos exibir e o operador deve fechar a
   janela (walk-away fecha o visualizador).
5. **Exfiltracao por enumeracao.** Identificadores tem 128 bits aleatorios;
   adivinhar nao e viavel. Tentativas autenticadas que falham (`0x03`/
   `0x04`) consomem o orcamento de backoff (secao 7). Negacoes de gate
   (`0x01`/`0x02`/`0x05`) nao carregam oraculo e nao gastam orcamento.

Fora do escopo deste documento (garantido pelo firmware, nao pelo
integrador): lacre do blob em NVS, selo AEAD dos registros e limpeza
pos-uso na memoria do dispositivo.

## 3. Autenticacao e caminho do quadro

Ordem canonica dos gates, igual em todos os transportes:

```
vinculo -> presenca (UP) -> PIN -> janela de 60 s
0x05        0x01             0x02    0x01 (walk-away fecha)
```

- **USB CTAPHID / serial:** HID INIT aloca o canal (CID), depois mensagens
  `CMD_MSG` (`0x83`) com carga `[opcode, CBOR...]`. Aqui o "vinculo" e a
  posse fisica: a janela de pareamento precisa estar aberta (acao no
  botao) e cada operacao consome o latch de presenca (uso unico por
  operacao). Sem janela: negacao de pareamento; sem toque: `0x01`.
- **BLE:** o opcode viaja como primeiro byte do fragmento (`0x43..=0x47`
  abrem transacao no reassembler, mesma faixa do serial). O vinculo e
  criptografico (telefone pareado); sem ele, `0x05`. Presenca e PIN seguem
  a mesma ordem e os mesmos codigos do serial.
- **Janela:** autorizacoes de vinculo e de presenca valem ate 60 s.
  Presenca velha reutilizada nega `0x01` mesmo com o bit de presenca
  ligado; vinculo velho nega `0x01` (walk-away fecha o visualizador).
- **PIN estrito:** GET e DELETE (e todo o resto da familia) so executam
  com sessao PIN valida ou guarda desbloqueada por PIN. Nos funis seriais
  nao existe atalho de modo de teste para o PIN do cofre.

Cada acesso ao cofre emite exatamente uma linha de auditoria no
dispositivo, sem segredos (secao 8).

## 4. CBOR de cada operacao (com exemplos hex)

Mapa CBOR com chaves de texto. Ordem de campos dos exemplos segue o
codificador de referencia. Todos os exemplos abaixo decodificam nos
testes do hospedeiro (`pm` do SDK e `pm_dispatch` do firmware).

### 4.1 PUT `0x43` — gravar

Pedido `{label, username, secret, url}`. `url` pode ser nulo. Limites:
rotulo ate 128 bytes, usuario ate 256, segredo 1..=512, URL ate 512.

Exemplo (rotulo `bank`, usuario `alice`, segredo `s3cr3t`, sem URL):

```
a4656c6162656c6462616e6b68757365726e616d6565616c69636566736563726574467333637233746375726cf6
```

Leitura do exemplo: mapa(4) `label`:`bank`, `username`:`alice`,
`secret`:bytes(6) `733363723374`, `url`:nulo.

Resposta de sucesso `0x00` + `{id}` (identificador opaco gerado pelo
dispositivo, 16 bytes neste exemplo):

```
a162696450aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

### 4.2 GET `0x44` — ler

Pedido `{id}` (identificador opaco obtido no PUT ou no LIST):

```
a1626964500102030405060708090a0b0c0d0e0f10
```

Resposta de sucesso `0x00` + `{id, username, secret}` (liberacao
pontual; exibir e zerar em seguida):

```
a362696442010268757365726e616d6565616c6963656673656372657446733363723374
```

Leitura do exemplo: mapa(3) `id`:bytes(2) `0102`,
`username`:`alice`, `secret`:bytes(6) `733363723374`.
Registro inexistente responde `0x03`, sem corpo util.

### 4.3 LIST `0x45` — paginar identificadores

Pedido `{cursor, limit}` (`limit: 0` significa 32):

```
a266637572736f7200656c696d69741820
```

Leitura do exemplo: mapa(2) `cursor`:0, `limit`:32 (`0x18 0x20`).

Resposta de sucesso `0x00` + `{ids, next_cursor, has_more}`:

```
a363696473824201024203046b6e6578745f637572736f7202686861735f6d6f7265f4
```

Leitura do exemplo: mapa(3) `ids`:[[byte `01 02`],[byte `03 04`]],
`next_cursor`:2, `has_more`:falso. Para continuar, repita o pedido com
`cursor = next_cursor` enquanto `has_more` for verdadeiro.

### 4.4 DELETE `0x46` — apagar

Pedido `{id}`, mesmo formato do GET:

```
a1626964500102030405060708090a0b0c0d0e0f10
```

Resposta de sucesso `0x00` sem corpo. Apagar o inexistente responde
`0x03` (nunca `0x00` falso).

### 4.5 STATUS `0x47` — censo do cofre

Pedido: mapa vazio:

```
a0
```

Resposta de sucesso `0x00` + `{entry_count, max_entries}` (contagem,
nenhum segredo):

```
a26b656e7472795f636f756e74036b6d61785f656e74726965731832
```

Leitura do exemplo: mapa(2) `entry_count`:3, `max_entries`:50
(`0x18 0x32`).

## 5. Codigos de estado

Primeiro byte de toda resposta (`[status, corpo...]`):

| Codigo | Nome | Significado | Quando sai |
|--------|------|-------------|------------|
| `0x00` | OK | Operacao executada | Gates passaram e cofre respondeu |
| `0x01` | Presenca requerida | Falta toque/confirmacao, ou presenca/vinculo fora da janela de 60 s | Sem UP, UP velha reutilizada, walk-away |
| `0x02` | PIN requerido | Sem sessao PIN valida | GET/DELETE (e demais ops) sem PIN |
| `0x03` | Sem registro | Identificador desconhecido | GET/DELETE de `id` inexistente |
| `0x04` | Falha generica | Formato invalido, falha de cofre ou backoff armado | CBOR malformado, limites estourados, martelamento |
| `0x05` | Vinculo requerido | Transporte nao vinculado | BLE sem pareamento; serial fora da janela fisica |
| `0x06` | Nao suportado | Preset sem cofre (dieta) | Builds sem a familia `0x43..=0x47` |

Ordem de avaliacao: opcode da familia -> vinculo (`0x05`) -> presenca
(`0x01`) -> PIN (`0x02`) -> janela (`0x01`) -> backoff (`0x04`) ->
execucao. A primeira falha vence e nada depois dela executa.

## 6. Limites

- Tamanhos (falha fecha em `0x04`): `id` 1..=64 bytes; rotulo ate 128;
  usuario ate 256; segredo 1..=512; URL ate 512; blob selado unico
  limitado pelo teto do envelope de armazenamento.
- Backoff anti-martelamento por transporte (memoria RAM, zera no boot):
  5 falhas autenticadas consecutivas (`0x03`/`0x04` com gates passados)
  armam 30 s de bloqueio, durante os quais toda operacao do cofre nega
  `0x04`. Sucesso (`0x00`) zera o contador. Negacoes de gate
  (`0x01`/`0x02`/`0x05`/`0x06`) nao gastam orcamento.
- Janelas: 60 s para vinculo e para presenca; presenca e latch de uso
  unico consumido pela propria operacao em todos os funis.
- Dieta: presets sem cofre respondem `0x06` a `0x43..=0x47` em todos os
  transportes, sem tocar em gate nem cofre.

## 7. Backoff na pratica (hospedeiro)

- Trate `0x04` repetido apos `0x03` como "aguarde 30 s e reapresente
  UP + PIN". Nao gire em tentativas: cada falha autenticada realimenta
  o orcamento.
- Nao confunda `0x04` de backoff com `0x04` de formato: se o primeiro
  pedido apos abrir a janela ja volta `0x04`, revise o CBOR (secao 4)
  antes de culpar o backoff.
- Operacoes de leitura do operador (STATUS/LIST sem toque) devolvem
  `0x01`, que nao gasta orcamento: pedir o toque e reenviar e o fluxo
  normal, nao um ataque.

## 8. Auditoria

Cada operacao do cofre emite exatamente uma linha no log do dispositivo:

```
[PM-AUDIT] op=0x44 st=0x00
```

So opcode e estado — por construcao o evento nao tem campo para carga,
rotulo, usuario, segredo, URL ou identificador. Verificacao recomendada
ao integrar: rode PUT/GET/LIST/DELETE/STATUS e confirme uma linha por
chamada, sem nenhum byte dos exemplos da secao 4 aparecendo no log.

## 9. Exemplo completo em Python (ponte HTTP e serial direta)

Os dois exemplos usam so a biblioteca padrao. Ajuste `PORTA`/`BASE`.
Valores ficticios. PIN, toque e janela de pareamento precisam estar
validos antes de chamar (sessoes e pareamento seguem o fluxo normal do
dispositivo, fora deste documento).

### 9.1 Via ponte HTTP local (quadro AEGN)

```python
import urllib.request

BASE = "http://192.168.4.1"  # base da ponte; ajuste ao ambiente

PUT_CBOR = bytes.fromhex(
    "a4656c6162656c6462616e6b"
    "68757365726e616d6565616c696365"
    "6673656372657446733363723374"
    "6375726cf6"
)

def ponte_post(caminho, corpo: bytes, tipo="application/octet-stream") -> bytes:
    req = urllib.request.Request(BASE + caminho, data=corpo,
                                 headers={"Content-Type": tipo}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()

def cofre(op: int, cbor_hex: str) -> tuple[int, bytes]:
    # A ponte espera o envelope do dispositivo; aqui vai a carga
    # [opcode, CBOR...] dentro do campo ja enquadrado pela ponte.
    # Consulte o manual da ponte para o enquadramento AEGN exato.
    corpo = bytes([op]) + bytes.fromhex(cbor_hex)
    resp = ponte_post("/ctap", corpo)
    return resp[0], resp[1:]  # (estado, CBOR)

estado, corpo = cofre(0x43, PUT_CBOR.hex())
assert estado == 0x00, f"PUT negou: 0x{estado:02X}"
print("PUT ok, id opaco:", corpo.hex())
```

### 9.2 Via serial direta (CTAPHID 64 B, INIT/CONT)

```python
import struct

PORTA, BAUD = "/dev/ttyUSB0", 115200  # ajuste a porta real
CMD_MSG = 0x83

def enquadrar(cid: int, cmd: int, carga: bytes):
    total = len(carga)
    assert total <= 0xFFFF
    primeiro = carga[:57]
    pkt = bytearray(64)
    struct.pack_into(">IBH", pkt, 0, cid, cmd, total)
    pkt[7:7 + len(primeiro)] = primeiro
    pacotes = [bytes(pkt)]
    seq, off = 0, len(primeiro)
    while off < total:
        parte = carga[off:off + 59]
        pkt = bytearray(64)
        struct.pack_into(">IB", pkt, 0, cid, seq)
        pkt[5:5 + len(parte)] = parte
        pacotes.append(bytes(pkt))
        off += len(parte)
        seq = (seq + 1) & 0xFF
    return pacotes

def cofre_serial(escrever, ler, cid: int, op: int, cbor_hex: str):
    # 1. INIT com nonce de 8 bytes recebe o CID (detalhe no manual CTAPHID).
    # 2. Envia [opcode, CBOR...] como CMD_MSG; a resposta chega
    #    enquadrada da mesma forma: [estado, CBOR...].
    carga = bytes([op]) + bytes.fromhex(cbor_hex)
    for p in enquadrar(cid, CMD_MSG, carga):
        escrever(p)
    return ler()  # (estado, CBOR) apos remontar INIT/CONT

LIST_REQ = "a266637572736f7200656c696d69741820"  # {cursor:0, limit:32}
print("LIST serial:", LIST_REQ)
```

Observacao: apos receber usuario e segredo no GET, zere os bytes na
memoria do hospedeiro (por exemplo sobrescrevendo o buffer) e nunca os
grave em disco ou log.

## 10. Exemplo de integracao em outro sistema

Cenario: um gerenciador de senhas de mesa quer oferecer "guardar no
dispositivo fisico" sem mudar seu formato interno.

1. No cadastro, o gerenciador monta o PUT da secao 4.1 com rotulo,
   usuario, segredo e URL opcionais, pede toque + PIN no dispositivo e
   envia `0x43`. Guarda **apenas** o `id` opaco devolvido, ao lado do
   registro local (o `id` sozinho nao revela nada).
2. No preenchimento, o gerenciador pede toque + PIN, envia GET `0x44`
   com o `id`, recebe `{username, secret}`, preenche o formulario, zera
   os buffers e descarta. Nada do segredo toca o disco.
3. Na listagem, pagina LIST `0x45` com `cursor`/`next_cursor` para
   reconciliar quais `id`s ainda existem (rotulos nunca trafegam).
4. Na exclusao, envia DELETE `0x46`; `0x00` confirma, `0x03` significa
   que ja nao existia.
5. Em tela de saude, STATUS `0x47` mostra ocupacao
   (`entry_count`/`max_entries`) sem expor conteudo.
6. Em erro `0x01`, o gerenciador mostra "toque no dispositivo e tente de
   novo"; em `0x02`, "desbloqueie com o PIN"; em `0x05`, "emparelhe o
   dispositivo"; em `0x04` repetido, "aguarde 30 s (backoff)".

## 11. Erros comuns

| Sintoma | Causa provavel | Acao |
|---------|----------------|------|
| `0x05` em tudo no BLE | Telefone nao pareado/vinculo ausente | Parear e vincular antes do cofre |
| `0x05`/`NeedPairing` no serial | Janela de pareamento fechada | Acao de 5 s no botao, reenviar em ate 60 s |
| `0x01` em tudo | Sem toque, ou presenca/vinculo fora da janela | Tocar/confirmar e reenviar; nao reutilizar latches velhos |
| `0x02` no GET/DELETE | Sem sessao PIN | Desbloquear com PIN (sem atalho) e reenviar |
| `0x03` no GET/DELETE | `id` desconhecido ou registro apagado | Relistar e reconciliar; `id`s sao opacos |
| `0x04` imediato | CBOR fora do formato ou limite estourado | Conferir secao 4 byte a byte; `url` ausente deve ser nulo, nao ausencia |
| `0x04` apos falhas | Backoff de 30 s armado | Aguardar, reapresentar UP + PIN; nao martelar |
| `0x06` em tudo | Preset sem cofre | Usar build com a familia `0x43..=0x47` |
| Resposta vazia/timeout | Enquadramento CTAPHID quebrado | Revisar INIT (CID) e remontagem CONT; checar secao 9.2 |

## 12. Rastreabilidade de verificacao

- Portas de entrada: funil serial (`serial_ctaphid` + `serial_vendor`),
  rota FreeRTOS (`freertos_route`) e despacho BLE (`run/ble_dispatch`),
  todos afunilando no mesmo executor (`pm_dispatch`) com os mesmos
  gates (`pm_store::authorize_pm_op`).
- Testes de hospedeiro executados: `pm_store` (gates, janela de UP,
  backoff, auditoria sem segredos), `pm_dispatch` (backoff ponta a
  ponta, UP velha, PIN estrito em GET/DELETE, transporte nao vinculado),
  `serial_vendor` (falha fechada sem vinculo, PIN estrito), SDK `pm`
  (CBOR ida e volta de todos os DTOs), suites de integracao do
  firmware (incluindo `wipe_total_pm` e `secure_guard_integration`).
- Comandos: `cargo test -p aegis-fido-firmware` (659 testes da lib +
  integracao, tudo verde), `cargo test -p universal-device-sdk
  --features pm pm`, `cargo clippy -p aegis-fido-firmware
  --all-targets` (sem avisos) e checagem do preset diet
  (`cap-fido-only`, que responde `0x06` sem tocar no cofre).
