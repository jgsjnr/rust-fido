# Manual de uso / AegisKey ident

## Abrir na worktree principal

O pacote fica em `E:\projetos\fido\ident`, na branch da worktree principal. É um protótipo visual independente dos companions instalados e do firmware.

Pré-requisitos: navegador moderno e Python 3 disponível no terminal.

No PowerShell:

```powershell
Set-Location E:\projetos\fido\ident
python -m http.server 8769 --bind 127.0.0.1
```

Abra http://127.0.0.1:8769 no navegador. Mantenha esse terminal aberto enquanto explora. O bind em loopback disponibiliza o conteúdo apenas neste computador. Não é necessário iniciar a bridge, conectar a placa ou instalar dependências JavaScript.

## Explorar a interface

1. **Visão geral:** mostra os estados da sessão e a ilustração conceitual da chave. A interface começa bloqueada.
2. Clique em **Explorar desbloqueio** e depois **Simular sessão ativa**. Essa ação mostra exemplos por cinco minutos, sem pedir PIN.
3. **Minhas chaves:** pesquise por nome ou conta, filtre por tipo e abra **Detalhes**. **Criar exemplo** adiciona apenas um cartão em memória. A confirmação por toque é uma demonstração.
4. **Códigos temporários:** explore o indicador de tempo e a ação de copiar. Os números são amostras fixas e não autenticam contas.
5. **Senhas:** a lista contém IDs opacos fictícios. **Visualizar** e **Ver conteúdo fictício** apresentam uma amostra. Fechar remove o conteúdo do diálogo.
6. **Dispositivos:** **Simular desconexão** bloqueia a sessão e oculta as listas protegidas. **Simular conexão** não desbloqueia a sessão automaticamente.
7. **Integrações:** consulte as famílias de recursos documentadas. Os botões não configuram serviços.
8. **Recuperação:** conheça o fluxo sem fornecer código real ou alterar o PIN.
9. **Preferências:** altere opções da demonstração ou reinicie. As opções não mudam configurações do sistema operacional.
10. **Identidade visual:** veja as aplicações da marca, paleta, tipografia e ícones. Os links de download entregam SVGs locais.

Atualizar a página restaura os padrões, bloqueia a sessão e remove exemplos adicionados. O protótipo não grava preferências ou dados em disco. Não informe credenciais reais.

## Celular e acessibilidade

A janela estreita usa uma barra lateral compacta. Os ícones têm nomes acessíveis e título. Use Tab para navegar e Enter para acionar controles. Esc fecha um diálogo. O link **Pular para conteúdo** aparece ao receber foco pelo teclado. Estados usam texto além de cor. Há suporte à preferência de redução de movimento.

A revisão responsiva foi feita no navegador com viewport móvel, sem execução em um telefone físico. O servidor em loopback não permite acesso a partir do celular na rede.

## Encerrar

Feche a aba e pressione **Ctrl+C** no terminal do servidor. Nenhum serviço é instalado e nenhuma configuração do dispositivo é alterada.

## Resolver problemas

| Situação | Ação |
|---|---|
| A porta 8769 já está em uso | Use `python -m http.server 8770 --bind 127.0.0.1` e abra a porta 8770. |
| Aparece uma lista de arquivos | Confira se o terminal está em `E:\projetos\fido\ident`. |
| Interface antiga após uma edição | Recarregue a página sem cache. Não há build ou hot reload. |
| Copiar não funciona | A política do navegador pode bloquear clipboard. O número de exemplo continua visível. |
| Página bloqueada após esperar | A sessão simulada tem limite de cinco minutos. Faça o desbloqueio de demonstração novamente. |

## Natureza da entrega

O protótipo usa HTML/CSS nativo alinhado ao Material 3 do projeto. Não implementa criptografia, autenticação, biometria, operações de firmware ou integração USB/BLE. A ilustração da chave não é um desenho de fabricação. O histórico de verificações e suas limitações está em [VALIDACAO.md](VALIDACAO.md).
