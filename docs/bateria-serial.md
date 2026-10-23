# Bateria serial — playbook padrão (opencode)

## Regra de ouro (vale para TUDO)

1. **Execução de testes é SEMPRE delegada a agente barato** (`sdk-test-engineer`).
   O orquestrador nunca roda bateria inline: planeja, delega, reconcilia,
   verifica artefatos. Sem exceção — nem "só um comando rápido".
2. **Tudo é Python automatizado**: `tools/app_simulator.py`, agentes host,
   `tools/e2e_user_test.py`, `scripts/battery-serial.ps1`, `tools/device_ops.py`.
   Nenhum teste manual avulso conta como evidência; log em arquivo sempre.
3. **Correções mecânicas também vão para agentes baratos** (`fixer`,
   `sdk-test-engineer`, `clean-code-enforcer`, `atomic-change-implementer`):
   harness/testes, scripts, docs, edits multi-arquivo delimitados. Firmware
   crítico o orquestrador implementa ou revisa; agente valida com host gates
   (`cargo test`, `clippy`) e reporta arquivos alterados + testes executados.
4. **Nunca delegar sem escopo**: todo dispatch cita paths exatos, o que pode e
   o que NÃO pode tocar, e quem valida. Revisar o artefato antes de confiar.

## Ferramentas (todas em Python, todas automatizáveis)

| Ferramenta | Uso |
|---|---|
| `scripts/battery-serial.ps1` | Entrada única da bateria (offline→base→all-safe→bench). |
| `tools/device_ops.py` | Operações de placa: `flash`, `verify`, `reset`, `boot-check`, `health`, `read-mac`, `flash-id`, `backup`. Sem BOOT físico (usa `--before default_reset`). |
| `tools/e2e_user_test.py` | Fases `--phase base\|all-safe\|bench` (seguras); `destructive\|wipe` SÓ com `--confirm` (+`--confirm-release`) e ordem explícita do usuário no turno. |
| `tools/app_simulator.py --self-test` | 17/17 offline, porta de entrada. |
| `tools/host/*/... proximity_agent.py --self-test` | Agentes host (3 OS). |

## Comando único (não inventar comandos próprios)

## Comando único (não inventar comandos próprios)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/battery-serial.ps1 -Port COM7 -Phase all
```

- `-Phase all` = offline → base → all-safe → bench (só fases seguras).
- `-Phase base|all-safe|bench|offline` = recorte para re-checagem focada.
- `-Phase destructive|wipe` = SÓ com `-Force` + ordem explícita do usuário
  **neste turno** + PIN 1234 provisionado (+ `C:\t\ota_test_key.bin` p/ D08).
- Log sempre em `C:\t\battery-serial-<data-hora>.log` (o script imprime o caminho).

## Pré-condições (checar antes de delegar)

1. Placa alvo ONLINE com firmware test-mode (ticks fluindo, sem reboot loop).
   Identificar a placa **pelo MAC do chip** (`esptool read_mac`), nunca só pela COM:
   - trabalho = `3c:84:27:c7:17:78` (flash 16 MB Winbond `EF 4018`).
   - bancada = `80:65:99:df:4b:cc`.
   Portas COM trocam ao reconectar USB — revalidar todo turno.
2. Se o handshake falhar 1x (`device did not answer TEST_LIFETIME_DUMP`),
   aguardar 15 s e tentar de novo (resíduo serial transitório, não bug).
3. Base NVS íntegra; destructive/wipe mudam estado (PIN/binding) — revalidar
   o mapa em `docs/teste-ponta-a-ponta.md` depois delas.

## Prompt padrão de delegação

> Na worktree E:\projetos\fido\.slim\worktrees\freertos-rust: rode a bateria
> serial PADRONIZADA na COM7 (placa <papel, MAC>). REGRAS: NÃO editar código;
> NÃO rodar cargo; NÃO flashear; NÃO abrir outra porta; NÃO rodar
> destructive/wipe. Comando: `...battery-serial.ps1 -Port COM7 -Phase all`.
> Retorne: tabela fase → RESUMO + erros literais + caminho do log. Se a placa
> travar (reboot loop/panic), PARE e reporte.

## Lendo o resultado

- `RESUMO pass=X divergente=Y fail=Z` por fase, no console e no fim do log.
- `divergente` = comportamento ≠ esperado pelo teste (anotar e corrigir firmware
  ou teste, caso a caso). `fail` = transporte/exceção (investigar COM/placa).
- Resíduo entre fases (NVS/RAM do device + timing latch 1,5 s / janela 60 s):
  T05/T13 intermitentes caem aqui; gates provados corretos por trace no device
  (`[VENDOR] op/pairing/up`) + sondas isoladas. Re-rodar; se persistir, logar
  o gate no fw-log.
- Resync storms: rajadas de texto (ticks 1/s, WiFi AP ao abrir janela) afogam
  frames; mitigado com WiFi em WARN + wire-guard no dreno TEST (não consome
  mid-assembly, teto 2 s) + `SerialGate` sem bloqueio.
- O próprio `e2e_user_test.py` apenda resultados em `docs/teste-ponta-a-ponta.md`.

## Simulação total em Python ("simular tudinho")

Cobertura completa, tudo via Python, sem HW além da placa serial:

| Camada | Comando | Porta HW? |
|---|---|---|
| Lógica pura (17/17) | `python tools/app_simulator.py --self-test` | não |
| Agentes host (3 OS) | `python tools/host/<win,linux,macos>/proximity_agent.py --self-test` + `test_proximity_agent.py` | não (modo real exige fob BLE) |
| E2E serial COM | `scripts/battery-serial.ps1` (base/all-safe/bench) | sim (COM7/COM14) |
| E2E destrutivo | e2e `--phase destructive --confirm` / `--phase wipe --confirm --confirm-release` | sim + PIN + ordem explícita |
| HW antigo (QEMU) | ARQUIVADO — QEMU não emula USB-OTG/ADC; bugs de periférico só no chip | n/a |

## Proibições (valem para orquestrador e agentes)

- Nenhuma operação de eFuse (burn/write), secure boot ou flash encryption.
- Nenhum flash/esptool dentro de lane de agente de teste.
- Nenhum `destructive`/`wipe` sem ordem explícita do usuário no turno.
- Nunca apagar NVS sem ordem explícita (backup integral antes: `read_flash 0x0 0x1000000`).
- QEMU arquivado: não usar para validação (só `cargo test` + host suites offline).
