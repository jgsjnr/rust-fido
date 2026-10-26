# Architecture: Validação USB + telas

## Approach
Três harness independentes cobrem o que nenhum cobre sozinho: emulador valida estados de UI sem hardware; simulador Python valida E2E serial (inclusive destrutivas) nos dois devices; sonda ADB investiga ponte emulador→host→serial. Monitores (`live_monitor`, LogScreen) fazem cross-check dos eventos.

## Components
- Harness-emulador: telas, permissões negadas, fallbacks, LogScreen sem device
- Harness-serial: `app_simulator.py` (CTAPHID/UART + HTTP AP + dump) nos dois COMs
- Sonda-ADB: proxy host HTTP↔serial + veredito de viabilidade
- Cross-check: `live_monitor` + `ltrace` vs ações executadas

## Data Flow
Ação executada → evidência (serial/logcat) → confronto com monitor → linha na matriz → modificação anotada

## Alternatives Considered
- USB no emulador via pass-through — rejected because plataforma não oferece USB host ao guest
- BLE em vez de USB — rejected because escopo da tarefa é USB
