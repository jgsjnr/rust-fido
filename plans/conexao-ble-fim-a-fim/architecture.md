# Architecture: Conexão BLE fim-a-fim

## Approach
Diagnosticar pelo Windows+bleak (isolando as variáveis do app Android): provar cada etapa do handshake até acesso total, corrigir o que bloqueia no firmware ou documentar workaround, e deixar script reutilizável.

## Components
- ble_connect_test.py: scan/connect/bond/subscribe/write + asserts por etapa
- Device S3: alvo, com pareamento 60s + UP físico
- App Android: referência de comportamento, sem mudanças

## Data Flow
Etapa executada → log bleak + log serial → confronto (LED/log) → causa → fix → re-teste

## Alternatives Considered
- Debugar pelo app Android — rejected because mais variáveis (stack BT do celular, permissões, APIs depreciadas)
