# SIZE Wave1 MAX-ESP baseline
Data 2026-10-18
Alvo ESP32-S3 devkitc tdisplay e ESP32 classic
Comando ESP idf.py size
Comando host cargo build e cargo test workspace
Baseline C t bins bytes aegis-app-esp32 1786736 devkitc 1785232 tdisplay 1824016
Regra sem regressao RAM flash sem justificativa
Envelope AEGN preservado CBOR IDs preservados journal NVS sem mudar layout flash
Medicao apos Wave1 host 77 testes verdes sem aumento de bin alem de poucas centenas de bytes de logica
