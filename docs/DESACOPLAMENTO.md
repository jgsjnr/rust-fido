# GUIA GERAL DE DESACOPLAMENTO - AegisKey FIDO2 (firmware)

Lane: modulos-novos. Regras: R15/R16 (atomico, SOLID, sem mock falso),
ASCII puro, sem segredo em log, fail-closed com Err tipado, sem flash/COM7.

## 1. Splits concluidos (verificavel por arquivo:linha)

- main.rs 4913 -> ~47 linhas: dono real e run.rs (run.rs:1-4330 loop/dispatch
  FreeRTOS). main.rs so faz boot + chama run. Prova: main.rs tem 47 linhas
  nesta lane; run.rs tem 4330 linhas.
- freertos.rs 2260 -> ~67 linhas shim: re-export de freertos_route.rs +
  freertos_sched.rs (freertos.rs:66-67 `pub use`). Scheduler candidato a
  god em freertos_sched.rs (1600 linhas) - ver secao 2.
- binding.rs: TrustFacade/Gap extraidos para trust_facade.rs / trust_gap.rs
  sem mudar comportamento (binding.rs:33-39 re-exports). Dono unico continua
  binding.rs para NVS de claim/challenge.
- nvs_backend.rs fino: logica OTA movida para ota_store.rs (run.rs:31-32
  importa dispatch_ota_request/is_ota_op de ota_store). nvs_backend.rs so
  guarda backend + NamespacedStore.
- vendor_exec.rs fail-closed via NamespacedStore (vendor_exec.rs:28,87-88
  vendor_ns; 50-70 VendorExecError + From<NamespacedStoreError>). PIN via
  Result com shims bool compat (vendor_exec.rs:138,186,688,732).
- ccid.rs DIP injetado: trait CcidApduHandler (ccid.rs:282-283), applet PIV
  injetado via with_piv/set_piv (ccid.rs:318,334); teste
  injected_piv_is_used_by_transport (ccid.rs:1165).
- bridge AEGN alinhado 4096 com paridade cruzada: uniffi-bridge/src/lib.rs:63-66
  MAX_PLAINTEXT_BYTES=4096, fonte canonica persistence.rs::MAX_PLAINTEXT_BYTES;
  teste aegn_cross_vector_matches_bridge_and_firmware (lib.rs:47).
- openpgp/piv APDU compartilhado: apdu.rs dono unico do parse
  (openpgp_cmd.rs:34 usa crate::apdu::{parse_apdu,...};
  piv_cmd.rs:34 reexporta crate::apdu; piv_cmd.rs:100 documenta que
  parse_apdu vive em crate::apdu). Regra: nunca duplicar parser APDU.

## 2. Restos reais ordenados (o que ainda e god / o que ja foi resolvido)

1. run.rs god RESOLVIDO (D1-D4, lane modulos-novos): era 4330 linhas,
   virou diretorio run/ (mod.rs 621 + ble_dispatch.rs + serial_io.rs +
   run_loop_freertos.rs + run_loop_legacy.rs). Dispatch BLE com struct
   propria no modulo; loops sao funcoes move-only com `use super::*`;
   kprintln! herdado por escopo textual. Callers externos usam
   `crate::run::{run_authenticator, run_authenticator_freertos}` (paths
   preservados). Regra: novo codigo de loop entra no modulo do loop,
   nunca de volta no mod.rs.
2. dispatch hub antigo: DELETADO. Nao existe
   crates/aegis-fido-firmware/src/dispatch*.rs nesta lane (ls confirma so
   ccid_dispatch.rs como dispatch de transporte). Nao recriar hub generico;
   dispatch vive em serial_ctaphid.rs (dispatch_serial_vendor/wallet/rescue/
   bind_mgmt/text_line/pairing_line) + ble_gatt dispatch_bind_*.
3. freertos_sched.rs slim (905 linhas; era 1600): fila em
   freertos_queue.rs (NOVO) + nativo ESP-IDF em freertos_native.rs (NOVO,
   so cfg espidf); sched guarda core + route. serial_text.rs (D5) e
   proximity_crypto.rs (D6) extraidos com re-export de compat no dono.
   freertos.rs continua so shim (re-export route+sched), nao recoloque
   logica nele.
4. openpgp->piv APDU: RESOLVIDO via apdu.rs compartilhado (ver secao 1).
   Qualquer novo comando APDU (oath/piv/openpgp) deve usar crate::apdu.
5. Re-export cadeias: binding.rs reexporta TrustFacade/TrustTransport
   (binding.rs:38-39), piv_cmd.rs reexporta apdu (piv_cmd.rs:34),
   freertos.rs reexporta route+sched (freertos.rs:66-67). Regra: re-export
   so para compat de caminho; dono logico e o modulo de origem. Nao
   adicionar logica nos arquivos de re-export.
6. prox_k triplo: chave "prox_k" tem dono unico proximity.rs
   (PROXIMITY_BOND_NVS_KEY proximity.rs:233; save/load proximity.rs:533-545).
   run.rs so chama load/rekey/delete (run.rs:2581,2591,2901-2926); nunca
   declarar segunda constante "prox_k" em outro modulo. Corrigido tambem no
   COMMS-map (linha 180 era "RAM-only", agora NVS cifrada).
7. bridge duplicado: bridge mantem copia documentada de MAX_PLAINTEXT_BYTES
   (uniffi-bridge/src/lib.rs:63-66) com paridade cruzada por teste. Regra:
   fonte canonica e firmware persistence.rs; bridge nunca diverge sem
   atualizar o teste cruzado.

## 3. NVS: 5 stores em NamespacedStore + diretos justificados

- NamespacedStore (via nvs_backend.rs): binding (app_bind_pub/app_bind_id),
  vendor_exec (pin/oath/vendor state), ota_store (staging/commit),
  cred_store (cred/* + index), vault/oath dedicados quando aplicavel.
  Dual-path eliminado: sem acesso direto + namespaced para a mesma chave.
- Diretos justificados (sem namespace, motivo):
  binding claim parcial (verify-after-write imediato), recovery.rs
  (rec_pin_hash/salt/retries - ciclo de vida independente de binding),
  wifi (wifi_ap_pass/wifi_sta_ssid/wifi_sta_pass - politica UP+PIN propria),
  boot_state (leitura pre-namespaco no boot), anti_rollback (monotonico,
  nunca migra de namespace), prox_k dono unico proximity.rs:233
  (save_proximity_key/load_proximity_key proximity.rs:533-545, envelope
  AEGN, TRNG injetavel).
- Corrigido COMMS-map: proximidade usa NVS cifrada, nao RAM-only.
- Corrigido nvs_schema.md: nonce TRNG interno (persistence.rs:95-122
  store() gera nonce via OsRng/TRNG injetavel, parametro fixo ignorado).

## 4. Gates (test-hooks / NotCompiled / lab-mocks / mocks prod)

- Test-hooks: so sob feature test-mode (dispatch_serial_text_line/
  dispatch_serial_pairing_line serial_ctaphid.rs:481-529; TEST_PAIRING_OPEN
  run.rs:2228 cfg test-mode). Release responde None, nunca executa.
- NotCompiled: so para feature off (require_* no SDK retorna NotCompiled com
  feature desligada). Nunca usar NotCompiled para erro de runtime; runtime
  usa Err tipado fail-closed (VendorExecError, StorageError, ApduError).
- Lab-mocks: MockFlashBackend SOMENTE em #[cfg(test)] (nvs_schema G0).
  CI grep FAIL fora de test.
- Mocks prod: gateados ou com excecao documentada (host shims inertes sem
  radio em wifi_ap.rs:436/wifi_station.rs:279, testados por unidade;
  trust_gap.rs documenta ExternalBlocked para killswitch/jig+HSM).

## 5. Mapa de arquivos -> teste (onde provar cada split)

- run/ (D1-D4): testes em run/mod.rs mod tests (dispatcher_touch_from_extra,
  pairing open/close) + serial_ctaphid.rs tests (vendor/wallet/rescue/
  bind_mgmt parity BLE). run/mod.rs 621; filhos: ble_dispatch,
  serial_io, run_loop_freertos, run_loop_legacy (`use super::*`).
- serial_vendor.rs (F3): dispatch_serial_vendor/wallet/rescue/bind_mgmt;
  testes no dono serial_ctaphid.rs (mod tests verbatim).
- serial_text.rs (D5): text/pairing lines test-mode; testes no dono.
- ble/ (F5): gatt_core (tipos/auth puro) + dispatch_bind (gates c/ binding)
  + nimble_backend (radio/FFI/shims); testes verbatim nos donos finos
  ble_gatt.rs/ble_nimble.rs.
- net/ (F6): ap_core + station + mdns + password_policy; testes verbatim
  nos donos finos wifi_ap.rs/wifi_station.rs/mdns.rs.
- usb/piv/ (F7): apdu.rs DONO UNICO dos parsers de campo PIV
  (piv_cmd consome via super::apdu); `CommandApdu::parse` ficou no
  transporte ccid.rs (fio cru, oraculo DIP intacto). Excecao justificada:
  piv_cmd.rs 2190 (applet coeso de dominio unico; seam falsa criaria refs
  circulares); openpgp_cmd nao criado (zero simbolos no crate usb);
  core/oath e ccid_dispatch intocados (sem cluster).
- stores/ota_store.rs + proximity/monitor.rs (F8, D6): dispatch_ota_request/
  is_ota_op e monitor/beacon; NVS sem dual-path (ota_* so em stores/,
  prox_k so em proximity.rs dono unico); cred_store_ns/vendor_ns NAO
  criados (cred/ tem dono cred_store.rs; pin/slots consumidos inline).
- proximity NVS: proximity.rs tests (rekey/load/delete roundtrip,
  CorruptedEnvelope/DecryptionFailed).
- apdu.rs: piv_cmd.rs tests (parse_apdu vetores, TooShort/TooLarge) +
  openpgp_cmd.rs:944 parse path.
- proximity NVS: proximity.rs tests (rekey/load/delete roundtrip,
  CorruptedEnvelope/DecryptionFailed).
- persistence TRNG: store_with_rng + store() OsRng (persistence.rs:95-122).
- ccid DIP: ccid.rs:1165 injected_piv_is_used_by_transport.
- bridge paridade: aegn_cross_vector_matches_bridge_and_firmware.
- ota_store: dispatch_ota_request/is_ota_op (run.rs:31-32,3384,4075-4099).

## 6. Rollback

- Deletar docs/DESACOPLAMENTO.md + git checkout -- docs/COMMS-map.md
  docs/nvs_schema.md plans/MATRIZ-TODO.md. Nenhum codigo tocado por esta
  lane de docs.

## 7. Cobertura deste guia

- Arquivos novos: docs/DESACOPLAMENTO.md (este).
- Editados: docs/COMMS-map.md (linha 180 NVS + 7 linhas cred/pin/vault/oath/
  openpgp/ctap_state/ext), docs/nvs_schema.md (tabelas prox_k, oath6/*,
  oath_ctr/*, opgp/*, cred/*+index, vault/*+index, pin/*, boot_state,
  anti_rollback_key + nonce TRNG), plans/MATRIZ-TODO.md (T-CR-01..06,
  T-FD-01..05, T-OT-01/02, T-ST-01..04, T-PI-01..03, T-SF-01..03, T-UI-01/02
  TODO->PRONTO com arquivo+teste; OTA segue EM CURSO).
