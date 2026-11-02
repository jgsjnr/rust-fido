/* AegisKey BLE real via NimBLE — GATT 0xFFFD (Etapa B).
 *
 * Padrão idêntico ao components/aegis_usb/aegis_usb.c: componente C fino,
 * chamado pelo Rust via `extern "C"` manual (sem bindgen, sem novos deps).
 * Lógica de framing/opcodes vive no Rust (`ble_gatt.rs` + `ble_nimble.rs`);
 * aqui só rádio: advertising, GATT 0xFFFD, bonding persistido (ble_store/NVS).
 *
 * Sequência de init copiada do exemplo oficial IDF v5.3.1
 * examples/bluetooth/nimble/bleprph (host NimBLE + FreeRTOS):
 *   nvs_flash -> nimble_port_init (controller+HCI+host internos)
 *   -> ble_hs_cfg (sync/reset/store_status, sm JustWorks+bonding)
 *   -> ble_store_config_init -> gap device name -> gatts_count/add
 *   -> nimble_port_freertos_init (o host publica o banco via ble_hs_start
 *   no sync; NUNCA chamar ble_gatts_start() direto — duplo start realoca
 *   o pool ATT e derruba em LoadProhibited).
 * NAO chamar esp_nimble_hci_init() separado: no IDF v5 ele ja vive dentro
 * de nimble_port_init()/esp_nimble_init(); a chamada avulsa falha com
 * ESP_FAIL (rc=-1 em loop) e quebra a coexistencia WiFi/BLE no S3.
 *
 * Concorrência: callbacks GAP/GATT rodam na task NimBLE; o loop Rust consome
 * por poll (poll-read-clear sob critical section). 1 fragmento FFF1 pendente
 * por vez (backpressure via ATT error); notify FFF2 sob demanda do Rust.
 */

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_bt.h"
#include "esp_err.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"

#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/ble_uuid.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

static const char *TAG = "aegis_ble";

/* Contrato congelado (docs/ble-protocol.md §1): mantidos em sync com
 * crates/aegis-fido-firmware/src/ble_nimble.rs (encode_adv_payload). */
#define AEGIS_BLE_SVC_UUID16   0xFFFD
#define AEGIS_BLE_CHR_CTRL     0xFFF1
#define AEGIS_BLE_CHR_STATUS   0xFFF2
#define AEGIS_BLE_CHR_LEN      0xFFF3
#define AEGIS_BLE_CHR_REV      0xFFF4
#define AEGIS_BLE_REVISION     0x01
#define AEGIS_BLE_NAME         "AegisKey"

/* Intervalos de advertising em unidades 0,625ms (== ADV_ITVL_* no Rust).
 * Lento quando o WiFi está ativo: BLE cede airtime (USB > WiFi > BLE). */
#define AEGIS_ADV_ITVL_NORMAL_MIN 160
#define AEGIS_ADV_ITVL_NORMAL_MAX 240
#define AEGIS_ADV_ITVL_COEX_MIN   400
#define AEGIS_ADV_ITVL_COEX_MAX   512

#define AEGIS_RX_BUF_MAX 256

/* Eventos p/ o Rust (== BLE_EVT_* no Rust; poll-read-clear). */
#define AEGIS_EVT_NONE         0
#define AEGIS_EVT_SECURED      1
#define AEGIS_EVT_DISCONNECTED 2
#define AEGIS_EVT_CONNECTED    3

void ble_store_config_init(void);

static uint8_t s_inited = 0;
static uint8_t s_synced = 0;
static uint8_t s_advertising = 0;
/* Fix preinit robusto (fail-closed, sem crash): máquina de estado do init.
 * `s_init_failed` + `s_init_rc` congelam o primeiro erro parcial e impedem
 * re-executar controller/HCI por cima (reentrância vazava heap até
 * `LoadProhibited EXCVADDR=0`). `s_init_in_progress` barra reentrância
 * concorrente (preinit/start simultâneos). Qualquer falha retorna rc != 0
 * com log; nunca panic/abort.
 * Ordem vs AP WiFi (S3+coex): PENDENTE de prova no device. Este C NÃO derruba
 * o AP aqui; se o AP ligado for o gatilho do EXCVADDR=0 pós-`phy_init`, o
 * chamador (Rust `run_authenticator_freertos`) deve serializar o preinit
 * antes de qualquer AP start. Sem chute de ordem no C: guarda + erro limpo. */
static uint8_t s_init_in_progress = 0;
static uint8_t s_init_failed = 0;
static int s_init_rc = 0;
static uint8_t s_own_addr_type = BLE_OWN_ADDR_PUBLIC;

static uint16_t s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
static uint16_t s_fff1_handle = 0;
static uint16_t s_fff2_handle = 0;
static uint16_t s_fff3_handle = 0;
static uint16_t s_fff4_handle = 0;
static uint8_t s_notify_on = 0;

/* FFF1 pendente (1 fragmento; task NimBLE produz, loop Rust consome). */
static uint8_t s_rx_buf[AEGIS_RX_BUF_MAX];
static int s_rx_len = -1; /* -1 = fila vazia */

/* FFF3 sombra (espelhada pelo Rust via aegis_ble_set_pending_len). */
static uint16_t s_pending_len = 0;
static uint8_t s_revision = AEGIS_BLE_REVISION;
static uint8_t s_status = 0;

static int s_evt = AEGIS_EVT_NONE;

static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;

static void set_evt(int evt)
{
    taskENTER_CRITICAL(&s_lock);
    if (s_evt == AEGIS_EVT_NONE) {
        s_evt = evt;
    }
    taskEXIT_CRITICAL(&s_lock);
}

/* --- GATT 0xFFFD -------------------------------------------------------- */

static const ble_uuid16_t s_svc_uuid  = BLE_UUID16_INIT(AEGIS_BLE_SVC_UUID16);
static const ble_uuid16_t s_ctrl_uuid = BLE_UUID16_INIT(AEGIS_BLE_CHR_CTRL);
static const ble_uuid16_t s_stat_uuid = BLE_UUID16_INIT(AEGIS_BLE_CHR_STATUS);
static const ble_uuid16_t s_len_uuid  = BLE_UUID16_INIT(AEGIS_BLE_CHR_LEN);
static const ble_uuid16_t s_rev_uuid  = BLE_UUID16_INIT(AEGIS_BLE_CHR_REV);

static int chr_access(uint16_t conn_handle, uint16_t attr_handle,
                      struct ble_gatt_access_ctxt *ctxt, void *arg);

static const struct ble_gatt_svc_def s_svcs[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &s_svc_uuid.u,
        .characteristics = (struct ble_gatt_chr_def[]) {
            {
                /* FFF1 control-point: write (fragmentos do host). */
                .uuid = &s_ctrl_uuid.u,
                .access_cb = chr_access,
                .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP,
            },
            {
                /* FFF2 status: notify (respostas) + read do byte de status. */
                .uuid = &s_stat_uuid.u,
                .access_cb = chr_access,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY,
            },
            {
                /* FFF3 len: read u16 LE (tamanho pendente do reassemble). */
                .uuid = &s_len_uuid.u,
                .access_cb = chr_access,
                .flags = BLE_GATT_CHR_F_READ,
            },
            {
                /* FFF4 revision: read/write (só aceita 0x01). */
                .uuid = &s_rev_uuid.u,
                .access_cb = chr_access,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE,
            },
            { 0 },
        },
    },
    { 0 },
};

static int
chr_access(uint16_t conn_handle, uint16_t attr_handle,
           struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    (void)conn_handle;
    (void)arg;
    uint16_t len = 0;
    int rc;

    if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
        if (ctxt->om == NULL) {
            return BLE_ATT_ERR_UNLIKELY;
        }
        if (attr_handle == s_fff1_handle) {
            /* FFF1: 1 fragmento pendente por vez (backpressure). */
            taskENTER_CRITICAL(&s_lock);
            int busy = (s_rx_len >= 0);
            taskEXIT_CRITICAL(&s_lock);
            if (busy) {
                return BLE_ATT_ERR_UNLIKELY;
            }
            uint8_t tmp[AEGIS_RX_BUF_MAX];
            rc = ble_hs_mbuf_to_flat(ctxt->om, tmp, sizeof(tmp), &len);
            if (rc != 0) {
                return BLE_ATT_ERR_UNLIKELY;
            }
            taskENTER_CRITICAL(&s_lock);
            memcpy(s_rx_buf, tmp, len);
            s_rx_len = (int)len;
            taskEXIT_CRITICAL(&s_lock);
            s_status = 1; /* processing */
            return 0;
        }
        if (attr_handle == s_fff4_handle) {
            /* FFF4: só aceita a revisão congelada 0x01. */
            uint8_t val = 0;
            rc = ble_hs_mbuf_to_flat(ctxt->om, &val, sizeof(val), &len);
            if (rc != 0 || len != 1) {
                return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
            }
            if (val != AEGIS_BLE_REVISION) {
                return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
            }
            s_revision = val;
            return 0;
        }
        return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
    }

    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        if (ctxt->om == NULL) {
            return BLE_ATT_ERR_UNLIKELY;
        }
        if (attr_handle == s_fff2_handle) {
            rc = os_mbuf_append(ctxt->om, &s_status, 1);
            return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
        }
        if (attr_handle == s_fff3_handle) {
            uint8_t le[2];
            taskENTER_CRITICAL(&s_lock);
            uint16_t pend = s_pending_len;
            taskEXIT_CRITICAL(&s_lock);
            le[0] = (uint8_t)(pend & 0xFF);
            le[1] = (uint8_t)((pend >> 8) & 0xFF);
            rc = os_mbuf_append(ctxt->om, le, sizeof(le));
            return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
        }
        if (attr_handle == s_fff4_handle) {
            rc = os_mbuf_append(ctxt->om, &s_revision, 1);
            return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
        }
        return BLE_ATT_ERR_READ_NOT_PERMITTED;
    }

    return BLE_ATT_ERR_UNLIKELY;
}

static void
register_cb(struct ble_gatt_register_ctxt *ctxt, void *arg)
{
    (void)arg;
    if (ctxt == NULL) {
        return;
    }
    if (ctxt->op != BLE_GATT_REGISTER_OP_CHR) {
        return;
    }
    if (ctxt->chr.chr_def == NULL || ctxt->chr.chr_def->uuid == NULL) {
        return;
    }
    uint16_t u16 = ble_uuid_u16(ctxt->chr.chr_def->uuid);
    if (u16 == AEGIS_BLE_CHR_CTRL) {
        s_fff1_handle = ctxt->chr.val_handle;
    } else if (u16 == AEGIS_BLE_CHR_STATUS) {
        s_fff2_handle = ctxt->chr.val_handle;
    } else if (u16 == AEGIS_BLE_CHR_LEN) {
        s_fff3_handle = ctxt->chr.val_handle;
    } else if (u16 == AEGIS_BLE_CHR_REV) {
        s_fff4_handle = ctxt->chr.val_handle;
    }
}

/* --- GAP ---------------------------------------------------------------- */

static int gap_event(struct ble_gap_event *event, void *arg);

static int
start_adv_raw(int pairing_flag, int coex_slow)
{
    struct ble_hs_adv_fields fields;
    struct ble_gap_adv_params params;
    uint8_t svc_data[3] = { (uint8_t)(AEGIS_BLE_SVC_UUID16 & 0xFF),
                            (uint8_t)((AEGIS_BLE_SVC_UUID16 >> 8) & 0xFF),
                            pairing_flag ? 0x01 : 0x00 };
    int rc;
    int active_antes;
    int stop_rc;
    int active_depois;
    int set_fields_rc;

    /* Stop-before-start INCONDICIONAL (lane root-cause, evidência de fio):
     * o stop condicionado a `ble_gap_adv_active()` (host) nunca executava
     * no fio (WARN nunca aparecia, stop sempre pulado) e o controller
     * recusava o primeiro set virgem com 0x07 (rc=519). O stop aqui NÃO
     * usa active p/ decidir — active_antes/depois + stop_rc são só
     * discriminante de log. Delay 20 ms só se houve stop real
     * (stop_rc==0), p/ não atrasar o set virgem nem colidir com o
     * `GAP procedure initiated: stop advertising` interno do host no sync.
     * NÃO mexer em BT_CTRL_BLE_MAX_ACT sem o discriminante active=0/0 +
     * 519 persistente. Parada mútua FFFD↔FFFE: este stop também derruba
     * resíduo do adv 0xFFFE antes de programar o 0xFFFD. */
    active_antes = ble_gap_adv_active();
    stop_rc = ble_gap_adv_stop();
    active_depois = ble_gap_adv_active();
    ESP_LOGW(TAG, "adv pre-stop stop_rc=%d active_antes=%d active_depois=%d s_advertising=%d",
             stop_rc, active_antes, active_depois, (int)s_advertising);
    if (stop_rc == 0) {
        s_advertising = 0;
        vTaskDelay(pdMS_TO_TICKS(20));
        active_depois = ble_gap_adv_active();
    }

    memset(&fields, 0, sizeof(fields));
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.uuids16 = (ble_uuid16_t[]){ BLE_UUID16_INIT(AEGIS_BLE_SVC_UUID16) };
    fields.num_uuids16 = 1;
    fields.uuids16_is_complete = 1;
    fields.svc_data_uuid16 = svc_data;
    fields.svc_data_uuid16_len = sizeof(svc_data);
    fields.name = (uint8_t *)AEGIS_BLE_NAME;
    fields.name_len = sizeof(AEGIS_BLE_NAME) - 1;
    fields.name_is_complete = 1;

    rc = ble_gap_adv_set_fields(&fields);
    set_fields_rc = rc;
    if (rc != 0) {
        ESP_LOGE(TAG, "adv_set_fields rc=%d stop_rc=%d active_antes=%d active_depois=%d",
                 rc, stop_rc, active_antes, active_depois);
        return rc;
    }

    memset(&params, 0, sizeof(params));
    params.conn_mode = BLE_GAP_CONN_MODE_UND;
    params.disc_mode = BLE_GAP_DISC_MODE_GEN;
    if (coex_slow) {
        params.itvl_min = AEGIS_ADV_ITVL_COEX_MIN;
        params.itvl_max = AEGIS_ADV_ITVL_COEX_MAX;
    } else {
        params.itvl_min = AEGIS_ADV_ITVL_NORMAL_MIN;
        params.itvl_max = AEGIS_ADV_ITVL_NORMAL_MAX;
    }

    ESP_LOGI(TAG, "adv pre-start active=%d own=%d itvl=%d/%d set_fields_rc=%d",
             ble_gap_adv_active(), (int)s_own_addr_type,
             (int)params.itvl_min, (int)params.itvl_max, set_fields_rc);
    rc = ble_gap_adv_start(s_own_addr_type, NULL, BLE_HS_FOREVER,
                           &params, gap_event, NULL);
    if (rc == 519) {
        /* HCI Memory Capacity Exceeded com controller inativo: instancia
         * residual recusada pelo controller. O Rust registra EV_ADV_NOMEM e
         * NAO consome as 3 tentativas do gate (backoff ate nova borda). */
        ESP_LOGE(TAG, "adv_start rc=519 NOMEM (residual recusado; sem retry cego) stop_rc=%d active_antes=%d active_depois=%d",
                 stop_rc, active_antes, active_depois);
        return rc;
    }
    if (rc != 0) {
        ESP_LOGE(TAG, "adv_start rc=%d", rc);
        return rc;
    }
    s_advertising = 1;
    ESP_LOGI(TAG, "adv on (pairing=%d coex_slow=%d)", pairing_flag, coex_slow);
    return 0;
}

static int
gap_event(struct ble_gap_event *event, void *arg)
{
    (void)arg;
    if (event == NULL) {
        return 0;
    }
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            s_conn_handle = event->connect.conn_handle;
            s_advertising = 0; /* stack para adv ao conectar */
            set_evt(AEGIS_EVT_CONNECTED);
            ESP_LOGI(TAG, "connect h=%d", (int)s_conn_handle);
        } else {
            /* Falha: se o Rust ainda quer anunciar, o edge-trigger religa. */
            s_advertising = 0;
            ESP_LOGW(TAG, "connect fail status=%d", event->connect.status);
        }
        return 0;

    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "disconnect reason=%d", event->disconnect.reason);
        s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
        s_advertising = 0;
        s_notify_on = 0;
        s_status = 0;
        set_evt(AEGIS_EVT_DISCONNECTED);
        return 0;

    case BLE_GAP_EVENT_ENC_CHANGE:
        if (event->enc_change.status == 0) {
            ESP_LOGI(TAG, "enc ok h=%d (bond persistido via ble_store/NVS)",
                     event->enc_change.conn_handle);
            set_evt(AEGIS_EVT_SECURED);
        } else {
            ESP_LOGW(TAG, "enc fail status=%d", event->enc_change.status);
        }
        return 0;

    case BLE_GAP_EVENT_REPEAT_PAIRING:
        /* Apaga o bond antigo e tenta de novo (padrão bleprph). */
        {
            struct ble_gap_conn_desc desc;
            if (ble_gap_conn_find(event->repeat_pairing.conn_handle, &desc) == 0) {
                ble_store_util_delete_peer(&desc.peer_id_addr);
            }
        }
        return BLE_GAP_REPEAT_PAIRING_RETRY;

    case BLE_GAP_EVENT_SUBSCRIBE:
        if (event->subscribe.attr_handle == s_fff2_handle) {
            s_notify_on = event->subscribe.cur_notify ? 1 : 0;
            ESP_LOGI(TAG, "fff2 notify %s", s_notify_on ? "on" : "off");
        }
        return 0;

    case BLE_GAP_EVENT_MTU:
        return 0;

    default:
        return 0;
    }
}

static void on_sync(void)
{
    int rc = ble_hs_util_ensure_addr(0);
    if (rc == 0) {
        rc = ble_hs_id_infer_auto(0, &s_own_addr_type);
    }
    if (rc != 0) {
        ESP_LOGE(TAG, "addr rc=%d", rc);
        return;
    }
    s_synced = 1;
    ESP_LOGI(TAG, "nimble synced");
}

static void on_reset(int reason)
{
    ESP_LOGW(TAG, "nimble reset reason=%d", reason);
    s_synced = 0;
    s_advertising = 0;
    s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
    s_notify_on = 0;
}

static void host_task(void *param)
{
    (void)param;
    nimble_port_run();
    nimble_port_freertos_deinit();
}

static int ensure_init(void)
{
    if (s_inited) {
        return 0;
    }
    if (s_init_failed) {
        /* Tentativa parcial anterior: nunca re-execute controller/HCI por
         * cima (reentrância/retry derrubava em LoadProhibited). Fail-closed. */
        return s_init_rc;
    }
    if (s_init_in_progress) {
        ESP_LOGE(TAG, "init reentrante (preinit/start concorrentes)");
        return -11;
    }
    s_init_in_progress = 1;
    /* Snapshot de heap p/ a prova no device (TEST_BLE_PREINIT): o `Malloc
     * failed` do controller (`BLE assert emi.c:164` -> Interrupt WDT) é
     * fragmentação/falta de bloco contíguo DMA/DRAM, não vazamento. Ref:
     * IDF v5.3.1 `nimble_port.c:168` (`nimble_port_init` = controller_init
     * + enable(BLE) + host); o `esp_bt_controller_mem_release(CLASSIC_BT)`
     * interno lá é `#if CONFIG_IDF_TARGET_ESP32` — no S3 (BLE-only por HW)
     * não há Classic p/ liberar, o fix é footprint (sdkconfig) + heap
     * fresco, não mem_release manual (não reintroduzir).
     *
     * Pinpoint do `hci inits failed` (build B8D47E, heap 35K/26K intacto):
     * `nimble_port_init` (nimble_port.c) imprime `controller init failed`,
     * `controller enable failed` ou `hci inits failed`+`nimble host init
     * failed` conforme a etapa. Com `BT controller compile version` visível
     * e sem `controller enable failed`, init+enable(BLE) passaram; o ESP_FAIL
     * vem de `esp_nimble_hci_init` (esp_nimble_hci.c), que só tem 3 retornos
     * de falha: `ble_buf_alloc` (6 callocs heap INTERNAL|8BIT, maior chunk =
     * MSYS_2 24x320 ~= 8 KiB), `esp_vhci_host_register_callback` (ESP_FAIL
     * se controller != ENABLED) e `xSemaphoreCreateBinary` (desprezível com
     * 35K livres). Os knobs slimmed (ACL 8 / EVT 10 / DISCARD 4 / MSYS_1 12
     * / GATT_PROCS 2 / BONDS 1 / CCCDs 4 / BLE_MAX_ACT 1) estão todos dentro
     * dos ranges do Kconfig (BLE_MAX_ACT 1..10; host sem range = só tamanho
     * de pool, sem mínimo de init; MSYS_1 12 É o default do path S3
     * `!SOC_ESP_NIMBLE_CONTROLLER`), logo nenhum viola piso de init — sem
     * chute de config aqui. O `internal maior` abaixo + `ctrl_status` no
     * erro desempatam em 1 run no device: status != 2 => VHCI; status == 2
     * (ENABLED) + internal maior < ~8K => NO_MEM no ble_buf_alloc;
     * status == 2 + internal folgado => recusa ROM do VHCI (callback obsoleto
     * de init parcial anterior no mesmo boot). Ref IDF v5.3.1:
     * `bt/host/nimble/nimble/porting/nimble/src/nimble_port.c`
     * (`esp_nimble_init`, `nimble_port_init`), `bt/host/nimble/esp-hci/src/
     * esp_nimble_hci.c` (`esp_nimble_hci_init`, `ble_buf_alloc` em
     * `nimble/nimble/transport/src/transport.c`), `bt/controller/esp32c3/
     * bt.c` (`esp_vhci_host_register_callback`), `bt/porting/mem/
     * os_msys_init.c`, `bt/host/nimble/Kconfig.in` (ranges). */
    ESP_LOGI(TAG, "preinit heap livre %u maior bloco %u (internal livre %u maior %u)",
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_DEFAULT),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT),
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    if (err != ESP_OK && err != ESP_ERR_NVS_NO_FREE_PAGES) {
        /* NVS pode já estar aberta por outro componente; segue mesmo assim. */
        ESP_LOGW(TAG, "nvs_flash_init: %s", esp_err_to_name(err));
    }

    /* IDF v5: nimble_port_init() ja faz controller_enable + hci_init
     * internamente; a chamada avulsa de esp_nimble_hci_init() aqui retornava
     * ESP_FAIL (-1) em loop. NAO reintroduzir. */
    err = nimble_port_init();
    if (err != ESP_OK) {
        /* Desempate do `hci inits failed` em 1 run (ver comentário acima):
         * ctrl_status 0=IDLE, 1=INITED, 2=ENABLED (esp_bt.h). */
        ESP_LOGE(TAG, "nimble_port_init: %s (heap livre %u maior bloco %u internal maior %u ctrl_status=%d)",
                 esp_err_to_name(err),
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_DEFAULT),
                 (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT),
                 (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
                 (int)esp_bt_controller_get_status());
        s_init_rc = -2;
        s_init_failed = 1;
        s_init_in_progress = 0;
        return s_init_rc;
    }

    ble_hs_cfg.reset_cb = on_reset;
    ble_hs_cfg.sync_cb = on_sync;
    ble_hs_cfg.gatts_register_cb = register_cb;
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;
    /* F-01 HARDENING (2026-11-02): MITM exigido no link-layer.
     * - `sm_mitm = 1` + `sm_sc = 1` + `sm_bonding = 1`: LE Secure Connections
     *   com bonding; pareamento JustWorks (sem MITM) eh REJEITADO fail-closed
     *   pelo NimBLE (`BLE_HS_SM_ERR_AUTH_REQUIREMENTS`), nunca cai para
     *   chave nao autenticada.
     * - SEMPRE com janela de pareamento 60 s + UP fisico por operacao (Rust
     *   `ble_nimble::on_link_secured`) + vinculo ECDSA app-layer
     *   (`ble_gatt` claim/challenge): defesa em profundidade inalterada.
     * - UX ONE-WAY, owner-authorized: bonds JustWorks antigos NAO reencriptam
     *   sob a nova politica (REPEAT_PAIRING apaga o peer e tenta de novo, que
     *   falha fechado sem metodo MITM) - o dono precisa re-parear dentro da
     *   janela com UP. Tentativas JustWorks sem metodo MITM (display/OOB)
     *   falham fechado; numeric-comparison/OOB eh follow-up (ver Rust
     *   `BLE_SM_MITM_REQUIRED` + `mitm_repair_notice()`).
     * - Antes: `sm_mitm = 0` (Sem MITM/passkey nesta etapa); ver audit F-01. */
    ble_hs_cfg.sm_io_cap = BLE_HS_IO_NO_INPUT_OUTPUT;
    ble_hs_cfg.sm_bonding = 1;
    ble_hs_cfg.sm_mitm = 1;
    ble_hs_cfg.sm_sc = 1;
    ble_hs_cfg.sm_our_key_dist |= BLE_SM_PAIR_KEY_DIST_ENC;
    ble_hs_cfg.sm_their_key_dist |= BLE_SM_PAIR_KEY_DIST_ENC;

    ble_store_config_init();

    /* Serviços padrão GAP (0x1800) + GATT (0x1801, Service Changed): sem
     * eles o banco ATT anuncia zero serviços e o Windows enumera vazio.
     * (NimBLE deste IDF: retorno void; falha aparece no count/add.) */
    ble_svc_gap_init();
    ble_svc_gatt_init();

    /* Ordem do exemplo oficial bleprph: device name ANTES do count/add.
     * NAO chamar ble_gatts_start() aqui: o host publica o banco via
     * ble_hs_start no sync (stage2). A chamada direta duplicava o start e
     * no 2o ble_att_svr_start() realocava o pool sem limpar a lista ->
     * 0 servicos + loop CCCD com ha_uuid NULL -> LoadProhibited. */
    int rc = ble_svc_gap_device_name_set(AEGIS_BLE_NAME);
    if (rc != 0) {
        ESP_LOGE(TAG, "gap_name rc=%d", rc);
        s_init_rc = -5;
        s_init_failed = 1;
        s_init_in_progress = 0;
        return s_init_rc;
    }

    rc = ble_gatts_count_cfg(s_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "gatts_count rc=%d", rc);
        s_init_rc = -3;
        s_init_failed = 1;
        s_init_in_progress = 0;
        return s_init_rc;
    }
    rc = ble_gatts_add_svcs(s_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "gatts_add rc=%d", rc);
        s_init_rc = -4;
        s_init_failed = 1;
        s_init_in_progress = 0;
        return s_init_rc;
    }
    /* O host publica o banco ATT via ble_hs_start no sync; sem start direto
     * aqui (ver comentario acima). Segue p/ nimble_port_freertos_init. */
    nimble_port_freertos_init(host_task);

    s_inited = 1;
    s_init_rc = 0;
    s_init_in_progress = 0;
    ESP_LOGI(TAG, "nimble init ok (0xFFFD, bonding NVS) heap livre %u maior bloco %u",
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_DEFAULT),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT));
    return 0;
}

/* --- API p/ o Rust -------------------------------------------------------- */

/* Pré-init no boot (heap fresco), sem anunciar. Idempotente via s_inited;
 * falha retorna o código sem retry aqui (o gate Rust faz backoff). */
int aegis_ble_preinit(void)
{
    return ensure_init();
}

int aegis_ble_start(int pairing_flag, int coex_slow)
{
    int rc = ensure_init();
    if (rc != 0) {
        return rc;
    }
    if (!s_synced) {
        return -10; /* host ainda sincronizando; Rust tenta de novo */
    }
    if (s_advertising) {
        return 0; /* idempotente */
    }
    return start_adv_raw(pairing_flag ? 1 : 0, coex_slow ? 1 : 0);
}

int aegis_ble_stop(void)
{
    if (!s_inited) {
        return 0;
    }
    /* Para mesmo se o stack já parou sozinho (pós-connect): ignora rc. */
    ble_gap_adv_stop();
    s_advertising = 0;
    return 0;
}

int aegis_ble_poll_event(void)
{
    int evt;
    taskENTER_CRITICAL(&s_lock);
    evt = s_evt;
    s_evt = AEGIS_EVT_NONE;
    taskEXIT_CRITICAL(&s_lock);
    return evt;
}

int aegis_ble_fetch_rx(uint8_t *out_buf, int max_len)
{
    int n;
    if (out_buf == NULL || max_len <= 0) {
        return -1;
    }
    taskENTER_CRITICAL(&s_lock);
    n = s_rx_len;
    if (n > 0) {
        if (n > max_len) {
            n = max_len;
        }
        memcpy(out_buf, s_rx_buf, (size_t)n);
        s_rx_len = -1;
    }
    taskEXIT_CRITICAL(&s_lock);
    return n; /* >0 bytes, 0 fila vazia, -1 sem init/pendente */
}

int aegis_ble_notify(const uint8_t *data, int len)
{
    struct os_mbuf *om;
    int rc;
    if (!s_inited || data == NULL || len <= 0) {
        return -1;
    }
    if (s_conn_handle == BLE_HS_CONN_HANDLE_NONE || !s_notify_on || s_fff2_handle == 0) {
        return -2;
    }
    om = ble_hs_mbuf_from_flat(data, (uint16_t)len);
    if (om == NULL) {
        return -3;
    }
    rc = ble_gatts_notify_custom(s_conn_handle, s_fff2_handle, om);
    if (rc == 0) {
        s_status = 0; /* idle após entregar a resposta */
    }
    return rc;
}

void aegis_ble_set_pending_len(uint16_t value)
{
    taskENTER_CRITICAL(&s_lock);
    s_pending_len = value;
    taskEXIT_CRITICAL(&s_lock);
}

int aegis_ble_conn_active(void)
{
    return (s_inited && s_conn_handle != BLE_HS_CONN_HANDLE_NONE) ? 1 : 0;
}

/* --- Wave2: anuncio de presenca 0xFFFE (rolling-code) ----------------------
 *
 * Service-data construido no Rust (proximity.rs + ble_nimble.rs, feature
 * proximity); aqui so transporte. GATT 0xFFFD intacto: este adv usa o UUID
 * 0xFFFE separado e nao altera o banco ATT. Layout total 30 B (<= 31 B).
 * Coex USB > WiFi > BLE: o Rust so chama com USB inativo; coex_slow != 0
 * quando o WiFi esta ativo (intervalo lento, BLE cede airtime).
 */
#define AEGIS_PROX_SVC_UUID16 0xFFFE
#define AEGIS_PROX_SVC_DATA_LEN 11

static int
start_proximity_adv_raw(const uint8_t *svc_data_11, int coex_slow)
{
    struct ble_hs_adv_fields fields;
    struct ble_gap_adv_params params;
    int rc;
    int active_antes;
    int stop_rc;
    int active_depois;
    int set_fields_rc;

    if (svc_data_11 == NULL) {
        return -1;
    }
    if (svc_data_11[0] != (uint8_t)(AEGIS_PROX_SVC_UUID16 & 0xFF) ||
        svc_data_11[1] != (uint8_t)((AEGIS_PROX_SVC_UUID16 >> 8) & 0xFF)) {
        return -1; /* fail-closed: UUID fora de 0xFFFE nao anuncia */
    }
    if (svc_data_11[2] != 0x01) {
        return -1; /* VER suportada: 0x01 */
    }

    /* Parada mútua FFFD↔FFFE (armadilha latente): mesmo stop-before-start
     * INCONDICIONAL do `start_adv_raw`. O adv 0xFFFD e o 0xFFFE usam a
     * mesma instância única do controller; trocar de um p/ o outro sem
     * stop prévio deixa resíduo e o próximo start cai em 519. Active só
     * discrimina no log; delay 20 ms só se houve stop real. */
    active_antes = ble_gap_adv_active();
    stop_rc = ble_gap_adv_stop();
    active_depois = ble_gap_adv_active();
    ESP_LOGW(TAG, "prox pre-stop stop_rc=%d active_antes=%d active_depois=%d s_advertising=%d",
             stop_rc, active_antes, active_depois, (int)s_advertising);
    if (stop_rc == 0) {
        s_advertising = 0;
        vTaskDelay(pdMS_TO_TICKS(20));
        active_depois = ble_gap_adv_active();
    }

    memset(&fields, 0, sizeof(fields));
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.uuids16 = (ble_uuid16_t[]){ BLE_UUID16_INIT(AEGIS_PROX_SVC_UUID16) };
    fields.num_uuids16 = 1;
    fields.uuids16_is_complete = 1;
    fields.svc_data_uuid16 = (uint8_t *)svc_data_11;
    fields.svc_data_uuid16_len = AEGIS_PROX_SVC_DATA_LEN;
    fields.name = (uint8_t *)AEGIS_BLE_NAME;
    fields.name_len = sizeof(AEGIS_BLE_NAME) - 1;
    fields.name_is_complete = 1;

    rc = ble_gap_adv_set_fields(&fields);
    set_fields_rc = rc;
    if (rc != 0) {
        ESP_LOGE(TAG, "prox_adv_set_fields rc=%d stop_rc=%d active_antes=%d active_depois=%d",
                 rc, stop_rc, active_antes, active_depois);
        return rc;
    }

    memset(&params, 0, sizeof(params));
    params.conn_mode = BLE_GAP_CONN_MODE_UND;
    params.disc_mode = BLE_GAP_DISC_MODE_GEN;
    if (coex_slow) {
        params.itvl_min = AEGIS_ADV_ITVL_COEX_MIN;
        params.itvl_max = AEGIS_ADV_ITVL_COEX_MAX;
    } else {
        params.itvl_min = AEGIS_ADV_ITVL_NORMAL_MIN;
        params.itvl_max = AEGIS_ADV_ITVL_NORMAL_MAX;
    }

    ESP_LOGI(TAG, "prox pre-start active=%d own=%d itvl=%d/%d set_fields_rc=%d",
             ble_gap_adv_active(), (int)s_own_addr_type,
             (int)params.itvl_min, (int)params.itvl_max, set_fields_rc);
    rc = ble_gap_adv_start(s_own_addr_type, NULL, BLE_HS_FOREVER,
                           &params, gap_event, NULL);
    if (rc == 519) {
        ESP_LOGE(TAG, "prox_adv_start rc=519 NOMEM (residual recusado; sem retry cego) stop_rc=%d active_antes=%d active_depois=%d",
                 stop_rc, active_antes, active_depois);
        return rc;
    }
    if (rc != 0) {
        ESP_LOGE(TAG, "prox_adv_start rc=%d stop_rc=%d active_antes=%d active_depois=%d",
                 rc, stop_rc, active_antes, active_depois);
        return rc;
    }
    s_advertising = 1;
    ESP_LOGI(TAG, "prox adv on (coex_slow=%d)", coex_slow);
    return 0;
}

/* Rust (ble_nimble.rs, feature proximity): svc_data de 11 B
 * [FE FF VER CTR u32LE TAG 4B]. Retorna 0 ok, negativo = erro. */
int aegis_ble_proximity_start(const uint8_t *svc_data, int svc_len, int coex_slow)
{
    int rc = ensure_init();
    if (rc != 0) {
        return rc;
    }
    if (!s_synced) {
        return -10; /* host ainda sincronizando; Rust tenta de novo */
    }
    if (s_advertising) {
        return 0; /* idempotente */
    }
    if (svc_data == NULL || svc_len != AEGIS_PROX_SVC_DATA_LEN) {
        return -1;
    }
    return start_proximity_adv_raw(svc_data, coex_slow ? 1 : 0);
}

/* MAC publico do NimBLE p/ o fob_short_id do beacon (feature proximity).
 * out[6] recebe o endereco; retorna 0 ok, negativo = erro (stack ainda nao
 * subiu: sem init/sync retorna != 0 e NUNCA inventa MAC; o Rust trata como
 * None e o beacon nao anuncia — fail-closed). */
int aegis_ble_own_addr(uint8_t out[6])
{
    int rc;
    if (out == NULL) {
        return -1;
    }
    if (!s_inited || !s_synced) {
        return -10; /* stack down; Rust tenta de novo no proximo tick */
    }
    rc = ble_hs_id_copy_addr(s_own_addr_type, out, NULL);
    if (rc != 0) {
        ESP_LOGW(TAG, "id_copy_addr rc=%d", rc);
        return rc;
    }
    return 0;
}
