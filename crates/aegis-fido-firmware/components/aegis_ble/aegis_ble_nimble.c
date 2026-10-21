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
 *   -> ble_store_config_init -> gatts_count/add -> gap device name
 *   -> nimble_port_freertos_init.
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

#include "esp_err.h"
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
    if (ctxt->op != BLE_GATT_REGISTER_OP_CHR) {
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
    if (rc != 0) {
        ESP_LOGE(TAG, "adv_set_fields rc=%d", rc);
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

    rc = ble_gap_adv_start(s_own_addr_type, NULL, BLE_HS_FOREVER,
                           &params, gap_event, NULL);
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
        ESP_LOGE(TAG, "nimble_port_init: %s (heap livre %lu)",
                 esp_err_to_name(err), (unsigned long)esp_get_free_heap_size());
        return -2;
    }

    ble_hs_cfg.reset_cb = on_reset;
    ble_hs_cfg.sync_cb = on_sync;
    ble_hs_cfg.gatts_register_cb = register_cb;
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;
    /* JustWorks + bonding + UP físico (UP exigido por operação no Rust).
     * Sem MITM/passkey (sem display de PIN no device nesta etapa). */
    ble_hs_cfg.sm_io_cap = BLE_HS_IO_NO_INPUT_OUTPUT;
    ble_hs_cfg.sm_bonding = 1;
    ble_hs_cfg.sm_mitm = 0;
    ble_hs_cfg.sm_sc = 1;
    ble_hs_cfg.sm_our_key_dist |= BLE_SM_PAIR_KEY_DIST_ENC;
    ble_hs_cfg.sm_their_key_dist |= BLE_SM_PAIR_KEY_DIST_ENC;

    ble_store_config_init();

    /* Serviços padrão GAP (0x1800) + GATT (0x1801, Service Changed): sem
     * eles o banco ATT anuncia zero serviços e o Windows enumera vazio.
     * (NimBLE deste IDF: retorno void; falha aparece no count/add.) */
    ble_svc_gap_init();
    ble_svc_gatt_init();

    int rc = ble_gatts_count_cfg(s_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "gatts_count rc=%d", rc);
        return -3;
    }
    rc = ble_gatts_add_svcs(s_svcs);
    if (rc != 0) {
        ESP_LOGE(TAG, "gatts_add rc=%d", rc);
        return -4;
    }
    /* Publica o banco ATT: sem start, centrals descobrem zero serviços. */
    rc = ble_gatts_start();
    if (rc != 0) {
        ESP_LOGE(TAG, "gatts_start rc=%d", rc);
        return -8;
    }
    rc = ble_svc_gap_device_name_set(AEGIS_BLE_NAME);
    if (rc != 0) {
        ESP_LOGE(TAG, "gap_name rc=%d", rc);
        return -5;
    }

    nimble_port_freertos_init(host_task);

    s_inited = 1;
    ESP_LOGI(TAG, "nimble init ok (0xFFFD, bonding NVS)");
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
    if (rc != 0) {
        ESP_LOGE(TAG, "prox_adv_set_fields rc=%d", rc);
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

    rc = ble_gap_adv_start(s_own_addr_type, NULL, BLE_HS_FOREVER,
                           &params, gap_event, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "prox_adv_start rc=%d", rc);
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
