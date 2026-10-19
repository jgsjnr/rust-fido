/* AegisKey WiFi real via esp-idf - AP + station + mDNS (Etapa B).
 *
 * Padrao identico ao components/aegis_ble/aegis_ble_nimble.c: componente C fino,
 * chamado pelo Rust via `extern "C"` manual (sem bindgen, sem novos deps, sem
 * nenhuma feature do esp-idf-svc além de `binstart`). Logica de politica vive
 * no Rust (`wifi_ap.rs` + `wifi_station.rs` + `mdns.rs`); aqui so radio:
 * AP (WPA2 com senha provisionada, aberto no bootstrap), station com DHCP e
 * mDNS responder minimo, com power-down total fora de uso (bateria).
 *
 * Sequencia copiada dos exemplos oficiais IDF v5.3.1
 * examples/wifi/getting_started/{softAP,station} e
 * examples/bluetooth/nimble/bleprph_wifi_coex (coex WiFi+BLE):
 *   nvs_flash -> esp_netif_init -> event loop -> create_default_wifi_ap/sta
 *   -> esp_wifi_init -> handlers (WIFI_EVENT/IP_EVENT) -> set_mode/set_config
 *   -> esp_wifi_start (+ esp_wifi_connect na station).
 *
 * Concorrencia: o handler WiFi roda na task de eventos; o loop Rust consome
 * por poll (`aegis_wifi_sta_state`, sem bloqueio). Credenciais chegam do Rust
 * a cada start (NVS cifrada `SecureStorage`); o storage do driver fica em RAM
 * (`WIFI_STORAGE_RAM`) para nunca gravar senha em claro na NVS do IDF.
 *
 * mDNS: o IDF v5.3 nao tem mais componente `mdns` no core (virou componente
 * gerenciado `espressif/mdns`, incompatível com `component_manager = false`);
 * por isso o responder aqui e minimo sobre sockets lwIP: responde A-query
 * `<host>.local` (unicast ou multicast) com o IP da station, ou o IP do AP
 * quando so o AP esta ativo. TTL 120s, cache-flush bit (registro unico).
 */

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_err.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "nvs_flash.h"

#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/netdb.h"

static const char *TAG = "aegis_wifi";

/* Estados p/ o Rust (== STA_* no Rust; poll sem bloqueio). */
#define AEGIS_STA_OFF        0
#define AEGIS_STA_CONNECTING 1
#define AEGIS_STA_CONNECTED  2
#define AEGIS_STA_FAILED     3

#define AEGIS_SSID_MAX 32
#define AEGIS_PASS_MAX 64 /* 63 + NUL */
#define AEGIS_HOST_MAX 64

/* AP: canal fixo documentado (docs/wifi.md), 4 clientes (provisionamento). */
#define AEGIS_AP_CHANNEL 6
#define AEGIS_AP_MAX_CONN 4

/* mDNS: 224.0.0.251:5353, TTL do anuncio, stack da task. */
#define AEGIS_MDNS_GROUP "224.0.0.251"
#define AEGIS_MDNS_PORT 5353
#define AEGIS_MDNS_TTL 120
#define AEGIS_MDNS_TASK_STACK 4096
#define AEGIS_MDNS_TASK_PRIO 5

static uint8_t s_inited = 0;
static uint8_t s_wifi_started = 0;
static esp_netif_t *s_netif_ap = NULL;
static esp_netif_t *s_netif_sta = NULL;

/* Intenções vindas do Rust (fonte da verdade p/ o modo). */
static uint8_t s_want_ap = 0;
static uint8_t s_want_sta = 0;

/* Config pendente (copiada a cada start; nunca logada). */
static uint8_t s_ap_ssid[AEGIS_SSID_MAX];
static uint8_t s_ap_ssid_len = 0;
static uint8_t s_ap_pass[AEGIS_PASS_MAX];
static uint8_t s_ap_pass_len = 0;
static uint8_t s_sta_ssid[AEGIS_SSID_MAX];
static uint8_t s_sta_ssid_len = 0;
static uint8_t s_sta_pass[AEGIS_PASS_MAX];
static uint8_t s_sta_pass_len = 0;

/* Estado da station (handler produz, loop Rust consome por poll). */
static volatile int s_sta_state = AEGIS_STA_OFF;
static uint32_t s_sta_ip = 0; /* network order */

/* mDNS responder (task propria; hostname sem ".local"). */
static char s_mdns_host[AEGIS_HOST_MAX];
static uint8_t s_mdns_host_len = 0;
static volatile uint8_t s_mdns_run = 0;
static TaskHandle_t s_mdns_task = NULL;

static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data);
static void ip_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data);
static int aegis_mdns_stop_inner(void);

/* --- init --------------------------------------------------------------- */

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
    if (err != ESP_OK) {
        /* NVS pode ja estar aberta por outro componente; segue mesmo assim. */
        ESP_LOGW(TAG, "nvs_flash_init: %s", esp_err_to_name(err));
    }

    err = esp_netif_init();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "esp_netif_init: %s", esp_err_to_name(err));
        return -1;
    }
    err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "event_loop: %s", esp_err_to_name(err));
        return -2;
    }
    if (s_netif_ap == NULL) {
        s_netif_ap = esp_netif_create_default_wifi_ap();
    }
    if (s_netif_sta == NULL) {
        s_netif_sta = esp_netif_create_default_wifi_sta();
    }
    if (s_netif_ap == NULL || s_netif_sta == NULL) {
        ESP_LOGE(TAG, "create_default_wifi_ap/sta falhou");
        return -3;
    }

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    err = esp_wifi_init(&cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_init: %s", esp_err_to_name(err));
        return -4;
    }
    /* Credenciais nunca persistem no IDF: o Rust entrega a cada start. */
    err = esp_wifi_set_storage(WIFI_STORAGE_RAM);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set_storage RAM: %s", esp_err_to_name(err));
        return -5;
    }
    err = esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                              wifi_event_handler, NULL, NULL);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wifi handler: %s", esp_err_to_name(err));
        return -6;
    }
    err = esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                              ip_event_handler, NULL, NULL);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "ip handler: %s", esp_err_to_name(err));
        return -7;
    }
    s_inited = 1;
    ESP_LOGI(TAG, "wifi init ok (storage RAM, coex BLE automatica)");
    return 0;
}

/* --- handlers (task de eventos produz; loop Rust consome por poll) ------- */

static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    (void)base;
    (void)data;
    if (id == WIFI_EVENT_STA_START) {
        if (s_want_sta) {
            esp_wifi_connect();
        }
    } else if (id == WIFI_EVENT_STA_CONNECTED) {
        /* Link ok, ainda sem IP: segue CONNECTING ate o GOT_IP. */
        s_sta_state = AEGIS_STA_CONNECTING;
    } else if (id == WIFI_EVENT_STA_DISCONNECTED) {
        s_sta_ip = 0;
        if (s_want_sta) {
            /* Sem retry automatico no C (bateria): o Rust re-arma com
             * backoff (`sta_retry_due`). Transiente vira FAILED e o Rust
             * decide; fora de uso o radio desliga (`aegis_wifi_off`). */
            ESP_LOGW(TAG, "sta disconnected (retry pelo Rust com backoff)");
            s_sta_state = AEGIS_STA_FAILED;
        } else {
            s_sta_state = AEGIS_STA_OFF;
        }
    } else if (id == WIFI_EVENT_AP_STACONNECTED) {
        ESP_LOGI(TAG, "ap: cliente conectou");
    } else if (id == WIFI_EVENT_AP_STADISCONNECTED) {
        ESP_LOGI(TAG, "ap: cliente saiu");
    }
}

static void ip_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    (void)base;
    if (id == IP_EVENT_STA_GOT_IP) {
        const ip_event_got_ip_t *ev = (const ip_event_got_ip_t *)data;
        s_sta_ip = ev->ip_info.ip.addr;
        s_sta_state = AEGIS_STA_CONNECTED;
        ESP_LOGI(TAG, "sta got ip");
    }
}

/* --- reconcilia modo/inicio ---------------------------------------------- */

static int bring_up(void)
{
    wifi_mode_t want = WIFI_MODE_NULL;
    if (s_want_ap && s_want_sta) {
        want = WIFI_MODE_APSTA;
    } else if (s_want_ap) {
        want = WIFI_MODE_AP;
    } else if (s_want_sta) {
        want = WIFI_MODE_STA;
    } else {
        return 0;
    }

    if (s_want_ap) {
        wifi_config_t ap_cfg;
        memset(&ap_cfg, 0, sizeof(ap_cfg));
        memcpy(ap_cfg.ap.ssid, s_ap_ssid, s_ap_ssid_len);
        ap_cfg.ap.ssid_len = s_ap_ssid_len;
        ap_cfg.ap.channel = AEGIS_AP_CHANNEL;
        ap_cfg.ap.max_connection = AEGIS_AP_MAX_CONN;
        if (s_ap_pass_len > 0) {
            memcpy(ap_cfg.ap.password, s_ap_pass, s_ap_pass_len);
            ap_cfg.ap.authmode = WIFI_AUTH_WPA2_PSK;
        } else {
            /* Bootstrap na janela curta de pareamento: rede aberta.
             * As rotas mgmt exigem binding+UP+PIN mesmo assim. */
            ap_cfg.ap.authmode = WIFI_AUTH_OPEN;
        }
        esp_err_t err = esp_wifi_set_mode(want);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "set_mode: %s", esp_err_to_name(err));
            return -10;
        }
        err = esp_wifi_set_config(WIFI_IF_AP, &ap_cfg);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "set_config AP: %s", esp_err_to_name(err));
            return -11;
        }
    }

    if (s_want_sta) {
        wifi_config_t sta_cfg;
        memset(&sta_cfg, 0, sizeof(sta_cfg));
        memcpy(sta_cfg.sta.ssid, s_sta_ssid, s_sta_ssid_len);
        memcpy(sta_cfg.sta.password, s_sta_pass, s_sta_pass_len);
        sta_cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
        if (!s_want_ap) {
            esp_err_t err = esp_wifi_set_mode(want);
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "set_mode: %s", esp_err_to_name(err));
                return -12;
            }
        }
        esp_err_t err = esp_wifi_set_config(WIFI_IF_STA, &sta_cfg);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "set_config STA: %s", esp_err_to_name(err));
            return -13;
        }
    }

    if (!s_wifi_started) {
        esp_err_t err = esp_wifi_start();
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "esp_wifi_start: %s", esp_err_to_name(err));
            return -14;
        }
        s_wifi_started = 1;
        /* Bateria: modem-sleep fora de transmissao. */
        (void)esp_wifi_set_ps(WIFI_PS_MAX_MODEM);
    }
    if (s_want_sta) {
        s_sta_state = AEGIS_STA_CONNECTING;
        esp_err_t err = esp_wifi_connect();
        if (err != ESP_OK && err != ESP_ERR_WIFI_CONN) {
            ESP_LOGE(TAG, "connect: %s", esp_err_to_name(err));
            return -15;
        }
    }
    return 0;
}

static int reconcile_after_stop(void)
{
    if (!s_want_ap && !s_want_sta) {
        if (s_wifi_started) {
            (void)aegis_mdns_stop_inner();
            esp_err_t err = esp_wifi_stop();
            s_wifi_started = 0;
            s_sta_state = AEGIS_STA_OFF;
            s_sta_ip = 0;
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "esp_wifi_stop: %s", esp_err_to_name(err));
                return -20;
            }
            ESP_LOGI(TAG, "radio off (bateria)");
        }
        return 0;
    }
    /* Ainda ha um modo ativo: rebaixa APSTA->AP/STA sem derrubar o outro. */
    wifi_mode_t want = s_want_ap ? (s_want_sta ? WIFI_MODE_APSTA : WIFI_MODE_AP)
                                : WIFI_MODE_STA;
    esp_err_t err = esp_wifi_set_mode(want);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "downgrade mode: %s", esp_err_to_name(err));
        return -21;
    }
    return 0;
}

/* --- mDNS minimo (A-query `<host>.local` -> IP atual) -------------------- */

static int mdns_label_eq(const uint8_t *a, int a_len, const char *b)
{
    int i = 0;
    while (b[i] != 0) {
        i++;
    }
    if (i != a_len) {
        return 0;
    }
    for (int k = 0; k < a_len; k++) {
        uint8_t ca = a[k];
        uint8_t cb = (uint8_t)b[k];
        if (ca >= 65 && ca <= 90) {
            ca += 32;
        }
        if (cb >= 65 && cb <= 90) {
            cb += 32;
        }
        if (ca != cb) {
            return 0;
        }
    }
    return 1;
}

/* Responde 1 query em `buf` (`len` bytes). Retorna bytes da resposta em
 * `out` (0 = ignorar). Sem alloc, sem log de nomes. */
static int mdns_build_response(const uint8_t *buf, int len, uint8_t *out, uint32_t ip_be)
{
    if (len < 12) {
        return 0;
    }
    /* Somente queries (QR=0) com ao menos 1 pergunta. */
    if ((buf[2] & 0x80) != 0) {
        return 0;
    }
    if (buf[4] != 0 || buf[5] < 1) {
        return 0;
    }
    int pos = 12;
    /* Esperado: exatamente `<host>` + `local` (2 labels). */
    const char *want[2];
    want[0] = s_mdns_host;
    want[1] = "local";
    for (int li = 0; li < 2; li++) {
        if (pos >= len) {
            return 0;
        }
        uint8_t llen = buf[pos];
        if (llen == 0 || (llen & 0xC0) != 0) {
            return 0; /* fim precoce ou compressao: ignora */
        }
        pos++;
        if (pos + llen > len) {
            return 0;
        }
        if (!mdns_label_eq(&buf[pos], llen, want[li])) {
            return 0;
        }
        pos += llen;
    }
    if (pos >= len || buf[pos] != 0) {
        return 0;
    }
    pos++;
    if (pos + 4 > len) {
        return 0;
    }
    int qtype = (buf[pos] << 8) | buf[pos + 1];
    int qclass = (buf[pos + 2] << 8) | buf[pos + 3];
    if (qtype != 1 && qtype != 255) {
        return 0; /* so A / ANY */
    }
    if ((qclass & 0x7FFF) != 1) {
        return 0; /* so IN */
    }

    /* Resposta: ID 0, flags response+authoritative, 1 answer, sem questions. */
    int n = 0;
    out[n++] = 0;
    out[n++] = 0;
    out[n++] = 0x84;
    out[n++] = 0x00;
    out[n++] = 0;
    out[n++] = 0;
    out[n++] = 0;
    out[n++] = 1;
    out[n++] = 0;
    out[n++] = 0;
    out[n++] = 0;
    out[n++] = 0;
    /* NAME: labels do host + "local" + raiz. */
    out[n++] = s_mdns_host_len;
    memcpy(&out[n], s_mdns_host, s_mdns_host_len);
    n += s_mdns_host_len;
    out[n++] = 5;
    memcpy(&out[n], "local", 5);
    n += 5;
    out[n++] = 0;
    /* TYPE A, CLASS IN+cache-flush, TTL, RDLENGTH 4, RDATA ip. */
    out[n++] = 0;
    out[n++] = 1;
    out[n++] = 0x80;
    out[n++] = 0x01;
    out[n++] = (uint8_t)((AEGIS_MDNS_TTL >> 24) & 0xFF);
    out[n++] = (uint8_t)((AEGIS_MDNS_TTL >> 16) & 0xFF);
    out[n++] = (uint8_t)((AEGIS_MDNS_TTL >> 8) & 0xFF);
    out[n++] = (uint8_t)(AEGIS_MDNS_TTL & 0xFF);
    out[n++] = 0;
    out[n++] = 4;
    out[n++] = (uint8_t)(ip_be & 0xFF);
    out[n++] = (uint8_t)((ip_be >> 8) & 0xFF);
    out[n++] = (uint8_t)((ip_be >> 16) & 0xFF);
    out[n++] = (uint8_t)((ip_be >> 24) & 0xFF);
    return n;
}

static uint32_t mdns_current_ip(void)
{
    if (s_sta_state == AEGIS_STA_CONNECTED && s_sta_ip != 0) {
        return s_sta_ip;
    }
    if (s_want_ap && s_netif_ap != NULL) {
        esp_netif_ip_info_t info;
        if (esp_netif_get_ip_info(s_netif_ap, &info) == ESP_OK && info.ip.addr != 0) {
            return info.ip.addr;
        }
    }
    if (s_netif_sta != NULL) {
        esp_netif_ip_info_t info;
        if (esp_netif_get_ip_info(s_netif_sta, &info) == ESP_OK && info.ip.addr != 0) {
            return info.ip.addr;
        }
    }
    return 0;
}

static void mdns_join(int sock, uint32_t if_ip, uint8_t join)
{
    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = inet_addr(AEGIS_MDNS_GROUP);
    mreq.imr_interface.s_addr = if_ip;
    (void)setsockopt(sock, IPPROTO_IP,
                     join ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP,
                     &mreq, sizeof(mreq));
}

static void mdns_task(void *arg)
{
    (void)arg;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "mdns socket falhou");
        s_mdns_run = 0;
        s_mdns_task = NULL;
        vTaskDelete(NULL);
        return;
    }
    int reuse = 1;
    (void)setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(AEGIS_MDNS_PORT);
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) != 0) {
        ESP_LOGE(TAG, "mdns bind falhou");
        close(sock);
        s_mdns_run = 0;
        s_mdns_task = NULL;
        vTaskDelete(NULL);
        return;
    }
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500 * 1000;
    (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint32_t joined_sta = 0;
    uint32_t joined_ap = 0;
    uint8_t rx[1500];
    uint8_t tx[256];

    ESP_LOGI(TAG, "mdns on (responde A-query)");
    while (s_mdns_run) {
        /* Re-join quando os IPs mudam (station sobe/desce, AP liga). */
        uint32_t sta_ip = 0;
        uint32_t ap_ip = 0;
        if (s_netif_sta != NULL) {
            esp_netif_ip_info_t info;
            if (esp_netif_get_ip_info(s_netif_sta, &info) == ESP_OK) {
                sta_ip = info.ip.addr;
            }
        }
        if (s_netif_ap != NULL) {
            esp_netif_ip_info_t info;
            if (esp_netif_get_ip_info(s_netif_ap, &info) == ESP_OK) {
                ap_ip = info.ip.addr;
            }
        }
        if (sta_ip != joined_sta) {
            if (joined_sta != 0) {
                mdns_join(sock, joined_sta, 0);
            }
            if (sta_ip != 0) {
                mdns_join(sock, sta_ip, 1);
            }
            joined_sta = sta_ip;
        }
        if (ap_ip != joined_ap) {
            if (joined_ap != 0) {
                mdns_join(sock, joined_ap, 0);
            }
            if (ap_ip != 0) {
                mdns_join(sock, ap_ip, 1);
            }
            joined_ap = ap_ip;
        }

        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        int n = recvfrom(sock, (char *)rx, sizeof(rx), 0,
                         (struct sockaddr *)&from, &from_len);
        if (n <= 0) {
            continue; /* timeout: revalida memberships e flag */
        }
        uint32_t ip = mdns_current_ip();
        if (ip == 0) {
            continue; /* sem IP: silencioso */
        }
        int m = mdns_build_response(rx, n, tx, ip);
        if (m > 0) {
            struct sockaddr_in dst;
            memset(&dst, 0, sizeof(dst));
            dst.sin_family = AF_INET;
            dst.sin_port = htons(AEGIS_MDNS_PORT);
            dst.sin_addr.s_addr = inet_addr(AEGIS_MDNS_GROUP);
            (void)sendto(sock, (const char *)tx, (size_t)m, 0,
                         (struct sockaddr *)&dst, sizeof(dst));
        }
    }

    if (joined_sta != 0) {
        mdns_join(sock, joined_sta, 0);
    }
    if (joined_ap != 0) {
        mdns_join(sock, joined_ap, 0);
    }
    close(sock);
    ESP_LOGI(TAG, "mdns off");
    s_mdns_task = NULL;
    vTaskDelete(NULL);
}

static int aegis_mdns_stop_inner(void)
{
    if (s_mdns_task == NULL) {
        s_mdns_run = 0;
        return 0;
    }
    s_mdns_run = 0;
    for (int i = 0; i < 30 && s_mdns_task != NULL; i++) {
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    return 0;
}

/* --- API p/ o Rust -------------------------------------------------------- */

static int copy_cred(const uint8_t *in, int in_len, uint8_t *out, int out_max)
{
    if (in_len < 0 || in_len >= out_max) {
        return -1;
    }
    if (in_len > 0 && in == NULL) {
        return -1;
    }
    if (in_len > 0) {
        memcpy(out, in, (size_t)in_len);
    }
    out[in_len] = 0;
    return 0;
}

int aegis_wifi_ap_start(const uint8_t *ssid, int ssid_len,
                        const uint8_t *pass, int pass_len)
{
    if (ssid_len < 1 || ssid_len > AEGIS_SSID_MAX || ssid == NULL) {
        return -1;
    }
    /* pass_len 0 = rede aberta (bootstrap na janela de pareamento);
     * com senha: bounds WPA2 8..63 (== wifi_ap.rs). */
    if (pass_len != 0 && (pass_len < 8 || pass_len > 63)) {
        return -2;
    }
    int rc = ensure_init();
    if (rc != 0) {
        return rc;
    }
    if (copy_cred(ssid, ssid_len, s_ap_ssid, sizeof(s_ap_ssid)) != 0) {
        return -3;
    }
    if (copy_cred(pass, pass_len, s_ap_pass, sizeof(s_ap_pass)) != 0) {
        return -4;
    }
    s_ap_ssid_len = (uint8_t)ssid_len;
    s_ap_pass_len = (uint8_t)pass_len;
    s_want_ap = 1;
    rc = bring_up();
    if (rc == 0) {
        ESP_LOGI(TAG, "ap on (clientes ate %d)", AEGIS_AP_MAX_CONN);
    }
    return rc;
}

int aegis_wifi_ap_stop(void)
{
    if (!s_inited) {
        return 0;
    }
    s_want_ap = 0;
    return reconcile_after_stop();
}

int aegis_wifi_sta_start(const uint8_t *ssid, int ssid_len,
                         const uint8_t *pass, int pass_len)
{
    if (ssid_len < 1 || ssid_len > AEGIS_SSID_MAX || ssid == NULL) {
        return -1;
    }
    if (pass_len < 8 || pass_len > 63 || pass == NULL) {
        return -2;
    }
    int rc = ensure_init();
    if (rc != 0) {
        return rc;
    }
    if (copy_cred(ssid, ssid_len, s_sta_ssid, sizeof(s_sta_ssid)) != 0) {
        return -3;
    }
    if (copy_cred(pass, pass_len, s_sta_pass, sizeof(s_sta_pass)) != 0) {
        return -4;
    }
    s_sta_ssid_len = (uint8_t)ssid_len;
    s_sta_pass_len = (uint8_t)pass_len;
    s_want_sta = 1;
    rc = bring_up();
    if (rc == 0) {
        ESP_LOGI(TAG, "sta connecting");
    }
    return rc;
}

int aegis_wifi_sta_stop(void)
{
    if (!s_inited) {
        return 0;
    }
    s_want_sta = 0;
    if (s_wifi_started) {
        (void)esp_wifi_disconnect();
    }
    s_sta_state = AEGIS_STA_OFF;
    s_sta_ip = 0;
    return reconcile_after_stop();
}

int aegis_wifi_sta_state(void)
{
    return s_sta_state;
}

int aegis_wifi_sta_ip(uint8_t out_ip[4])
{
    if (out_ip == NULL) {
        return -1;
    }
    uint32_t ip = (s_sta_state == AEGIS_STA_CONNECTED) ? s_sta_ip : 0;
    out_ip[0] = (uint8_t)(ip & 0xFF);
    out_ip[1] = (uint8_t)((ip >> 8) & 0xFF);
    out_ip[2] = (uint8_t)((ip >> 16) & 0xFF);
    out_ip[3] = (uint8_t)((ip >> 24) & 0xFF);
    return (ip != 0) ? 1 : 0;
}

/* Power-down total do radio (bateria): chamar quando AP off + STA off. */
int aegis_wifi_off(void)
{
    if (!s_inited) {
        return 0;
    }
    s_want_ap = 0;
    s_want_sta = 0;
    (void)aegis_mdns_stop_inner();
    if (s_wifi_started) {
        esp_err_t err = esp_wifi_stop();
        s_wifi_started = 0;
        s_sta_state = AEGIS_STA_OFF;
        s_sta_ip = 0;
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "off: %s", esp_err_to_name(err));
            return -30;
        }
        ESP_LOGI(TAG, "radio off (bateria)");
    }
    /* Limpa credenciais da RAM (nunca persistem no C). */
    memset(s_ap_pass, 0, sizeof(s_ap_pass));
    memset(s_sta_pass, 0, sizeof(s_sta_pass));
    s_ap_pass_len = 0;
    s_sta_pass_len = 0;
    return 0;
}

int aegis_mdns_start(const uint8_t *host, int host_len)
{
    if (host == NULL || host_len < 1 || host_len >= AEGIS_HOST_MAX) {
        return -1;
    }
    for (int i = 0; i < host_len; i++) {
        uint8_t c = host[i];
        int ok = (c >= 48 && c <= 57) || (c >= 65 && c <= 90) ||
                 (c >= 97 && c <= 122) || c == 45;
        if (!ok) {
            return -2;
        }
    }
    /* Nao exige WiFi ligado aqui: o Rust so chama com station up, e o
     * responder fica silencioso sem IP (mdns_current_ip == 0). */
    if (s_mdns_task != NULL) {
        if (s_mdns_host_len == host_len && memcmp(s_mdns_host, host, (size_t)host_len) == 0) {
            return 0; /* idempotente */
        }
        (void)aegis_mdns_stop_inner();
    }
    memcpy(s_mdns_host, host, (size_t)host_len);
    s_mdns_host[host_len] = 0;
    s_mdns_host_len = (uint8_t)host_len;
    s_mdns_run = 1;
    if (xTaskCreate(mdns_task, "aegis_mdns", AEGIS_MDNS_TASK_STACK, NULL,
                    AEGIS_MDNS_TASK_PRIO, &s_mdns_task) != pdPASS) {
        s_mdns_run = 0;
        s_mdns_task = NULL;
        return -3;
    }
    return 0;
}

int aegis_mdns_stop(void)
{
    return aegis_mdns_stop_inner();
}
