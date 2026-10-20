/*
 * AegisKey S3 CCID Transport Driver (minimal, PIV-only).
 *
 * TinyUSB has no CCID device class in IDF v5.3.1, so this file implements
 * the smallest compliant custom class driver and registers it through the
 * `usbd_app_driver_get_cb` hook (application drivers are consulted first).
 *
 * Design: dumb pipe. Bulk-OUT bytes are reassembled into complete CCID
 * frames (10-byte header + dwLength) and queued; Rust (`ccid_dispatch`)
 * owns the PIV applet and answers; `aegis_ccid_send` ships the RPDU back
 * over bulk-IN and raises the interrupt-IN slot-change notice.
 * Class-specific control requests stall (v1: OpenSC only needs bulk
 * PC_to_RDR / RDR_to_PC + enumeration, which is static bytes).
 */

#include "tusb_option.h"

#if CFG_TUD_ENABLED

#include "device/usbd.h"
#include "device/usbd_pvt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "string.h"
#include "aegis_usb.h"

static const char *TAG = "AegisCCID";

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

#define CCID_EP_OUT_MAX 0x02u
#define CCID_EP_IN_MAX 0x82u
#define CCID_EP_NOTIFY_MAX 0x83u
#define CCID_BULK_MPS 64u
#define CCID_NOTIFY_MPS 8u
#define CCID_FRAME_MAX 2048u
#define CCID_QUEUE_DEPTH 4u
#define CCID_FUNC_DESC_TYPE 0x21u
#define CCID_NOTIFY_SLOT_CHANGE 0x50u

typedef struct {
    uint16_t len;
    uint8_t data[CCID_FRAME_MAX];
} ccid_frame_t;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

static QueueHandle_t s_ccid_queue = NULL;
static uint8_t s_itf_num = 0;
static uint8_t s_ep_out = 0;
static uint8_t s_ep_in = 0;
static uint8_t s_ep_notify = 0;
static volatile bool s_configured = false;
static volatile bool s_tx_busy = false;

static uint8_t s_rx_chunk[CCID_BULK_MPS];
static uint8_t s_rx_asm[CCID_FRAME_MAX];
static uint16_t s_rx_len = 0;
static uint8_t s_tx_buf[CCID_FRAME_MAX];
static uint8_t s_notify_buf[2];

static void ccid_reset_state(void) {
    s_itf_num = 0;
    s_ep_out = 0;
    s_ep_in = 0;
    s_ep_notify = 0;
    s_configured = false;
    s_tx_busy = false;
    s_rx_len = 0;
}

static void ccid_arm_out(uint8_t rhport) {
    if (s_ep_out == 0) {
        return;
    }
    memset(s_rx_chunk, 0, sizeof(s_rx_chunk));
    usbd_edpt_xfer(rhport, s_ep_out, s_rx_chunk, CCID_BULK_MPS);
}

// Enqueue one complete frame; drops (with log) when the Rust side lags.
static void ccid_push_frame(const uint8_t *data, uint16_t len) {
    if (s_ccid_queue == NULL || len == 0 || len > CCID_FRAME_MAX) {
        return;
    }
    ccid_frame_t f;
    f.len = len;
    memcpy(f.data, data, len);
    if (xQueueSend(s_ccid_queue, &f, 0) != pdTRUE) {
        ESP_LOGW(TAG, "frame queue full, dropping %u B", len);
    }
}

// Append bulk-OUT bytes; emit complete frames (10 B header + dwLength).
static void ccid_on_bulk_out(const uint8_t *data, uint16_t n) {
    if (n == 0) {
        return;
    }
    if ((uint32_t)s_rx_len + n > CCID_FRAME_MAX) {
        ESP_LOGW(TAG, "reassembly overflow, resetting");
        s_rx_len = 0;
        return;
    }
    memcpy(&s_rx_asm[s_rx_len], data, n);
    s_rx_len += n;

    while (s_rx_len >= 10) {
        uint32_t body = ((uint32_t)s_rx_asm[1]) | ((uint32_t)s_rx_asm[2] << 8) |
                        ((uint32_t)s_rx_asm[3] << 16) | ((uint32_t)s_rx_asm[4] << 24);
        if (body > CCID_FRAME_MAX - 10) {
            ESP_LOGW(TAG, "bogus dwLength %lu, resetting", (unsigned long)body);
            s_rx_len = 0;
            return;
        }
        uint32_t total = 10 + body;
        if (s_rx_len < total) {
            break; // wait for more chunks
        }
        ccid_push_frame(s_rx_asm, (uint16_t)total);
        uint16_t rest = s_rx_len - (uint16_t)total;
        if (rest > 0) {
            memmove(s_rx_asm, &s_rx_asm[total], rest);
        }
        s_rx_len = rest;
    }
}

// ---------------------------------------------------------------------------
// TinyUSB class driver
// ---------------------------------------------------------------------------

static void ccidd_init(void) {
    if (s_ccid_queue == NULL) {
        s_ccid_queue = xQueueCreate(CCID_QUEUE_DEPTH, sizeof(ccid_frame_t));
    }
    ccid_reset_state();
    ESP_LOGI(TAG, "CCID driver online (class 0x0B, PIV-only)");
}

static bool ccidd_deinit(void) {
    return true;
}

static void ccidd_reset(uint8_t rhport) {
    (void)rhport;
    ccid_reset_state();
}

static uint16_t ccidd_open(uint8_t rhport, tusb_desc_interface_t const *desc_itf,
                           uint16_t max_len) {
    TU_VERIFY(TUSB_CLASS_SMART_CARD == desc_itf->bInterfaceClass, 0);
    TU_ASSERT(desc_itf->bNumEndpoints == 3, 0);

    uint8_t const *p_desc = tu_desc_next(desc_itf);
    // CCID functional descriptor (0x21) comes first; skip it.
    if (tu_desc_type(p_desc) == CCID_FUNC_DESC_TYPE) {
        p_desc = tu_desc_next(p_desc);
    }

    uint8_t ep_out = 0, ep_in = 0, ep_notify = 0;
    uint16_t drv_len = (uint16_t)((uintptr_t)p_desc - (uintptr_t)desc_itf);
    for (uint8_t i = 0; i < desc_itf->bNumEndpoints; i++) {
        TU_ASSERT(tu_desc_type(p_desc) == TUSB_DESC_ENDPOINT, 0);
        tusb_desc_endpoint_t const *desc_ep = (tusb_desc_endpoint_t const *)p_desc;
        TU_ASSERT(usbd_edpt_open(rhport, desc_ep), 0);
        if (tu_edpt_dir(desc_ep->bEndpointAddress) == TUSB_DIR_OUT) {
            ep_out = desc_ep->bEndpointAddress;
        } else if (desc_ep->bmAttributes.xfer == TUSB_XFER_BULK) {
            ep_in = desc_ep->bEndpointAddress;
        } else {
            ep_notify = desc_ep->bEndpointAddress;
        }
        p_desc = tu_desc_next(p_desc);
        drv_len = (uint16_t)((uintptr_t)p_desc - (uintptr_t)desc_itf);
    }
    TU_ASSERT(max_len >= drv_len, 0);
    TU_ASSERT(ep_out != 0 && ep_in != 0 && ep_notify != 0, 0);

    s_itf_num = desc_itf->bInterfaceNumber;
    s_ep_out = ep_out;
    s_ep_in = ep_in;
    s_ep_notify = ep_notify;
    s_configured = true;
    ESP_LOGI(TAG, "CCID open itf=%u out=0x%02X in=0x%02X notify=0x%02X", s_itf_num, s_ep_out,
             s_ep_in, s_ep_notify);
    ccid_arm_out(rhport);
    return drv_len;
}

// Class-specific control (Abort / GetClockFrequencies / ...): stall.
// Enumeration is unaffected (static config bytes served by the stack).
static bool ccidd_control_xfer_cb(uint8_t rhport, uint8_t stage,
                                  tusb_control_request_t const *request) {
    (void)rhport;
    (void)stage;
    (void)request;
    return false;
}

static bool ccidd_xfer_cb(uint8_t rhport, uint8_t ep_addr, xfer_result_t result,
                          uint32_t xferred_bytes) {
    if (result != XFER_RESULT_SUCCESS) {
        if (ep_addr == s_ep_out) {
            ccid_arm_out(rhport);
        } else if (ep_addr == s_ep_in) {
            s_tx_busy = false;
        }
        return true;
    }

    if (ep_addr == s_ep_out) {
        ccid_on_bulk_out(s_rx_chunk, (uint16_t)xferred_bytes);
        ccid_arm_out(rhport);
    } else if (ep_addr == s_ep_in) {
        s_tx_busy = false;
    }
    // notify endpoint: fire-and-forget
    return true;
}

static usbd_class_driver_t const ccid_driver = {
#if CFG_TUSB_DEBUG >= 2
    .name = "ccid",
#endif
    .init = ccidd_init,
    .deinit = ccidd_deinit,
    .reset = ccidd_reset,
    .open = ccidd_open,
    .control_xfer_cb = ccidd_control_xfer_cb,
    .xfer_cb = ccidd_xfer_cb,
    .xfer_isr = NULL,
    .sof = NULL,
};

// Application drivers are consulted before built-ins.
usbd_class_driver_t const *usbd_app_driver_get_cb(uint8_t *driver_count) {
    *driver_count = 1;
    return &ccid_driver;
}

// ---------------------------------------------------------------------------
// Rust FFI
// ---------------------------------------------------------------------------

uint16_t aegis_ccid_pop_frame(uint8_t *out_buf, uint16_t max_len) {
    if (s_ccid_queue == NULL || out_buf == NULL || max_len == 0) {
        return 0;
    }
    ccid_frame_t f;
    if (xQueueReceive(s_ccid_queue, &f, 0) != pdTRUE) {
        return 0;
    }
    uint16_t n = (f.len < max_len) ? f.len : max_len;
    memcpy(out_buf, f.data, n);
    return n;
}

bool aegis_ccid_send(const uint8_t *data, uint16_t len) {
    if (!s_configured || s_ep_in == 0 || data == NULL || len == 0 || len > CCID_FRAME_MAX) {
        return false;
    }
    if (s_tx_busy) {
        ESP_LOGW(TAG, "tx busy, dropping %u B", len);
        return false;
    }
    memcpy(s_tx_buf, data, len);
    s_tx_busy = true;
    if (!usbd_edpt_xfer(0, s_ep_in, s_tx_buf, len)) {
        s_tx_busy = false;
        return false;
    }
    // Slot-change notice (best effort; host also just reads bulk-IN).
    s_notify_buf[0] = CCID_NOTIFY_SLOT_CHANGE;
    s_notify_buf[1] = 0x00;
    usbd_edpt_xfer(0, s_ep_notify, s_notify_buf, sizeof(s_notify_buf));
    return true;
}

bool aegis_ccid_is_mounted(void) {
    return s_configured;
}

#endif // CFG_TUD_ENABLED
