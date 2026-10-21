/*
 * AegisKey S3 USB Transport Bridge (TinyUSB HID CTAPHID)
 *
 * Implements standard USB HID FIDO2 interface for ESP32-S3.
 */

#include <string.h>
#include "esp_log.h"
#include "esp_err.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "soc/rtc_cntl_reg.h"
#include "soc/soc.h"
#include "tinyusb.h"
#include "tusb.h"
#include "class/hid/hid_device.h"
#include "aegis_usb.h"

static const char *TAG = "AegisUSB";

// ----------------------------------------------------------------------------
// Descriptors
// ----------------------------------------------------------------------------

static const tusb_desc_device_t desc_device = {
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = 0x0200,
    .bDeviceClass       = 0x00,
    .bDeviceSubClass    = 0x00,
    .bDeviceProtocol    = 0x00,
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor           = 0x303A,
    .idProduct          = 0xAE61,
    .bcdDevice          = 0x0100,
    .iManufacturer      = 0x01,
    .iProduct           = 0x02,
    .iSerialNumber      = 0x03,
    .bNumConfigurations = 0x01
};

// Standard FIDO2 / CTAPHID Report Descriptor (34 bytes)
static const uint8_t desc_hid_report[] = {
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance 0xF1D0)
    0x09, 0x01,       // Usage (U2F / FIDO Authenticator 0x0001)
    0xA1, 0x01,       // Collection (Application)
    0x09, 0x20,       //   Usage (Data In)
    0x15, 0x00,       //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08,       //   Report Size (8 bits)
    0x95, 0x40,       //   Report Count (64 bytes)
    0x81, 0x02,       //   Input (Data, Variable, Absolute)
    0x09, 0x21,       //   Usage (Data Out)
    0x15, 0x00,       //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08,       //   Report Size (8 bits)
    0x95, 0x40,       //   Report Count (64 bytes)
    0x91, 0x02,       //   Output (Data, Variable, Absolute)
    0xC0              // End Collection
};

#define EPNUM_HID_OUT 0x01
#define EPNUM_HID_IN  0x81
// F4: CCID (PIV) endpoints — bulk OUT/IN + interrupt notify.
#define EPNUM_CCID_OUT 0x02
#define EPNUM_CCID_IN 0x82
#define EPNUM_CCID_NOTIFY 0x83

// Interface CCID (9) + funcional CCID (54) + 3 endpoints (3x7).
#define CCID_DESC_LEN (9 + 54 + 3 * 7)
#define CONFIG_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_HID_INOUT_DESC_LEN + CCID_DESC_LEN)

static const uint8_t desc_configuration[] = {
    // Config number, interface count, string index, total length, attribute, power in mA
    TUD_CONFIG_DESCRIPTOR(1, 2, 0, CONFIG_TOTAL_LEN, 0x80, 250),

    // Interface 0: HID FIDO2 (intacto, em 1o lugar).
    // Interface number, string index, protocol, report descriptor len, EP Out & In address, size & polling interval
    TUD_HID_INOUT_DESCRIPTOR(0, 0, HID_ITF_PROTOCOL_NONE, sizeof(desc_hid_report), EPNUM_HID_OUT, EPNUM_HID_IN, 64, 5),

    // Interface 1: CCID smartcard (F4 PIV; driver `ccid_device.c`).
    // 9 (iface) + 54 (funcional, contar!) + 3x7 (EPs) = 84 = CCID_DESC_LEN.
    9, TUSB_DESC_INTERFACE, 1, 0, 3, 0x0B, 0x00, 0x00, 0,
    // CCID functional descriptor (54 B exatos, tipo 0x21, ordem da spec).
    54, 0x21,
    0x10, 0x01,             // bcdCCID 1.10
    0x00,                   // bMaxSlotIndex (1 slot)
    0x07,                   // bVoltageSupport (5V/3V/1.8V)
    0x02, 0x00, 0x00, 0x00, // dwProtocols (T=1)
    0x38, 0x7D, 0x36, 0x00, // dwDefaultClock (3571 = 9600*372/1000)
    0x38, 0x7D, 0x36, 0x00, // dwMaximumClock
    0x00,                   // bNumClockSupported
    0x80, 0x25, 0x00, 0x00, // dwDataRate (9600; coerente com TA1=0x11 do ATR)
    0x80, 0x25, 0x00, 0x00, // dwMaxDataRate (9600)
    0x00,                   // bNumDataRatesSupported
    0xFE, 0x00, 0x00, 0x00, // dwMaxIFSD (254)
    0x00, 0x00, 0x00, 0x00, // dwSynchProtocols
    0x00, 0x00, 0x00, 0x00, // dwMechanical
    0x00, 0x00, 0x0C, 0x00, // dwFeatures: SHORT_APDU|SHORT_AND_EXTENDED
    0x00, 0x08, 0x00, 0x00, // dwMaxCCIDMessageLength (2048)
    0x00,                   // bClassGetResponse
    0x00,                   // bClassEnvelope
    0x00, 0x00,             // wLcdLayout
    0x00,                   // bPINSupport
    0x01,                   // bMaxCCIDBusySlots
// EP bulk OUT
    7, TUSB_DESC_ENDPOINT, EPNUM_CCID_OUT, TUSB_XFER_BULK, 64, 0, 0,
    // EP bulk IN
    7, TUSB_DESC_ENDPOINT, EPNUM_CCID_IN, TUSB_XFER_BULK, 64, 0, 0,
    // EP interrupt IN (slot-change notice)
    7, TUSB_DESC_ENDPOINT, EPNUM_CCID_NOTIFY, TUSB_XFER_INTERRUPT, 8, 0, 32,
};

static const char *string_desc_arr[] = {
    (const char[]) { 0x09, 0x04 }, // 0: Supported language: English (0x0409)
    "Aegis Security",              // 1: Manufacturer
    "AegisKey S3 Authenticator",   // 2: Product
    "AEGIS-S3-0001",               // 3: Serial
};

// ----------------------------------------------------------------------------
// State & Packet Queue
// ----------------------------------------------------------------------------

#define RX_QUEUE_SIZE 8
typedef struct {
    uint8_t data[64];
    uint16_t len;
} hid_packet_t;

static QueueHandle_t s_rx_queue = NULL;
static aegis_hid_rx_callback_t s_rx_callback = NULL;
static volatile bool s_is_mounted = false;

// ----------------------------------------------------------------------------
// TinyUSB Callbacks
// ----------------------------------------------------------------------------

void tud_mount_cb(void) {
    s_is_mounted = true;
    ESP_LOGI(TAG, "USB Device mounted by Host (FIDO2 HID ready)");
}

void tud_umount_cb(void) {
    s_is_mounted = false;
    ESP_LOGW(TAG, "USB Device unmounted");
}

void tud_suspend_cb(bool remote_wakeup_en) {
    (void)remote_wakeup_en;
    s_is_mounted = false;
    ESP_LOGD(TAG, "USB Suspend");
}

void tud_resume_cb(void) {
    s_is_mounted = tud_mounted();
    ESP_LOGD(TAG, "USB Resume (mounted: %d)", s_is_mounted);
}

uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance) {
    (void)instance;
    return desc_hid_report;
}

uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type, uint8_t* buffer, uint16_t reqlen) {
    (void)instance;
    (void)report_id;
    (void)report_type;
    (void)buffer;
    (void)reqlen;
    return 0;
}

void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type, uint8_t const* buffer, uint16_t bufsize) {
    (void)instance;
    (void)report_id;
    (void)report_type;

    if (bufsize == 0 || buffer == NULL) {
        return;
    }

    // Call registered Rust callback if available
    if (s_rx_callback != NULL) {
        s_rx_callback(buffer, bufsize);
    }

    // Also push into queue for polling
    if (s_rx_queue != NULL) {
        hid_packet_t pkt;
        uint16_t copy_len = (bufsize > 64) ? 64 : bufsize;
        memcpy(pkt.data, buffer, copy_len);
        pkt.len = copy_len;
        xQueueSend(s_rx_queue, &pkt, 0);
    }
}

// ----------------------------------------------------------------------------
// Public API
// ----------------------------------------------------------------------------

esp_err_t aegis_usb_init(void) {
    ESP_LOGI(TAG, "Initializing TinyUSB FIDO2 HID stack...");

    if (s_rx_queue == NULL) {
        s_rx_queue = xQueueCreate(RX_QUEUE_SIZE, sizeof(hid_packet_t));
    }

    const tinyusb_config_t tusb_cfg = {
        .device_descriptor = &desc_device,
        .string_descriptor = string_desc_arr,
        .string_descriptor_count = sizeof(string_desc_arr) / sizeof(string_desc_arr[0]),
        .external_phy = false,
        .configuration_descriptor = desc_configuration,
        .self_powered = false,
        .vbus_monitor_io = -1
    };

    esp_err_t err = tinyusb_driver_install(&tusb_cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "tinyusb_driver_install failed: 0x%x", err);
        return err;
    }

    ESP_LOGI(TAG, "TinyUSB FIDO2 HID driver online (VID: 0x%04X, PID: 0x%04X, Usage: 0xF1D0)",
             desc_device.idVendor, desc_device.idProduct);
    return ESP_OK;
}

bool aegis_usb_is_mounted(void) {
    return s_is_mounted || tud_mounted();
}

bool aegis_usb_send_report(const uint8_t *packet, uint16_t len) {
    if (packet == NULL || len == 0) {
        return false;
    }
    // Wait for USB IN endpoint to become ready (up to 200ms)
    int retries = 200;
    while (!tud_hid_ready() && retries > 0) {
        vTaskDelay(1);
        retries--;
    }
    if (!tud_hid_ready()) {
        ESP_LOGW(TAG, "aegis_usb_send_report: timeout waiting for tud_hid_ready");
        return false;
    }
    bool sent = tud_hid_report(0, packet, len);
    if (!sent) {
        vTaskDelay(1);
        sent = tud_hid_report(0, packet, len);
    }
    return sent;
}

void aegis_usb_set_rx_callback(aegis_hid_rx_callback_t callback) {
    s_rx_callback = callback;
}

uint16_t aegis_usb_pop_packet(uint8_t *out_buf, uint16_t max_len) {
    if (s_rx_queue == NULL || out_buf == NULL || max_len == 0) {
        return 0;
    }

    hid_packet_t pkt;
    if (xQueueReceive(s_rx_queue, &pkt, 0) == pdTRUE) {
        uint16_t to_copy = (pkt.len < max_len) ? pkt.len : max_len;
        memcpy(out_buf, pkt.data, to_copy);
        return to_copy;
    }
    return 0;
}

void aegis_reboot_to_download(void) {
    ESP_LOGW(TAG, "TEST_DOWNLOAD: rebooting into ROM download via RTC_CNTL");
    REG_SET_BIT(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_restart();
    for (;;) {
    }
}

bool aegis_usb_reconnect(void) {
    ESP_LOGI(TAG, "TEST_USB_RECONNECT: drop + re-enumerate");
    if (!tud_disconnect()) {
        return false;
    }
    vTaskDelay(pdMS_TO_TICKS(300));
    return tud_connect();
}
