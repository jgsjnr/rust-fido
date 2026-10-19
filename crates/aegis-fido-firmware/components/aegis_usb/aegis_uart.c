/*
 * AegisKey S3 / Classic UART Serial Transport Bridge
 *
 * Implements standard CTAPHID packet transport over UART Serial
 * for classic ESP32 boards (e.g. LilyGO TTGO T-Display) without USB-OTG.
 */

#include "aegis_usb.h"
#include "driver/uart.h"
#include "esp_log.h"
#include <string.h>

#define UART_PORT UART_NUM_0
#define PACKET_SIZE 64
#define RX_BUF_SIZE 2048

static const char *TAG = "AegisUART";
static bool s_initialized = false;

esp_err_t aegis_usb_init(void) {
    if (s_initialized) {
        return ESP_OK;
    }

    uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    esp_err_t err = uart_param_config(UART_PORT, &uart_config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to configure UART: %d", err);
        return err;
    }

    err = uart_driver_install(UART_PORT, RX_BUF_SIZE, RX_BUF_SIZE, 0, NULL, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to install UART driver: %d", err);
        return err;
    }

    s_initialized = true;
    ESP_LOGI(TAG, "CTAPHID Serial Transport online on UART0 (115200 baud)");
    return ESP_OK;
}

bool aegis_usb_is_mounted(void) {
    return s_initialized;
}

bool aegis_usb_send_report(const uint8_t *packet, uint16_t len) {
    if (!s_initialized || packet == NULL || len == 0) {
        return false;
    }
    int written = uart_write_bytes(UART_PORT, (const char *)packet, len);
    return (written == len);
}

void aegis_usb_set_rx_callback(aegis_hid_rx_callback_t callback) {
    (void)callback;
}

uint16_t aegis_usb_read_chunk(uint8_t *out_buf, uint16_t max_len) {
    if (!s_initialized || out_buf == NULL || max_len == 0) {
        return 0;
    }

    size_t buffered = 0;
    uart_get_buffered_data_len(UART_PORT, &buffered);

    // Never split a 64-byte packet: packets always win the wire.
    if (buffered == 0 || buffered >= PACKET_SIZE) {
        return 0;
    }

    uint16_t want = (buffered < max_len) ? (uint16_t)buffered : max_len;
    int read_bytes = uart_read_bytes(UART_PORT, out_buf, want, 0);
    return (read_bytes > 0) ? (uint16_t)read_bytes : 0;
}

uint16_t aegis_usb_pop_packet(uint8_t *out_buf, uint16_t max_len) {
    if (!s_initialized || out_buf == NULL || max_len < PACKET_SIZE) {
        return 0;
    }

    size_t buffered = 0;
    uart_get_buffered_data_len(UART_PORT, &buffered);

    if (buffered >= PACKET_SIZE) {
        int read_bytes = uart_read_bytes(UART_PORT, out_buf, PACKET_SIZE, 10 / portTICK_PERIOD_MS);
        if (read_bytes == PACKET_SIZE) {
            return PACKET_SIZE;
        }
    }
    return 0;
}
