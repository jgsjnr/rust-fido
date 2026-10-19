/*
 * AegisKey S3/S2 Serial CTAPHID Diagnostic Channel (UART0 115200 8N1).
 *
 * Same 64-byte CTAPHID framing as USB (INIT/CONT, CID, keepalive) plus
 * TEST_LIFETIME_DUMP text lines on the same wire (test-mode firmware).
 * Heartbeat/log text stays outside the framing; the Rust router
 * (serial_ctaphid) ignores text without breaking packet reassembly.
 */

#include "aegis_serial.h"
#include "driver/uart.h"
#include "esp_log.h"
#include <string.h>

#define SERIAL_UART_PORT UART_NUM_0
#define SERIAL_PACKET_SIZE 64
#define SERIAL_RX_BUF_SIZE 2048

static const char *TAG = "AegisSerial";
static bool s_serial_initialized = false;

esp_err_t aegis_serial_init(void) {
    if (s_serial_initialized) {
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

    esp_err_t err = uart_param_config(SERIAL_UART_PORT, &uart_config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to configure UART: %d", err);
        return err;
    }

    err = uart_driver_install(SERIAL_UART_PORT, SERIAL_RX_BUF_SIZE, SERIAL_RX_BUF_SIZE, 0, NULL, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to install UART driver: %d", err);
        return err;
    }

    s_serial_initialized = true;
    ESP_LOGI(TAG, "Serial CTAPHID channel online on UART0 (115200 8N1, framing = USB)");
    return ESP_OK;
}

bool aegis_serial_send_report(const uint8_t *packet, uint16_t len) {
    if (!s_serial_initialized || packet == NULL || len == 0) {
        return false;
    }
    int written = uart_write_bytes(SERIAL_UART_PORT, (const char *)packet, len);
    return (written == len);
}

uint16_t aegis_serial_pop_packet(uint8_t *out_buf, uint16_t max_len) {
    if (!s_serial_initialized || out_buf == NULL || max_len < SERIAL_PACKET_SIZE) {
        return 0;
    }

    size_t buffered = 0;
    uart_get_buffered_data_len(SERIAL_UART_PORT, &buffered);

    if (buffered >= SERIAL_PACKET_SIZE) {
        int read_bytes = uart_read_bytes(SERIAL_UART_PORT, out_buf, SERIAL_PACKET_SIZE, 10 / portTICK_PERIOD_MS);
        if (read_bytes == SERIAL_PACKET_SIZE) {
            return SERIAL_PACKET_SIZE;
        }
    }
    return 0;
}

uint16_t aegis_serial_read_chunk(uint8_t *out_buf, uint16_t max_len) {
    if (!s_serial_initialized || out_buf == NULL || max_len == 0) {
        return 0;
    }

    size_t buffered = 0;
    uart_get_buffered_data_len(SERIAL_UART_PORT, &buffered);

    // Never split a 64-byte packet: packets always win the wire.
    if (buffered == 0 || buffered >= SERIAL_PACKET_SIZE) {
        return 0;
    }

    uint16_t want = (buffered < max_len) ? (uint16_t)buffered : max_len;
    int read_bytes = uart_read_bytes(SERIAL_UART_PORT, out_buf, want, 0);
    return (read_bytes > 0) ? (uint16_t)read_bytes : 0;
}
