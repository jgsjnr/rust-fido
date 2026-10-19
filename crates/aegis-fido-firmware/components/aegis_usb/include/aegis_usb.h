/*
 * AegisKey S3 USB Transport Bridge (TinyUSB HID CTAPHID)
 *
 * Implements standard USB HID FIDO2 interface for ESP32-S3.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*aegis_hid_rx_callback_t)(const uint8_t *packet, uint16_t len);

/**
 * Initializes native USB-OTG controller with TinyUSB stack as a FIDO2 HID security key.
 */
esp_err_t aegis_usb_init(void);

/**
 * Returns true if the device is enumerated and mounted by the host USB.
 */
bool aegis_usb_is_mounted(void);

/**
 * Sends a 64-byte CTAPHID report back to the host via Interrupt IN endpoint.
 */
bool aegis_usb_send_report(const uint8_t *packet, uint16_t len);

/**
 * Registers callback invoked when a 64-byte CTAPHID packet is received from the host.
 */
void aegis_usb_set_rx_callback(aegis_hid_rx_callback_t callback);

/**
 * Pops the next available 64-byte CTAPHID packet from the RX ring buffer.
 * Returns bytes read (0 if buffer is empty).
 */
uint16_t aegis_usb_pop_packet(uint8_t *out_buf, uint16_t max_len);

/**
 * Non-blocking diagnostic text read (TEST_LIFETIME_DUMP with test-mode).
 * Yields bytes ONLY while fewer than 64 are buffered, so a 64-byte CTAPHID
 * packet is never split by the dump path.
 */
uint16_t aegis_usb_read_chunk(uint8_t *out_buf, uint16_t max_len);

#ifdef __cplusplus
}
#endif
