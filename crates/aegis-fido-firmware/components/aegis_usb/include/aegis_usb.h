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

/**
 * Reboots straight into the ROM download bootloader via RTC_CNTL
 * FORCE_DOWNLOAD_BOOT (no buttons, no DTR/RTS circuit needed).
 * TEST-HOOK: called only from test-mode serial `TEST_DOWNLOAD`.
 * Never returns.
 */
void aegis_reboot_to_download(void);

/**
 * Pops one complete reassembled CCID frame (F4, `ccid_device.c`).
 * Returns bytes read (0 when the queue is empty); truncates at `max_len`.
 */
uint16_t aegis_ccid_pop_frame(uint8_t *out_buf, uint16_t max_len);

/**
 * Sends one RPDU over CCID bulk-IN (auto-chunked) + slot-change notice.
 * Best-effort: `false` when unconfigured or a transfer is in flight.
 */
bool aegis_ccid_send(const uint8_t *data, uint16_t len);

/**
 * `true` once the host selected the configuration (CCID interface open).
 */
bool aegis_ccid_is_mounted(void);

#ifdef __cplusplus
}
#endif
