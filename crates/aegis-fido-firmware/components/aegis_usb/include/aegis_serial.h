/*
 * AegisKey S3/S2 Serial CTAPHID Diagnostic Channel (UART 115200 8N1).
 *
 * Carries the same 64-byte CTAPHID framing as USB (INIT/CONT, CID,
 * keepalive) plus TEST_LIFETIME_DUMP text lines (test-mode firmware).
 * Native USB-OTG (aegis_usb.c) stays the primary FIDO2 transport.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Installs the UART0 driver for the serial CTAPHID channel (115200 8N1).
 * Coexists with ROM log output on TX (same pattern as the classic UART
 * transport); idempotent.
 */
esp_err_t aegis_serial_init(void);

/**
 * Writes raw bytes to the serial channel (64B CTAPHID packets or dump text).
 */
bool aegis_serial_send_report(const uint8_t *packet, uint16_t len);

/**
 * Pops one 64-byte CTAPHID packet. Returns bytes read (0 when fewer than
 * 64 are buffered, so packets are never split).
 */
uint16_t aegis_serial_pop_packet(uint8_t *out_buf, uint16_t max_len);

/**
 * Non-blocking diagnostic text read. Yields bytes ONLY while fewer than 64
 * are buffered, so a 64-byte CTAPHID packet is never split by the dump path.
 * Returns bytes read (0 when idle or while a packet is arriving).
 */
uint16_t aegis_serial_read_chunk(uint8_t *out_buf, uint16_t max_len);

#ifdef __cplusplus
}
#endif
