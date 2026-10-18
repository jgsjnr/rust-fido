/*
 * AegisKey Hardware Display Driver Header (ST7789)
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t aegis_display_init(void);
void aegis_display_set_backlight(bool on);
void aegis_display_flush(uint16_t x1, uint16_t y1, uint16_t x2, uint16_t y2, const uint16_t *pixels, uint32_t count);

#ifdef __cplusplus
}
#endif
