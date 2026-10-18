/*
 * AegisKey Hardware ST7789 Display Driver via official esp_lcd
 */

#include "aegis_display.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_vendor.h"
#include "esp_lcd_panel_ops.h"
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

#define TAG "AegisDisplay"

#if defined(CONFIG_IDF_TARGET_ESP32)
// LilyGO TTGO T-Display Classic (ESP32)
#define LCD_HOST       SPI2_HOST
#define PIN_NUM_MISO   -1
#define PIN_NUM_MOSI   19
#define PIN_NUM_CLK    18
#define PIN_NUM_CS     5
#define PIN_NUM_DC     16
#define PIN_NUM_RST    23
#define PIN_NUM_BCKL   4

#define LCD_WIDTH      135
#define LCD_HEIGHT     240
#define GAP_X          52
#define GAP_Y          40

#elif defined(CONFIG_IDF_TARGET_ESP32S3)
// LilyGO T-Display-S3 (ESP32-S3)
#define LCD_HOST       SPI2_HOST
#define PIN_NUM_MISO   -1
#define PIN_NUM_MOSI   11
#define PIN_NUM_CLK    12
#define PIN_NUM_CS     10
#define PIN_NUM_DC     13
#define PIN_NUM_RST    1
#define PIN_NUM_BCKL   38
#define PIN_NUM_PWR    15

#define LCD_WIDTH      170
#define LCD_HEIGHT     320
#define GAP_X          35
#define GAP_Y          0

#else
#define LCD_HOST       SPI2_HOST
#define PIN_NUM_MISO   -1
#define PIN_NUM_MOSI   19
#define PIN_NUM_CLK    18
#define PIN_NUM_CS     5
#define PIN_NUM_DC     16
#define PIN_NUM_RST    23
#define PIN_NUM_BCKL   4

#define LCD_WIDTH      135
#define LCD_HEIGHT     240
#define GAP_X          52
#define GAP_Y          40
#endif

static esp_lcd_panel_handle_t s_panel_handle = NULL;
static bool s_initialized = false;

esp_err_t aegis_display_init(void) {
    if (s_initialized) return ESP_OK;

#ifdef PIN_NUM_PWR
    gpio_config_t pwr_cfg = {
        .pin_bit_mask = (1ULL << PIN_NUM_PWR),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&pwr_cfg);
    gpio_set_level((gpio_num_t)PIN_NUM_PWR, 1);
    vTaskDelay(pdMS_TO_TICKS(10));
#endif

    // Backlight GPIO config (OFF initially)
    gpio_config_t bl_cfg = {
        .pin_bit_mask = (1ULL << PIN_NUM_BCKL),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&bl_cfg);
    gpio_set_level((gpio_num_t)PIN_NUM_BCKL, 0);

    // Initialize SPI Bus
    spi_bus_config_t buscfg = {
        .sclk_io_num = PIN_NUM_CLK,
        .mosi_io_num = PIN_NUM_MOSI,
        .miso_io_num = PIN_NUM_MISO,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = LCD_WIDTH * LCD_HEIGHT * sizeof(uint16_t),
    };

    esp_err_t ret = spi_bus_initialize(LCD_HOST, &buscfg, SPI_DMA_CH_AUTO);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "spi_bus_initialize failed: %d", ret);
        return ret;
    }

    // Attach LCD IO panel to SPI bus
    esp_lcd_panel_io_handle_t io_handle = NULL;
    esp_lcd_panel_io_spi_config_t io_config = {
        .dc_gpio_num = PIN_NUM_DC,
        .cs_gpio_num = PIN_NUM_CS,
        .pclk_hz = 20 * 1000 * 1000, // 20 MHz stable
        .lcd_cmd_bits = 8,
        .lcd_param_bits = 8,
        .spi_mode = 0,
        .trans_queue_depth = 10,
    };

    ret = esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)LCD_HOST, &io_config, &io_handle);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_lcd_new_panel_io_spi failed: %d", ret);
        return ret;
    }

    // Attach ST7789 driver
    esp_lcd_panel_dev_config_t panel_config = {
        .reset_gpio_num = PIN_NUM_RST,
        .rgb_endian = LCD_RGB_ENDIAN_BGR,
        .bits_per_pixel = 16,
    };

    ret = esp_lcd_new_panel_st7789(io_handle, &panel_config, &s_panel_handle);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_lcd_new_panel_st7789 failed: %d", ret);
        return ret;
    }

    esp_lcd_panel_reset(s_panel_handle);
    esp_lcd_panel_init(s_panel_handle);
    esp_lcd_panel_invert_color(s_panel_handle, true);
    esp_lcd_panel_set_gap(s_panel_handle, GAP_X, GAP_Y);
    esp_lcd_panel_disp_on_off(s_panel_handle, true);

    // Turn ON Backlight
    gpio_set_level((gpio_num_t)PIN_NUM_BCKL, 1);

    s_initialized = true;
    ESP_LOGI(TAG, "ST7789 glass initialized via esp_lcd (%dx%d, gap %d/%d, INVON, BL on)",
             LCD_WIDTH, LCD_HEIGHT, GAP_X, GAP_Y);
    return ESP_OK;
}

void aegis_display_set_backlight(bool on) {
    gpio_set_level((gpio_num_t)PIN_NUM_BCKL, on ? 1 : 0);
}

void aegis_display_flush(uint16_t x1, uint16_t y1, uint16_t x2, uint16_t y2, const uint16_t *pixels, uint32_t count) {
    if (!s_initialized || s_panel_handle == NULL || pixels == NULL || count == 0) return;
    esp_lcd_panel_draw_bitmap(s_panel_handle, x1, y1, x2 + 1, y2 + 1, pixels);
}
