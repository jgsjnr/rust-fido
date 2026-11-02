idf_build_get_property(target IDF_TARGET)

if(NOT (${target} STREQUAL "esp32s3" OR ${target} STREQUAL "esp32s2"))
    idf_component_register(SRCS "aegis_uart.c" "aegis_display_st7789.c"
                           INCLUDE_DIRS "include"
                           REQUIRES freertos driver esp_driver_uart esp_driver_spi esp_driver_gpio esp_lcd
                           )
    return()
endif()

idf_component_register(SRCS "aegis_usb.c" "ccid_device.c" "aegis_serial.c" "aegis_display_st7789.c"
                       INCLUDE_DIRS "include"
                       # v6: `usb` host stack dropped (unused here: tud_*/usbd_* device symbols only).
                       # v5.3.1 in-tree names were: espressif__esp_tinyusb tinyusb usb.
                       PRIV_REQUIRES espressif__esp_tinyusb tinyusb
                       REQUIRES freertos driver esp_driver_uart esp_driver_spi esp_driver_gpio esp_lcd
                       )
