idf_build_get_property(target IDF_TARGET)

if(NOT (${target} STREQUAL "esp32s3" OR ${target} STREQUAL "esp32s2"))
    idf_component_register(SRCS "aegis_uart.c" "aegis_display_st7789.c"
                           INCLUDE_DIRS "include"
                           REQUIRES freertos driver esp_driver_uart esp_driver_spi esp_driver_gpio esp_lcd
                           )
    return()
endif()

idf_component_register(SRCS "aegis_usb.c" "aegis_display_st7789.c"
                       INCLUDE_DIRS "include"
                       PRIV_REQUIRES espressif__esp_tinyusb tinyusb usb
                       REQUIRES freertos driver esp_driver_spi esp_driver_gpio esp_lcd
                       )
