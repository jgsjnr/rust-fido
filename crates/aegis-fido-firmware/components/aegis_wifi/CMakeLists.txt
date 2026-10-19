idf_component_register(SRCS "aegis_wifi.c"
                        INCLUDE_DIRS "."
                        REQUIRES esp_wifi esp_netif esp_event nvs_flash lwip freertos)
