idf_component_register(
    SRCS "main.c" "ota_lab.c" "cfg_store.c"
    INCLUDE_DIRS "."
    EMBED_FILES "manifest_public.der"
    REQUIRES app_update esp_app_format esp_driver_uart esp_psram esp_timer
             esp_system esp_partition spi_flash nvs_flash
             esp_https_ota esp_http_client esp_wifi esp_netif esp_event
             esp-tls mbedtls lwip
)
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    LAB_VERSION_CODE=${LAB_VERSION_CODE} LAB_CFG_SCHEMA=${LAB_CFG_SCHEMA})

# A dedicated negative-test build can use -DLAB_HEALTH_FAIL=ON.
# No eFuse or persistent security settings are changed by this fixture.
if(DEFINED LAB_HEALTH_FAIL)
    if(LAB_HEALTH_FAIL)
        target_compile_definitions(${COMPONENT_LIB} PRIVATE LAB_HEALTH_FAIL_OVERRIDE=1)
    else()
        target_compile_definitions(${COMPONENT_LIB} PRIVATE LAB_HEALTH_FAIL_OVERRIDE=0)
    endif()
endif()
