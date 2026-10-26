#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "driver/uart.h"
#include "esp_app_desc.h"
#include "esp_chip_info.h"
#include "esp_err.h"
#include "esp_flash.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_psram.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "ota_lab.h"
#include "cfg_store.h"

#ifndef LAB_HEALTH_FAIL_OVERRIDE
#ifdef CONFIG_LAB_HEALTH_FAIL
#define LAB_HEALTH_FAIL_OVERRIDE 1
#else
#define LAB_HEALTH_FAIL_OVERRIDE 0
#endif
#endif

#define LAB_UART ((uart_port_t)CONFIG_ESP_CONSOLE_UART_NUM)
#define LAB_LINE_SIZE 1536
#define LAB_HEARTBEAT_MS 10000

static const char *TAG = "lab";
static bool s_nvs_ready;
static bool s_selftest_passed;
static bool s_trial;
static bool s_ota_ready;
static bool s_service_mode;
static int64_t s_trial_deadline_us;

static const char *state_name(esp_ota_img_states_t state)
{
    switch (state) {
    case ESP_OTA_IMG_NEW: return "NEW";
    case ESP_OTA_IMG_PENDING_VERIFY: return "PENDING_VERIFY";
    case ESP_OTA_IMG_VALID: return "VALID";
    case ESP_OTA_IMG_INVALID: return "INVALID";
    case ESP_OTA_IMG_ABORTED: return "ABORTED";
    case ESP_OTA_IMG_UNDEFINED: return "UNDEFINED";
    default: return "UNKNOWN";
    }
}

static esp_ota_img_states_t running_state(void)
{
    esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (running) {
        esp_err_t err = esp_ota_get_state_partition(running, &state);
        if (err != ESP_OK && err != ESP_ERR_NOT_FOUND) {
            ESP_LOGW(TAG, "OTA_STATE_READ error=%s", esp_err_to_name(err));
        }
    }
    return state;
}

static const char *part_label(const esp_partition_t *partition)
{
    return partition ? partition->label : "none";
}

static void dump_partitions(void)
{
    esp_partition_iterator_t iter = esp_partition_find(ESP_PARTITION_TYPE_ANY,
                                                     ESP_PARTITION_SUBTYPE_ANY, NULL);
    while (iter) {
        const esp_partition_t *p = esp_partition_get(iter);
        ESP_LOGI(TAG, "PART label=%s type=0x%02x subtype=0x%02x offset=0x%08" PRIx32
                 " size=0x%08" PRIx32 " encrypted=%u",
                 p->label, p->type, p->subtype, p->address, p->size, p->encrypted);
        iter = esp_partition_next(iter);
    }
    esp_partition_iterator_release(iter);
}

static void report_status(bool full)
{
    const esp_app_desc_t *app = esp_app_get_description();
    const esp_partition_t *running = esp_ota_get_running_partition();
    const esp_partition_t *boot = esp_ota_get_boot_partition();
    const esp_partition_t *next = esp_ota_get_next_update_partition(NULL);
    uint32_t flash_bytes = 0;
    esp_chip_info_t chip;
    esp_chip_info(&chip);
    esp_flash_get_size(NULL, &flash_bytes);
    ESP_LOGI(TAG, "STATUS version=%s project=%s sdk=%s built=%s_%s reset=%d"
             " uptime_ms=%" PRId64 " health_fail=%d selftest=%s service_mode=%u",
             app->version, app->project_name, app->idf_ver, app->date, app->time,
             esp_reset_reason(), esp_timer_get_time() / 1000,
             LAB_HEALTH_FAIL_OVERRIDE, s_selftest_passed ? "PASS" : "NOT_PASSED", s_service_mode);
    ESP_LOGI(TAG, "BOARD model=ESP32-S3 revision=%u cores=%u flash_bytes=%" PRIu32
             " psram_bytes=%u internal_free=%u internal_largest=%u minimum_free=%u",
             chip.revision, chip.cores, flash_bytes, (unsigned)esp_psram_get_size(),
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
             (unsigned)esp_get_minimum_free_heap_size());
    ESP_LOGI(TAG, "OTA running=%s@0x%08" PRIx32 " boot=%s next=%s state=%s",
             part_label(running), running ? running->address : 0,
             part_label(boot), part_label(next), state_name(running_state()));
    if (full) {
        char elf_sha[65];
        esp_app_get_elf_sha256(elf_sha, sizeof(elf_sha));
        ESP_LOGI(TAG, "BUILD elf_sha256=%s secure_version=%" PRIu32,
                 elf_sha, app->secure_version);
        dump_partitions();
        cfg_store_status();
    }
}

/* Never erase data to hide a corrupt/incompatible NVS partition. */
static bool init_nvs(void)
{
    const char *partitions[] = { "nvs", "nvs_cfg", "ota_meta" };
    bool ready = true;
    for (size_t i = 0; i < sizeof(partitions) / sizeof(partitions[0]); ++i) {
        esp_err_t err = nvs_flash_init_partition(partitions[i]);
        ESP_LOGI(TAG, "NVS_INIT partition=%s result=%s erase_performed=false",
                 partitions[i], esp_err_to_name(err));
        if (err != ESP_OK) ready = false;
    }
    return ready;
}

static bool self_test(void)
{
    uint32_t flash_bytes = 0;
    bool ok = esp_flash_get_size(NULL, &flash_bytes) == ESP_OK;
    ok = ok && flash_bytes == 16 * 1024 * 1024;
    ok = ok && esp_psram_is_initialized() && esp_psram_get_size() == 8 * 1024 * 1024;
    ok = ok && heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT) >= 24576;
    ok = ok && heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT) >= 16384;
    uint8_t *test = heap_caps_malloc(1024, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (test) {
        for (size_t i = 0; i < 1024; ++i) test[i] = (uint8_t)(i ^ 0xa5);
        for (size_t i = 0; i < 1024; ++i) {
            if (test[i] != (uint8_t)(i ^ 0xa5)) ok = false;
        }
        heap_caps_free(test);
    } else {
        ok = false;
    }
    bool cfg_ok = s_nvs_ready && cfg_store_prepare();
    ok = ok && cfg_ok;
    ESP_LOGI(TAG, "SELFTEST result=%s flash_psram_heap_cfg_checked=true", ok ? "PASS" : "FAIL");
    return ok;
}

static void print_help(void)
{
    ESP_LOGI(TAG, "COMMANDS status | partitions | seed | reboot | failtrial | testreset | help");
    ESP_LOGI(TAG, "seed only accepts UNDEFINED baseline; failtrial=SDK INVALID rollback, testreset=unconfirmed reset; both require PENDING_VERIFY");
    ESP_LOGI(TAG, "CONFIG_COMMANDS cfg show | cfg parser-tests | cfg arm-valid-reset");
    ESP_LOGI(TAG, "OTA/network provisioning commands are handled by ota_lab; credentials are not echoed");
}

static void handle_line(char *line)
{
    if (!line[0]) return;
    if (strcmp(line, "status") == 0) {
        report_status(true);
    } else if (strcmp(line, "partitions") == 0) {
        dump_partitions();
    } else if (strcmp(line, "help") == 0) {
        print_help();
    } else if (strcmp(line, "reboot") == 0) {
        ESP_LOGI(TAG, "REBOOT requested state=%s", state_name(running_state()));
        vTaskDelay(pdMS_TO_TICKS(200));
        esp_restart();
    } else if (strcmp(line, "seed") == 0) {
        if (running_state() != ESP_OTA_IMG_UNDEFINED || !s_selftest_passed) {
            ESP_LOGW(TAG, "SEED_REJECT state=%s selftest=%u", state_name(running_state()), s_selftest_passed);
            return;
        }
        const esp_partition_t *running = esp_ota_get_running_partition();
        esp_err_t err = esp_ota_set_boot_partition(running);
        ESP_LOGI(TAG, "SEED running=%s result=%s next_boot=trial_then_selftest",
                 part_label(running), esp_err_to_name(err));
        if (err == ESP_OK) {
            vTaskDelay(pdMS_TO_TICKS(250));
            esp_restart();
        }
    } else if (strcmp(line, "failtrial") == 0 || strcmp(line, "testreset") == 0) {
        if (running_state() != ESP_OTA_IMG_PENDING_VERIFY) {
            ESP_LOGW(TAG, "TRIAL_RESET_REJECT state=%s required=PENDING_VERIFY", state_name(running_state()));
            return;
        }
        if (strcmp(line, "failtrial") == 0) {
            ESP_LOGW(TAG, "TRIAL_INVALID requesting SDK explicit rollback; verify fallback in next boot log");
            vTaskDelay(pdMS_TO_TICKS(200));
            esp_err_t err = esp_ota_mark_app_invalid_rollback_and_reboot();
            /* A successful call reboots. A returned error is not rollback success. */
            ESP_LOGE(TAG, "TRIAL_INVALID_RETURN result=%s state=%s fallback_not_proven=true",
                     esp_err_to_name(err), state_name(running_state()));
        } else {
            ESP_LOGW(TAG, "TRIAL_RESET deliberately leaving image unconfirmed; next boot must prove ABORTED/fallback");
            vTaskDelay(pdMS_TO_TICKS(200));
            esp_restart();
        }
    } else if (cfg_store_command(line)) {
        /* Config commands never print Wi-Fi credentials. */
    } else if (!s_ota_ready || !ota_lab_command(line)) {
        ESP_LOGW(TAG, "COMMAND_REJECT unknown command; use help");
    }
}

void app_main(void)
{
    s_nvs_ready = init_nvs();
    s_selftest_passed = self_test();
    s_service_mode = !s_selftest_passed;
    report_status(true);

    esp_err_t uart_err = uart_driver_install(LAB_UART, 2048, 0, 0, NULL, 0);
    if (uart_err != ESP_OK) {
        ESP_LOGE(TAG, "UART_INIT error=%s", esp_err_to_name(uart_err));
        return;
    }
    uart_set_baudrate(LAB_UART, CONFIG_ESP_CONSOLE_UART_BAUDRATE);
    s_trial = running_state() == ESP_OTA_IMG_PENDING_VERIFY;
    s_trial_deadline_us = esp_timer_get_time() + 5000000;
    if (s_trial) {
        ESP_LOGI(TAG, "TRIAL begin confirmation_window_ms=5000 health_fail=%u", LAB_HEALTH_FAIL_OVERRIDE);
    }
    if (!s_trial && s_nvs_ready) {
        if (running_state() == ESP_OTA_IMG_VALID && !cfg_store_confirmed()) s_service_mode = true;
        ota_lab_init();
        s_ota_ready = true;
    } else if (!s_nvs_ready) ESP_LOGE(TAG, "OTA_DISABLED reason=NVS_init_failed_no_erase");
    print_help();

    char line[LAB_LINE_SIZE];
    size_t used = 0;
    bool overflow = false;
    int64_t next_heartbeat = esp_timer_get_time() + LAB_HEARTBEAT_MS * 1000LL;
    while (true) {
        uint8_t byte;
        int count = uart_read_bytes(LAB_UART, &byte, 1, pdMS_TO_TICKS(50));
        if (count == 1) {
            if (byte == '\r' || byte == '\n') {
                if (overflow) ESP_LOGW(TAG, "COMMAND_REJECT line_too_long maximum=%u", LAB_LINE_SIZE - 1);
                else {
                    line[used] = '\0';
                    handle_line(line);
                }
                memset(line, 0, sizeof(line));
                used = 0;
                overflow = false;
            } else if ((byte == 8 || byte == 127) && used && !overflow) {
                line[--used] = '\0';
            } else if (byte >= 32 && byte != 127 && !overflow) {
                if (used + 1 < sizeof(line)) line[used++] = (char)byte;
                else overflow = true;
            }
        }
        int64_t now = esp_timer_get_time();
        if (s_trial && now >= s_trial_deadline_us) {
            s_trial = false;
            if (LAB_HEALTH_FAIL_OVERRIDE || !s_selftest_passed) {
                ESP_LOGE(TAG, "HEALTH_FAIL intentional=%u selftest=%u mark_valid=false reset_for_rollback=true",
                         LAB_HEALTH_FAIL_OVERRIDE, s_selftest_passed);
                vTaskDelay(pdMS_TO_TICKS(250));
                esp_restart();
            }
            if (!ota_lab_trial_health()) {
                s_selftest_passed = false;
                s_service_mode = true;
                ESP_LOGE(TAG, "HEALTH_FAIL reason=candidate_identity_or_digest mark_valid=false reset_for_rollback=true");
                vTaskDelay(pdMS_TO_TICKS(250));
                esp_restart();
            }
#if LAB_PREVALID_RESET
            ESP_LOGW(TAG, "FAULT_RESET point=after_health_before_SDK_VALID method=software_reset mark_valid_called=false");
            vTaskDelay(pdMS_TO_TICKS(150));
            esp_restart();
#endif
            esp_err_t err = esp_ota_mark_app_valid_cancel_rollback();
            ESP_LOGI(TAG, "MARK_VALID result=%s state=%s", esp_err_to_name(err), state_name(running_state()));
            if (err == ESP_OK) {
                if (cfg_store_take_reset_after_valid()) {
                    ESP_LOGW(TAG, "FAULT_RESET window=after_SDK_VALID_before_active_schema_commit");
                    vTaskDelay(pdMS_TO_TICKS(200));
                    esp_restart();
                }
                if (!cfg_store_confirmed()) s_service_mode = true;
                ota_lab_init();
                s_ota_ready = true;
            }
        }
        if (now >= next_heartbeat) {
            report_status(false);
            next_heartbeat = now + LAB_HEARTBEAT_MS * 1000LL;
        }
    }
}
