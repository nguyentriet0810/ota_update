#include "cfg_store.h"
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs.h"

#ifndef LAB_CFG_SCHEMA
#define LAB_CFG_SCHEMA 1
#endif

#define CFG_MAGIC 0x4346474cUL
#define CFG_FORMAT 1U
#define V1_LEN 28U
#define V2_LEN 44U
#define MAX_RECORD_LEN 64U
#define MIGRATION_ID 0x00010002UL

typedef struct {
    uint16_t schema;
    uint32_t generation;
    uint32_t sample_ms;
    int32_t threshold;
    int32_t offset;
    uint32_t source_generation;
    uint32_t source_crc;
    uint32_t crc;
} cfg_record_t;

static const char *TAG = "cfg";
static bool s_ready;
static cfg_record_t s_source;
static cfg_record_t s_current;
static uint32_t s_active;

static uint16_t get16(const uint8_t *p) { return (uint16_t)p[0] | ((uint16_t)p[1] << 8); }
static uint32_t get32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void put16(uint8_t *p, uint16_t v) { p[0] = v; p[1] = v >> 8; }
static void put32(uint8_t *p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }

/* CRC-32/ISO-HDLC detects storage faults; it provides no authenticity. */
static uint32_t crc32(const uint8_t *p, size_t length)
{
    uint32_t crc = 0xffffffffU;
    for (size_t i = 0; i < length; ++i) {
        crc ^= p[i];
        for (unsigned bit = 0; bit < 8; ++bit) crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1U)));
    }
    return ~crc;
}

static bool decode(const uint8_t *p, size_t length, uint16_t expected, cfg_record_t *out)
{
    const size_t required = expected == 1 ? V1_LEN : expected == 2 ? V2_LEN : 0;
    if (!required || length != required || get32(p) != CFG_MAGIC || get16(p + 4) != CFG_FORMAT ||
        get16(p + 6) != expected || get32(p + 8) != length || crc32(p, length - 4) != get32(p + length - 4)) {
        return false;
    }
    cfg_record_t parsed = {
        .schema = expected,
        .generation = get32(p + 12),
        .sample_ms = get32(p + 16),
        .threshold = (int32_t)get32(p + 20),
        .crc = get32(p + length - 4),
    };
    if (!parsed.generation || parsed.sample_ms < 10 || parsed.sample_ms > 60000) return false;
    if (expected == 1) {
        if (parsed.threshold < -40 || parsed.threshold > 125) return false;
    } else {
        parsed.offset = (int32_t)get32(p + 24);
        parsed.source_generation = get32(p + 32);
        parsed.source_crc = get32(p + 36);
        if (parsed.threshold < -40000 || parsed.threshold > 125000 || parsed.offset < -20000 ||
            parsed.offset > 20000 || get32(p + 28) != MIGRATION_ID || !parsed.source_generation) return false;
    }
    *out = parsed;
    return true;
}

static size_t encode(uint8_t *p, const cfg_record_t *record)
{
    size_t length = record->schema == 1 ? V1_LEN : V2_LEN;
    memset(p, 0, length);
    put32(p, CFG_MAGIC);
    put16(p + 4, CFG_FORMAT);
    put16(p + 6, record->schema);
    put32(p + 8, length);
    put32(p + 12, record->generation);
    put32(p + 16, record->sample_ms);
    put32(p + 20, (uint32_t)record->threshold);
    if (record->schema == 2) {
        put32(p + 24, (uint32_t)record->offset);
        put32(p + 28, MIGRATION_ID);
        put32(p + 32, record->source_generation);
        put32(p + 36, record->source_crc);
    }
    put32(p + length - 4, crc32(p, length - 4));
    return length;
}

static esp_err_t read_record(nvs_handle_t handle, const char *key, uint16_t schema, cfg_record_t *out)
{
    size_t length = 0;
    esp_err_t err = nvs_get_blob(handle, key, NULL, &length);
    if (err != ESP_OK) return err;
    if (length > MAX_RECORD_LEN || length < V1_LEN) return ESP_ERR_INVALID_SIZE;
    uint8_t bytes[MAX_RECORD_LEN];
    err = nvs_get_blob(handle, key, bytes, &length);
    if (err != ESP_OK) return err;
    return decode(bytes, length, schema, out) ? ESP_OK : ESP_ERR_INVALID_CRC;
}

static esp_err_t write_record(nvs_handle_t handle, const char *key, const cfg_record_t *record)
{
    uint8_t bytes[MAX_RECORD_LEN];
    size_t length = encode(bytes, record);
    esp_err_t err = nvs_set_blob(handle, key, bytes, length);
#if LAB_CFG_FAULT_SHADOW_RESET
    if (err == ESP_OK && record->schema == 2) {
        ESP_LOGW(TAG, "FAULT_RESET point=after_schema2_set_blob_before_nvs_commit method=software_reset source_schema1_preserved=true");
        /* This identifies the API call window. It does not claim that set_blob
         * buffers every physical write until commit, or emulate a power cut. */
        vTaskDelay(pdMS_TO_TICKS(150));
        esp_restart();
    }
#endif
    if (err == ESP_OK) err = nvs_commit(handle);
    cfg_record_t readback;
    if (err == ESP_OK) err = read_record(handle, key, record->schema, &readback);
    if (err == ESP_OK && (readback.schema != record->schema || readback.generation != record->generation ||
                         readback.sample_ms != record->sample_ms || readback.threshold != record->threshold ||
                         readback.offset != record->offset || readback.source_generation != record->source_generation ||
                         readback.source_crc != record->source_crc)) {
        err = ESP_ERR_INVALID_RESPONSE;
    }
    return err;
}

static bool service(const char *reason, esp_err_t error)
{
    s_ready = false;
    ESP_LOGE(TAG, "SERVICE reason=%s error=%s no_erase=true outputs_gated=true", reason, esp_err_to_name(error));
    return false;
}

bool cfg_store_prepare(void)
{
    s_ready = false;
    nvs_handle_t handle;
    esp_err_t err = nvs_open_from_partition("nvs_cfg", "cfg", NVS_READWRITE, &handle);
    if (err != ESP_OK) return service("open", err);
    s_active = 1;
    esp_err_t pointer_err = nvs_get_u32(handle, "active_schema", &s_active);
    if (pointer_err != ESP_OK && pointer_err != ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(handle);
        return service("pointer_type", pointer_err);
    }
    if (s_active != 1 && s_active != 2) {
        nvs_close(handle);
        return service("unsupported_active_schema", ESP_ERR_NOT_SUPPORTED);
    }
    err = read_record(handle, "schema1", 1, &s_source);
    if (err == ESP_ERR_NVS_NOT_FOUND && pointer_err == ESP_ERR_NVS_NOT_FOUND) {
        /* Only a demonstrably empty namespace is a fresh fixture. */
        size_t shadow_length = 0;
        esp_err_t shadow_err = nvs_get_blob(handle, "schema2", NULL, &shadow_length);
        if (shadow_err != ESP_ERR_NVS_NOT_FOUND) {
            nvs_close(handle);
            return service("source_missing_existing_shadow", shadow_err);
        }
        cfg_record_t fresh = { .schema = 1, .generation = 1, .sample_ms = 1000, .threshold = 30 };
        err = write_record(handle, "schema1", &fresh);
        if (err == ESP_OK) err = nvs_set_u32(handle, "active_schema", 1);
        if (err == ESP_OK) err = nvs_commit(handle);
        if (err == ESP_OK) err = read_record(handle, "schema1", 1, &s_source);
        ESP_LOGI(TAG, "FIXTURE schema1 sample_ms=1000 threshold_c=30 generation=1 result=%s", esp_err_to_name(err));
    }
    if (err != ESP_OK) {
        nvs_close(handle);
        return service("source_invalid", err);
    }
    if (LAB_CFG_SCHEMA == 1) {
        s_current = s_source;
        s_ready = true;
        ESP_LOGI(TAG, "READER_V1 active=%" PRIu32 " use=schema1 fallback_snapshot=%u source_preserved=true", s_active, s_active == 2);
    } else if (LAB_CFG_SCHEMA == 2) {
        cfg_record_t shadow;
        esp_err_t shadow_err = read_record(handle, "schema2", 2, &shadow);
        bool matches = shadow_err == ESP_OK && shadow.source_generation == s_source.generation &&
                       shadow.source_crc == s_source.crc && shadow.sample_ms == s_source.sample_ms &&
                       shadow.threshold == s_source.threshold * 1000 && shadow.offset == 0;
        if (s_active == 2 && !matches) {
            nvs_close(handle);
            return service("active_shadow_invalid", shadow_err == ESP_OK ? ESP_ERR_INVALID_RESPONSE : shadow_err);
        }
        if (shadow_err != ESP_OK && shadow_err != ESP_ERR_NVS_NOT_FOUND) {
            nvs_close(handle);
            return service("shadow_invalid_no_overwrite", shadow_err);
        }
        if (!matches) {
            if (s_source.generation == UINT32_MAX) {
                nvs_close(handle);
                return service("generation_overflow", ESP_ERR_INVALID_ARG);
            }
            shadow = (cfg_record_t){
                .schema = 2, .generation = s_source.generation + 1, .sample_ms = s_source.sample_ms,
                .threshold = s_source.threshold * 1000, .offset = 0,
                .source_generation = s_source.generation, .source_crc = s_source.crc,
            };
            err = write_record(handle, "schema2", &shadow);
            if (err == ESP_OK) err = read_record(handle, "schema2", 2, &shadow);
            ESP_LOGI(TAG, "SHADOW_COMMIT result=%s source_generation=%" PRIu32 " source_crc=%08" PRIx32
                     " target_generation=%" PRIu32 " source_preserved=true", esp_err_to_name(err),
                     s_source.generation, s_source.crc, shadow.generation);
            if (err != ESP_OK) {
                nvs_close(handle);
                return service("shadow_commit_readback", err);
            }
        } else {
            ESP_LOGI(TAG, "SHADOW_REUSE migration_id=%08lx source_generation=%" PRIu32 " conversion_repeated=false",
                     (unsigned long)MIGRATION_ID, s_source.generation);
        }
        s_current = shadow;
        s_ready = true;
    } else {
        nvs_close(handle);
        return service("unsupported_reader_schema", ESP_ERR_NOT_SUPPORTED);
    }
    nvs_close(handle);
    cfg_store_status();
    return s_ready;
}

bool cfg_store_confirmed(void)
{
    if (!s_ready) return false;
    if (LAB_CFG_SCHEMA == 1) return true;
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
    esp_err_t err = esp_ota_get_state_partition(running, &state);
    if (err != ESP_OK || state != ESP_OTA_IMG_VALID) {
        ESP_LOGW(TAG, "ACTIVATE_DEFER SDK_state=%d required=VALID", state);
        return false;
    }
    nvs_handle_t handle;
    err = nvs_open_from_partition("nvs_cfg", "cfg", NVS_READWRITE, &handle);
    if (err != ESP_OK) return service("activate_open", err);
    cfg_record_t checked;
    err = read_record(handle, "schema2", 2, &checked);
    if (err == ESP_OK && (checked.source_generation != s_source.generation || checked.source_crc != s_source.crc)) {
        err = ESP_ERR_INVALID_RESPONSE;
    }
    if (err == ESP_OK) err = nvs_set_u32(handle, "active_schema", 2);
    if (err == ESP_OK) err = nvs_commit(handle);
    uint32_t readback = 0;
    if (err == ESP_OK) err = nvs_get_u32(handle, "active_schema", &readback);
    if (err == ESP_OK && readback != 2) err = ESP_ERR_INVALID_RESPONSE;
    nvs_close(handle);
    if (err != ESP_OK) return service("active_pointer_commit", err);
    s_active = 2;
    ESP_LOGI(TAG, "RECONCILE SDK_state=VALID active_schema=2 source_schema1_retained=true conversion_repeated=false");
    return true;
}

void cfg_store_status(void)
{
    ESP_LOGI(TAG, "CONFIG ready=%u reader_schema=%u active_schema=%" PRIu32 " used_schema=%u generation=%" PRIu32
             " sample_ms=%" PRIu32 " threshold=%" PRId32 " units=%s sensor_offset_mc=%" PRId32
             " source_generation=%" PRIu32 " source_crc=%08" PRIx32,
             s_ready, LAB_CFG_SCHEMA, s_active, s_current.schema, s_current.generation, s_current.sample_ms,
             s_current.threshold, s_current.schema == 1 ? "degree_C" : "milli_degree_C", s_current.offset,
             s_source.generation, s_source.crc);
}

bool cfg_store_take_reset_after_valid(void)
{
    nvs_handle_t handle;
    if (nvs_open_from_partition("nvs_cfg", "cfg", NVS_READWRITE, &handle) != ESP_OK) return false;
    uint8_t armed = 0;
    esp_err_t err = nvs_get_u8(handle, "reset_valid", &armed);
    if (err == ESP_OK && armed == 1) {
        err = nvs_set_u8(handle, "reset_valid", 0);
        if (err == ESP_OK) err = nvs_commit(handle);
    }
    nvs_close(handle);
    return err == ESP_OK && armed == 1;
}

static void parser_tests(void)
{
    uint8_t bytes[MAX_RECORD_LEN];
    cfg_record_t source = { .schema = 1, .generation = 1, .sample_ms = 1000, .threshold = 30 };
    cfg_record_t parsed;
    size_t length = encode(bytes, &source);
    bool valid = decode(bytes, length, 1, &parsed);
    bool short_rejected = !decode(bytes, length - 1, 1, &parsed);
    bytes[20] ^= 1;
    bool crc_rejected = !decode(bytes, length, 1, &parsed);
    length = encode(bytes, &source);
    put32(bytes + 16, 60001);
    put32(bytes + length - 4, crc32(bytes, length - 4));
    bool range_rejected = !decode(bytes, length, 1, &parsed);
    bool schema_rejected = !decode(bytes, length, 3, &parsed);
    ESP_LOGI(TAG, "PARSER_TESTS valid=%u short_rejected=%u crc_rejected=%u range_rejected=%u schema3_rejected=%u result=%s NVS_mutated=false",
             valid, short_rejected, crc_rejected, range_rejected, schema_rejected,
             valid && short_rejected && crc_rejected && range_rejected && schema_rejected ? "PASS" : "FAIL");
}

bool cfg_store_command(const char *line)
{
    if (strcmp(line, "cfg show") == 0) cfg_store_status();
    else if (strcmp(line, "cfg parser-tests") == 0) parser_tests();
    else if (strcmp(line, "cfg arm-valid-reset") == 0) {
        nvs_handle_t handle;
        esp_err_t err = nvs_open_from_partition("nvs_cfg", "cfg", NVS_READWRITE, &handle);
        if (err == ESP_OK) {
            err = nvs_set_u8(handle, "reset_valid", 1);
            if (err == ESP_OK) err = nvs_commit(handle);
            nvs_close(handle);
        }
        ESP_LOGI(TAG, "ARM_VALID_RESET result=%s next_trial_resets_after_SDK_VALID_before_pointer_commit=true", esp_err_to_name(err));
    } else return false;
    return true;
}
