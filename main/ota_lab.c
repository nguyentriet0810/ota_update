/* ESP32-S3 OTA study lab: custom controller states are distinct from otadata.
 * No code in this module writes eFuses, the bootloader, or the partition table.
 * Every Flash writer is owned by the single worker. Secrets never enter logs.
 */
#include "ota_lab.h"

#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <sys/time.h>

#include "cJSON.h"
#include "esp_app_desc.h"
#include "esp_crt_bundle.h"
#include "esp_event.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_random.h"
#include "esp_rom_crc.h"
#include "esp_sntp.h"
#include "esp_system.h"
#include "esp_tls_errors.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "nvs.h"
#include "psa/crypto.h"

#ifndef LAB_VERSION_CODE
#define LAB_VERSION_CODE 1
#endif
#ifndef LAB_CFG_SCHEMA
#define LAB_CFG_SCHEMA 1
#endif
#ifndef LAB_FAULT_PROFILE
#define LAB_FAULT_PROFILE 0
#endif

#define URL_CAP 513U
#define REDIRECT_CAP 2049U
#define MANIFEST_CAP 4096U
#define SIGNATURE_LEN 384U
#define SLOT_CAP 0x300000U
#define CHECKPOINT_STEP 0x10000U
#define RECORD_MAGIC 0x43504f54U
#define RECORD_FORMAT 1U
/* Policy 2 checkpoints were created only after a full inactive-slot erase.
 * Policy 1 snapshots cannot prove the signature tail was cleared, so they are
 * deliberately invalidated and restarted from zero after this updater fix.
 */
#define RECORD_POLICY 2U
#define NET_UP BIT0
#define HTTP_TIMEOUT_MS 12000
#define HTTP_ATTEMPTS 3U
#define MAX_RETRY_DELAY_MS 60000U
#define SESSION_DEADLINE_US (INT64_C(600) * 1000000)
#define PRODUCT "esp32s3-ota-lab"
#define BOARD "esp32s3-n16r8-lab"
#define LAYOUT "s3-16m-2x3m-v1"

static const char *TAG = "OTA";
extern const uint8_t manifest_key_start[] asm("_binary_manifest_public_der_start");
extern const uint8_t manifest_key_end[] asm("_binary_manifest_public_der_end");
#if LAB_FAULT_PROFILE
/* Optional public test CA. It is not embedded or trusted in production builds. */
extern const uint8_t lab_ca_start[] asm("_binary_lab_test_ca_pem_start");
extern const uint8_t lab_ca_end[] asm("_binary_lab_test_ca_pem_end");
#endif

typedef struct {
    uint32_t schema_version, version_code, secure_version, config_schema;
    uint32_t min_updater_version, size;
    char version[32], release[64], url[URL_CAP];
    uint8_t digest[32], release_id[32], origin_digest[32];
} manifest_t;

/* A single NVS blob is the commit unit. All padding is initialized to zero;
 * format/length/CRC are checked before any field can influence Flash erase.
 */
typedef struct {
    uint32_t magic, format, length, generation, policy;
    uint32_t target_addr, target_size, running_addr, image_size, q, phase;
    uint8_t release_id[32], file_digest[32], origin_digest[32];
    char target_label[17], layout[32];
    uint32_t crc;
} checkpoint_t;

typedef struct {
    uint32_t magic, format, length, target_addr, image_size;
    uint32_t version_code, config_schema, confirmed, quarantined, boot_selected;
    uint8_t release_id[32], file_digest[32];
    char version[32];
    uint32_t crc;
} identity_t;

typedef struct {
    int http_status;
    uint32_t retry_after_ms;
    bool retryable, server_delay_blocked;
} retry_hint_t;

typedef struct {
    esp_http_client_handle_t client;
    char location[REDIRECT_CAP], content_range[96], encoding[32], content_type[80], retry_after[80];
    unsigned location_count, range_count, encoding_count, length_count, type_count, retry_after_count;
    bool invalid_headers;
    int status;
    int64_t content_length;
} http_t;

typedef struct {
    char manifest_url[URL_CAP], signature_url[URL_CAP];
#if LAB_FAULT_PROFILE
    bool one_call;
#endif
} request_t;

static nvs_handle_t s_meta;
static EventGroupHandle_t s_network;
static psa_key_id_t s_manifest_key;
static bool s_ready, s_wifi_started, s_sntp_started;
static atomic_uint s_wifi_retries;
static atomic_bool s_wifi_reconnect_suppressed;
static atomic_bool s_busy, s_cancel;
/* 0 accepts cancellation, -1 cancelled, 1 activation commit has started. */
static atomic_int s_activation_gate;
static atomic_uint s_written, s_total, s_durable_q, s_reset_at, s_wifi_drop_at;
#if LAB_FAULT_PROFILE
static atomic_bool s_lab_clock_not_ready;
static atomic_bool s_lab_radio_off;
static atomic_uint s_lab_reset_before_checkpoint;
#endif
static portMUX_TYPE s_status_lock = portMUX_INITIALIZER_UNLOCKED;
static char s_phase[32] = "NOT_INITIALIZED";
static char s_reason[64] = "";
static uint32_t s_generation;
static esp_err_t partition_hash(const esp_partition_t *part, uint32_t length, uint8_t out[32]);
static esp_err_t network_ready(int64_t started);

static void status_set(const char *phase, const char *reason)
{
    taskENTER_CRITICAL(&s_status_lock);
    snprintf(s_phase, sizeof(s_phase), "%s", phase);
    snprintf(s_reason, sizeof(s_reason), "%s", reason ? reason : "");
    taskEXIT_CRITICAL(&s_status_lock);
    ESP_LOGI(TAG, "phase=%s reason=%s", phase, reason ? reason : "none");
}

static bool cancelled_or_expired(int64_t started)
{
    return atomic_load(&s_cancel) || atomic_load(&s_activation_gate) < 0 ||
        esp_timer_get_time() - started > SESSION_DEADLINE_US;
}

static bool http_status_retryable(int status)
{
    return status == 429 || status == 500 || status == 502 || status == 503 || status == 504;
}

/* Only delta-seconds Retry-After is supported. Unsupported HTTP-date or a
 * delay exceeding the local 60s wait budget defers this session; it must never
 * be truncated and retried before the server's requested deadline.
 */
static bool parse_retry_after(const char *value, uint32_t *delay_ms)
{
    const unsigned char *p = (const unsigned char *)value;
    while (*p == ' ' || *p == '\t') { ++p; }
    if (*p < '0' || *p > '9') { return false; }
    uint32_t seconds = 0;
    while (*p >= '0' && *p <= '9') {
        if (seconds <= MAX_RETRY_DELAY_MS / 1000U) { seconds = seconds * 10U + (*p - '0'); }
        ++p;
    }
    while (*p == ' ' || *p == '\t') { ++p; }
    if (*p || seconds > MAX_RETRY_DELAY_MS / 1000U) { return false; }
    *delay_ms = seconds * 1000U; return true;
}

static int request_timeout_ms(int64_t started)
{
    int64_t remaining = (SESSION_DEADLINE_US - (esp_timer_get_time() - started)) / 1000;
    if (remaining <= 0 || cancelled_or_expired(started)) { return 0; }
    return remaining < HTTP_TIMEOUT_MS ? (int)remaining : HTTP_TIMEOUT_MS;
}

static bool retry_wait(const char *phase, unsigned attempt, esp_err_t error,
                       const retry_hint_t *hint, int64_t started)
{
    ESP_LOGW(TAG, "http_attempt phase=%s attempt=%u budget=%u status=%d error=%s retryable=%u",
        phase, attempt, HTTP_ATTEMPTS, hint->http_status, esp_err_to_name(error), hint->retryable);
    if (!hint->retryable || cancelled_or_expired(started)) { return false; }
    if (hint->server_delay_blocked) {
        ESP_LOGW(TAG, "retry_deferred phase=%s reason=Retry-After_unsupported_or_exceeds_local_budget", phase);
        return false;
    }
    if (attempt >= HTTP_ATTEMPTS) {
        ESP_LOGW(TAG, "retry_budget_exhausted phase=%s attempts=%u", phase, attempt); return false;
    }
    uint32_t delay = (1000U << (attempt - 1U)) + esp_random() % 1001U;
    if (delay < hint->retry_after_ms) { delay = hint->retry_after_ms; }
    if (delay > MAX_RETRY_DELAY_MS) { delay = MAX_RETRY_DELAY_MS; }
    int64_t remaining_ms = (SESSION_DEADLINE_US - (esp_timer_get_time() - started)) / 1000;
    if (remaining_ms < delay) {
        ESP_LOGW(TAG, "retry_deferred phase=%s reason=session_deadline_before_server_or_local_delay", phase);
        return false;
    }
    ESP_LOGW(TAG, "retry_backoff phase=%s failed_attempt=%u next_attempt=%u delay_ms=%" PRIu32
        " status=%d retry_after_ms=%" PRIu32, phase, attempt, attempt + 1U, delay, hint->http_status, hint->retry_after_ms);
    int64_t waited_from = esp_timer_get_time();
    int64_t until = waited_from + (int64_t)delay * 1000;
    while (esp_timer_get_time() < until) {
        if (cancelled_or_expired(started)) {
            ESP_LOGW(TAG, "retry_backoff_cancelled phase=%s waited_ms=%" PRId64,
                phase, (esp_timer_get_time() - waited_from) / 1000); return false;
        }
        int64_t left_ms = (until - esp_timer_get_time() + 999) / 1000;
        uint32_t slice = left_ms > 100 ? 100U : (uint32_t)left_ms;
        if (slice) { vTaskDelay(pdMS_TO_TICKS(slice) ? pdMS_TO_TICKS(slice) : 1); }
    }
    ESP_LOGI(TAG, "retry_backoff_complete phase=%s waited_ms=%" PRId64 " requested_ms=%" PRIu32,
        phase, (esp_timer_get_time() - waited_from) / 1000, delay);
    return !cancelled_or_expired(started);
}

static esp_err_t hash_bytes(const void *data, size_t length, uint8_t out[32])
{
    size_t actual = 0;
    return psa_hash_compute(PSA_ALG_SHA_256, data, length, out, 32, &actual) == PSA_SUCCESS &&
        actual == 32 ? ESP_OK : ESP_FAIL;
}

static uint32_t blob_crc(const void *record, size_t length)
{
    return esp_rom_crc32_le(0, (const uint8_t *)record, (uint32_t)length);
}

static bool same_bytes(const uint8_t *a, const uint8_t *b, size_t length)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < length; ++i) { diff |= a[i] ^ b[i]; }
    return diff == 0;
}

#if LAB_FAULT_PROFILE
static bool is_lab_url(const char *url)
{
    if (strncmp(url, "https://", 8)) { return false; }
    const char *authority = url + 8, *slash = strchr(authority, '/');
    if (!slash) { return false; }
    static const char *const authorities[] = {
        "192.168.137.1:8443", "192.168.137.1:8444", "192.168.137.1:8445",
        "unresolvable.invalid", "unresolvable.invalid:8443"
    };
    size_t length = (size_t)(slash - authority);
    for (unsigned i = 0; i < sizeof(authorities)/sizeof(authorities[0]); ++i) {
        if (strlen(authorities[i]) == length && !memcmp(authority, authorities[i], length)) { return true; }
    }
    return false;
}
#endif

static void hex_digest(const uint8_t digest[32], char text[65])
{
    static const char digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < 32; ++i) { text[2*i] = digits[digest[i] >> 4]; text[2*i+1] = digits[digest[i] & 15]; }
    text[64] = 0;
}

static bool valid_url(const char *url, bool origin)
{
    if (strncmp(url, "https://", 8) != 0) { return false; }
    const char *host = url + 8, *slash = strchr(host, '/');
    if (!slash || slash == host || strlen(url) >= (origin ? URL_CAP : REDIRECT_CAP)) { return false; }
    size_t host_len = (size_t)(slash - host);
    const char *allowed[] = { "github.com", "release-assets.githubusercontent.com",
        "objects.githubusercontent.com", "github-releases.githubusercontent.com" };
    bool match = false;
    for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); ++i) {
        if (strlen(allowed[i]) == host_len && strncmp(host, allowed[i], host_len) == 0) {
            match = true;
            if (origin && i != 0) { return false; }
            break;
        }
    }
#if LAB_FAULT_PROFILE
    if (!match && is_lab_url(url)) { match = true; }
#endif
    if (!match || strchr(url, '#') || (origin && (strchr(url, '?') || !strstr(slash, "/releases/download/")))) {
        return false;
    }
    /* No whitespace, control bytes, backslashes, userinfo, ports or credentials. */
    for (const unsigned char *p = (const unsigned char *)url; *p; ++p) {
        if (*p <= 32 || *p >= 127 || *p == '\\') { return false; }
    }
    return true;
}

static esp_err_t http_event(esp_http_client_event_t *event)
{
    if (event->event_id != HTTP_EVENT_ON_HEADER) { return ESP_OK; }
    http_t *h = event->user_data;
    const char *k = event->header_key, *v = event->header_value;
    if (!k || !v || !h) { return ESP_FAIL; }
    char *dest = NULL; size_t cap = 0; unsigned *count = NULL;
    if (!strcasecmp(k, "Location")) { dest = h->location; cap = sizeof(h->location); count = &h->location_count; }
    else if (!strcasecmp(k, "Content-Range")) { dest = h->content_range; cap = sizeof(h->content_range); count = &h->range_count; }
    else if (!strcasecmp(k, "Content-Encoding")) { dest = h->encoding; cap = sizeof(h->encoding); count = &h->encoding_count; }
    else if (!strcasecmp(k, "Content-Type")) { dest = h->content_type; cap = sizeof(h->content_type); count = &h->type_count; }
    else if (!strcasecmp(k, "Retry-After")) { dest = h->retry_after; cap = sizeof(h->retry_after); count = &h->retry_after_count; }
    else if (!strcasecmp(k, "Content-Length")) { if (++h->length_count > 1) { h->invalid_headers = true; } }
    if (dest) {
        if (++*count > 1 || strlen(v) >= cap) { h->invalid_headers = true; }
        else { memcpy(dest, v, strlen(v) + 1); }
    }
    return ESP_OK;
}

static void http_close(http_t *h)
{
    if (h->client) {
        (void)esp_http_client_close(h->client);
        (void)esp_http_client_cleanup(h->client);
        h->client = NULL;
    }
}

/* Redirects are opened individually: HTTPS, certificate chain and hostname are
 * checked afresh at every hop. Expiring CDN URL strings are never persisted.
 */
static esp_err_t http_open(http_t *h, const char *origin, uint32_t offset,
                           int64_t started, retry_hint_t *hint)
{
    memset(hint, 0, sizeof(*hint));
    if (!valid_url(origin, true)) { return ESP_ERR_INVALID_ARG; }
    char current[REDIRECT_CAP];
    snprintf(current, sizeof(current), "%s", origin);
    for (unsigned hop = 0; hop <= 5; ++hop) {
        int timeout_ms = request_timeout_ms(started);
        if (!timeout_ms) { return ESP_ERR_TIMEOUT; }
        hint->http_status = 0;
        memset(h, 0, sizeof(*h));
        esp_http_client_config_t config = {
            .url = current, .crt_bundle_attach = esp_crt_bundle_attach,
            .timeout_ms = timeout_ms, .disable_auto_redirect = true,
            .max_authorization_retries = -1, .event_handler = http_event,
            .user_data = h, .buffer_size = 4096, .buffer_size_tx = 2048,
            .keep_alive_enable = false,
        };
#if LAB_FAULT_PROFILE
        if (is_lab_url(current)) {
            config.crt_bundle_attach = NULL;
            config.cert_pem = (const char *)lab_ca_start;
            config.cert_len = (size_t)(lab_ca_end - lab_ca_start);
            /* Do not set skip_cert_common_name_check or override common_name.
             * CA, SAN hostname/IP and certificate time checks remain enabled.
             */
        }
#endif
        h->client = esp_http_client_init(&config);
        if (!h->client) { return ESP_ERR_NO_MEM; }
        esp_http_client_set_header(h->client, "Accept-Encoding", "identity");
        esp_http_client_set_header(h->client, "User-Agent", "ESP32S3-OTA-Study/1");
        if (offset) {
            char range[48]; snprintf(range, sizeof(range), "bytes=%" PRIu32 "-", offset);
            esp_http_client_set_header(h->client, "Range", range);
        }
        esp_err_t err = esp_http_client_open(h->client, 0);
        if (err != ESP_OK) {
            int tls_error = 0, verify_flags = 0;
            esp_err_t tls = esp_http_client_get_and_clear_last_tls_error(h->client, &tls_error, &verify_flags);
            bool tls_permanent = verify_flags != 0 || tls == ESP_ERR_MBEDTLS_X509_CRT_PARSE_FAILED ||
                tls == ESP_ERR_MBEDTLS_SSL_SET_HOSTNAME_FAILED || tls == ESP_ERR_MBEDTLS_SSL_HANDSHAKE_FAILED;
            hint->retryable = !tls_permanent && (err == ESP_ERR_HTTP_CONNECT || err == ESP_ERR_TIMEOUT ||
                err == ESP_FAIL || tls == ESP_ERR_ESP_TLS_CANNOT_RESOLVE_HOSTNAME ||
                tls == ESP_ERR_ESP_TLS_FAILED_CONNECT_TO_HOST || tls == ESP_ERR_ESP_TLS_CONNECTION_TIMEOUT ||
                tls == ESP_ERR_ESP_TLS_SERVER_HANDSHAKE_TIMEOUT);
            ESP_LOGW(TAG, "https_open_failed error=%s tls=0x%x tls_error=%d verify_flags=0x%x retryable=%u",
                esp_err_to_name(err), (unsigned)tls, tls_error, verify_flags, hint->retryable);
            http_close(h); return err;
        }
        timeout_ms = request_timeout_ms(started);
        if (!timeout_ms) { http_close(h); return ESP_ERR_TIMEOUT; }
        (void)esp_http_client_set_timeout_ms(h->client, timeout_ms);
        h->content_length = esp_http_client_fetch_headers(h->client);
        h->status = esp_http_client_get_status_code(h->client);
        hint->http_status = h->status;
        if (h->invalid_headers) { http_close(h); return ESP_ERR_INVALID_RESPONSE; }
        if (h->content_length < 0) { hint->retryable = true; http_close(h); return ESP_ERR_HTTP_FETCH_HEADER; }
        if (http_status_retryable(h->status)) {
            hint->retryable = true;
            if (h->retry_after_count && !parse_retry_after(h->retry_after, &hint->retry_after_ms)) {
                hint->server_delay_blocked = true;
            }
            ESP_LOGW(TAG, "http_response_transient status=%d retry_after_ms=%" PRIu32 " blocked=%u",
                h->status, hint->retry_after_ms, hint->server_delay_blocked);
            http_close(h); return ESP_ERR_HTTP_EAGAIN;
        }
        if (h->status == 301 || h->status == 302 || h->status == 303 || h->status == 307 || h->status == 308) {
            if (hop == 5 || h->location_count != 1 || !valid_url(h->location, false)) {
                http_close(h); return ESP_ERR_INVALID_RESPONSE;
            }
            snprintf(current, sizeof(current), "%s", h->location);
            http_close(h);
            continue;
        }
        if (esp_http_client_is_chunked_response(h->client) || h->length_count != 1 ||
            (h->encoding_count && strcasecmp(h->encoding, "identity"))) {
            http_close(h); return ESP_ERR_INVALID_RESPONSE;
        }
        return ESP_OK;
    }
    return ESP_FAIL;
}

static esp_err_t fetch_small(const char *url, uint8_t *out, size_t cap, size_t *length,
                             int64_t started, retry_hint_t *hint)
{
    http_t h;
    esp_err_t err = http_open(&h, url, 0, started, hint);
    if (err != ESP_OK) { return err; }
    if (h.status != 200 || h.content_length <= 0 || h.content_length > (int64_t)cap ||
        (h.type_count && !strncasecmp(h.content_type, "text/html", 9))) {
        http_close(&h); return ESP_ERR_INVALID_RESPONSE;
    }
    size_t used = 0, expected = (size_t)h.content_length;
    while (used < expected) {
        int timeout_ms = request_timeout_ms(started);
        if (!timeout_ms) { http_close(&h); return ESP_ERR_TIMEOUT; }
        (void)esp_http_client_set_timeout_ms(h.client, timeout_ms);
        int n = esp_http_client_read(h.client, (char *)out + used, (int)(expected - used));
        if (n <= 0) { hint->retryable = true; http_close(&h); return ESP_ERR_HTTP_CONNECTION_CLOSED; }
        used += (size_t)n;
    }
    bool complete = used == expected && esp_http_client_is_complete_data_received(h.client);
    http_close(&h);
    if (!complete) { hint->retryable = true; return ESP_ERR_HTTP_CONNECTION_CLOSED; }
    *length = used;
    return ESP_OK;
}

static bool utf8_valid(const uint8_t *s, size_t n)
{
    size_t i = 0;
    while (i < n) {
        uint32_t c = s[i++], min = 0; unsigned more = 0;
        if (c == 0) { return false; }
        if (c < 0x80) { continue; }
        if (c >= 0xc2 && c <= 0xdf) { c &= 0x1f; more = 1; min = 0x80; }
        else if (c >= 0xe0 && c <= 0xef) { c &= 0xf; more = 2; min = 0x800; }
        else if (c >= 0xf0 && c <= 0xf4) { c &= 7; more = 3; min = 0x10000; }
        else { return false; }
        if (n - i < more) { return false; }
        while (more--) { if ((s[i] & 0xc0) != 0x80) { return false; } c = (c << 6) | (s[i++] & 0x3f); }
        if (c < min || c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff)) { return false; }
    }
    return true;
}

static bool json_u32(const cJSON *root, const char *name, uint32_t min, uint32_t max, uint32_t *out)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(root, name);
    if (!cJSON_IsNumber(v) || v->valuedouble < min || !(v->valuedouble <= max)) { return false; }
    uint32_t number = (uint32_t)v->valuedouble;
    if ((double)number != v->valuedouble) { return false; }
    *out = number; return true;
}

static const char *json_string(const cJSON *root, const char *name, size_t max)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(root, name);
    if (!cJSON_IsString(v) || !v->valuestring || !v->valuestring[0] || strlen(v->valuestring) > max) { return NULL; }
    return v->valuestring;
}

static bool json_equal(const cJSON *root, const char *name, const char *expected)
{
    const char *value = json_string(root, name, strlen(expected));
    return value && !strcmp(value, expected);
}

static esp_err_t parse_manifest(uint8_t *raw, size_t length, manifest_t *m)
{
    const char *fields[] = { "schema_version", "product", "board", "chip", "layout_id", "release", "version",
        "version_code", "secure_version", "config_schema", "min_updater_version", "manifest_key_id", "size", "sha256", "url" };
    if (!utf8_valid(raw, length)) { return ESP_ERR_INVALID_ARG; }
    /* cJSON stores strings as NUL-terminated C strings. Explicitly reject the
     * JSON escape for NUL, so a signed string cannot be compared by its prefix.
     */
    for (size_t i = 0; i + 5 < length; ++i) {
        if (raw[i] == '\\' && raw[i+1] == 'u' && !memcmp(raw+i+2, "0000", 4)) { return ESP_ERR_INVALID_ARG; }
    }
    raw[length] = 0;
    const char *end = NULL;
    cJSON *root = cJSON_ParseWithLengthOpts((const char *)raw, length + 1, &end, true);
    if (!root || !cJSON_IsObject(root)) { cJSON_Delete(root); return ESP_ERR_INVALID_ARG; }
    unsigned seen = 0;
    for (const cJSON *item = root->child; item; item = item->next) {
        unsigned i = 0;
        for (; i < sizeof(fields)/sizeof(fields[0]); ++i) {
            if (item->string && !strcmp(item->string, fields[i])) { break; }
        }
        if (i == sizeof(fields)/sizeof(fields[0]) || (seen & (1U << i))) { cJSON_Delete(root); return ESP_ERR_INVALID_ARG; }
        seen |= 1U << i;
    }
    const char *version = json_string(root, "version", 31), *release = json_string(root, "release", 63);
    const char *url = json_string(root, "url", 512), *hex = json_string(root, "sha256", 64);
    bool ok = seen == ((1U << 15)-1) &&
        json_u32(root, "schema_version", 1, 1, &m->schema_version) &&
        json_equal(root, "product", PRODUCT) && json_equal(root, "board", BOARD) &&
        json_equal(root, "chip", "esp32s3") && json_equal(root, "layout_id", LAYOUT) &&
        json_equal(root, "manifest_key_id", "manifest-1") &&
        json_u32(root, "version_code", 1, INT32_MAX, &m->version_code) &&
        json_u32(root, "secure_version", 0, 0, &m->secure_version) &&
        json_u32(root, "config_schema", 1, 2, &m->config_schema) &&
        json_u32(root, "min_updater_version", 1, 1, &m->min_updater_version) &&
        json_u32(root, "size", 1, SLOT_CAP, &m->size) && version && release && url && hex &&
        strlen(hex) == 64 && valid_url(url, true);
    if (ok) {
        for (unsigned i = 0; i < 64; ++i) {
            unsigned char c = (unsigned char)hex[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) { ok = false; break; }
            uint8_t nibble = c <= '9' ? c-'0' : c-'a'+10;
            if (!(i & 1)) { m->digest[i/2] = (uint8_t)(nibble << 4); }
            else { m->digest[i/2] |= nibble; }
        }
    }
    if (ok) {
        snprintf(m->version, sizeof(m->version), "%s", version);
        snprintf(m->release, sizeof(m->release), "%s", release);
        snprintf(m->url, sizeof(m->url), "%s", url);
        ok = hash_bytes(raw, length, m->release_id) == ESP_OK &&
            hash_bytes(url, strlen(url), m->origin_digest) == ESP_OK;
    }
    cJSON_Delete(root);
    return ok ? ESP_OK : ESP_ERR_INVALID_ARG;
}

static bool cp_valid(const checkpoint_t *cp)
{
    return cp->magic == RECORD_MAGIC && cp->format == RECORD_FORMAT && cp->length == sizeof(*cp) &&
        cp->policy == RECORD_POLICY && cp->crc == blob_crc(cp, offsetof(checkpoint_t, crc)) &&
        cp->target_label[sizeof(cp->target_label)-1] == 0 && cp->layout[sizeof(cp->layout)-1] == 0 &&
        !strcmp(cp->layout, LAYOUT) && cp->phase == 1 && cp->q > 0 && cp->q < cp->image_size &&
        !(cp->q % CHECKPOINT_STEP) && cp->image_size <= SLOT_CAP && cp->target_size == SLOT_CAP;
}

static bool cp_load(checkpoint_t *result)
{
    checkpoint_t candidates[2]; bool valid[2] = { false, false };
    const char *keys[] = { "cp0", "cp1" };
    for (unsigned i = 0; i < 2; ++i) {
        size_t size = sizeof(candidates[i]);
        esp_err_t err = nvs_get_blob(s_meta, keys[i], &candidates[i], &size);
        valid[i] = err == ESP_OK && size == sizeof(candidates[i]) && cp_valid(&candidates[i]);
        if (err != ESP_ERR_NVS_NOT_FOUND && !valid[i]) { ESP_LOGW(TAG, "checkpoint_%u invalid/unreadable; never guess Q", i); }
    }
    if (!valid[0] && !valid[1]) { return false; }
    unsigned index = valid[1] && (!valid[0] || (int32_t)(candidates[1].generation - candidates[0].generation) > 0) ? 1 : 0;
    *result = candidates[index]; s_generation = result->generation; return true;
}

static esp_err_t cp_clear(void)
{
    esp_err_t a = nvs_erase_key(s_meta, "cp0"), b = nvs_erase_key(s_meta, "cp1");
    if ((a != ESP_OK && a != ESP_ERR_NVS_NOT_FOUND) || (b != ESP_OK && b != ESP_ERR_NVS_NOT_FOUND)) { return ESP_FAIL; }
    esp_err_t err = nvs_commit(s_meta);
    if (err == ESP_OK) { atomic_store(&s_durable_q, 0); }
    return err;
}

static esp_err_t cp_save(const manifest_t *m, const esp_partition_t *target, uint32_t running, uint32_t q)
{
    checkpoint_t cp = {0}, readback;
    cp.magic = RECORD_MAGIC; cp.format = RECORD_FORMAT; cp.length = sizeof(cp);
    cp.generation = s_generation + 1; cp.policy = RECORD_POLICY;
    cp.target_addr = target->address; cp.target_size = target->size; cp.running_addr = running;
    cp.image_size = m->size; cp.q = q; cp.phase = 1;
    memcpy(cp.release_id, m->release_id, 32); memcpy(cp.file_digest, m->digest, 32); memcpy(cp.origin_digest, m->origin_digest, 32);
    snprintf(cp.target_label, sizeof(cp.target_label), "%s", target->label);
    snprintf(cp.layout, sizeof(cp.layout), "%s", LAYOUT);
    cp.crc = blob_crc(&cp, offsetof(checkpoint_t, crc));
    const char *key = cp.generation & 1 ? "cp1" : "cp0";
    esp_err_t err = nvs_set_blob(s_meta, key, &cp, sizeof(cp));
    if (err == ESP_OK) { err = nvs_commit(s_meta); }
    size_t n = sizeof(readback);
    if (err == ESP_OK) { err = nvs_get_blob(s_meta, key, &readback, &n); }
    if (err != ESP_OK) { return err; }
    if (n != sizeof(readback) || !cp_valid(&readback) || memcmp(&readback, &cp, n)) { return ESP_ERR_INVALID_CRC; }
    s_generation = cp.generation; atomic_store(&s_durable_q, q);
    ESP_LOGI(TAG, "checkpoint_committed q=%" PRIu32 " generation=%" PRIu32, q, cp.generation);
    return ESP_OK;
}

static const char *identity_key(const esp_partition_t *partition)
{
    return partition->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_0 ? "slot0" : "slot1";
}

static bool identity_load(const char *key, identity_t *record)
{
    size_t n = sizeof(*record);
    return nvs_get_blob(s_meta, key, record, &n) == ESP_OK && n == sizeof(*record) &&
        record->magic == RECORD_MAGIC && record->format == RECORD_FORMAT && record->length == sizeof(*record) &&
        record->image_size > 0 && record->image_size <= SLOT_CAP &&
        record->version[sizeof(record->version)-1] == 0 && record->crc == blob_crc(record, offsetof(identity_t, crc));
}

static bool identity_matches_running(const identity_t *record, const esp_partition_t *running)
{
    uint8_t actual[32];
    const esp_app_desc_t *desc = esp_app_get_description();
    return running && record->target_addr == running->address && record->image_size > 0 &&
        record->image_size <= running->size && record->version_code == LAB_VERSION_CODE &&
        record->config_schema == LAB_CFG_SCHEMA && !strncmp(desc->version, record->version, sizeof(desc->version)) &&
        partition_hash(running, record->image_size, actual) == ESP_OK && same_bytes(actual, record->file_digest, 32);
}

static esp_err_t identity_save(const char *key, identity_t *record)
{
    record->crc = blob_crc(record, offsetof(identity_t, crc));
    esp_err_t err = nvs_set_blob(s_meta, key, record, sizeof(*record));
    if (err == ESP_OK) { err = nvs_commit(s_meta); }
    identity_t readback;
    if (err != ESP_OK || !identity_load(key, &readback) || memcmp(record, &readback, sizeof(*record))) { return ESP_FAIL; }
    return ESP_OK;
}

static esp_err_t save_candidate(const manifest_t *m, const esp_partition_t *target)
{
    identity_t record = {0};
    record.magic = RECORD_MAGIC; record.format = RECORD_FORMAT; record.length = sizeof(record);
    record.target_addr = target->address; record.image_size = m->size;
    record.version_code = m->version_code; record.config_schema = m->config_schema;
    memcpy(record.release_id, m->release_id, 32); memcpy(record.file_digest, m->digest, 32);
    snprintf(record.version, sizeof(record.version), "%s", m->version);
    return identity_save(identity_key(target), &record);
}

static esp_err_t reconcile_identities(void)
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (!running) { return ESP_FAIL; }
    for (unsigned i = 0; i < 2; ++i) {
        const esp_partition_t *part = esp_partition_find_first(ESP_PARTITION_TYPE_APP,
            ESP_PARTITION_SUBTYPE_APP_OTA_0 + i, NULL);
        identity_t record;
        if (!part || !identity_load(identity_key(part), &record) || record.target_addr != part->address) { continue; }
        esp_ota_img_states_t state;
        if (esp_ota_get_state_partition(part, &state) != ESP_OK) { continue; }
        if (part->address == running->address && state == ESP_OTA_IMG_VALID) {
            if (!identity_matches_running(&record, running)) { return ESP_ERR_INVALID_CRC; }
            if (!record.confirmed) {
                record.confirmed = 1;
                if (identity_save(identity_key(part), &record) != ESP_OK) { return ESP_FAIL; }
            }
            char release_id[65], file_digest[65];
            hex_digest(record.release_id, release_id); hex_digest(record.file_digest, file_digest);
            ESP_LOGI(TAG, "confirmed_identity slot=%s version=%s version_code=%" PRIu32,
                part->label, record.version, record.version_code);
            ESP_LOGI(TAG, "running_release_id=%s file_sha256=%s size=%" PRIu32, release_id, file_digest, record.image_size);
        } else if (part->address != running->address && !record.confirmed && record.boot_selected &&
            (state == ESP_OTA_IMG_INVALID || state == ESP_OTA_IMG_ABORTED) && !record.quarantined) {
            record.quarantined = 1;
            if (identity_save(identity_key(part), &record) != ESP_OK || identity_save("bad", &record) != ESP_OK) { return ESP_FAIL; }
            ESP_LOGW(TAG, "failed_trial_quarantined slot=%s state=%d version=%s", part->label, state, record.version);
        }
    }
    checkpoint_t cp;
    if (cp_load(&cp) && cp.target_addr == running->address) {
        ESP_LOGW(TAG, "discard_stale_checkpoint target_is_running");
        if (cp_clear() != ESP_OK) { return ESP_FAIL; }
    }
    return ESP_OK;
}

static esp_err_t manifest_policy(const manifest_t *m, const esp_partition_t **target_out)
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    const esp_partition_t *target = esp_ota_get_next_update_partition(NULL);
    esp_ota_img_states_t state;
    if (!running || !target || target->address == running->address || target->type != ESP_PARTITION_TYPE_APP ||
        (target->subtype != ESP_PARTITION_SUBTYPE_APP_OTA_0 && target->subtype != ESP_PARTITION_SUBTYPE_APP_OTA_1) ||
        target->size != SLOT_CAP || m->size > target->size ||
        esp_ota_get_state_partition(running, &state) != ESP_OK || state != ESP_OTA_IMG_VALID) {
        return ESP_ERR_INVALID_STATE;
    }
    identity_t bad;
    /* The code actually running owns its numeric policy version. Never let
     * stale custom NVS override compiled identity after a serial reflash.
     */
    if (m->version_code <= LAB_VERSION_CODE) { return ESP_ERR_INVALID_VERSION; }
    if (identity_load("bad", &bad) && (same_bytes(bad.release_id, m->release_id, 32) || same_bytes(bad.file_digest, m->digest, 32))) {
        return ESP_ERR_NOT_ALLOWED;
    }
    *target_out = target; return ESP_OK;
}

static esp_err_t record_boot_selected(const manifest_t *m, const esp_partition_t *target)
{
    identity_t record;
    if (!identity_load(identity_key(target), &record) || record.target_addr != target->address ||
        !same_bytes(record.release_id, m->release_id, 32)) { return ESP_ERR_INVALID_STATE; }
    record.boot_selected = 1;
    return identity_save(identity_key(target), &record);
}

static esp_err_t partition_hash(const esp_partition_t *part, uint32_t length, uint8_t out[32])
{
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    uint8_t buffer[4096]; size_t actual = 0;
    if (psa_hash_setup(&op, PSA_ALG_SHA_256) != PSA_SUCCESS) { return ESP_FAIL; }
    esp_err_t err = ESP_OK;
    for (uint32_t at = 0; at < length; ) {
        size_t n = length - at; if (n > sizeof(buffer)) { n = sizeof(buffer); }
        if (esp_partition_read(part, at, buffer, n) != ESP_OK || psa_hash_update(&op, buffer, n) != PSA_SUCCESS) { err = ESP_FAIL; break; }
        at += n;
    }
    if (err == ESP_OK && (psa_hash_finish(&op, out, 32, &actual) != PSA_SUCCESS || actual != 32)) { err = ESP_FAIL; }
    (void)psa_hash_abort(&op); return err;
}

static bool range_matches(const http_t *h, uint32_t q, uint32_t total)
{
    if (!q) { return h->status == 200 && h->range_count == 0 && h->content_length == total; }
    if (h->status != 206 || h->range_count != 1 || h->content_length != (int64_t)(total - q)) { return false; }
    char expected[96];
    snprintf(expected, sizeof(expected), "bytes %" PRIu32 "-%" PRIu32 "/%" PRIu32, q, total-1U, total);
    return !strcmp(h->content_range, expected);
}

static esp_err_t download(const manifest_t *m, const esp_partition_t *target, int64_t started, retry_hint_t *hint)
{
    memset(hint, 0, sizeof(*hint));
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (!running || running->address == target->address) { return ESP_ERR_INVALID_STATE; }
    checkpoint_t cp; uint32_t q = 0;
    if (cp_load(&cp)) {
        if (cp.target_addr == running->address) {
            ESP_LOGW(TAG, "checkpoint_rejected target_is_running=true before_erase=true");
            if (cp_clear() != ESP_OK) { return ESP_FAIL; }
        } else {
            bool match = cp.target_addr == target->address && cp.target_size == target->size &&
                cp.running_addr == running->address && cp.image_size == m->size && !strcmp(cp.target_label, target->label) &&
                same_bytes(cp.release_id, m->release_id, 32) && same_bytes(cp.file_digest, m->digest, 32) &&
                same_bytes(cp.origin_digest, m->origin_digest, 32);
            if (match) { q = cp.q; }
            else { ESP_LOGW(TAG, "checkpoint_identity_mismatch; fresh candidate only"); if (cp_clear() != ESP_OK) { return ESP_FAIL; } }
        }
    }
    atomic_store(&s_written, q); atomic_store(&s_durable_q, q); atomic_store(&s_total, m->size);
    http_t h;
    esp_err_t err = http_open(&h, m->url, q, started, hint);
    if (err != ESP_OK) { return err; }
    if (q && h.status == 200) {
        ESP_LOGW(TAG, "range_ignored; discard body and restart from zero");
        http_close(&h); if (cp_clear() != ESP_OK) { return ESP_FAIL; }
        q = 0; atomic_store(&s_written, 0);
        err = http_open(&h, m->url, 0, started, hint); if (err != ESP_OK) { return err; }
    }
    if (!range_matches(&h, q, m->size) ||
        (h.type_count && !strncasecmp(h.content_type, "text/html", 9))) {
        ESP_LOGE(TAG, "stream_header_reject status=%d offset=%" PRIu32, h.status, q);
        http_close(&h); return ESP_ERR_INVALID_RESPONSE;
    }
    /* Recheck just before the first mutation. Sequential resume erases/replays
     * sectors beginning at aligned Q; it never erases the validated prefix.
     */
    const esp_partition_t *now = esp_ota_get_running_partition();
    if (!now || now->address != running->address || target->address == now->address) { http_close(&h); return ESP_ERR_INVALID_STATE; }
    esp_ota_handle_t handle = 0; bool live = false, reconnect_after_cleanup = false;
    /* SDK app verification reads the partition, not merely manifest.size.
     * A sequential fresh erase could leave an old native signature beyond a
     * newly advertised unsigned file and validate stale tail bytes. Erase the
     * WHOLE inactive slot on every fresh attempt. Resumes may preserve a prefix
     * only when policy-2 identity-bound checkpoints prove this initial erase.
     */
    err = q ? esp_ota_resume(target, OTA_WITH_SEQUENTIAL_WRITES, q, &handle) :
        esp_ota_begin(target, target->size, &handle);
    if (err != ESP_OK) { http_close(&h); return err; }
    live = true;
    ESP_LOGI(TAG, "writer_started target=%s offset=%" PRIu32 " mode=%s", target->label, q, q ? "resume" : "fresh");
    uint8_t buffer[4096]; uint32_t written = q, last_percent = UINT32_MAX;
    while (written < m->size) {
        if (cancelled_or_expired(started)) { err = ESP_ERR_TIMEOUT; goto cleanup; }
        size_t need = m->size - written;
        uint32_t boundary = CHECKPOINT_STEP - (written % CHECKPOINT_STEP);
        if (need > sizeof(buffer)) { need = sizeof(buffer); }
        if (need > boundary) { need = boundary; }
        int timeout_ms = request_timeout_ms(started);
        if (!timeout_ms) { err = ESP_ERR_TIMEOUT; goto cleanup; }
        (void)esp_http_client_set_timeout_ms(h.client, timeout_ms);
        int n = esp_http_client_read(h.client, (char *)buffer, need);
        if (n <= 0) { hint->retryable = true; err = ESP_ERR_HTTP_CONNECTION_CLOSED; goto cleanup; }
        err = esp_ota_write(handle, buffer, n);
        if (err != ESP_OK) { goto cleanup; }
        written += n; atomic_store(&s_written, written);
        if (!(written % CHECKPOINT_STEP) && written < m->size) {
#if LAB_FAULT_PROFILE
            uint32_t reset_before = atomic_load(&s_lab_reset_before_checkpoint);
            if (reset_before && written >= reset_before) {
                atomic_store(&s_lab_reset_before_checkpoint, 0);
                ESP_LOGW(TAG, "fault_method=software_reset_before_checkpoint written=%" PRIu32
                    " old_durable_q=%u nvs_commit_for_new_q=false", written, atomic_load(&s_durable_q));
                vTaskDelay(pdMS_TO_TICKS(50)); esp_restart();
            }
#endif
            err = cp_save(m, target, running->address, written);
            if (err != ESP_OK) { goto cleanup; }
        }
        unsigned percent = (unsigned)((uint64_t)written * 100 / m->size);
        if (percent / 10 != last_percent / 10) {
            ESP_LOGI(TAG, "download=%u%% written=%" PRIu32 " durable_q=%u", percent, written, atomic_load(&s_durable_q));
            last_percent = percent;
        }
        uint32_t cut = atomic_load(&s_reset_at);
        if (cut && written >= cut && written < m->size) {
            atomic_store(&s_reset_at, 0);
            ESP_LOGW(TAG, "fault_method=software_reset written=%" PRIu32 " q=%u", written, atomic_load(&s_durable_q));
            vTaskDelay(pdMS_TO_TICKS(50)); esp_restart();
        }
        /* Explicit lab fault: this interrupts the radio connection, not just
         * a simulated HTTP response. The one-shot setting is volatile. Keep
         * the durable prefix, abort this live writer, then exercise real Range
         * resumption through the ordinary bounded retry path.
         */
        uint32_t drop = atomic_load(&s_wifi_drop_at);
        if (drop && written >= drop && written < m->size) {
            atomic_store(&s_wifi_drop_at, 0);
            atomic_store(&s_wifi_reconnect_suppressed, true);
            xEventGroupClearBits(s_network, NET_UP);
            esp_err_t disconnected = esp_wifi_disconnect();
            ESP_LOGW(TAG, "fault_method=wifi_disconnect written=%" PRIu32 " q=%u result=%s hold_ms=2000",
                written, atomic_load(&s_durable_q), esp_err_to_name(disconnected));
            reconnect_after_cleanup = true;
            for (unsigned tick = 0; tick < 20 && !cancelled_or_expired(started); ++tick) {
                vTaskDelay(pdMS_TO_TICKS(100));
            }
            hint->retryable = true;
            err = ESP_ERR_HTTP_CONNECTION_CLOSED;
            goto cleanup;
        }
        taskYIELD();
    }
    if (!esp_http_client_is_complete_data_received(h.client)) { hint->retryable = true; err = ESP_ERR_HTTP_CONNECTION_CLOSED; goto cleanup; }
    status_set("VERIFY_IMAGE", "SDK native signature validation");
    err = esp_ota_end(handle); live = false;
cleanup: ;
    bool aborted = live;
    esp_err_t abort_result = live ? esp_ota_abort(handle) : ESP_OK;
    http_close(&h);
    ESP_LOGI(TAG, "payload_cleanup target=%s writer_abort=%u http_closed=true result=%s transfer_error=%s",
        target->label, aborted, esp_err_to_name(abort_result), esp_err_to_name(err));
    if (reconnect_after_cleanup) {
#if LAB_FAULT_PROFILE
        if (atomic_load(&s_lab_radio_off)) {
            ESP_LOGI(TAG, "fault_wifi_restore deferred_by_lab_radio_off=true durable_q=%u", atomic_load(&s_durable_q));
            return err;
        }
#endif
        atomic_store(&s_wifi_retries, 0);
        atomic_store(&s_wifi_reconnect_suppressed, false);
        esp_err_t reconnected = esp_wifi_connect();
        ESP_LOGI(TAG, "fault_wifi_restore result=%s writer_aborted=true http_closed=true durable_q=%u",
            esp_err_to_name(reconnected), atomic_load(&s_durable_q));
    }
    return err;
}

static esp_err_t verify_candidate(const manifest_t *m, const esp_partition_t *target)
{
    uint8_t actual[32];
    esp_err_t err = partition_hash(target, m->size, actual);
    if (err != ESP_OK || !same_bytes(actual, m->digest, 32)) { return ESP_ERR_INVALID_CRC; }
    esp_app_desc_t desc;
    err = esp_ota_get_partition_description(target, &desc);
    if (err != ESP_OK || !memchr(desc.version, 0, sizeof(desc.version)) ||
        !memchr(desc.project_name, 0, sizeof(desc.project_name)) || strcmp(desc.version, m->version) ||
        strcmp(desc.project_name, "studybook_ota_lab") || desc.secure_version != m->secure_version) {
        return ESP_ERR_INVALID_VERSION;
    }
    return ESP_OK;
}

static void wifi_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
#if LAB_FAULT_PROFILE
        if (atomic_load(&s_lab_radio_off)) {
            xEventGroupClearBits(s_network, NET_UP);
            ESP_LOGW(TAG, "lab_radio_off ignoring_late_IP_event=true"); return;
        }
#endif
        atomic_store(&s_wifi_retries, 0); xEventGroupSetBits(s_network, NET_UP); ESP_LOGI(TAG, "wifi=connected");
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        xEventGroupClearBits(s_network, NET_UP);
        const wifi_event_sta_disconnected_t *event = data;
        ESP_LOGW(TAG, "wifi=disconnected reason=%u", event ? event->reason : 0U);
        bool suppress = atomic_load(&s_wifi_reconnect_suppressed);
#if LAB_FAULT_PROFILE
        suppress = suppress || atomic_load(&s_lab_radio_off);
#endif
        if (suppress) {
            ESP_LOGI(TAG, "wifi_auto_reconnect=suppressed_by_lab_fault");
        } else if (atomic_fetch_add(&s_wifi_retries, 1) < 5) { (void)esp_wifi_connect(); }
        else { ESP_LOGW(TAG, "wifi_retry_budget_exhausted; provision/reconnect explicitly"); }
    }
}

static esp_err_t set_wifi(const char *ssid, const char *password, bool persist)
{
#if LAB_FAULT_PROFILE
    if (atomic_load(&s_lab_radio_off)) { return ESP_ERR_INVALID_STATE; }
#endif
    size_t sl = strlen(ssid), pl = strlen(password);
    if (sl == 0 || sl > 32 || pl > 64 || (pl > 0 && pl < 8)) { return ESP_ERR_INVALID_ARG; }
    wifi_config_t config = {0};
    memcpy(config.sta.ssid, ssid, sl); memcpy(config.sta.password, password, pl);
    config.sta.threshold.authmode = pl ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
    config.sta.pmf_cfg.capable = true;
    esp_err_t err;
    if (!s_wifi_started) { err = esp_wifi_start(); if (err != ESP_OK) { memset(&config, 0, sizeof(config)); return err; } s_wifi_started = true; }
    (void)esp_wifi_disconnect(); atomic_store(&s_wifi_retries, 0);
    err = esp_wifi_set_config(WIFI_IF_STA, &config);
    memset(&config, 0, sizeof(config));
    if (err != ESP_OK) { return err; }
    if (persist) {
        nvs_handle_t net;
        err = nvs_open_from_partition("nvs_cfg", "net", NVS_READWRITE, &net);
        if (err != ESP_OK) { return err; }
        /* A single credential blob avoids mixed SSID/password after reset. */
        struct { char ssid[33]; char password[65]; } credentials = {0};
        snprintf(credentials.ssid, sizeof(credentials.ssid), "%s", ssid);
        snprintf(credentials.password, sizeof(credentials.password), "%s", password);
        err = nvs_set_blob(net, "credentials", &credentials, sizeof(credentials));
        if (err == ESP_OK) { err = nvs_commit(net); }
        memset(&credentials, 0, sizeof(credentials)); nvs_close(net);
        if (err != ESP_OK) { return err; }
    }
    return esp_wifi_connect();
}

static esp_err_t connect_saved_wifi(void)
{
    nvs_handle_t net;
    esp_err_t err = nvs_open_from_partition("nvs_cfg", "net", NVS_READONLY, &net);
    if (err != ESP_OK) { return err; }
    struct { char ssid[33]; char password[65]; } credentials = {0};
    size_t length = sizeof(credentials);
    err = nvs_get_blob(net, "credentials", &credentials, &length);
    nvs_close(net);
    if (err == ESP_OK && (length != sizeof(credentials) || credentials.ssid[32] || credentials.password[64])) {
        err = ESP_ERR_INVALID_SIZE;
    }
    if (err == ESP_OK) { err = set_wifi(credentials.ssid, credentials.password, false); }
    memset(&credentials, 0, sizeof(credentials)); return err;
}

static esp_err_t network_ready(int64_t started)
{
#if LAB_FAULT_PROFILE
    if (atomic_load(&s_lab_clock_not_ready)) {
        ESP_LOGW(TAG, "fault_profile_clock_policy=NOT_READY before_TLS=true skip_time_verification=false");
        return ESP_ERR_INVALID_STATE;
    }
#endif
    EventBits_t bits = 0;
    for (unsigned i = 0; i < 30; ++i) {
        if (cancelled_or_expired(started)) { return ESP_ERR_TIMEOUT; }
        bits = xEventGroupWaitBits(s_network, NET_UP, pdFALSE, pdTRUE, pdMS_TO_TICKS(1000));
        if (bits & NET_UP) { break; }
    }
    if (!(bits & NET_UP)) { return ESP_ERR_TIMEOUT; }
    if (!s_sntp_started) {
        esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
        esp_sntp_setservername(0, "pool.ntp.org");
        esp_sntp_setservername(1, "time.cloudflare.com");
        esp_sntp_init(); s_sntp_started = true;
    }
    /* Time validity is a prerequisite, never bypassed to make TLS pass. */
    for (unsigned i = 0; i < 30; ++i) {
        time_t now = time(NULL);
        if (now >= 1704067200) { return ESP_OK; }
        if (cancelled_or_expired(started)) { return ESP_ERR_TIMEOUT; }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    return ESP_ERR_TIMEOUT;
}

/* One retry budget for the metadata PAIR. A failed signature fetch refetches
 * the manifest as well, so a publisher rotation never mixes attempts. Neither
 * fetch_small nor http_open has an internal retry loop.
 */
static esp_err_t fetch_metadata(const request_t *request, uint8_t *raw, size_t *raw_len,
                                uint8_t *signature, size_t *signature_len, int64_t started)
{
    esp_err_t err = ESP_FAIL;
    for (unsigned attempt = 1; attempt <= HTTP_ATTEMPTS; ++attempt) {
        if (cancelled_or_expired(started)) { return ESP_ERR_TIMEOUT; }
        if (attempt > 1) {
            err = network_ready(started); if (err != ESP_OK) { return err; }
        }
        *raw_len = 0; *signature_len = 0;
        retry_hint_t hint = {0};
        const char *phase = "metadata_manifest";
        status_set("FETCH_MANIFEST", "exact bytes; bounded metadata pair budget");
        err = fetch_small(request->manifest_url, raw, MANIFEST_CAP, raw_len, started, &hint);
        if (err == ESP_OK) {
            phase = "metadata_signature";
            err = fetch_small(request->signature_url, signature, SIGNATURE_LEN, signature_len, started, &hint);
        }
        if (err == ESP_OK) { return ESP_OK; }
        if (!retry_wait(phase, attempt, err, &hint, started)) { return err; }
    }
    return err;
}

static void ota_worker(void *argument)
{
    request_t *request = argument;
    uint8_t *raw = malloc(MANIFEST_CAP + 1), *signature = malloc(SIGNATURE_LEN);
    manifest_t *manifest = calloc(1, sizeof(*manifest));
    esp_err_t err = ESP_ERR_NO_MEM;
    const esp_partition_t *target = NULL;
    bool boot_selected = false;
    int64_t started = esp_timer_get_time();
    if (!raw || !signature || !manifest) { goto finish; }
#if !defined(CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT) || !CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT
    status_set("REJECTED", "native signed-app verification disabled");
    err = ESP_ERR_NOT_SUPPORTED; goto finish;
#endif
    status_set("WAIT_NETWORK_TIME", "bounded prerequisites");
    err = network_ready(started); if (err != ESP_OK) { goto finish; }
    size_t raw_len = 0, signature_len = 0;
    err = fetch_metadata(request, raw, &raw_len, signature, &signature_len, started);
    if (err != ESP_OK) { goto finish; }
    if (signature_len != SIGNATURE_LEN) { err = ESP_ERR_INVALID_SIZE; goto finish; }
    status_set("AUTH_MANIFEST", "RSA-PSS3072 SHA256 salt32");
    if (psa_verify_message(s_manifest_key, PSA_ALG_RSA_PSS(PSA_ALG_SHA_256), raw, raw_len, signature, signature_len) != PSA_SUCCESS) {
        err = ESP_ERR_INVALID_CRC; goto finish;
    }
    err = parse_manifest(raw, raw_len, manifest); if (err != ESP_OK) { goto finish; }
    err = manifest_policy(manifest, &target); if (err != ESP_OK) { goto finish; }
    ESP_LOGI(TAG, "accepted_metadata version=%s version_code=%" PRIu32 " size=%" PRIu32 " slot=%s",
        manifest->version, manifest->version_code, manifest->size, target->label);
    char release_id[65], file_digest[65];
    hex_digest(manifest->release_id, release_id); hex_digest(manifest->digest, file_digest);
    ESP_LOGI(TAG, "accepted_release_id=%s file_sha256=%s", release_id, file_digest);
#if LAB_FAULT_PROFILE
    if (request->one_call) {
        /* E04's introductory route is deliberately separate from the strict
         * checkpointed route. The SDK one-call owns download and set_boot;
         * file readback happens after that API and before our explicit reset.
         * Persist identity first so trial health can independently recheck it.
         */
        int open_gate = 0;
        if (!atomic_compare_exchange_strong(&s_activation_gate, &open_gate, 1)) {
            err = ESP_ERR_TIMEOUT; goto finish;
        }
        err = save_candidate(manifest, target); if (err != ESP_OK) { goto finish; }
        err = cp_clear(); if (err != ESP_OK) { goto finish; }
        /* Prevent a stale signature tail even if the SDK erases sequentially. */
        err = esp_partition_erase_range(target, 0, target->size);
        if (err != ESP_OK) { goto finish; }
        esp_http_client_config_t http = {
            .url = manifest->url, .crt_bundle_attach = esp_crt_bundle_attach,
            .timeout_ms = request_timeout_ms(started), .keep_alive_enable = false,
            .buffer_size = 4096, .buffer_size_tx = 2048,
            .max_redirection_count = 5, .max_authorization_retries = -1,
        };
        esp_https_ota_config_t basic = { .http_config = &http, .bulk_flash_erase = true };
        status_set("BASIC_ONE_CALL", "E04 lab only; no checkpoint/cancel contract during SDK call");
        ESP_LOGI(TAG, "E04_ONE_CALL begin target=%s task=ota_worker TLS_CA_hostname_time=true", target->label);
        err = esp_https_ota(&basic);
        ESP_LOGI(TAG, "E04_ONE_CALL result=%s", esp_err_to_name(err));
        if (err != ESP_OK) { goto finish; }
        boot_selected = true;
        status_set("VERIFY_FILE", "E04 post-one-call readback; SDK already selected NEW");
        err = verify_candidate(manifest, target); if (err != ESP_OK) { goto finish; }
        err = record_boot_selected(manifest, target); if (err != ESP_OK) { goto finish; }
        status_set("BOOT_SELECTED", "E04 one-call NEW; success still requires trial health and VALID");
        free(request); free(raw); free(signature); free(manifest);
        vTaskDelay(pdMS_TO_TICKS(1000)); esp_restart();
    }
#endif
    status_set("DOWNLOAD", "inactive slot only");
    for (unsigned attempt = 1; attempt <= HTTP_ATTEMPTS; ++attempt) {
        if (attempt > 1) {
            status_set("WAIT_RETRY_NETWORK", "bounded reconnect before checkpoint resume");
            err = network_ready(started);
            if (err != ESP_OK || cancelled_or_expired(started)) { break; }
            status_set("DOWNLOAD", "retry from durable checkpoint");
        }
        retry_hint_t hint = {0};
        err = download(manifest, target, started, &hint);
        if (err == ESP_OK || cancelled_or_expired(started)) { break; }
        /* Only explicitly classified network/HTTP transient failures retry.
         * Storage, native image, parser/auth and contract failures never inherit
         * a generic ESP_FAIL retry merely because they share an error number.
         */
        if (!retry_wait("payload", attempt, err, &hint, started)) { break; }
    }
    if (err != ESP_OK) { goto finish; }
    status_set("VERIFY_FILE", "readback final signed bytes and descriptor");
    err = verify_candidate(manifest, target); if (err != ESP_OK) { (void)cp_clear(); goto finish; }
    if (cancelled_or_expired(started)) { err = ESP_ERR_TIMEOUT; goto finish; }
    err = manifest_policy(manifest, &target); if (err != ESP_OK) { goto finish; }
    status_set("READY_TO_BOOT", "persisting per-slot identity");
    err = save_candidate(manifest, target); if (err != ESP_OK) { goto finish; }
    err = cp_clear(); if (err != ESP_OK) { goto finish; }
    if (cancelled_or_expired(started)) { err = ESP_ERR_TIMEOUT; goto finish; }
    int open_gate = 0;
    if (!atomic_compare_exchange_strong(&s_activation_gate, &open_gate, 1)) { err = ESP_ERR_TIMEOUT; goto finish; }
    err = esp_ota_set_boot_partition(target); if (err != ESP_OK) { goto finish; }
    boot_selected = true;
    err = record_boot_selected(manifest, target);
    if (err != ESP_OK) { goto finish; }
    status_set("BOOT_SELECTED", "NEW; success requires health and VALID after restart");
    atomic_store(&s_reset_at, 0); atomic_store(&s_wifi_drop_at, 0);
#if LAB_FAULT_PROFILE
    atomic_store(&s_lab_reset_before_checkpoint, 0);
#endif
    free(request); free(raw); free(signature); free(manifest);
    vTaskDelay(pdMS_TO_TICKS(1000)); esp_restart();
finish:
    atomic_store(&s_reset_at, 0); atomic_store(&s_wifi_drop_at, 0);
#if LAB_FAULT_PROFILE
    atomic_store(&s_lab_reset_before_checkpoint, 0);
#endif
    if (boot_selected) {
        /* Boot selection and custom NVS cannot be one atomic transaction.
         * The pre-selection identity still reconciles a successful trial.
         * Do not misreport failure after otadata already selected a candidate.
         */
        status_set("BOOT_SELECTED_REPORT_FAILED", "metadata failure; next reset may trial candidate");
    } else if (atomic_load(&s_cancel) || atomic_load(&s_activation_gate) < 0) {
        if (s_ready && cp_clear() != ESP_OK) { ESP_LOGE(TAG, "cancel_checkpoint_clear_failed"); }
        status_set("CANCELLED", "app unchanged");
    } else { status_set("FAILED", esp_err_to_name(err)); }
    free(request); free(raw); free(signature); free(manifest);
    atomic_store(&s_busy, false); vTaskDelete(NULL);
}

bool ota_lab_trial_health(void)
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (!running || psa_crypto_init() != PSA_SUCCESS) { return false; }
    nvs_handle_t meta;
    esp_err_t open_err = nvs_open_from_partition("ota_meta", "dl", NVS_READONLY, &meta);
    if (open_err != ESP_OK) {
        /* The one explicit bootstrap is v1/schema1 provisioned over serial.
         * A normal network candidate always has a committed identity record.
         */
        bool bootstrap = open_err == ESP_ERR_NVS_NOT_FOUND && LAB_VERSION_CODE == 1 && LAB_CFG_SCHEMA == 1;
        ESP_LOGI(TAG, "trial_identity bootstrap=%u no_metadata_namespace", bootstrap);
        return bootstrap;
    }
    identity_t record = {0}; size_t size = sizeof(record);
    esp_err_t err = nvs_get_blob(meta, identity_key(running), &record, &size);
    nvs_close(meta);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        bool bootstrap = LAB_VERSION_CODE == 1 && LAB_CFG_SCHEMA == 1;
        ESP_LOGI(TAG, "trial_identity bootstrap=%u no_candidate_record", bootstrap);
        return bootstrap;
    }
    bool valid = err == ESP_OK && size == sizeof(record) && record.magic == RECORD_MAGIC &&
        record.format == RECORD_FORMAT && record.length == sizeof(record) &&
        record.version[sizeof(record.version)-1] == 0 && record.crc == blob_crc(&record, offsetof(identity_t, crc)) &&
        identity_matches_running(&record, running);
    ESP_LOGI(TAG, "trial_identity valid=%u compiled_code=%u compiled_schema=%u", valid, LAB_VERSION_CODE, LAB_CFG_SCHEMA);
    return valid;
}

void ota_lab_init(void)
{
    if (s_ready) { return; }
    if (psa_crypto_init() != PSA_SUCCESS) { status_set("DISABLED", "PSA init failed"); return; }
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PSS(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_bits(&attributes, 3072);
    psa_status_t crypto = psa_import_key(&attributes, manifest_key_start,
        (size_t)(manifest_key_end-manifest_key_start), &s_manifest_key);
    psa_reset_key_attributes(&attributes);
    if (crypto != PSA_SUCCESS) { status_set("DISABLED", "trusted manifest key import failed"); return; }
    if (nvs_open_from_partition("ota_meta", "dl", NVS_READWRITE, &s_meta) != ESP_OK || reconcile_identities() != ESP_OK) {
        status_set("DISABLED", "OTA metadata unreadable; no automatic erase"); return;
    }
    s_network = xEventGroupCreate();
    if (!s_network) { status_set("DISABLED", "network event allocation failed"); return; }
    esp_err_t err = esp_netif_init();
    if (err == ESP_OK) { err = esp_event_loop_create_default(); }
    if (err != ESP_OK) { status_set("DISABLED", "network init failed"); return; }
    if (!esp_netif_create_default_wifi_sta()) { status_set("DISABLED", "STA allocation failed"); return; }
    wifi_init_config_t wifi = WIFI_INIT_CONFIG_DEFAULT();
    err = esp_wifi_init(&wifi);
    if (err == ESP_OK) { err = esp_wifi_set_storage(WIFI_STORAGE_RAM); }
    if (err == ESP_OK) { err = esp_wifi_set_mode(WIFI_MODE_STA); }
    if (err == ESP_OK) { err = esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, wifi_event, NULL); }
    if (err == ESP_OK) { err = esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event, NULL); }
    if (err != ESP_OK) { status_set("DISABLED", "Wi-Fi initialization failed"); return; }
    s_ready = true; status_set("IDLE", "local OTA controller ready");
#if LAB_FAULT_PROFILE
    ESP_LOGW(TAG, "LAB_FAULT_PROFILE=ON test_CA_and_local_origins_enabled production=false TLS_checks=enabled");
    uint8_t offline_once = 0;
    if (nvs_get_u8(s_meta, "offline_once", &offline_once) == ESP_OK && offline_once == 1) {
        atomic_store(&s_lab_radio_off, true);
        atomic_store(&s_wifi_reconnect_suppressed, true);
        xEventGroupClearBits(s_network, NET_UP);
        esp_err_t cleared = nvs_erase_key(s_meta, "offline_once");
        if (cleared == ESP_OK) { cleared = nvs_commit(s_meta); }
        uint8_t readback = 0;
        bool consumed = cleared == ESP_OK && nvs_get_u8(s_meta, "offline_once", &readback) == ESP_ERR_NVS_NOT_FOUND;
        ESP_LOGW(TAG, "lab_offline_boot one_shot_consumed=%u wifi_autostart=false credentials_unchanged=true clear_result=%s",
            consumed, esp_err_to_name(cleared));
        /* Even if consuming the one-shot flag failed, keep this boot offline
         * and report the error. Never erase the OTA/config partitions.
         */
        return;
    }
#endif
    err = connect_saved_wifi();
    if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) { ESP_LOGW(TAG, "saved_wifi_connect_failed=%s", esp_err_to_name(err)); }
}

static void print_status(void)
{
    char phase[sizeof(s_phase)], reason[sizeof(s_reason)];
    taskENTER_CRITICAL(&s_status_lock);
    memcpy(phase, s_phase, sizeof(phase)); memcpy(reason, s_reason, sizeof(reason));
    taskEXIT_CRITICAL(&s_status_lock);
    bool connected = s_network && (xEventGroupGetBits(s_network) & NET_UP);
    ESP_LOGI(TAG, "status ready=%u busy=%u phase=%s reason=%s wifi=%s bytes=%u total=%u durable_q=%u",
        s_ready, atomic_load(&s_busy), phase, reason, connected ? "up" : "down",
        atomic_load(&s_written), atomic_load(&s_total), atomic_load(&s_durable_q));
}

#if LAB_FAULT_PROFILE
/* These commands exist only in the optional laboratory build. They mutate the
 * checkpoint test records, never otadata, credentials, config or trust keys.
 */
static bool lab_fault_command(const char *line)
{
    if (strncmp(line, "lab-", 4)) { return false; }
    if (!strcmp(line, "lab-radio-off") || !strcmp(line, "lab-radio-on")) {
        if (!s_ready) { ESP_LOGW(TAG, "lab_radio_rejected controller_not_ready"); return true; }
        if (!strcmp(line, "lab-radio-off")) {
            atomic_store(&s_lab_radio_off, true);
            atomic_store(&s_wifi_reconnect_suppressed, true);
            xEventGroupClearBits(s_network, NET_UP);
            esp_err_t disconnected = esp_wifi_disconnect();
            esp_err_t stopped = esp_wifi_stop();
            if (stopped == ESP_OK || stopped == ESP_ERR_WIFI_NOT_STARTED) { s_wifi_started = false; }
            const esp_partition_t *running = esp_ota_get_running_partition();
            esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
            bool valid = running && esp_ota_get_state_partition(running, &state) == ESP_OK && state == ESP_OTA_IMG_VALID;
            ESP_LOGW(TAG, "lab_radio_off disconnect_result=%s stop_result=%s auto_reconnect_suppressed=true sdk_state=%s credentials_unchanged=true",
                esp_err_to_name(disconnected), esp_err_to_name(stopped), valid ? "VALID" : "OTHER");
        } else {
            atomic_store(&s_lab_radio_off, false);
            atomic_store(&s_wifi_reconnect_suppressed, false);
            atomic_store(&s_wifi_retries, 0);
            esp_err_t restored = connect_saved_wifi();
            ESP_LOGI(TAG, "lab_radio_on stored_credentials_restore_result=%s credentials_unchanged=true",
                esp_err_to_name(restored));
        }
        return true;
    }
    if (!strcmp(line, "lab-retry-policy-tests")) {
        static const struct { int status; bool retry; } statuses[] = {
            {429, true}, {500, true}, {502, true}, {503, true}, {504, true},
            {200, false}, {206, false}, {301, false}, {401, false}, {403, false},
            {404, false}, {416, false}, {501, false}
        };
        static const struct { const char *text; bool valid; uint32_t ms; } delays[] = {
            {"0", true, 0}, {"1", true, 1000}, {"60", true, 60000}, {" 2\t", true, 2000},
            {"61", false, 0}, {"42949672960", false, 0}, {"-1", false, 0}, {"+1", false, 0},
            {"1.5", false, 0}, {"", false, 0}, {"1,2", false, 0},
            {"Wed, 21 Oct 2026 07:28:00 GMT", false, 0}
        };
        unsigned passed = 0;
        for (unsigned i = 0; i < sizeof(statuses)/sizeof(statuses[0]); ++i) {
            passed += http_status_retryable(statuses[i].status) == statuses[i].retry;
        }
        for (unsigned i = 0; i < sizeof(delays)/sizeof(delays[0]); ++i) {
            uint32_t ms = UINT32_MAX;
            bool valid = parse_retry_after(delays[i].text, &ms);
            passed += valid == delays[i].valid && (!valid || ms == delays[i].ms);
        }
        unsigned total = sizeof(statuses)/sizeof(statuses[0]) + sizeof(delays)/sizeof(delays[0]);
        ESP_LOGI(TAG, "lab_retry_policy_tests passed=%u total=%u result=%s runtime_network_test=false",
            passed, total, passed == total ? "PASS" : "FAIL");
        return true;
    }
    if (!strcmp(line, "lab-checkpoint-status")) {
        if (!s_ready) { ESP_LOGW(TAG, "lab_checkpoint_status controller_not_ready"); return true; }
        const char *keys[] = { "cp0", "cp1" };
        for (unsigned i = 0; i < 2; ++i) {
            checkpoint_t cp = {0}; size_t size = sizeof(cp);
            esp_err_t err = nvs_get_blob(s_meta, keys[i], &cp, &size);
            bool found = err == ESP_OK && size == sizeof(cp);
            ESP_LOGI(TAG, "lab_checkpoint key=%s found=%u valid_crc_format=%u q=%" PRIu32
                " generation=%" PRIu32 " target=0x%" PRIx32 " read=%s",
                keys[i], found, found && cp_valid(&cp), cp.q, cp.generation, cp.target_addr, esp_err_to_name(err));
        }
        return true;
    }
    if (!s_ready || atomic_load(&s_busy)) {
        ESP_LOGW(TAG, "lab_fault_command_rejected controller_not_ready_or_busy"); return true;
    }
    if (!strcmp(line, "lab-offline-next-boot")) {
        esp_err_t err = nvs_set_u8(s_meta, "offline_once", 1);
        if (err == ESP_OK) { err = nvs_commit(s_meta); }
        uint8_t readback = 0;
        bool armed = err == ESP_OK && nvs_get_u8(s_meta, "offline_once", &readback) == ESP_OK && readback == 1;
        ESP_LOGW(TAG, "lab_offline_next_boot armed=%u result=%s credentials_unchanged=true current_radio_unchanged=true",
            armed, esp_err_to_name(err)); return true;
    }
    if (!strcmp(line, "lab-clock-not-ready on") || !strcmp(line, "lab-clock-not-ready off")) {
        bool enabled = !strcmp(line, "lab-clock-not-ready on");
        atomic_store(&s_lab_clock_not_ready, enabled);
        ESP_LOGW(TAG, "lab_clock_not_ready=%u actual_clock_unchanged=true TLS_time_checks_enabled=true", enabled);
        return true;
    }
    static const char reset_prefix[] = "lab-reset-before-checkpoint ";
    if (!strncmp(line, reset_prefix, sizeof(reset_prefix)-1)) {
        const char *value = line + sizeof(reset_prefix)-1;
        char *end; unsigned long q = strtoul(value, &end, 10);
        if (!*value || *end || q >= SLOT_CAP || q % CHECKPOINT_STEP) {
            ESP_LOGW(TAG, "lab_reset_before_checkpoint_invalid use_64KiB_boundary_or_zero");
        } else {
            atomic_store(&s_lab_reset_before_checkpoint, q);
            ESP_LOGW(TAG, "lab_reset_before_checkpoint_q=%lu next_session_only=true", q);
        }
        return true;
    }
    if (!strcmp(line, "lab-corrupt-checkpoints")) {
        const char *keys[] = { "cp0", "cp1" };
        unsigned changed = 0; esp_err_t result = ESP_OK;
        for (unsigned i = 0; i < 2; ++i) {
            checkpoint_t cp = {0}; size_t size = sizeof(cp);
            esp_err_t err = nvs_get_blob(s_meta, keys[i], &cp, &size);
            if (err == ESP_ERR_NVS_NOT_FOUND) { continue; }
            if (err != ESP_OK || size != sizeof(cp)) { result = err == ESP_OK ? ESP_ERR_INVALID_SIZE : err; break; }
            /* Derive a wrong CRC from the payload, rather than toggling the
             * current value: repeated diagnostics must remain corrupt.
             */
            cp.crc = blob_crc(&cp, offsetof(checkpoint_t, crc)) ^ UINT32_C(0x01010101);
            err = nvs_set_blob(s_meta, keys[i], &cp, sizeof(cp));
            if (err != ESP_OK) { result = err; break; }
            ++changed;
        }
        if (changed) {
            esp_err_t committed = nvs_commit(s_meta);
            if (committed != ESP_OK) { result = committed; }
        }
        atomic_store(&s_durable_q, 0);
        ESP_LOGW(TAG, "fault_method=checkpoint_crc_xor records_changed=%u result=%s credentials_and_cfg_unchanged=true",
            changed, esp_err_to_name(result));
        return true;
    }
    if (!strcmp(line, "lab-seed-stale-running")) {
        const esp_partition_t *running = esp_ota_get_running_partition();
        esp_err_t err = running ? cp_clear() : ESP_ERR_INVALID_STATE;
        manifest_t fixture = {0}; fixture.size = 2 * CHECKPOINT_STEP;
        (void)hash_bytes("lab-stale-running", strlen("lab-stale-running"), fixture.release_id);
        if (err == ESP_OK) { err = cp_save(&fixture, running, running->address, CHECKPOINT_STEP); }
        ESP_LOGW(TAG, "fault_method=stale_checkpoint_target_running target=0x%" PRIx32 " q=%u result=%s flash_image_unchanged=true",
            running ? running->address : 0U, CHECKPOINT_STEP, esp_err_to_name(err));
        return true;
    }
    ESP_LOGW(TAG, "lab_fault_command_unknown"); return true;
}
#endif

bool ota_lab_command(const char *line)
{
#if LAB_FAULT_PROFILE
    if (lab_fault_command(line)) { return true; }
#endif
    if (!strcmp(line, "otahelp")) {
        ESP_LOGI(TAG, "otastatus | wifi SSID|PASSWORD (no echo) | ota MANIFEST_URL SIGNATURE_URL | cancel | clearresume");
        ESP_LOGI(TAG, "Lab faults: ota-reset-at OFFSET | ota-wifi-drop-at OFFSET (0 disarms; idle only)");
        ESP_LOGI(TAG, "Use public GitHub /releases/download/ HTTPS origins; no PAT in firmware. Reset injection is a software reset, not a power cut.");
#if LAB_FAULT_PROFILE
        ESP_LOGW(TAG, "Optional test mode: lab-clock-not-ready on/off | lab-reset-before-checkpoint Q | lab-checkpoint-status | lab-corrupt-checkpoints | lab-seed-stale-running | lab-retry-policy-tests");
        ESP_LOGW(TAG, "E04 demo only: ota-basic MANIFEST_URL SIGNATURE_URL uses esp_https_ota one-call, without low-level resume/cancel guarantees");
        ESP_LOGW(TAG, "Offline lab controls: lab-radio-off | lab-radio-on | lab-offline-next-boot");
#endif
        return true;
    }
    if (!strcmp(line, "otastatus")) { print_status(); return true; }
    if (!strncmp(line, "clock ", 6)) {
        const char *digits = line + 6;
        bool valid = strlen(digits) == 10;
        for (size_t i = 0; valid && digits[i]; ++i) valid = isdigit((unsigned char)digits[i]);
        unsigned long long seconds = valid ? strtoull(digits, NULL, 10) : 0;
        if (!s_ready || atomic_load(&s_busy) || seconds < 1704067200ULL || seconds >= 2082758400ULL) {
            ESP_LOGW(TAG, "CLOCK_REJECT require_idle_and_UTC_2024_to_2035=true");
        } else {
            struct timeval utc = { .tv_sec = (time_t)seconds, .tv_usec = 0 };
            int result = settimeofday(&utc, NULL);
            ESP_LOGI(TAG, "CLOCK_PROVISION source=trusted_serial UTC_seconds=%llu result=%d TLS_time_checks_unchanged=true", seconds, result);
        }
        return true;
    }
    if (!strcmp(line, "cancel")) {
        if (!atomic_load(&s_busy)) { ESP_LOGI(TAG, "cancel_no_active_session"); return true; }
        int open_gate = 0;
        if (atomic_compare_exchange_strong(&s_activation_gate, &open_gate, -1) || open_gate < 0) {
            atomic_store(&s_cancel, true); ESP_LOGI(TAG, "cancel_requested_before_activation");
        } else { ESP_LOGW(TAG, "cancel_rejected activation_commit_started; observe trial outcome"); }
        return true;
    }
    if (!strncmp(line, "wifi ", 5)) {
        if (!s_ready || atomic_load(&s_busy)) { ESP_LOGW(TAG, "wifi rejected: controller unavailable/busy"); return true; }
        const char *separator = strchr(line + 5, '|');
        if (!separator || separator == line + 5 || separator - (line+5) > 32 || strlen(separator+1) > 64) {
            ESP_LOGW(TAG, "wifi_format_invalid; secret not logged"); return true;
        }
        char ssid[33] = {0}, password[65] = {0};
        memcpy(ssid, line+5, separator-(line+5)); memcpy(password, separator+1, strlen(separator+1));
        esp_err_t err = set_wifi(ssid, password, true);
        memset(ssid, 0, sizeof(ssid)); memset(password, 0, sizeof(password));
        ESP_LOGI(TAG, "wifi_provision_result=%s; credentials omitted", esp_err_to_name(err)); return true;
    }
    if (!strcmp(line, "clearresume")) {
        if (!s_ready || atomic_load(&s_busy)) { ESP_LOGW(TAG, "clearresume rejected: controller unavailable/busy"); }
        else { ESP_LOGI(TAG, "clearresume_result=%s", esp_err_to_name(cp_clear())); }
        return true;
    }
    if (!strncmp(line, "ota-reset-at ", 13)) {
        char *end; unsigned long n = strtoul(line+13, &end, 10);
        if (!line[13] || *end || n > SLOT_CAP || atomic_load(&s_busy)) { ESP_LOGW(TAG, "reset_offset_invalid_or_busy"); }
        else { atomic_store(&s_reset_at, n); ESP_LOGW(TAG, "software_reset_injection_offset=%lu next_session_only", n); }
        return true;
    }
    if (!strncmp(line, "ota-wifi-drop-at ", 17)) {
        char *end; unsigned long n = strtoul(line+17, &end, 10);
        if (!line[17] || *end || n > SLOT_CAP || atomic_load(&s_busy)) { ESP_LOGW(TAG, "wifi_drop_offset_invalid_or_busy"); }
        else { atomic_store(&s_wifi_drop_at, n); ESP_LOGW(TAG, "wifi_disconnect_injection_offset=%lu next_session_only", n); }
        return true;
    }
    const char *first = NULL;
    if (!strncmp(line, "ota ", 4)) { first = line + 4; }
#if LAB_FAULT_PROFILE
    bool one_call = !strncmp(line, "ota-basic ", 10);
    if (one_call) { first = line + 10; }
#endif
    if (!first) { return false; }
    if (!s_ready) { ESP_LOGW(TAG, "ota rejected: controller unavailable"); return true; }
    bool expected = false;
    if (!atomic_compare_exchange_strong(&s_busy, &expected, true)) { ESP_LOGW(TAG, "ota rejected: one worker already owns updater"); return true; }
    request_t *request = calloc(1, sizeof(*request));
    if (!request) { atomic_store(&s_busy, false); ESP_LOGE(TAG, "request allocation failed"); return true; }
#if LAB_FAULT_PROFILE
    request->one_call = one_call;
#endif
    const char *space = strchr(first, ' ');
    if (!space || space-first == 0 || space-first > 512 || !space[1] || strlen(space+1) > 512 || strchr(space+1, ' ')) {
        free(request); atomic_store(&s_busy, false); ESP_LOGW(TAG, "ota_format_invalid"); return true;
    }
    memcpy(request->manifest_url, first, space-first); snprintf(request->signature_url, sizeof(request->signature_url), "%s", space+1);
    if (!valid_url(request->manifest_url, true) || !valid_url(request->signature_url, true)) {
        free(request); atomic_store(&s_busy, false); ESP_LOGW(TAG, "origin_url_policy_rejected"); return true;
    }
    atomic_store(&s_activation_gate, 0); atomic_store(&s_cancel, false);
    atomic_store(&s_written, 0); atomic_store(&s_total, 0); atomic_store(&s_durable_q, 0);
    if (xTaskCreate(ota_worker, "ota_worker", 16384, request, 5, NULL) != pdPASS) {
        free(request); atomic_store(&s_busy, false); status_set("FAILED", "worker allocation failed");
    }
    return true;
}
