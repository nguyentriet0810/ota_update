# E10: configuration schema and reset contract

This file describes implemented source behavior. Board execution evidence is
recorded separately; the matrix below is an expected-behavior contract until
matched with captured logs.

## Storage and compatibility

- `nvs`: framework/Wi-Fi state. The application never erases it on an init error.
- `nvs_cfg`, namespace `cfg`: `schema1`, `schema2`, `active_schema`, and the explicit
  lab fault flag `reset_valid`. Wi-Fi credentials are not stored in these blobs.
- `ota_meta`: OTA metadata/checkpoints owned by the OTA module.
- `otadata`: SDK boot selection and image state; it remains the boot authority.

`LAB_CFG_SCHEMA=1` builds a reader for schema1. It accepts active pointer 1 or 2,
always reads schema1 in degrees C, and logs when this is the retained snapshot.
It rejects unsupported pointer values. `LAB_CFG_SCHEMA=2` understands both
records and uses validated schema2, in milli-degrees C.

The late-rollback policy is **retain the schema1 snapshot**. There is no external
configuration setter in this lab. Future v2-only configuration writes would not
automatically update schema1; adding such a setter requires an explicit
dual-write/back-conversion or downgrade restriction policy.

## Wire format

All integers are little endian. Signed values use 32-bit two's complement.
Records are encoded field by field, not by persisting a compiler-dependent C
struct. A record is rejected before its values are used unless its actual
length, header length, magic, format, expected schema, CRC and field bounds pass.

| Byte offset | Both schemas | Schema1 | Schema2 |
| --- | --- | --- | --- |
| 0 | magic `0x4346474c`, uint32 | | |
| 4 | format `1`, uint16 | | |
| 6 | schema, uint16 | 1 | 2 |
| 8 | complete record length, uint32 | 28 | 44 |
| 12 | nonzero generation, uint32 | 1 initially | source generation + 1 |
| 16 | sample_ms, uint32, 10..60000 | 1000 initially | copied from schema1 |
| 20 | threshold, int32 | degrees C, -40..125 | milli-degrees C, -40000..125000 |
| 24 | | CRC32 | sensor_offset_mc, int32, -20000..20000 |
| 28 | | | migration_id `0x00010002`, uint32 |
| 32 | | | source_generation, uint32 |
| 36 | | | source schema1 CRC32, uint32 |
| 40 | | | CRC32 |

CRC32 uses CRC-32/ISO-HDLC over all preceding bytes. It detects accidental
storage faults and provides no authenticity. Schema2 is bound to the exact
source generation and CRC. The initial schema1 fixture is generation1,
sample1000ms, threshold30 degrees C. Its schema2 shadow contains threshold30000
milli-degrees C and sensor offset0. The source is range-checked before multiplying
by1000, and a generation overflow is rejected.

## Migration and confirmation

1. Open `nvs_cfg/cfg`; validate schema1. A fixture is created only when both the
   source, active pointer and shadow are absent. Existing invalid data is retained.
2. Schema2 reader reuses a valid shadow with matching source identity. Otherwise,
   if no shadow exists or a valid old shadow refers to a changed source while
   pointer1 is active, build a fresh shadow from schema1.
3. Write shadow, commit, read back, validate. An existing corrupt shadow is not
   silently overwritten.
4. Run local health checks using the validated configuration. During trial, no
   external settings mutation is available.
5. Mark the image VALID through the SDK only after health passes.
6. Revalidate shadow and commit `active_schema=2`, then read back the pointer.
7. On a later VALID boot, repeat the reconciliation idempotently. Schema1 remains.

There is no shared atomic transaction between NVS and `otadata`. A pointer-commit
or report error after successful SDK confirmation does not invalidate the app;
it enters logged service/recovery behavior and can be retried on reboot.

## Reset and fault matrix

| Fault/reset window | Expected behavior |
| --- | --- |
| Before shadow commit | Schema1 remains intact; a later candidate can recreate shadow. |
| After shadow commit, before confirmation | Candidate remains unconfirmed; reset causes SDK rollback and v1 uses schema1. |
| After SDK VALID, before pointer commit | Reboot remains in v2 VALID and activates the existing shadow without converting it again. |
| After pointer commit | V2 reuses valid schema2; retained schema1 remains readable by v1. |
| Existing shadow wrong length/CRC/range | Service reason, no silent overwrite, candidate health fails and is not confirmed. |
| Active pointer2 with invalid shadow | Service reason; no guessed defaults or NVS erase. |
| Unsupported active schema3 | Service rejection; no erase. |
| NVS init error | Log partition/error; no automatic erase of config or Wi-Fi credentials. |

Commands:

- `cfg show`: print validated values, schema, generation and source identity.
- `cfg parser-tests`: RAM-only valid/short/CRC/range/schema3 parser tests. It does
  not mutate NVS and is not evidence of injected power-loss behavior.
- `cfg arm-valid-reset`: explicitly arm one reset after the next successful trial
  SDK confirmation and before `active_schema` commit. The flag is consumed before
  reset; a subsequent VALID boot should log `SHADOW_REUSE` and `RECONCILE`.
- `testreset`: reset only while SDK state is PENDING_VERIFY, leaving the image
  unconfirmed so that the bootloader can mark it ABORTED and choose a valid fallback.
- `failtrial`: request `esp_ota_mark_app_invalid_rollback_and_reboot()` only while
  PENDING_VERIFY, exercising the explicit INVALID path. A returned API error is
  logged without claiming rollback success. The following boot log must prove
  the actual fallback.

Physical power-cut tests and deliberate persistent blob-corruption tests remain
separate from the RAM parser tests and must be identified accurately in evidence.
