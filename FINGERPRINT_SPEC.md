# FINGERPRINT_SPEC — `fingerprint_v1` Contract

**Status:** Frozen for v1.x
**Owner:** `pra_effect.py` → `ParsedTrace.compute_fingerprint()`

## 1. Definition

```
payload = "fingerprint_v1:" + runtime + ":" + error_type + ":"
          + normalized_message + ":" + project_frame_signature
fingerprint = SHA256(payload) hex, first 16 characters
```

| Component | Source | Rules |
|---|---|---|
| `runtime` | `python` \| `node` | Fixed literal. |
| `error_type` | Exception class / error header | Verbatim, no normalization. |
| `normalized_message` | Message after normalization | UUID→`<UUID>`, `0x…`→`<HEX>`, `user\|order\|id … <digits>`→`<ID>`, whitespace collapsed, hard-capped at 4096 chars. |
| `project_frame_signature` | `logical_key()` of project frames, `\|`-joined | `normalized_path::function_name`. **Line numbers excluded.** If no project frame matches, fallback = last 2 frames of the stack. |

## 2. Invariants (do not break in `fingerprint_v1`)

1. **Line numbers never enter the payload.** Refactors that move code must not fork history.
2. **Chained exceptions:** only the outermost exception feeds `error_type`/`normalized_message`/frames. Cause tracebacks ride along in `raw_text` for diagnostics and never touch the payload.
3. **`raw_text` never enters the payload.** Presentation-only changes (escaping, formatting, disclaimers) are fingerprint-neutral.
4. **Truncation flags never enter the payload.** `is_truncated` is metadata.
5. **Normalizer changes are fingerprint-breaking.** Any change to `normalize_message` output requires a new version string (`fingerprint_v2`) plus a data migration decision — never a silent edit.

## 3. Persistence rules

- Every row in `runs` and `incidents` carries `fingerprint_version`.
- `query_historical_incidents()` filters `WHERE fingerprint_version = <active version>`, so rows from other versions can exist in the table but can never leak into aggregated history.
- Cross-version comparison is out of scope for v1.x: aggregate each version separately.

## 4. Version bump checklist

1. Set `FINGERPRINT_VERSION = "fingerprint_v2"` in `pra_effect.py`.
2. Document the delta in this file (keep `fingerprint_v1` section intact — it is immutable history).
3. Decide migration: re-hash existing rows, or keep v1 rows read-only under v1 view.
4. Add a regression fixture proving old and new fingerprints for the same input differ, and that v1 history is unchanged.