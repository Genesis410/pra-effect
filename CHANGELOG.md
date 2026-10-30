# Changelog

Semua perubahan berarti bagi Pra-Effect tercatat di sini. Format mengikuti
[Keep a Changelog](https://keepachangelog.com/) dan pemantauan
[Semantic Versioning](https://semver.org/).

## [1.4.2] - 2026-10-30
### Fixed & Hardened
- **ReDoS Defense & Linear Regex Matching:** Hardened regex patterns across all runtimes (`RE_NODE_FRAME`, `RE_GO_FUNC`, `RE_GO_FILE_LINE`, `RE_RUST_PANIC_HEADER`, `RE_BEARER_AUTH`, `RE_API_KEY_KV`) to eliminate catastrophic backtracking on adversarial input strings.
- **Polyglot Cross-Parser Collision Prevention:** Disambiguated `RE_NODE_ERROR_HEADER` from Java package names to prevent false positive Node traces on Java exceptions; enforced strict `len(self.frames) > 0` validation before emitting Node and Java traces.
- **JSONL Nested Error Fields:** Added non-recursive 1-level dictionary extraction for structured loggers (Pino, Winston, Zap, Logstash) under `error`, `err`, `exception`, and `context` keys.
- **JSONL Source Path Normalization:** Resolved frame paths in embedded JSONL stacks against `cwd` and `src_dir` for accurate project identification.

## [1.4.1] - 2026-10-30
### Added
- **TracebackParser API Parity:** Added convenience methods `parse_go_traces()`, `parse_rust_traces()`, and `parse_jsonl_traces()`, with `parse_all()` now aggregating traces across all 6 runtimes (Python, Node, Java, Go, Rust, JSONL).
- **HTML Report Polyglot Badges:** Added CSS styling for `.badge-go` (#00add8), `.badge-rust` (#de5526), and `.badge-jsonl` (#a855f7).

## [1.4.0] - 2026-10-29
### Added
- **Go Panic Streaming Parser (`GoTraceStream`):** Native streaming parser for Go runtime panics, extracting goroutine IDs, panic messages, source locations, and function frames with interleaved log tolerance.
- **Rust Backtrace Streaming Parser (`RustTraceStream`):** Streaming parser for Rust panic backtraces (`stack backtrace:`), normalizing symbol hashes (`::h[0-9a-f]{16}`) and extracting frame paths.
- **Structured JSON Lines Parser (`JsonlStream`):** Streaming parser for newline-delimited JSON logs containing structured error levels and nested stack traces.
- **End-to-End Stability Test Suite:** 16 user flow tests (`test_e2e_v14.py`) validating polyglot streaming ingestion across all 6 runtimes and regression gates.

### Fixed
- **Bearer Secret Redaction:** Updated `RE_BEARER_AUTH` to support optional colon separators (`Bearer: <token>`).
- **Interleaved Log Noise Tolerance in Go Panic:** Maintained frame collection context across up to 2 lines of non-frame noise without premature trace reset.

## [1.3.0] - 2026-10-25
### Added
- **Java Stack Trace Support:** Streaming parser for Java exceptions (`JavaTraceStream`, `RE_JAVA_*`), including standard multiline stack traces and chained exception context (`Caused by:` -> `ParsedTrace.chain`).
- **Vendor Frame Filtering:** Automatic suppression/classification of runtime and framework internals (`java.`, `javax.`, `jdk.`, `sun.`, `org.springframework.`, `org.apache.`, `org.junit.`).
- **Foreign Crash Detection:** Heuristic classification (`RE_FOREIGN_HEADER`) for unrecognized foreign stack traces and crash dumps with dedicated visual badge.
- **Sandboxed Source Context Preview (`--src`):** Secure source code preview in HTML reports with strict directory containment check (`os.path.commonpath`) to prevent path traversal and symlink escapes.
- **Visual Diagnostics:** New `.badge-java` and `.badge-foreign` status tags with dedicated styling in generated HTML reports.

## [1.2.0] - 2026-10-25
### Added
- `pra-effect diff <run_a> <run_b>`: historical run comparison detecting newly introduced, resolved, and persistent incident groups across SQLite history.
- `--fail-on-new`: CI quality gate flag for `diff` returning exit code 2 when target run introduces any new incident groups.

## [1.1.0] - 2026-10-25
### Added
- `--scrub-secrets`: redaction filter for Bearer tokens, JWTs, HTTP basic auth URI credentials, AWS access keys, and key-value secret assignments.
- `--fail-if-groups-exceed <N>`: CI quality gate flag returning exit code 2 when deduplicated incident groups exceed threshold.

## [1.0.1] - 2026-10-25

### Fixed
- **ANSI Escape Code Stripping:** Added automatic per-line ANSI escape stripping (`\x1b\[[0-9;]*[a-zA-Z]`) in the stream reader pipeline. Colored stack traces from terminal loggers (e.g. Rich, chalk, pytest) now produce identical fingerprints and error groupings as plain logs.
- **Graceful Process Interruption:** Handled `BrokenPipeError` (exit code 0) and `KeyboardInterrupt` / SIGINT (exit code 130) cleanly across `ingest` and `scan` pipelines without dumping Python runtime tracebacks to stderr.

---

## [1.0.0] - 2026-10-25

### Added
- Streaming state-machine parser (`PythonTraceStream`, `NodeTraceStream`) — ingestion
  `O(1)`; memori kini berskala dengan jumlah grup unik `O(G)`, bukan ukuran input.
- `--max-input-mb` backstop ukuran input mentah (default 100 MB, `0` menonaktifkan).
- `--version` flag di CLI untuk konsistensi rilis (paket, CLI, dan tag selaras).
- `__version__` di modul inti dan test konsistensi versi `test_release_version_consistency`.
- Split release gate memori: `GATE-MEM-01A` (pipeline ingestion) dan `GATE-MEM-01B`
  (realistic workload end-to-end).

### Changed
- Development status Bump dari Beta ke `Production/Stable` (classifiers PyPI).
- `fingerprint_v1` dibekukan permanen (lihat `FINGERPRINT_SPEC.md`); perubahan aturan
  hashing wajib namespace baru (`fingerprint_v2`).

### Notes
- High-cardinality boundary terkarakterisasi: tidak ada jaminan universal Peak RSS
  `<= 50 MB` pada log dengan kardinalitas keluaran ekstrem tinggi. `representative_trace`
  tetap dipertahankan utuh. `--max-input-mb` membatasi ukuran input mentah, bukan jumlah
  grup unik.
