# Changelog

Semua perubahan berarti bagi Pra-Effect tercatat di sini. Format mengikuti
[Keep a Changelog](https://keepachangelog.com/) dan pemantauan
[Semantic Versioning](https://semver.org/).

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
