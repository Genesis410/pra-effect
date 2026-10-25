# Changelog

Semua perubahan berarti bagi Pra-Effect tercatat di sini. Format mengikuti
[Keep a Changelog](https://keepachangelog.com/) dan pemantauan
[Semantic Versioning](https://semver.org/).

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
