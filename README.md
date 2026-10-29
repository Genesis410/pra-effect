# Pra-Effect

> Zero-dependency local CLI for parsing, deduplicating, and fingerprinting Python, Node.js, Java, Go, Rust, and JSONL error stack traces with low-memory streaming ingestion ($O(1)$ reader, $O(G)$ unique-group memory), ReDoS resilience, SQLite persistence, and standalone HTML reporting with sandboxed source previews.

[![PyPI Version](https://img.shields.io/pypi/v/pra-effect.svg)](https://pypi.org/project/pra-effect/)
[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)]()

---

## Highlights

- **Zero Third-Party Dependencies:** Pure Python standard library (`argparse`, `hashlib`, `html`, `re`, `sqlite3`, `pathlib`).
- **Resilient Fingerprinting (`fingerprint_v1`):** Normalizes dynamic memory addresses (`0x7f...`), variable line numbers, timestamps, UUIDs, and ephemeral ports so identical incidents aggregate into one canonical hash.
- **Polyglot Runtime Support:** Natively parses Python tracebacks (standard, chained exceptions, multiline messages), Node.js call stacks (V8 engine), Java stack traces (`Caused by:` exception chaining, vendor package suppression), Go panics (`GoTraceStream`), Rust backtraces (`RustTraceStream`), and structured JSON lines (`JsonlStream`). Automatically flags unrecognized foreign crash dumps.
- **Diagnostic Source Previews (`--src`):** Embeds sandboxed 5-line source code context around target frames in HTML incident reports with strict directory containment check (`os.path.commonpath`).
- **CI & Regression Quality Gates:**
  - `--fail-if-groups-exceed <N>` to guard against incident sprawl.
  - `pra-effect diff <run_a> <run_b> --fail-on-new` to block builds introducing new unhandled error groups.
- **Automated Secret Scrubbing (`--scrub-secrets`):** Zero-regex-leak masking of Bearer tokens, JWTs, URI credentials, AWS access keys, and passwords.
- **Robust Input Handling:**
  - Hard line truncation at 4,096 characters to prevent catastrophic regex backtracking (ReDoS).
  - Interleaving tolerance up to 2 lines of interleaved non-trace log noise.
  - Bounded message collection: log lines (`INFO ...`, timestamps) never leak into an error message.
  - Chained Python exceptions collapse to a single root incident (causes kept as diagnostic context, never split the fingerprint).
- **Streaming Architecture & Performance:**
  - Input parsed line-by-line through state machines — reader memory footprint is $O(1)$ (0.0047 MB tracemalloc for pure stream ingestion).
  - Total memory scales with the number of *unique incident groups* $O(G)$, not total input byte size ($G$ distinct error patterns retained in memory).
  - Benchmark (Python 3.14 on Windows, synthetic multi-group logs):
    - *Typical log stream (28.2 MB, ~72k traces, ~6.8k unique groups):* ~6.1 MB Python heap, ~36.5 MB Peak RSS (GATE-MEM-01B PASS).
    - *Adversarial high-cardinality stream (21.4 MB, ~54k traces, ~44.7k unique groups):* ~39.8 MB Python heap, ~106 MB Peak RSS (characterized in DEC-017).
  - Optional `--max-input-mb` backstop rejects oversized raw log files (default 100 MB, 0 disables).
- **Local Persistence & Export:**
  - WAL-mode SQLite storage for thread-safe concurrent writes and query performance.
  - Self-contained, single-file HTML reports with zero external CDN assets.
- **Semantic Exit Codes:** POSIX standard compliance (`0` = success/analysis complete, `1` = fatal I/O, `2` = invalid CLI invocation).

---

## Installation

### From PyPI (Recommended)
```bash
pip install pra-effect
```

Run directly via the registered console command:
```bash
pra-effect --help
```

Or run as a Python module (useful if user-installed scripts directory is not in your system PATH):
```bash
python -m pra_effect --help
```

### Standalone (Zero Install)
You can directly invoke the script without installation:
```bash
python pra_effect.py --help
```

### From Source (Editable / Development Mode)
```bash
git clone https://github.com/Genesis410/pra-effect.git
cd pra-effect
pip install -e .
```

---

## CLI Usage

Pra-Effect provides three primary commands: `ingest`, `scan`, and `history`.

### 1. Ingest via STDIN (Pipe Mode)
Pipe stdout or stderr from test runners, logs, or services directly into Pra-Effect:

```bash
# Direct pipe from a failing script
python app.py 2>&1 | pra-effect ingest

# Save run to SQLite and export an HTML dashboard
pytest 2>&1 | pra-effect ingest --save --html report.html

# Check installed version (must match pyproject + git tag)
pra-effect --version
```

### 2. Scan Existing Log Files
Analyze log dumps or application error logs on disk — a single file or a whole directory:

```bash
# Explicit file (must be readable, otherwise exit 1)
pra-effect scan /var/log/application.log --save --html report.html

# Directory scan: default pattern *.log,*.txt, comma-separated globs supported
pra-effect scan /var/log --pattern "*.log,*.txt,*.out"

# Files that cannot be read (binary/unreadable) are skipped with a warning on stderr.
# Exit 1 if zero readable files matched — never a silent "0 errors found".

# Input-size backstop (default 100 MB, streaming already bounds the pipeline; 0 disables)
pra-effect scan /var/log/huge --max-input-mb 250
```

### 3. Historical Incident Aggregation
Query grouped incident metrics stored in your local SQLite database:

```bash
pra-effect history
```

Example Output:
```text
=== Pra-Effect Historical Incident Groups ===
Fingerprint:  f9e160e1d88bbca1 (v1)
Runtime:      python
Error Type:   ValueError
Message:      bad <script>alert(1)</script>
Occurrences:  3 total across 2 runs
First Seen:   2026-10-24 16:30:00 UTC
Last Seen:    2026-10-24 16:45:12 UTC
```

### 4. Regression Diffing (CI Quality Gate)
Compare two test runs from SQLite history to detect newly introduced errors:

```bash
# Compare runs and fail build (exit code 2) if new incident groups appeared
pra-effect diff run_123 run_124 --fail-on-new
```

### 5. Diagnostics with Source Code Previews
Generate HTML report embedding 5-line source snippets around failing frames:

```bash
pra-effect scan /var/log/app.log --src ./src --html report.html
```

---

## Architecture & Data Flow

```text
Log Stream (STDIN / File)
       │
       ▼
Pre-check Sanitizer (4,096 char cutoff, ReDoS guard)
       │
       ▼
Grammar Parsers (Python Tracebacks / Node.js V8 Stacks)
       │
       ▼
Message Normalizer (UUID / hex / ID collapse — not PII redaction)
       │
       ▼
Fingerprint Engine (SHA-256 top-frame + message -> 16-hex ID)
       │
       ├─────────────────────────┬─────────────────────────┐
       ▼                         ▼                         ▼
Terminal ANSI Output       SQLite Storage (WAL)      HTML Dashboard
```

---

## Database & Schema

When `--save` is passed, runs are stored in `./.pra-effect/traces.db` (override via `--db <path>`):

- `runs`: Metadata per execution (duration, line counts, unique group count).
- `incidents`: Normalized error incidents linked by foreign keys, tracking `is_truncated`, occurrence counts, and project frames.
- `v_historical_incidents`: High-performance view aggregating cross-run recurrence.

---

## Testing

Run the included verification suite (standard `unittest` discovery, works from any directory):

```bash
python -m unittest discover -s . -p "test_*.py"
# or
python test_pra_effect.py
```

Memory benchmarks for release gates (`GATE-MEM-01A` streaming pipeline & `GATE-MEM-01B` realistic workload):

```bash
python bench_memory.py            # exit 0 = PASS (<= 50 MB Peak RSS), 1 = gate exceeded, 2 = RSS NOT_RUN
```

Benchmark & Performance Gates:
- **GATE-MEM-01A (Pipeline Ingestion Stream)**: Peak RSS $\le$ 35 MB, tracemalloc $<$ 1 MB. Empirically measured **24.36 MB Peak RSS** and **0.0047 MB tracemalloc** across 54,000+ tracebacks ($O(1)$ streaming ingestion).
- **GATE-MEM-01B (Realistic Workload End-to-End)**: Peak RSS $\le$ 50 MB on files $\ge$ 25 MB with realistic deduplication ($\le$ 10,000 unique groups). Empirically measured **36.50 MB Peak RSS** and **6.12 MB tracemalloc** on 28.2 MB / 72,316 tracebacks.
- **High-Cardinality Boundary**: In-memory grouping memory scales linearly $O(G)$ with unique error groups (~963 bytes per group with complete `representative_trace`). Peak RSS 50 MB is not guaranteed for adversarial logs where every single error is unique. `--max-input-mb` (default 100 MB) provides raw input byte capping.

Tests cover:
- Python & Node.js grouping and line drift resilience.
- Message normalization and hex address masking.
- ReDoS guard and bounded multiline collection.
- Interleaved non-trace log line tolerance.
- SQLite WAL mode and concurrent transaction safety.
- Single-file HTML generation with full XSS escaping on every rendered field, plus a PII notice (normalization is not redaction).
- Chained exception collapse, bounded message collector, directory scan `--pattern` with skip/exit semantics.
- Fingerprint version isolation in history queries (`FINGERPRINT_SPEC.md`).
- CLI exit codes (0, 1, 2).
- Streaming pipeline memory regression ($O(1)$ constant memory ingestion).
- Raw input file cap backstop (`--max-input-mb`).
- Golden CLI output parity (byte-identical across refactors).

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Genesis410/pra-effect&type=Date)](https://star-history.com/#Genesis410/pra-effect&Date)

---

## Release & Changelog

See [CHANGELOG.md](CHANGELOG.md) for the version history. Current release: `1.3.0`.

Version consistency across the package (`pyproject.toml`), the CLI (`--version`), and
the git tag is enforced by `test_release_version_consistency`.
