# Pra-Effect

> Zero-dependency local CLI for parsing, deduplicating, and fingerprinting Python & Node.js error stack traces with sub-second execution, ReDoS resilience, SQLite persistence, and standalone HTML reporting.

[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)]()

---

## Highlights

- **Zero Third-Party Dependencies:** Pure Python standard library (`argparse`, `hashlib`, `html`, `re`, `sqlite3`, `pathlib`).
- **Resilient Fingerprinting (`fingerprint_v1`):** Normalizes dynamic memory addresses (`0x7f...`), variable line numbers, timestamps, UUIDs, and ephemeral ports so identical incidents aggregate into one canonical hash.
- **Dual Runtime Support:** Natively parses Python tracebacks (standard, chained exceptions, multiline messages) and Node.js call stacks (V8 engine).
- **Robust Input Handling:**
  - Hard line truncation at 4,096 characters to prevent catastrophic regex backtracking (ReDoS).
  - Interleaving tolerance up to 2 lines of interleaved non-trace log noise.
  - Bounded message collection: log lines (`INFO ...`, timestamps) never leak into an error message.
  - Chained Python exceptions collapse to a single root incident (causes kept as diagnostic context, never split the fingerprint).
- **Local Persistence & Export:**
  - WAL-mode SQLite storage for thread-safe concurrent writes and query performance.
  - Self-contained, single-file HTML reports with zero external CDN assets.
- **Semantic Exit Codes:** POSIX standard compliance (`0` = success/analysis complete, `1` = fatal I/O, `2` = invalid CLI invocation).

---

## Installation

### From Source (Editable / Tool Mode)
```bash
git clone https://github.com/Genesis410/pra-effect.git
cd pra-effect
pip install -e .
```

### Standalone (Zero Install)
You can directly invoke the script without installation:
```bash
python pra_effect.py --help
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

Memory benchmark for the release gate (`GATE-MEM-01`, ~21 MB synthetic log):

```bash
python bench_memory.py            # exit 0 = PASS, 1 = gate exceeded, 2 = RSS NOT_RUN
```

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

---

## License

MIT License. See [LICENSE](LICENSE) for details.
