"""test_pra_effect.py - Verification suite for Pra-Effect grouping rules.

Runs two ways (TSK-010):
  python -m unittest discover -s <repo>
  python test_pra_effect.py
Both work from any working directory.
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent
SCRIPT = REPO_DIR / "pra_effect.py"
if str(REPO_DIR) not in sys.path:
    sys.path.insert(0, str(REPO_DIR))

from pra_effect import (
    FINGERPRINT_VERSION,
    TracebackParser,
    group_traces,
    normalize_message,
)

FIXTURE_PYTHON_LOG = """
INFO 2026-10-24 10:00:01 Starting service
Traceback (most recent call last):
  File "/app/src/parser.py", line 81, in parse_item
    val = process(item)
  File "/app/src/utils.py", line 12, in process
    raise ValueError("invalid item 9812 for request-id: 123e4567-e89b-12d3-a456-426614174000")
ValueError: invalid item 9812 for request-id: 123e4567-e89b-12d3-a456-426614174000

INFO 2026-10-24 10:00:02 Handling next
Traceback (most recent call last):
  File "/app/src/parser.py", line 106, in parse_item
    val = process(item)
  File "/app/src/utils.py", line 12, in process
    raise ValueError("invalid item 4173 for request-id: 987e6543-e21b-12d3-a456-426614174111")
ValueError: invalid item 4173 for request-id: 987e6543-e21b-12d3-a456-426614174111

INFO 2026-10-24 10:00:03 Critical failure
Traceback (most recent call last):
  File "/app/src/auth.py", line 45, in verify
    raise PermissionError("token expired at 0x7fff5fbff8a0")
PermissionError: token expired at 0x7fff5fbff8a0
"""

FIXTURE_NODE_LOG = """
Error: Failed to fetch user 12345
    at fetchUser (/app/src/api.js:42:15)
    at handleRequest (/app/src/server.js:88:9)
    at Layer.handle [as handle_request] (/app/node_modules/express/lib/router/layer.js:95:5)

Error: Failed to fetch user 67890
    at fetchUser (/app/src/api.js:50:15)
    at handleRequest (/app/src/server.js:88:9)
    at Layer.handle [as handle_request] (/app/node_modules/express/lib/router/layer.js:95:5)

TypeError: Cannot read properties of undefined (reading 'token')
    at authMiddleware (/app/src/auth.js:20:10)
    at processTicksAndRejections (internal/process/task_queues.js:95:5)
"""

# --- Phase 2 fixtures (TSK-007) ---
CHAIN_ROOT_ONLY_LOG = """Traceback (most recent call last):
  File "/app/src/api.py", line 55, in get_profile
    data = query(uid)
  File "/app/src/db.py", line 12, in query
    raise KeyError("user 42")
KeyError: failed to load profile
"""

CHAINED_PYTHON_LOG = """Traceback (most recent call last):
  File "/app/src/db.py", line 12, in query
    raise KeyError("user 42")
KeyError: user 42

During handling of the above exception, another exception occurred:

""" + CHAIN_ROOT_ONLY_LOG


def test_message_normalization():
    msg1 = "invalid item 9812 for request-id: 123e4567-e89b-12d3-a456-426614174000"
    norm1, trunc1 = normalize_message(msg1)
    assert not trunc1
    assert "<UUID>" in norm1
    assert "<ID>" in norm1 or "9812" in norm1

    msg_hex = "token expired at 0x7fff5fbff8a0"
    norm_hex, trunc_hex = normalize_message(msg_hex)
    assert not trunc_hex
    assert norm_hex == "token expired at <HEX>"

    # Numbers with different status codes must NOT be collapsed
    s1, _ = normalize_message("Connection failed with status 10000")
    s2, _ = normalize_message("Connection failed with status 20000")
    assert s1 != s2, "False merge: distinct status codes should not collapse"


def test_python_grouping_and_line_number_resilience():
    parser = TracebackParser(cwd=Path("/app"), src_dir=Path("/app/src"))
    traces = parser.parse_python_traces(FIXTURE_PYTHON_LOG)
    assert len(traces) == 3, f"Expected 3 traces, got {len(traces)}"

    # Traces 0 & 1 have different line numbers in parser.py (81 vs 106) and different UUIDs/IDs
    # but share same logical function chain and normalized message.
    # Check if they share the fingerprint
    groups = group_traces(traces)
    assert len(groups) == 2, f"Expected 2 unique groups (1 grouped ValueError + 1 PermissionError), got {len(groups)}"

    value_err_group = next(g for g in groups if g.error_type == "ValueError")
    assert value_err_group.occurrences == 2, "Line number difference must not prevent grouping of identical logic"


def test_node_grouping_and_vendor_exclusion():
    parser = TracebackParser(cwd=Path("/app"), src_dir=Path("/app/src"))
    traces = parser.parse_node_traces(FIXTURE_NODE_LOG)
    assert len(traces) == 3, f"Expected 3 traces, got {len(traces)}"

    # node_modules and internal/process must be marked is_in_project = False
    for t in traces:
        for f in t.frames:
            if "node_modules" in f.filepath or "internal/" in f.filepath:
                assert not f.is_in_project, f"Vendor frame falsely marked as in-project: {f.filepath}"

    groups = group_traces(traces)
    assert len(groups) == 2, f"Expected 2 groups (1 grouped Error + 1 TypeError), got {len(groups)}"
    err_group = next(g for g in groups if g.error_type == "Error")
    assert err_group.occurrences == 2


def test_sqlite_and_html():
    from pra_effect import (
        save_run_to_db,
        query_historical_incidents,
        query_recent_runs,
        generate_html_report,
    )
    import tempfile
    import sqlite3

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_traces.db"
        parser = TracebackParser()
        traces = parser.parse_all(FIXTURE_PYTHON_LOG + "\n" + FIXTURE_NODE_LOG)
        groups = group_traces(traces)

        # Run 1
        run1_id = save_run_to_db(
            db_path=db_path,
            command="scan",
            total_lines=37,
            total_exceptions=len(traces),
            duration_ms=12.5,
            groups=groups,
        )
        assert run1_id == 1

        # Run 2 (same incidents to verify historical aggregation)
        run2_id = save_run_to_db(
            db_path=db_path,
            command="ingest",
            total_lines=37,
            total_exceptions=len(traces),
            duration_ms=8.4,
            groups=groups,
        )
        assert run2_id == 2

        hist = query_historical_incidents(db_path)
        assert len(hist) == len(groups)
        # Total occurrences should be doubled across 2 runs
        for item in hist:
            assert item["total_runs_seen"] == 2
            assert item["total_seen_count"] > 1

        runs = query_recent_runs(db_path)
        assert len(runs) == 2

        # Verify WAL mode enabled
        conn = sqlite3.connect(str(db_path))
        journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert journal_mode.lower() == "wal", f"Expected wal mode, got {journal_mode}"
        conn.close()

        # HTML generation check
        html_doc = generate_html_report(37, len(traces), groups, 0.01)
        assert "<!DOCTYPE html>" in html_doc
        assert "filterIncidents()" in html_doc
        assert "copyTrace(" in html_doc
        assert "&lt;UUID&gt;" in html_doc or "<UUID>" not in html_doc  # escaped or not raw HTML injection


def test_multiline_collector():
    multiline_py = '''Traceback (most recent call last):
  File "/app/src/validator.py", line 18, in validate_payload
    raise ValidationError("Validation failed:")
ValidationError: Validation failed:
  Field 'username': cannot be empty
  Field 'age': must be greater than 18
  Field 'email': invalid format
2026-10-24 10:00:00 INFO Processing next
'''
    parser = TracebackParser(cwd=Path("/app"))
    traces = parser.parse_python_traces(multiline_py)
    assert len(traces) == 1
    assert "Field 'username'" in traces[0].original_message
    assert "invalid format" in traces[0].original_message
    # Bounded collector boundary (TSK-007): log lines never join the message
    assert "Processing next" not in traces[0].original_message


def test_line_length_truncation_redos():
    # Long message line exceeding 4096 characters
    giant_msg = "Error: " + ("a" * 10000)
    norm, trunc = normalize_message(giant_msg)
    assert trunc is True
    assert len(norm) <= 4096

    # Test parser on trace with 50,000 char line - must finish quickly without hanging
    import time
    long_line = " " * 4 + "x = " + ("9" * 50000)
    fake_log = f"""Traceback (most recent call last):
  File "/app/src/slow.py", line 10, in run
{long_line}
RuntimeError: oversized line test
"""
    parser = TracebackParser(cwd=Path("/app"))
    t0 = time.time()
    traces = parser.parse_python_traces(fake_log)
    elapsed = time.time() - t0
    assert elapsed < 0.1, f"Parsing took too long ({elapsed:.3f}s), possible ReDoS or unbuffered processing"
    assert len(traces) == 1
    assert traces[0].is_truncated is True
    groups = group_traces(traces)
    assert groups[0].is_truncated is True


def test_interleaving_tolerance():
    # Python traceback with 2 interleaved worker log lines between frames
    interleaved_py = """Traceback (most recent call last):
  File "/app/src/worker.py", line 40, in handle
    val = execute(task)
[worker-2] Heartbeat OK
[worker-3] Cache refreshed
  File "/app/src/db.py", line 15, in execute
    cursor.query()
ConnectionError: DB unreachable
"""
    parser = TracebackParser(cwd=Path("/app"))
    traces = parser.parse_python_traces(interleaved_py)
    assert len(traces) == 1, f"Expected 1 trace, got {len(traces)}"
    assert len(traces[0].frames) == 2
    # The interleaved lines must NOT be in raw_text or frames
    assert "[worker-2]" not in traces[0].raw_text
    assert "[worker-3]" not in traces[0].raw_text

    # Node traceback with 1 interleaved log line
    interleaved_node = """Error: Request timed out
    at Timeout._onTimeout (/app/src/net.js:55:10)
2026-10-24 10:12:00 [http] GET /health 200 OK
    at listOnTimeout (internal/timers.js:554:17)
"""
    node_traces = parser.parse_node_traces(interleaved_node)
    assert len(node_traces) == 1, f"Expected 1 node trace, got {len(node_traces)}"
    assert len(node_traces[0].frames) == 2
    assert "GET /health" not in node_traces[0].raw_text


def test_exit_codes():
    # 1. Valid execution with errors -> Exit 0
    p0 = subprocess.run(
        [sys.executable, str(SCRIPT), "ingest"],
        input=FIXTURE_PYTHON_LOG,
        text=True,
        capture_output=True,
        cwd=str(REPO_DIR),
    )
    assert p0.returncode == 0, f"Expected exit 0 on valid ingest, got {p0.returncode}"

    # 2. File not found -> Exit 1
    p1 = subprocess.run(
        [sys.executable, str(SCRIPT), "scan", "non_existent_log_file_12345.log"],
        capture_output=True,
        cwd=str(REPO_DIR),
    )
    assert p1.returncode == 1, f"Expected exit 1 on missing file, got {p1.returncode}"

    # 3. Invalid CLI args -> Exit 2
    p2 = subprocess.run(
        [sys.executable, str(SCRIPT), "--invalid-unknown-flag"],
        capture_output=True,
        cwd=str(REPO_DIR),
    )
    assert p2.returncode == 2, f"Expected exit 2 on CLI parse error, got {p2.returncode}"


# --- Phase 2 tests (TSK-007..TSK-012) ---


def test_chained_exception_single_root_incident():
    """DEC-011: outermost exception is the incident; causes stay diagnostic context."""
    parser = TracebackParser(cwd=Path("/app"), src_dir=Path("/app"))
    traces = parser.parse_python_traces(CHAINED_PYTHON_LOG)
    assert len(traces) == 1, f"Chained block must collapse to 1 root incident, got {len(traces)}"

    root = traces[0]
    assert root.error_type == "KeyError"
    # Root identity = outermost exception message only
    assert root.normalized_message == "failed to load profile", root.normalized_message
    # Cause kept as context in raw_text (rendered), never in the payload
    assert "During handling of the above exception" in root.raw_text
    assert "KeyError: user 42" in root.raw_text

    isolated = parser.parse_python_traces(CHAIN_ROOT_ONLY_LOG)[0]
    assert root.fingerprint == isolated.fingerprint, (
        "Root fingerprint must not change when cause details change"
    )
    assert len(group_traces(traces)) == 1


def test_collector_stops_at_log_lines():
    text = '''Traceback (most recent call last):
  File "/app/src/x.py", line 3, in run
    boom()
RuntimeError: connection lost
2026-10-24 10:00:00 INFO service recovered
DEBUG worker pool refilled
'''
    parser = TracebackParser(cwd=Path("/app"))
    traces = parser.parse_python_traces(text)
    assert len(traces) == 1
    assert "recovered" not in traces[0].original_message
    assert "refilled" not in traces[0].original_message


def test_scan_pattern_and_skip_policy():
    """DEC-012: --pattern globbing, binary/unreadable skip, explicit failure signals."""
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        (tdp / "a.log").write_text(FIXTURE_PYTHON_LOG, encoding="utf-8")
        (tdp / "b.txt").write_text("INFO healthy run\n", encoding="utf-8")
        (tdp / "c.log").write_bytes(b"\x00\x01binary payload")

        # Directory scan: binary skipped with stderr warning, readable files analyzed -> 0
        p = subprocess.run(
            [sys.executable, str(SCRIPT), "scan", str(tdp)],
            capture_output=True, text=True, cwd=str(REPO_DIR),
        )
        assert p.returncode == 0, f"dir scan should succeed, got {p.returncode}: {p.stderr}"
        assert "skipped" in p.stderr and "binary" in p.stderr, p.stderr

        # Explicit binary file target -> hard failure 1
        p1 = subprocess.run(
            [sys.executable, str(SCRIPT), "scan", str(tdp / "c.log")],
            capture_output=True, text=True, cwd=str(REPO_DIR),
        )
        assert p1.returncode == 1, f"explicit unreadable file must exit 1, got {p1.returncode}"
        assert "cannot read" in p1.stderr

        # --pattern custom glob with no match -> explicit failure, not silent empty success
        p2 = subprocess.run(
            [sys.executable, str(SCRIPT), "scan", str(tdp), "--pattern", "*.md"],
            capture_output=True, text=True, cwd=str(REPO_DIR),
        )
        assert p2.returncode == 1, f"zero readable files must exit 1, got {p2.returncode}"
        assert "no readable log files" in p2.stderr, p2.stderr

        # --pattern selects only *.txt
        p3 = subprocess.run(
            [sys.executable, str(SCRIPT), "scan", str(tdp), "--pattern", "*.txt"],
            capture_output=True, text=True, cwd=str(REPO_DIR),
        )
        assert p3.returncode == 0, p3.stderr
        assert "ValueError" not in p3.stdout, "*.txt pattern must not read a.log"


def test_html_escapes_all_trace_fields():
    """DEC-013: every rendered token is escaped; disclaimer present."""
    from pra_effect import IncidentGroup, generate_html_report

    xss = "<script>alert(1)</script>"
    g = IncidentGroup(
        fingerprint="abc123def456",
        runtime="python",
        error_type=f"Error{xss}",
        normalized_message=xss,
        occurrences=3,
        representative_trace=f'  File "{xss}", line 1, in run_{xss}\n{xss}',
        project_locations=[f"{xss}:1"],
    )
    doc = generate_html_report(10, 1, [g], 0.01)
    import html as html_mod
    assert xss not in doc, "Raw XSS payload leaked into HTML output"
    assert html_mod.escape(xss) in doc, "Escaped form missing"
    assert "PII redaction" in doc, "PII disclaimer footer missing"


def test_golden_cli_parity():
    """TSK-015: streaming refactor must be byte-identical to the v0.2 baseline.

    Baselines in golden/ were captured from the pre-streaming implementation
    (duration scrubbed). Covers: mixed ingest, chained collapse, python-then-
    node ordering on reversed input, CRLF files, multi-file dir scan with the
    legacy join line-count artifacts, and binary skip warnings.
    """
    import re
    gold = REPO_DIR / "golden"

    def scrub(s):
        return re.sub(r"(Duration:\s+)[\d.]+ms", r"\1<TIME>", s)

    ingest_cases = {
        "g1_ingest_mixed.txt": "mixed.log",
        "g2_ingest_chained.txt": "chained.log",
        "g3_ingest_reversed.txt": "reversed.log",
    }
    for out_name, in_name in ingest_cases.items():
        p = subprocess.run(
            [sys.executable, str(SCRIPT), "ingest"],
            input=(gold / in_name).read_text(encoding="utf-8"),
            text=True, capture_output=True, cwd=str(REPO_DIR),
        )
        assert p.returncode == 0, (out_name, p.stderr)
        want = (gold / out_name).read_text(encoding="utf-8")
        assert scrub(p.stdout) == want, f"stdout drift vs baseline: {out_name}"

    scan_cases = {
        "g4_scan_crlf.txt": ["scan", str(gold / "crlf.log")],
        "g5_scan_dir.txt": ["scan", str(gold / "dir")],
        "g6_scan_mixed.txt": ["scan", str(gold / "mixed.log")],
    }
    for out_name, argv in scan_cases.items():
        p = subprocess.run(
            [sys.executable, str(SCRIPT)] + argv,
            text=True, capture_output=True, cwd=str(REPO_DIR),
        )
        assert p.returncode == 0, (out_name, p.stderr)
        want = (gold / out_name).read_text(encoding="utf-8")
        assert scrub(p.stdout) == want, f"stdout drift vs baseline: {out_name}"
        err_file = gold / (out_name + ".stderr")
        if err_file.exists():
            assert p.stderr.strip() == err_file.read_text(encoding="utf-8").strip(), (
                f"stderr drift vs baseline: {out_name}"
            )


def test_max_input_mb_backstop():
    """DEC-016: --max-input-mb rejects oversized input with exit 1."""
    p = subprocess.run(
        [sys.executable, str(SCRIPT), "ingest", "--max-input-mb", "0.00001"],
        input=FIXTURE_PYTHON_LOG, text=True, capture_output=True, cwd=str(REPO_DIR),
    )
    assert p.returncode == 1, f"expected exit 1 on cap violation, got {p.returncode}"
    assert "max-input-mb" in p.stderr, p.stderr
    assert "Pra-Effect — Analysis Complete" not in p.stdout, "no report on rejected input"

    # Cap disabled with 0 -> normal success
    p2 = subprocess.run(
        [sys.executable, str(SCRIPT), "ingest", "--max-input-mb", "0"],
        input=FIXTURE_PYTHON_LOG, text=True, capture_output=True, cwd=str(REPO_DIR),
    )
    assert p2.returncode == 0, p2.stderr


def test_fingerprint_version_isolation():
    """TSK-012: foreign fingerprint versions never leak into aggregated history."""
    from pra_effect import init_db, query_historical_incidents, save_run_to_db

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_traces.db"
        parser = TracebackParser()
        traces = parser.parse_all(FIXTURE_PYTHON_LOG)
        groups = group_traces(traces)
        save_run_to_db(
            db_path=db_path, command="scan", total_lines=10,
            total_exceptions=len(traces), duration_ms=5.0, groups=groups,
        )

        # Inject a future-version row directly (simulates post-migration data)
        conn = init_db(db_path)
        with conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO runs (timestamp_utc, command, total_lines, total_exceptions,"
                " unique_groups, duration_ms, fingerprint_version)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("2030-01-01T00:00:00+00:00", "scan", 1, 1, 1, 1.0, "fingerprint_v2"),
            )
            cur.execute(
                "INSERT INTO incidents (run_id, fingerprint, fingerprint_version, runtime,"
                " error_type, normalized_message, occurrences, representative_trace,"
                " project_locations_json, is_truncated)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (cur.lastrowid, "feedfacefeedface", "fingerprint_v2", "python",
                 "ValueError", "from the future", 1, "trace", "[]", 0),
            )
        conn.close()

        hist = query_historical_incidents(db_path)
        assert hist, "v1 history must still be visible"
        versions = {h["fingerprint_version"] for h in hist}
        assert versions == {FINGERPRINT_VERSION}, f"version leak: {versions}"
        assert not any(h["fingerprint"] == "feedfacefeedface" for h in hist)


class TestPraEffect(unittest.TestCase):
    """unittest bridge so `python -m unittest discover` runs the same suite."""

    def test_message_normalization(self):
        test_message_normalization()

    def test_python_grouping_and_line_number_resilience(self):
        test_python_grouping_and_line_number_resilience()

    def test_node_grouping_and_vendor_exclusion(self):
        test_node_grouping_and_vendor_exclusion()

    def test_sqlite_and_html(self):
        test_sqlite_and_html()

    def test_multiline_collector(self):
        test_multiline_collector()

    def test_line_length_truncation_redos(self):
        test_line_length_truncation_redos()

    def test_interleaving_tolerance(self):
        test_interleaving_tolerance()

    def test_exit_codes(self):
        test_exit_codes()

    def test_chained_exception_single_root_incident(self):
        test_chained_exception_single_root_incident()

    def test_collector_stops_at_log_lines(self):
        test_collector_stops_at_log_lines()

    def test_scan_pattern_and_skip_policy(self):
        test_scan_pattern_and_skip_policy()

    def test_html_escapes_all_trace_fields(self):
        test_html_escapes_all_trace_fields()

    def test_fingerprint_version_isolation(self):
        test_fingerprint_version_isolation()

    def test_golden_cli_parity(self):
        test_golden_cli_parity()

    def test_max_input_mb_backstop(self):
        test_max_input_mb_backstop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
