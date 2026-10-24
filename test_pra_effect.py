"""test_pra_effect.py - Verification suite for Pra-Effect grouping rules."""

from pathlib import Path
from pra_effect import (
    TracebackParser,
    group_traces,
    normalize_message,
    normalize_frame_path,
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
    import subprocess
    import sys
    py_exec = sys.executable

    # 1. Valid execution with errors -> Exit 0
    p0 = subprocess.run(
        [py_exec, "pra_effect.py", "ingest"],
        input=FIXTURE_PYTHON_LOG,
        text=True,
        capture_output=True,
    )
    assert p0.returncode == 0, f"Expected exit 0 on valid ingest, got {p0.returncode}"

    # 2. File not found -> Exit 1
    p1 = subprocess.run(
        [py_exec, "pra_effect.py", "scan", "non_existent_log_file_12345.log"],
        capture_output=True,
    )
    assert p1.returncode == 1, f"Expected exit 1 on missing file, got {p1.returncode}"

    # 3. Invalid CLI args -> Exit 2
    p2 = subprocess.run(
        [py_exec, "pra_effect.py", "--invalid-unknown-flag"],
        capture_output=True,
    )
    assert p2.returncode == 2, f"Expected exit 2 on CLI parse error, got {p2.returncode}"


if __name__ == "__main__":
    test_message_normalization()
    test_python_grouping_and_line_number_resilience()
    test_node_grouping_and_vendor_exclusion()
    test_sqlite_and_html()
    test_multiline_collector()
    test_line_length_truncation_redos()
    test_interleaving_tolerance()
    test_exit_codes()
    print("ALL TESTS PASSED.")
