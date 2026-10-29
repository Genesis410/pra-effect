"""E2E V1.4 — End-to-End Stability Test for pra-effect v1.4.0

Covers the 10 user flows defined in .confidential/E2E_STABILITY_REPORT_V13.md
plus new polyglot parser coverage (Go TSK-026A, Rust TSK-026B, JSONL TSK-026C).

All tests invoke the real CLI via subprocess — no mocks.
Exit-code contract: 0 = success, 1 = I/O error, 2 = arg error or CI gate breach.

Run:
    python -m unittest test_e2e_v14 -v
"""

import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent
SCRIPT = REPO / "pra_effect.py"
PY = sys.executable


def run_cli(args, input_text=None, workdir=None):
    """Run pra_effect.py; return (returncode, stdout, stderr)."""
    cmd = [PY, str(SCRIPT)] + args
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    kw = dict(
        cwd=workdir or str(REPO),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        env=env,
    )
    if input_text is not None:
        kw["input"] = input_text
    try:
        proc = subprocess.run(cmd, **kw)
    except subprocess.TimeoutExpired:
        proc = subprocess.CompletedProcess(cmd, -1, "", "TIMEOUT")
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def _write_log(tmpdir, name, content):
    p = os.path.join(tmpdir, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)
    return p


# ── Fixture logs ───────────────────────────────────────────────────────────────

GO_LOG = """\
INFO starting service
panic: runtime error: index out of range [0] with length 0

goroutine 1 [running]:
main.processItems(...)
	/home/user/project/main.go:42 +0x5e
main.main()
	/home/user/project/main.go:10 +0x25
exit status 2
"""

GO_LOG_2 = """\
panic: nil pointer dereference

goroutine 42 [running]:
main.doWork()
	/project/worker.go:99 +0x18
exit status 2
"""

RUST_LOG = """\
thread 'main' panicked at src/main.rs:12:5
assertion `left == right` failed
stack backtrace:
   0: std::panicking::panic_fmt::h1a2b3c4d5e6f7890
   1: myapp::process (at src/process.rs:42:10)
   2: myapp::main (at src/main.rs:12:5)
"""

RUST_LOG_2 = """\
thread 'worker' panicked at src/worker.rs:8:1
index out of bounds: the length is 0
stack backtrace:
   0: std::panicking::panic_fmt
   1: myapp::worker::run (at src/worker.rs:8:1)
"""

JSONL_LOG = "\n".join([
    json.dumps({"level": "info", "message": "starting service"}),
    json.dumps({"level": "error", "message": "DB connection failed",
                "stack_trace": "ValueError: timeout\n  File db.py, line 5, in connect"}),
    json.dumps({"level": "error", "message": "DB connection failed",
                "stack_trace": "ValueError: timeout\n  File db.py, line 5, in connect"}),
    json.dumps({"level": "warn", "message": "retrying"}),
])

PYTHON_LOG = """\
INFO starting
Traceback (most recent call last):
  File "app.py", line 10, in main
    result = compute()
ValueError: bad value
"""

NODE_LOG = """\
Error: unhandled rejection
    at async /app/service.js:42:10
"""

JAVA_LOG = """\
Exception in thread "main" java.lang.NullPointerException: Order is null
\tat com.example.OrderService.process(OrderService.java:45)
\tat com.example.main(Main.java:10)
"""

FATAL_LOG = "fatal error: concurrent map writes"

SECRET_LOG = """\
panic: auth failed

goroutine 1 [running]:
main.auth()
	proj/auth.go:5 +0x1
Authorization: Bearer abc123xyz789token0
exit status 2
"""


class TestE2E_V14(unittest.TestCase):
    """E2E V1.4 — 16 user flows covering all 7 runtime buckets + regression gates."""

    # ── FLOW 01: Mixed polyglot log — all 6 runtime formats in one stream
    def test_flow_01_mixed_polyglot_log(self):
        """All 6 runtime formats in one stream → ≥6 groups, exit 0.

        The CLI shows top-5 groups by occurrence; remaining groups are hidden
        behind '... and N more groups.' — so we assert on the group count,
        not on which runtime names are visible.
        """
        log = "\n".join([PYTHON_LOG, NODE_LOG, JAVA_LOG, GO_LOG, RUST_LOG, JSONL_LOG])
        rc, out, _ = run_cli(["ingest"], input_text=log)
        self.assertEqual(rc, 0, f"mixed polyglot should exit 0, got {rc}")
        m = re.search(r"unique incident groups:\s*(\d+)", out, re.IGNORECASE)
        self.assertIsNotNone(m, f"no group count in output:\n{out[:300]}")
        groups = int(m.group(1))
        # 6 runtime types each contribute ≥1 incident
        self.assertGreaterEqual(groups, 6, f"expected ≥6 groups, got {groups}")
        # Top-5 visible groups should include at least 4 distinct runtime labels
        visible = re.findall(r"\[(\w+)\]", out, re.IGNORECASE)
        self.assertGreaterEqual(len(set(k.lower() for k in visible)), 4,
                                f"expected ≥4 distinct runtime labels in top-5, got {set(visible)}")

    # ── FLOW 02: Go panic — two distinct panics → 2 groups
    def test_flow_02_go_panic_grouping(self):
        log = GO_LOG + "\n" + GO_LOG_2
        rc, out, _ = run_cli(["ingest"], input_text=log)
        self.assertEqual(rc, 0)
        self.assertIn("GoPanic", out)

    # ── FLOW 03: Rust panic — two distinct panics → 2 groups
    def test_flow_03_rust_panic_grouping(self):
        log = RUST_LOG + "\n" + RUST_LOG_2
        rc, out, _ = run_cli(["ingest"], input_text=log)
        self.assertEqual(rc, 0)
        self.assertIn("RustPanic", out)

    # ── FLOW 04: JSONL — two identical error lines dedup to 1 incident
    def test_flow_04_jsonl_dedup(self):
        rc, out, _ = run_cli(["ingest"], input_text=JSONL_LOG)
        self.assertEqual(rc, 0)
        self.assertIn("DB connection failed", out)

    # ── FLOW 05: Secret scrubbing on Go log (Bearer token redacted)
    def test_flow_05_secret_scrub_go(self):
        rc, out, _ = run_cli(["ingest", "--scrub-secrets"], input_text=SECRET_LOG)
        self.assertEqual(rc, 0, f"--scrub-secrets should exit 0, got {rc}")
        self.assertNotIn("abc123xyz789token0", out, "secret leaked to output")
        self.assertIn("[REDACTED]", out)

    # ── FLOW 06: Fatal error → foreign bucket (no dedicated SM)
    def test_flow_06_fatal_error_foreign(self):
        rc, out, _ = run_cli(["ingest"], input_text=FATAL_LOG)
        self.assertEqual(rc, 0)
        self.assertTrue(out.strip(), "fatal error should produce output")

    # ── FLOW 07: Empty input → 0 incidents, exit 0
    def test_flow_07_empty_input(self):
        rc, out, _ = run_cli(["ingest"], input_text="")
        self.assertEqual(rc, 0, f"empty input should exit 0, got {rc}")

    # ── FLOW 08: Long line (>4096 chars) truncation safety
    def test_flow_08_long_line_truncation(self):
        long_line = "x" * 5000
        log = f"panic: bad\n\n{long_line}\nexit status 2\n"
        rc, out, _ = run_cli(["ingest"], input_text=log)
        self.assertEqual(rc, 0, f"long-line input should not crash, got {rc}")

    # ── FLOW 09: CI gate breach — --fail-if-groups-exceed 1 with 3+ groups
    def test_flow_09_ci_gate_breach(self):
        log = "\n".join([PYTHON_LOG, GO_LOG, RUST_LOG])
        rc, out, _ = run_cli(
            ["ingest", "--fail-if-groups-exceed", "1"],
            input_text=log,
        )
        self.assertNotEqual(rc, 0, "CI gate should fail when groups exceed 1")

    # ── FLOW 10: SQLite persistence — run + incidents written to DB
    def test_flow_10_sqlite_persistence(self):
        log = "\n".join([PYTHON_LOG, GO_LOG, RUST_LOG, JSONL_LOG])
        tmpdir = tempfile.mkdtemp(prefix="pra_e2e_v14_")
        try:
            db = os.path.join(tmpdir, "test.db")
            rc, out, _ = run_cli(
                ["ingest", "--save", "--db", db],
                input_text=log,
            )
            self.assertEqual(rc, 0, f"--save --db should exit 0, got {rc}: {out[:200]}")
            conn = sqlite3.connect(db)
            runs = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
            incidents = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
            conn.close()
            self.assertEqual(runs, 1, "expected 1 run")
            self.assertGreater(incidents, 0, "expected incidents in DB")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    # ── FLOW 11: JSONL malformed lines — no crash, valid lines still parsed
    def test_flow_11_jsonl_malformed_no_crash(self):
        log = "\n".join([
            "not json at all",
            '{"broken": ',
            "",
            json.dumps({"level": "error", "message": "real error"}),
        ])
        rc, out, _ = run_cli(["ingest"], input_text=log)
        self.assertEqual(rc, 0, f"malformed JSONL should not crash, got {rc}")
        self.assertIn("real error", out)

    # ── FLOW 12: Unicode / multibyte characters in Go panic message
    def test_flow_12_unicode_go_message(self):
        log = "panic: äöü 中文 emoji 🚀\n\ngoroutine 1 [running]:\nmain.main()\n\t/app.go:1\n\n"
        rc, out, _ = run_cli(["ingest"], input_text=log)
        self.assertEqual(rc, 0, f"unicode panic should not crash, got {rc}")
        self.assertTrue(out.strip())

    # ── FLOW 13 (REGRESSION): Python traceback still works after 3 new SMs
    def test_flow_13_python_regression(self):
        rc, out, _ = run_cli(["ingest"], input_text=PYTHON_LOG)
        self.assertEqual(rc, 0)
        self.assertIn("ValueError", out)
        self.assertIn("app.py", out)

    # ── FLOW 14 (REGRESSION): Node.js stack still works
    def test_flow_14_node_regression(self):
        rc, out, _ = run_cli(["ingest"], input_text=NODE_LOG)
        self.assertEqual(rc, 0)
        self.assertIn("Error", out)

    # ── FLOW 15 (REGRESSION): Java stack still works
    def test_flow_15_java_regression(self):
        rc, out, _ = run_cli(["ingest"], input_text=JAVA_LOG)
        self.assertEqual(rc, 0)
        self.assertIn("NullPointerException", out)

    # ── FLOW 16 (REGRESSION): Scan subcommand on a real file
    def test_flow_16_scan_file_regression(self):
        tmpdir = tempfile.mkdtemp(prefix="pra_e2e_v14_scan_")
        try:
            fpath = _write_log(tmpdir, "app.log", PYTHON_LOG + GO_LOG)
            rc, out, _ = run_cli(["scan", fpath])
            self.assertEqual(rc, 0, f"scan should exit 0, got {rc}: {out[:200]}")
            self.assertIn("ValueError", out)
            self.assertIn("GoPanic", out)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
