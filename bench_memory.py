"""bench_memory.py - GATE-MEM-01 memory benchmark (TSK-011 / DEC-014 / TSK-013).

Two phases in separate processes so Peak RSS measures the streaming pipeline
alone and never the fixture builder:

  python bench_memory.py [target_mb]   # parent: build temp log, spawn child, relay gate
  python bench_memory.py --child FILE   # child: stream-parse FILE, report + gate

The synthetic input generator is byte-identical to the pre-streaming baseline
run (2026-10-24: tracemalloc 88.6 MB, Peak RSS 303.3 MB, 85.12s) so before/
after numbers stay comparable. Gate: peak RSS <= 50 MB on a ~21 MB input.

Exit: 0 = PASS, 1 = gate exceeded, 2 = RSS unavailable (NOT_RUN)
"""

import ctypes
import subprocess
import sys
import tempfile
import time
import tracemalloc
from ctypes import wintypes
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_DIR))

GATE_MB = 50

BLOCK = """INFO 2026-10-24 10:00:01 handling request {n}
Traceback (most recent call last):
  File "/app/src/api.py", line {l}, in handle_request
    payload = process(item_{n})
  File "/app/src/worker.py", line {l2}, in process
    raise ValueError("invalid item {n} for request-id: 123e4567-e89b-12d3-a456-{u:012d}")
ValueError: invalid item {n} for request-id: 123e4567-e89b-12d3-a456-{u:012d}

"""


def peak_rss_bytes():
    """Process Peak Working Set. Returns None when unavailable (NOT_RUN)."""
    if sys.platform != "win32":
        return None  # ponytail: POSIX path uses resource.getrusage; add when benching on Linux

    class PMC(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    counters = PMC()
    counters.cb = ctypes.sizeof(PMC)
    handle = ctypes.windll.kernel32.GetCurrentProcess()
    psapi = ctypes.windll.psapi
    psapi.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    ok = psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb)
    return counters.PeakWorkingSetSize if ok else None


def build_log(target_mb: float) -> str:
    """Byte-identical to baseline generator with valid 12-hex UUID tail."""
    block = BLOCK.format(n=1, l=42, l2=17, u=1)
    repeats = int((target_mb * 1024 * 1024) // len(block)) + 1
    # Vary ids per block so grouping work is representative (not one giant duplicate)
    parts = [
        BLOCK.format(
            n=i,
            l=40 + (i % 900),
            l2=10 + (i % 300),
            u=i % 1_000_000_000_000,
        )
        for i in range(repeats)
    ]
    return "".join(parts)


def run_child(path: Path) -> int:
    """Parse phase: the exact streaming pipeline the CLI uses (scan <file>)."""
    from pra_effect import iter_scan_lines, stream_analyze

    rss_start = peak_rss_bytes()
    tracemalloc.start()
    t0 = time.perf_counter()
    total_lines, total_exceptions, groups = stream_analyze(
        iter_scan_lines(path, "*.log"), REPO_DIR, None, None
    )
    elapsed = time.perf_counter() - t0
    py_peak, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    rss_peak = peak_rss_bytes()

    print(
        f"Parse+group (streaming): {elapsed:.2f}s, {total_lines:,} lines, "
        f"{total_exceptions:,} traces, {len(groups):,} groups"
    )
    print(f"tracemalloc peak: {py_peak / 1024 / 1024:.1f} MB (Python allocations only)")
    if rss_peak is None:
        print("Peak RSS: NOT_RUN (platform API unavailable) — gate not evaluated")
        return 2
    print(
        f"Peak RSS: {rss_peak / 1024 / 1024:.1f} MB "
        f"(at parse start: {(rss_start or 0) / 1024 / 1024:.1f} MB)"
    )

    if rss_peak <= GATE_MB * 1024 * 1024:
        print(f"GATE-MEM-01: PASS (<= {GATE_MB} MB)")
        return 0
    print(f"GATE-MEM-01: FAIL ({rss_peak / 1024 / 1024:.1f} MB > {GATE_MB} MB)")
    return 1


def main() -> int:
    if len(sys.argv) >= 3 and sys.argv[1] == "--child":
        return run_child(Path(sys.argv[2]))

    target_mb = float(sys.argv[1]) if len(sys.argv) > 1 else 20.0
    print(
        f"Pra-Effect GATE-MEM-01: target input {target_mb:.0f} MB, "
        f"gate <={GATE_MB} MB peak RSS"
    )

    text = build_log(target_mb)
    actual_mb = len(text) / (1024 * 1024)
    n_tb = text.count("Traceback")
    print(f"Synthetic log built: {actual_mb:.1f} MB, {n_tb:,} tracebacks")

    with tempfile.NamedTemporaryFile(
        "w", suffix=".log", delete=False, encoding="utf-8", dir=str(REPO_DIR)
    ) as tf:
        tf.write(text)
        tmp_path = Path(tf.name)
    try:
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--child", str(tmp_path)],
            text=True,
            capture_output=True,
            cwd=str(REPO_DIR),
        )
        sys.stdout.write(proc.stdout)
        if proc.stderr.strip():
            sys.stderr.write(proc.stderr)
        return proc.returncode
    finally:
        tmp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
