"""bench_memory.py - GATE-MEM-01 memory benchmark (TSK-011 / DEC-014).

Synthesizes a ~20 MB Python traceback log, runs the real parse+group pipeline
in-process, and reports BOTH tracemalloc peak (Python allocations) and process
Peak Working Set (RSS). Gate: peak RSS <= 50 MB on a 20 MB input.

Usage:
    python bench_memory.py [target_mb]
Exit: 0 = PASS, 1 = gate exceeded (evaluate streaming parser before v1.0), 2 = RSS unavailable (NOT_RUN)
"""

import ctypes
import os
import sys
import time
import tracemalloc
from ctypes import wintypes
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_DIR))

from pra_effect import TracebackParser, group_traces  # noqa: E402

GATE_MB = 50

BLOCK = """INFO 2026-10-24 10:00:01 handling request {n}
Traceback (most recent call last):
  File "/app/src/api.py", line {l}, in handle_request
    payload = process(item_{n})
  File "/app/src/worker.py", line {l2}, in process
    raise ValueError("invalid item {n} for request-id: 123e4567-e89b-12d3-a456-42661417{n:04d}")
ValueError: invalid item {n} for request-id: 123e4567-e89b-12d3-a456-42661417{n:04d}

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
    ok = psapi.GetProcessMemoryInfo(
        handle, ctypes.byref(counters), counters.cb
    )
    return counters.PeakWorkingSetSize if ok else None


def build_log(target_mb: float) -> str:
    block = BLOCK.format(n=1, l=42, l2=17)
    repeats = int((target_mb * 1024 * 1024) // len(block)) + 1
    # Vary ids per block so grouping work is representative (not one giant duplicate)
    parts = [
        BLOCK.format(n=i, l=40 + (i % 900), l2=10 + (i % 300)) for i in range(repeats)
    ]
    return "".join(parts)


def main() -> int:
    target_mb = float(sys.argv[1]) if len(sys.argv) > 1 else 20.0
    print(f"Pra-Effect GATE-MEM-01: target input {target_mb:.0f} MB, gate <={GATE_MB} MB peak RSS")

    text = build_log(target_mb)
    actual_mb = len(text) / (1024 * 1024)
    print(f"Synthetic log built: {actual_mb:.1f} MB, {text.count('Traceback'):,} tracebacks")

    rss_before = peak_rss_bytes()
    tracemalloc.start()
    t0 = time.perf_counter()
    traces = TracebackParser(cwd=REPO_DIR).parse_all(text)
    groups = group_traces(traces)
    elapsed = time.perf_counter() - t0
    py_peak, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    rss_peak = peak_rss_bytes()

    print(f"Parse+group: {elapsed:.2f}s, {len(traces):,} traces, {len(groups):,} groups")
    print(f"tracemalloc peak: {py_peak / 1024 / 1024:.1f} MB (Python allocations only)")
    if rss_peak is None:
        print("Peak RSS: NOT_RUN (platform API unavailable) — gate not evaluated")
        return 2
    print(
        f"Peak RSS: {rss_peak / 1024 / 1024:.1f} MB "
        f"(before parse: {(rss_before or 0) / 1024 / 1024:.1f} MB)"
    )

    if rss_peak <= GATE_MB * 1024 * 1024:
        print(f"GATE-MEM-01: PASS (<= {GATE_MB} MB)")
        return 0
    print(
        f"GATE-MEM-01: FAIL ({rss_peak / 1024 / 1024:.1f} MB > {GATE_MB} MB) — "
        "evaluate incremental streaming parser before finalizing v1.0 design"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())