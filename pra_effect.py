"""pra_effect.py - Core parser, fingerprinting, and CLI for Pra-Effect.
Zero external dependencies. Python standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import io
import json
import os
import re
import sqlite3
import sys
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Sequence, Tuple

FINGERPRINT_VERSION = "fingerprint_v1"
__version__ = "1.3.0"
MAX_LINE_LENGTH = 4096
MAX_CONTINUATION_LINES = 5
MAX_INTERLEAVED_LINES = 2
# DEC-016: input-size backstop, defense-in-depth alongside streaming (not a
# substitute for it). Default proven by bench_memory.py runs recorded in
# .confidential/TASKS.md (TSK-014). 0 disables the cap.
DEFAULT_MAX_INPUT_MB = 100.0


class InputTooLargeError(Exception):
    """Input exceeded --max-input-mb."""


class ScanInputError(Exception):
    """Fatal scan/ingest source error; message is already user-facing."""

# Normalization patterns
RE_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
RE_HEX = re.compile(r"\b0x[0-9a-fA-F]+\b")
RE_DYNAMIC_ID = re.compile(
    r"\b(user|order|item|account|task|job|id|req|request)[-_:\s](\d{3,})\b",
    re.IGNORECASE,
)
RE_CONSECUTIVE_WHITESPACE = re.compile(r"\s+")
# TSK-022 / v1.0.1: ANSI escape code stripping in stream reader
RE_ANSI = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

# TSK-023 / v1.1.0: Secret redaction patterns
RE_BEARER_AUTH = re.compile(r"(?i)\b(bearer\s+)([A-Za-z0-9\-_\.=]{16,})")
RE_BASIC_AUTH_URI = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^:\s/@]+):([^@\s/]+)@")
RE_API_KEY_KV = re.compile(r"(?i)\b(api[_-]?key|secret|token|password|passwd|auth)[_-]?(?:key)?\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{8,})['\"]?")
RE_AWS_KEY = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
RE_JWT = re.compile(r"\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b")

# Python traceback pattern
RE_PY_TRACE_START = re.compile(r"^Traceback \(most recent call last\):")
RE_PY_FRAME = re.compile(r'^\s*File "([^"]+)", line (\d+), in (\S+)')
RE_PY_ERROR = re.compile(r"^([a-zA-Z_][a-zA-Z0-9_\.]*(?:Error|Exception|Exit|Interrupt|Warning|Fault))(?::\s*(.*))?$")

# Chained exception marker (DEC-011): separates cause traceback from outer root traceback
RE_CHAIN_MARKER = re.compile(
    r"^(?:During handling of the above exception, another exception occurred:|"
    r"The above exception was the direct cause of the following exception:)$"
)

# Bounded message collector boundary: stop when a normal log line begins (DEC-006 + TSK-007)
RE_LOG_LEVEL_LINE = re.compile(
    r"^(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\s+)?"
    r"(?:DEBUG|INFO|NOTICE|WARNING|WARN|ERROR|CRITICAL|TRACE)\b"
)
RE_TIMESTAMP_LINE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\s+\S")

# Node.js stack pattern
RE_NODE_ERROR_HEADER = re.compile(
    r"^([a-zA-Z0-9_\.]*?Error|[a-zA-Z0-9_\.]*?Exception)(?::\s*(.*))?$"
)
RE_NODE_FRAME = re.compile(
    r"^\s*at (?:(.+?)\s+\()?([^\s\(\)]+?):(\d+):(\d+)\)?$"
)

# Java stack patterns (TSK-025)
RE_JAVA_HEADER = re.compile(
    r"^(?:Exception in thread \"[^\"]*\"\s+)?([a-zA-Z0-9_$]+\.[a-zA-Z0-9_$.]+(?:Exception|Error|Throwable))(?::\s*(.*))?$"
)
RE_JAVA_FRAME = re.compile(
    r"^\s*at\s+([a-zA-Z0-9_$./<>]+)\((?:([^:]+):(\d+)|Native Method|Unknown Source)\)"
)
RE_JAVA_CAUSED_BY = re.compile(
    r"^Caused by:\s+([a-zA-Z0-9_$.]+(?:Exception|Error|Throwable))(?::\s*(.*))?$"
)

# Foreign stack patterns (C++ core dumps, signals — Go/Rust handled by dedicated SM) (TSK-025)
RE_FOREIGN_HEADER = re.compile(
    r"^(?:fatal error:\s*(.*)|SIGSEGV|SIGABRT)"
)

# Go panic streaming patterns (TSK-026A)
# Header: "panic: <message>" or "panic(<type>): <msg>"
RE_GO_PANIC_HEADER = re.compile(r"^panic(?:\([^)]*\))?:\s*(.*)")
# Goroutine header: "goroutine 1 [running]:"  (any status)
RE_GO_GOROUTINE = re.compile(r"^goroutine\s+(\d+)\s+\[([^\]]+)\]:$")
# Frame function: "main.foo(...)" or "runtime.gopanic(...)"
RE_GO_FUNC = re.compile(r"^([a-zA-Z0-9_./\(\)]*[a-zA-Z0-9_])(?:\(.*\))?$")
# Frame file line: "\t/path/to/file.go:42 +0x5e"
RE_GO_FILE_LINE = re.compile(r"^\s+(.+\.go):(\d+)(?:\s+\+0x[0-9a-fA-F]+)?$")
# Normalization: goroutine ID and memory addresses
RE_GO_PTR = re.compile(r"\b0x[0-9a-fA-F]+\b")
RE_GO_GOROUTINE_ID = re.compile(r"\bgoroutine\s+\d+\b")

# Known vendor / runtime directory segments
VENDOR_SEGMENTS = {
    "site-packages",
    "dist-packages",
    "node_modules",
    "<frozen",
    "internal/modules",
    "internal/process",
    ".venv",
    "venv",
    "virtualenv",
}

JAVA_VENDOR_PREFIXES = (
    "java.",
    "javax.",
    "jdk.",
    "sun.",
    "com.sun.",
    "org.springframework.",
    "org.apache.catalina.",
    "org.apache.tomcat.",
    "org.eclipse.jetty.",
    "io.netty.",
    "org.hibernate.",
    "org.junit.",
)


@dataclass
class StackFrame:
    filepath: str
    line_number: int
    function_name: str
    is_in_project: bool = False
    normalized_path: str = ""

    def logical_key(self) -> str:
        """Key ignoring line numbers for resilient logic-level grouping."""
        norm = self.normalized_path or self.filepath
        return f"{norm}::{self.function_name}"


@dataclass
class ParsedTrace:
    runtime: str  # "python" | "node" | "java" | "foreign"
    error_type: str
    original_message: str
    normalized_message: str
    frames: List[StackFrame]
    raw_text: str
    fingerprint: str = ""
    timestamp: Optional[str] = None
    is_truncated: bool = False
    chain: Optional["ParsedTrace"] = None

    def compute_fingerprint(self) -> str:
        # 1. Project frames prioritized
        proj_frames = [f.logical_key() for f in self.frames if f.is_in_project]
        if not proj_frames:
            # Fallback to last 2 frames of original stack
            proj_frames = [f.logical_key() for f in self.frames[-2:]]

        frame_sig = "|".join(proj_frames)
        payload = (
            f"{FINGERPRINT_VERSION}:{self.runtime}:{self.error_type}:"
            f"{self.normalized_message}:{frame_sig}"
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


@dataclass
class IncidentGroup:
    fingerprint: str
    runtime: str
    error_type: str
    normalized_message: str
    occurrences: int = 0
    representative_trace: str = ""
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    project_locations: List[str] = field(default_factory=list)
    is_truncated: bool = False


def normalize_message(msg: str) -> Tuple[str, bool]:
    if not msg:
        return "", False
    truncated = False
    if len(msg) > MAX_LINE_LENGTH:
        msg = msg[:MAX_LINE_LENGTH]
        truncated = True
    m = msg.strip()
    m = RE_UUID.sub("<UUID>", m)
    m = RE_HEX.sub("<HEX>", m)
    m = RE_DYNAMIC_ID.sub(r"\1 <ID>", m)
    m = RE_CONSECUTIVE_WHITESPACE.sub(" ", m)
    return m.strip(), truncated


@lru_cache(maxsize=8192)
def normalize_frame_path(raw_path: str, cwd: Path, src_override: Optional[Path] = None) -> Tuple[str, bool]:
    clean = raw_path.replace("\\", "/")
    # Check vendor segments
    lower = clean.lower()
    for v in VENDOR_SEGMENTS:
        if v in lower:
            return clean, False

    try:
        p = Path(raw_path).resolve()
        cwd_res = cwd.resolve()
        base_target = src_override.resolve() if src_override else cwd_res

        # Safe boundary check (not startswith string match)
        try:
            rel = p.relative_to(base_target)
            return rel.as_posix(), True
        except ValueError:
            return clean, False
    except Exception:
        return clean, False


# --- Streaming core (DEC-015): line-fed state machines -----------------------
# Single source of truth for parse rules; parse_python_traces / parse_node_traces
# are thin wrappers over these so every consumer (tests, CLI, bench) sees the
# exact same behavior.


def _collect_stream(sm, lines: Iterable[str]) -> List[ParsedTrace]:
    out: List[ParsedTrace] = []
    for raw in lines:
        if len(raw) > MAX_LINE_LENGTH:
            out.extend(sm.feed(raw[:MAX_LINE_LENGTH], True))
        else:
            out.extend(sm.feed(raw, False))
    out.extend(sm.finish())
    return out


class PythonTraceStream:
    """Line-fed Python traceback parser.

    Faithful port of the index-based parser: ReDoS pre-truncation, bounded
    5-line message collector with log-line/timestamp/chain-marker boundary,
    2-line interleaving window with rewind-to-header+1, and chained-exception
    handling where the OUTER exception owns the incident (DEC-011): the most
    recently completed traceback is held; a chain marker parks it; the next
    completed traceback absorbs parked causes into raw_text only (never into
    the fingerprint payload).

    Bounded divergence (documented in DEC-015): a chain marker with no held
    traceback is ignored instead of popping an earlier already-folded trace.
    CPython always prints a marker directly after its cause traceback, so
    real logs are unaffected; only malformed double-marker sequences differ,
    and only in cause-context retention.
    """

    def __init__(self, cwd: Path, src_dir: Optional[Path] = None):
        self.cwd = cwd
        self.src_dir = src_dir
        self.pend: "deque[Tuple[str, bool]]" = deque()
        self.held: Optional[ParsedTrace] = None
        self.parked: List[Tuple[ParsedTrace, str]] = []
        self._reset_candidate()

    def _reset_candidate(self) -> None:
        self.mode = "idle"  # idle | frame | collect
        self.frames: List[StackFrame] = []
        self.trace_lines: List[Tuple[str, bool]] = []
        self.trunc_any = False
        self.interleaved = 0
        self.await_source = False
        self.err_type = ""
        self.raw_msg = ""
        self.extra: List[str] = []
        self.collected = 0

    def feed(self, line: str, truncated: bool) -> List[ParsedTrace]:
        self.pend.append((line, truncated))
        return self._drain()

    def finish(self) -> List[ParsedTrace]:
        out = self._drain()
        if self.mode == "collect":
            # Input ends inside the message collector: the original assembles
            # the trace right there.
            out.extend(self._complete())
            self._reset_candidate()
        elif self.mode == "frame":
            # Candidate never reached an exception line: dropped, as before.
            self._reset_candidate()
        if self.held is not None:
            out.append(self.held)
            self.held = None
        for cause, _marker in self.parked:
            out.append(cause)
        self.parked = []
        return out

    def _drain(self) -> List[ParsedTrace]:
        out: List[ParsedTrace] = []
        stall = 0
        while self.pend:
            line, truncated = self.pend[0]
            if self._step(line, truncated, out):
                self.pend.popleft()
                stall = 0
            else:
                stall += 1
                if stall > 10_000:
                    raise RuntimeError("PythonTraceStream made no progress")
        return out

    def _step(self, line: str, truncated: bool, out: List[ParsedTrace]) -> bool:
        stripped = line.strip()

        if self.mode == "idle":
            if RE_PY_TRACE_START.match(stripped):
                self.mode = "frame"
                self.frames = []
                self.trace_lines = [(line, truncated)]
                self.trunc_any = truncated
                self.interleaved = 0
                self.await_source = False
                return True
            if RE_CHAIN_MARKER.match(stripped) and self.held is not None:
                self.parked.append((self.held, stripped))
                self.held = None
            return True

        if self.mode == "frame":
            if self.await_source:
                if line.startswith("    ") and not RE_PY_FRAME.match(line):
                    self.trace_lines.append((line, truncated))
                    self.trunc_any = truncated
                    self.await_source = False
                    return True
                self.await_source = False

            frame_match = RE_PY_FRAME.match(line)
            if frame_match:
                raw_fpath, line_no, func_name = frame_match.groups()
                norm_p, in_proj = normalize_frame_path(
                    raw_fpath, self.cwd, self.src_dir
                )
                self.frames.append(
                    StackFrame(
                        filepath=raw_fpath,
                        line_number=int(line_no),
                        function_name=func_name,
                        is_in_project=in_proj,
                        normalized_path=norm_p,
                    )
                )
                self.trace_lines.append((line, truncated))
                self.trunc_any = self.trunc_any or truncated
                self.interleaved = 0
                self.await_source = True
                return True

            err_match = RE_PY_ERROR.match(stripped)
            if err_match:
                self.err_type = err_match.group(1)
                self.raw_msg = err_match.group(2) or ""
                self.trace_lines.append((line, truncated))
                self.trunc_any = self.trunc_any or truncated
                self.mode = "collect"
                self.extra = []
                self.collected = 0
                return True

            if RE_PY_TRACE_START.match(stripped) or RE_NODE_ERROR_HEADER.match(stripped):
                # New header before any exception line: abandon candidate and
                # re-dispatch this line under idle rules.
                self._reset_candidate()
                return False

            if self.interleaved < MAX_INTERLEAVED_LINES:
                self.interleaved += 1
                return True  # interleaved noise: consumed, not part of trace

            # Decision 1B rewind: re-scan everything after the header.
            rest = list(self.pend)[1:]
            self.pend = deque(self.trace_lines[1:] + [(line, truncated)] + rest)
            self._reset_candidate()
            return False

        # mode == "collect"
        stop = (
            self.collected >= MAX_CONTINUATION_LINES
            or not stripped
            or RE_PY_TRACE_START.match(stripped)
            or RE_PY_FRAME.match(line)
            or RE_PY_ERROR.match(stripped)
            or RE_NODE_ERROR_HEADER.match(stripped)
            or RE_CHAIN_MARKER.match(stripped)
            or RE_LOG_LEVEL_LINE.match(stripped)
            or RE_TIMESTAMP_LINE.match(stripped)
        )
        if stop:
            out.extend(self._complete())
            self._reset_candidate()
            return False  # the stopping line is re-dispatched in idle
        self.extra.append(stripped)
        self.trace_lines.append((line, truncated))
        self.trunc_any = self.trunc_any or truncated
        self.collected += 1
        return True

    def _complete(self) -> List[ParsedTrace]:
        raw_block = "\n".join(l for l, _ in self.trace_lines)
        if self.parked:
            # DEC-011: causes ride along in the rendered trace only.
            parts: List[str] = []
            for cause, marker in self.parked:
                parts.append(cause.raw_text)
                parts.append(marker)
            parts.append(raw_block)
            raw_block = "\n".join(parts)
            self.parked = []
        raw_msg = self.raw_msg
        if self.extra:
            raw_msg = (
                raw_msg + " " + " ".join(self.extra) if raw_msg else " ".join(self.extra)
            )
        norm_msg, is_trunc = normalize_message(raw_msg)
        trace = ParsedTrace(
            runtime="python",
            error_type=self.err_type,
            original_message=raw_msg,
            normalized_message=norm_msg,
            frames=self.frames,
            raw_text=raw_block,
            is_truncated=is_trunc or self.trunc_any,
        )
        trace.fingerprint = trace.compute_fingerprint()
        emitted: List[ParsedTrace] = []
        if self.held is not None:
            emitted.append(self.held)  # released: no marker followed it
        self.held = trace
        return emitted


class NodeTraceStream:
    """Line-fed Node.js V8 stack parser (no chaining in V8 output)."""

    def __init__(self, cwd: Path, src_dir: Optional[Path] = None):
        self.cwd = cwd
        self.src_dir = src_dir
        self.pend: "deque[Tuple[str, bool]]" = deque()
        self._reset()

    def _reset(self) -> None:
        self.mode = "idle"  # idle | await | frames
        self.frames: List[StackFrame] = []
        self.trace_lines: List[Tuple[str, bool]] = []
        self.trunc_any = False
        self.interleaved = 0
        self.err_type = ""
        self.raw_msg = ""

    def feed(self, line: str, truncated: bool) -> List[ParsedTrace]:
        self.pend.append((line, truncated))
        return self._drain()

    def finish(self) -> List[ParsedTrace]:
        out = self._drain()
        if self.mode == "frames":
            out.append(self._make_trace())
        # mode "await": header with no `at ` frame — dropped, as before.
        self._reset()
        return out

    def _drain(self) -> List[ParsedTrace]:
        out: List[ParsedTrace] = []
        stall = 0
        while self.pend:
            line, truncated = self.pend[0]
            if self._step(line, truncated, out):
                self.pend.popleft()
                stall = 0
            else:
                stall += 1
                if stall > 10_000:
                    raise RuntimeError("NodeTraceStream made no progress")
        return out

    def _step(self, line: str, truncated: bool, out: List[ParsedTrace]) -> bool:
        stripped = line.strip()

        if self.mode == "idle":
            header = RE_NODE_ERROR_HEADER.match(stripped)
            if header:
                self.err_type = header.group(1)
                self.raw_msg = header.group(2) or ""
                self.mode = "await"
                self.frames = []
                self.trace_lines = [(line, truncated)]
                self.trunc_any = truncated
                self.interleaved = 0
                return True
            return True  # non-header noise

        if self.mode == "await":
            if not stripped:
                return True  # blank between header and first frame
            if stripped.startswith("at "):
                self.mode = "frames"
                return False  # re-dispatch under frame rules
            self._reset()  # header without frames: drop header
            return False  # re-dispatch this line under idle rules

        # mode == "frames"
        if not stripped:
            return True  # blank inside stack: consumed, never in raw_text
        frame_match = RE_NODE_FRAME.match(stripped)
        if frame_match:
            fn_name, raw_fpath, line_no, _col = frame_match.groups()
            fn_name = fn_name or "<anonymous>"
            norm_p, in_proj = normalize_frame_path(raw_fpath, self.cwd, self.src_dir)
            self.frames.append(
                StackFrame(
                    filepath=raw_fpath,
                    line_number=int(line_no),
                    function_name=fn_name,
                    is_in_project=in_proj,
                    normalized_path=norm_p,
                )
            )
            self.trace_lines.append((line, truncated))
            self.trunc_any = self.trunc_any or truncated
            self.interleaved = 0
            return True

        if RE_NODE_ERROR_HEADER.match(stripped) or RE_PY_TRACE_START.match(stripped):
            out.append(self._make_trace())
            self._reset()
            return False  # new header re-dispatched in idle

        if self.interleaved < MAX_INTERLEAVED_LINES:
            self.interleaved += 1
            return True  # interleaved noise: consumed, not in raw_text

        out.append(self._make_trace())
        self._reset()
        return False  # the overflowing line re-dispatched in idle

    def _make_trace(self) -> ParsedTrace:
        raw_block = "\n".join(l for l, _ in self.trace_lines)
        norm_msg, is_trunc = normalize_message(self.raw_msg)
        trace = ParsedTrace(
            runtime="node",
            error_type=self.err_type,
            original_message=self.raw_msg,
            normalized_message=norm_msg,
            frames=self.frames,
            raw_text=raw_block,
            is_truncated=is_trunc or self.trunc_any,
        )
        trace.fingerprint = trace.compute_fingerprint()
        return trace


class GoTraceStream:
    """Line-fed Go panic parser (TSK-026A).

    Handles format:
      panic: <message>         ← header (may include type assertion, runtime error, etc.)
      [blank line optional]
      goroutine N [status]:    ← goroutine header (any status string)
      pkg.Function(...)        ← function name line
      \t/path/to/file.go:L    ← file+line (pairs with function above)
      ...more goroutines...
      exit status 2            ← noise: ignored

    State machine: idle → panic_seen → goroutine → frames → idle
    Multiple goroutines in one panic dump are folded into a single trace
    (first goroutine frames only — matching runtime behavior where goroutine 1
    is always the panicking goroutine and its dump appears first).

    Invariants:
    - O(1) streaming: no buffering of whole file.
    - Truncated stack (EOF mid-frame): emitted via finish().
    - Pointer addresses normalized to <PTR>; goroutine IDs stripped from message.
    - Zero new dependencies.
    """

    def __init__(self, cwd: Path, src_dir: Optional[Path] = None):
        self.cwd = cwd
        self.src_dir = src_dir
        self.pend: "deque[Tuple[str, bool]]" = deque()
        self._reset()

    def _reset(self) -> None:
        self.mode = "idle"       # idle | panic_seen | goroutine | frames
        self.raw_msg = ""
        self.pending_func = ""   # function name waiting for its file:line pair
        self.frames: List[StackFrame] = []
        self.trace_lines: List[Tuple[str, bool]] = []
        self.trunc_any = False

    def feed(self, line: str, truncated: bool) -> List[ParsedTrace]:
        self.pend.append((line, truncated))
        return self._drain()

    def finish(self) -> List[ParsedTrace]:
        out = self._drain()
        if self.mode in ("goroutine", "frames"):
            out.append(self._make_trace())
        self._reset()
        return out

    def _drain(self) -> List[ParsedTrace]:
        out: List[ParsedTrace] = []
        stall = 0
        while self.pend:
            line, truncated = self.pend[0]
            if self._step(line, truncated, out):
                self.pend.popleft()
                stall = 0
            else:
                stall += 1
                if stall > 10_000:
                    raise RuntimeError("GoTraceStream made no progress")
        return out

    def _step(self, line: str, truncated: bool, out: List[ParsedTrace]) -> bool:
        stripped = line.strip()

        if self.mode == "idle":
            m = RE_GO_PANIC_HEADER.match(stripped)
            if m:
                self.raw_msg = m.group(1).strip()
                self.mode = "panic_seen"
                self.trace_lines = [(line, truncated)]
                self.trunc_any = truncated
            return True

        if self.mode == "panic_seen":
            # Allow blank line between panic header and goroutine header
            if not stripped:
                self.trace_lines.append((line, truncated))
                return True
            gm = RE_GO_GOROUTINE.match(stripped)
            if gm:
                self.trace_lines.append((line, truncated))
                self.trunc_any = self.trunc_any or truncated
                self.mode = "goroutine"
                return True
            # Non-goroutine continuation — treat as additional message context
            self.raw_msg = (self.raw_msg + " " + stripped).strip() if self.raw_msg else stripped
            self.trace_lines.append((line, truncated))
            return True

        if self.mode == "goroutine":
            # Waiting for first function frame
            if not stripped:
                return True
            # Check for file:line (shouldn't happen yet, but be safe)
            fm = RE_GO_FILE_LINE.match(line)
            if fm:
                # orphan file line with no function; skip
                self.trace_lines.append((line, truncated))
                return True
            # Another goroutine header — stop collecting frames for first goroutine,
            # emit trace (we only fingerprint the panicking goroutine)
            gm = RE_GO_GOROUTINE.match(stripped)
            if gm:
                out.append(self._make_trace())
                self._reset()
                return False  # re-dispatch: will become a new panic (or idle)
            # Should be a function name
            func_m = RE_GO_FUNC.match(stripped)
            if func_m:
                self.pending_func = func_m.group(1)
                self.trace_lines.append((line, truncated))
                self.mode = "frames"
                self.trunc_any = self.trunc_any or truncated
                return True
            # Something else (e.g. "exit status 2") — end of panic dump
            out.append(self._make_trace())
            self._reset()
            return False

        # mode == "frames"
        if not stripped:
            # blank line after frames = goroutine separator or end
            # peek: if next non-blank is another goroutine, emit now
            out.append(self._make_trace())
            self._reset()
            return True

        fm = RE_GO_FILE_LINE.match(line)
        if fm:
            filepath = fm.group(1)
            line_no = int(fm.group(2))
            norm_p, in_proj = normalize_frame_path(filepath, self.cwd, self.src_dir)
            # Vendor check: runtime/ and vendor/ are not project frames
            lower_fp = filepath.lower().replace("\\", "/")
            is_runtime = lower_fp.startswith("runtime/") or "/vendor/" in lower_fp or lower_fp.startswith("vendor/")
            if is_runtime:
                in_proj = False
            self.frames.append(StackFrame(
                filepath=filepath,
                line_number=line_no,
                function_name=self.pending_func,
                is_in_project=in_proj,
                normalized_path=norm_p,
            ))
            self.pending_func = ""
            self.trace_lines.append((line, truncated))
            self.trunc_any = self.trunc_any or truncated
            return True

        # Could be another function line (next frame pair)
        gm = RE_GO_GOROUTINE.match(stripped)
        if gm:
            # Second goroutine: emit first, reset (don't parse remaining goroutines)
            out.append(self._make_trace())
            self._reset()
            return False

        func_m = RE_GO_FUNC.match(stripped)
        if func_m:
            # If there's a pending_func with no file line (truncated), add a partial frame
            if self.pending_func:
                self.frames.append(StackFrame(
                    filepath="",
                    line_number=0,
                    function_name=self.pending_func,
                    is_in_project=False,
                    normalized_path="",
                ))
            self.pending_func = func_m.group(1)
            self.trace_lines.append((line, truncated))
            self.trunc_any = self.trunc_any or truncated
            return True

        # Unrecognized line (e.g. "exit status 2") — end of dump
        out.append(self._make_trace())
        self._reset()
        return False

    def _normalize_go_msg(self, msg: str) -> str:
        """Normalize Go panic message: strip ptr addresses and dynamic IDs."""
        msg = RE_GO_PTR.sub("<PTR>", msg)
        msg, _ = normalize_message(msg)
        return msg

    def _make_trace(self) -> ParsedTrace:
        raw_block = "\n".join(l for l, _ in self.trace_lines)
        norm_msg = self._normalize_go_msg(self.raw_msg)
        # If pending_func has no file pair (truncated stack), add partial frame
        if self.pending_func and (not self.frames or self.frames[-1].function_name != self.pending_func):
            self.frames.append(StackFrame(
                filepath="",
                line_number=0,
                function_name=self.pending_func,
                is_in_project=False,
                normalized_path="",
            ))
        trace = ParsedTrace(
            runtime="go",
            error_type="GoPanic",
            original_message=self.raw_msg,
            normalized_message=norm_msg,
            frames=self.frames,
            raw_text=raw_block,
            is_truncated=self.trunc_any or bool(self.pending_func),
        )
        trace.fingerprint = trace.compute_fingerprint()
        return trace



class JavaTraceStream:
    """Line-fed Java stack trace parser with Caused-by chaining support (TSK-025)."""

    def __init__(self, cwd: Path, src_dir: Optional[Path] = None):
        self.cwd = cwd
        self.src_dir = src_dir
        self.pend: "deque[Tuple[str, bool]]" = deque()
        self._reset()

    def _reset(self) -> None:
        self.mode = "idle"  # idle | await | frames
        self.frames: List[StackFrame] = []
        self.trace_lines: List[Tuple[str, bool]] = []
        self.trunc_any = False
        self.interleaved = 0
        self.err_type = ""
        self.raw_msg = ""
        self.chain_target: Optional[ParsedTrace] = None

    def feed(self, line: str, truncated: bool) -> List[ParsedTrace]:
        self.pend.append((line, truncated))
        return self._drain()

    def finish(self) -> List[ParsedTrace]:
        out = self._drain()
        if self.mode == "frames":
            out.append(self._make_trace())
        self._reset()
        return out

    def _drain(self) -> List[ParsedTrace]:
        out: List[ParsedTrace] = []
        stall = 0
        while self.pend:
            line, truncated = self.pend[0]
            if self._step(line, truncated, out):
                self.pend.popleft()
                stall = 0
            else:
                stall += 1
                if stall > 10_000:
                    raise RuntimeError("JavaTraceStream made no progress")
        return out

    def _step(self, line: str, truncated: bool, out: List[ParsedTrace]) -> bool:
        stripped = line.strip()

        if self.mode == "idle":
            # Match Java header (e.g. Exception in thread "main" java.lang.NullPointerException: msg)
            header = RE_JAVA_HEADER.match(stripped)
            if header and ("Exception" in header.group(1) or "Error" in header.group(1) or "Throwable" in header.group(1)):
                self.err_type = header.group(1)
                self.raw_msg = header.group(2) or ""
                self.mode = "await"
                self.frames = []
                self.trace_lines = [(line, truncated)]
                self.trunc_any = truncated
                self.interleaved = 0
                self.chain_target = None
                return True
            return True  # noise

        if self.mode == "await":
            if not stripped:
                return True
            if stripped.startswith("at "):
                self.mode = "frames"
                return False  # re-dispatch under frame rules
            self._reset()
            return False

        # mode == "frames"
        if not stripped:
            return True

        # Check Caused by: chaining marker
        caused = RE_JAVA_CAUSED_BY.match(stripped)
        if caused:
            # Previous trace becomes parent or gets chained
            parent = self._make_trace()
            out.append(parent)
            self.err_type = caused.group(1)
            self.raw_msg = caused.group(2) or ""
            self.frames = []
            self.trace_lines.append((line, truncated))
            self.chain_target = parent
            self.mode = "await"
            return True

        if stripped.startswith("... ") and "more" in stripped:
            self.trace_lines.append((line, truncated))
            return True

        frame_match = RE_JAVA_FRAME.match(line)
        if frame_match:
            method_path = frame_match.group(1)
            file_name = frame_match.group(2) or ""
            line_str = frame_match.group(3)
            line_no = int(line_str) if line_str else 0

            # Vendor exclusion check
            is_vendor = any(method_path.startswith(prefix) for prefix in JAVA_VENDOR_PREFIXES)
            in_proj = not is_vendor

            norm_p, path_in_proj = normalize_frame_path(file_name, self.cwd, self.src_dir) if file_name else (method_path, False)
            if not is_vendor:
                in_proj = True

            self.frames.append(
                StackFrame(
                    filepath=file_name or method_path,
                    line_number=line_no,
                    function_name=method_path,
                    is_in_project=in_proj,
                    normalized_path=norm_p or method_path,
                )
            )
            self.trace_lines.append((line, truncated))
            self.trunc_any = self.trunc_any or truncated
            self.interleaved = 0
            return True

        if RE_JAVA_HEADER.match(stripped) or RE_PY_TRACE_START.match(stripped) or RE_NODE_ERROR_HEADER.match(stripped):
            out.append(self._make_trace())
            self._reset()
            return False

        if self.interleaved < MAX_INTERLEAVED_LINES:
            self.interleaved += 1
            return True

        out.append(self._make_trace())
        self._reset()
        return False

    def _make_trace(self) -> ParsedTrace:
        raw_block = "\n".join(l for l, _ in self.trace_lines)
        norm_msg, is_trunc = normalize_message(self.raw_msg)
        trace = ParsedTrace(
            runtime="java",
            error_type=self.err_type,
            original_message=self.raw_msg,
            normalized_message=norm_msg,
            frames=self.frames,
            raw_text=raw_block,
            is_truncated=is_trunc or self.trunc_any,
            chain=self.chain_target,
        )
        trace.fingerprint = trace.compute_fingerprint()
        return trace


def fold_traces(traces: Iterable[ParsedTrace], groups: "dict[str, IncidentGroup]") -> None:
    """Incrementally fold traces into a fingerprint->IncidentGroup bucket."""
    for t in traces:
        if t.fingerprint not in groups:
            locations = []
            for f in t.frames:
                if f.is_in_project:
                    locations.append(f"{f.normalized_path}:{f.line_number}")
            rep_loc = locations[:2] if locations else [f"{f.filepath}:{f.line_number}" for f in t.frames[-1:]]

            groups[t.fingerprint] = IncidentGroup(
                fingerprint=t.fingerprint,
                runtime=t.runtime,
                error_type=t.error_type,
                normalized_message=t.normalized_message,
                occurrences=1,
                representative_trace=t.raw_text,
                project_locations=rep_loc,
                is_truncated=t.is_truncated,
            )
        else:
            g = groups[t.fingerprint]
            g.occurrences += 1
            if t.is_truncated:
                g.is_truncated = True


def strip_ansi(text: str) -> str:
    """Strip ANSI escape sequences from text (TSK-022)."""
    return RE_ANSI.sub("", text) if "\x1b" in text else text


def scrub_secrets_text(text: str) -> str:
    """Scrub sensitive credentials (JWT, Bearer, API keys, URIs) from trace text (TSK-023)."""
    if not text:
        return text
    # 1. JWT token (before bearer strip so standard JWT gets explicit REDACTED_JWT)
    text = RE_JWT.sub("[REDACTED_JWT]", text)
    # 2. Bearer token
    text = RE_BEARER_AUTH.sub(r"\1[REDACTED]", text)
    # 3. Basic auth in URLs: http://user:pass@host -> http://user:[REDACTED]@host
    text = RE_BASIC_AUTH_URI.sub(r"\1\2:[REDACTED]@", text)
    # 4. AWS access key
    text = RE_AWS_KEY.sub("[REDACTED_AWS_KEY]", text)
    # 5. Key-value secrets: api_key = "xyz" -> api_key = "[REDACTED]"
    text = RE_API_KEY_KV.sub(r"\1=[REDACTED]", text)
    return text


def iter_pairs(lines: Iterable[str], max_bytes: Optional[int] = None) -> Iterator[Tuple[str, bool]]:
    """Truncate-to-4096 pre-check (ReDoS guard), ANSI strip, plus --max-input-mb backstop."""
    used = 0
    for raw in lines:
        if "\x1b" in raw:
            raw = RE_ANSI.sub("", raw)
        if max_bytes is not None:
            used += len(raw.encode("utf-8", "replace")) + 1
            if used > max_bytes:
                raise InputTooLargeError(
                    f"Error: input exceeds --max-input-mb limit "
                    f"({max_bytes // (1024 * 1024)} MB); raise the limit or split the input"
                )
        if len(raw) > MAX_LINE_LENGTH:
            yield raw[:MAX_LINE_LENGTH], True
        else:
            yield raw, False


def stream_analyze(
    lines: Iterable[str],
    cwd: Path,
    src_dir: Optional[Path] = None,
    max_bytes: Optional[int] = None,
    scrub_secrets: bool = False,
) -> Tuple[int, int, List[IncidentGroup]]:
    """Single-pass streaming analysis: (total_lines, total_exceptions, groups).

    All state machines see every line; folds stay separate so the merged bucket
    preserves insertion order across runtimes.
    """
    py = PythonTraceStream(cwd, src_dir)
    node = NodeTraceStream(cwd, src_dir)
    java = JavaTraceStream(cwd, src_dir)
    go = GoTraceStream(cwd, src_dir)
    fpy: "dict[str, IncidentGroup]" = {}
    fnode: "dict[str, IncidentGroup]" = {}
    fjava: "dict[str, IncidentGroup]" = {}
    fgo: "dict[str, IncidentGroup]" = {}
    fforeign: "dict[str, IncidentGroup]" = {}
    total_lines = 0
    total_exceptions = 0
    for line, truncated in iter_pairs(lines, max_bytes):
        total_lines += 1
        tl = py.feed(line, truncated)
        fold_traces(tl, fpy)
        total_exceptions += len(tl)
        nl = node.feed(line, truncated)
        fold_traces(nl, fnode)
        total_exceptions += len(nl)
        jl = java.feed(line, truncated)
        fold_traces(jl, fjava)
        total_exceptions += len(jl)
        gl = go.feed(line, truncated)
        fold_traces(gl, fgo)
        total_exceptions += len(gl)

        # Foreign stack detection (fatal errors, core dumps — Go panic handled by GoTraceStream)
        fmatch = RE_FOREIGN_HEADER.match(line.strip())
        if fmatch and not tl and not nl and not jl and not gl:
            header_str = line.strip()
            err_type = "FatalError"
            if "SIGSEGV" in header_str:
                err_type = "SIGSEGV"
            elif "SIGABRT" in header_str:
                err_type = "SIGABRT"

            ftrace = ParsedTrace(
                runtime="foreign",
                error_type=err_type,
                original_message=header_str,
                normalized_message=header_str,
                frames=[],
                raw_text=line,
                is_truncated=truncated,
            )
            ftrace.fingerprint = ftrace.compute_fingerprint()
            fold_traces([ftrace], fforeign)
            total_exceptions += 1

    fl = py.finish()
    fold_traces(fl, fpy)
    total_exceptions += len(fl)
    nl2 = node.finish()
    fold_traces(nl2, fnode)
    total_exceptions += len(nl2)
    jl2 = java.finish()
    fold_traces(jl2, fjava)
    total_exceptions += len(jl2)
    gl2 = go.finish()
    fold_traces(gl2, fgo)
    total_exceptions += len(gl2)

    merged = {**fpy, **fnode, **fjava, **fgo, **fforeign}
    if scrub_secrets:
        for g in merged.values():
            g.representative_trace = scrub_secrets_text(g.representative_trace)
            g.normalized_message = scrub_secrets_text(g.normalized_message)
    groups = sorted(merged.values(), key=lambda g: g.occurrences, reverse=True)
    return total_lines, total_exceptions, groups


def iter_stdin_lines() -> Iterator[str]:
    for line in sys.stdin:
        if line.endswith("\n"):
            line = line[:-1]
        if line.endswith("\r"):
            line = line[:-1]
        yield line


def _probe_binary(path: Path) -> io.BufferedReader:
    """Open and NUL-probe a file. Raises OSError with a user-facing reason."""
    try:
        fb = open(path, "rb")
    except OSError as e:
        raise OSError(e.strerror or str(e))
    try:
        head = fb.read(8192)
    except OSError as e:
        fb.close()
        raise OSError(e.strerror or str(e))
    if b"\x00" in head:
        fb.close()
        raise OSError("binary content (NUL byte)")
    fb.seek(0)
    return fb


def _stream_file(fb: io.BufferedReader, state: dict) -> Iterator[str]:
    """Decode one probed binary handle into terminator-stripped text lines.

    `state` records whether any line was seen and whether the last raw line
    ended with a newline — the inputs needed to reproduce the legacy
    '\\n'.join() line count between files exactly.
    """
    state["any"] = False
    state["ends_nl"] = False
    try:
        with io.TextIOWrapper(fb, encoding="utf-8", errors="replace", newline=None) as tw:
            for raw in tw:
                state["any"] = True
                state["ends_nl"] = raw.endswith("\n")
                if raw.endswith("\n"):
                    raw = raw[:-1]
                if raw.endswith("\r"):
                    raw = raw[:-1]
                yield raw
    except OSError as e:
        # Mid-file I/O failure: treat as a skip (legacy read-whole-file would
        # have failed the probe instead; this path is disk-error rare).
        sys.stderr.write(f"[Pra-Effect] skipped partial read: {e}\n")
    finally:
        fb.close()


def iter_scan_lines(target: Path, pattern: str) -> Iterator[str]:
    """Stream an explicit file or a globbed directory (DEC-012 + DEC-015).

    Preserves legacy semantics: glob order (pattern-major, first-match dedup),
    skip warnings for unreadable/binary files on stderr, ScanInputError when an
    explicit file fails or a directory yields zero readable files, and the exact
    empty-line artifacts the old '\\n'.join() produced between files.
    """
    if target.is_file():
        try:
            fb = _probe_binary(target)
        except OSError as e:
            raise ScanInputError(f"Error: cannot read {target}: {e}")
        state: dict = {}
        yield from _stream_file(fb, state)
        return

    globs = [p.strip() for p in pattern.split(",") if p.strip()]
    seen: dict = {}
    for g in globs:
        for f in sorted(target.glob(f"**/{g}")):
            if f.is_file():
                seen[f] = None

    read_ok = 0
    prev: Optional[dict] = None  # terminal state of the previous READ file
    for f in seen:
        try:
            fb = _probe_binary(f)
        except OSError as e:
            sys.stderr.write(f"[Pra-Effect] skipped {f}: {e}\n")
            continue
        # Legacy join separator: an empty line appears between two read files
        # when the previous one ended with a newline or was empty. Emitted
        # before this file's lines so it survives even if this file is empty.
        if prev is not None and (prev["empty"] or prev["ends_nl"]):
            yield ""
        state = {}
        yield from _stream_file(fb, state)
        read_ok += 1
        prev = {"empty": not state.get("any", False), "ends_nl": state.get("ends_nl", False)}
    if read_ok == 0:
        raise ScanInputError(
            f"Error: no readable log files matched pattern '{pattern}' in {target}"
        )


class TracebackParser:
    def __init__(self, cwd: Optional[Path] = None, src_dir: Optional[Path] = None):
        self.cwd = cwd or Path.cwd()
        self.src_dir = src_dir

    def parse_python_traces(self, text: str) -> List[ParsedTrace]:
        """Whole-text convenience API — thin wrapper over the streaming machine."""
        return _collect_stream(PythonTraceStream(self.cwd, self.src_dir), text.splitlines())

    def parse_node_traces(self, text: str) -> List[ParsedTrace]:
        """Whole-text convenience API — thin wrapper over the streaming machine."""
        return _collect_stream(NodeTraceStream(self.cwd, self.src_dir), text.splitlines())

    def parse_java_traces(self, text: str) -> List[ParsedTrace]:
        """Whole-text convenience API — thin wrapper over the streaming machine (TSK-025)."""
        return _collect_stream(JavaTraceStream(self.cwd, self.src_dir), text.splitlines())

    def parse_all(self, text: str) -> List[ParsedTrace]:
        py_traces = self.parse_python_traces(text)
        node_traces = self.parse_node_traces(text)
        java_traces = self.parse_java_traces(text)
        return py_traces + node_traces + java_traces


def group_traces(traces: Iterable[ParsedTrace]) -> List[IncidentGroup]:
    groups: "dict[str, IncidentGroup]" = {}
    fold_traces(traces, groups)
    # Sorted by frequency descending
    return sorted(groups.values(), key=lambda g: g.occurrences, reverse=True)


def init_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    with conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_utc TEXT NOT NULL,
                command TEXT NOT NULL,
                total_lines INTEGER NOT NULL,
                total_exceptions INTEGER NOT NULL,
                unique_groups INTEGER NOT NULL,
                duration_ms REAL NOT NULL,
                fingerprint_version TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
                fingerprint TEXT NOT NULL,
                fingerprint_version TEXT NOT NULL,
                runtime TEXT NOT NULL,
                error_type TEXT NOT NULL,
                normalized_message TEXT,
                occurrences INTEGER NOT NULL,
                representative_trace TEXT,
                project_locations_json TEXT,
                is_truncated INTEGER DEFAULT 0,
                UNIQUE(run_id, fingerprint)
            );

            DROP VIEW IF EXISTS v_historical_incidents;

            CREATE VIEW v_historical_incidents AS
            SELECT
                i.fingerprint,
                i.fingerprint_version,
                i.runtime,
                i.error_type,
                i.normalized_message,
                SUM(i.occurrences) AS total_seen_count,
                COUNT(DISTINCT i.run_id) AS total_runs_seen,
                MIN(r.timestamp_utc) AS first_seen_utc,
                MAX(r.timestamp_utc) AS last_seen_utc,
                MAX(i.is_truncated) AS is_truncated
            FROM incidents i
            JOIN runs r ON i.run_id = r.id
            GROUP BY i.fingerprint, i.fingerprint_version;
            """
        )
    return conn


def save_run_to_db(
    db_path: Path,
    command: str,
    total_lines: int,
    total_exceptions: int,
    duration_ms: float,
    groups: Sequence[IncidentGroup],
) -> int:
    from datetime import datetime, timezone

    conn = init_db(db_path)
    now_utc = datetime.now(timezone.utc).isoformat()

    with conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO runs (
                timestamp_utc, command, total_lines, total_exceptions,
                unique_groups, duration_ms, fingerprint_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now_utc,
                command,
                total_lines,
                total_exceptions,
                len(groups),
                duration_ms,
                FINGERPRINT_VERSION,
            ),
        )
        run_id = cur.lastrowid
        assert run_id is not None

        for g in groups:
            cur.execute(
                """
                INSERT INTO incidents (
                    run_id, fingerprint, fingerprint_version, runtime,
                    error_type, normalized_message, occurrences,
                    representative_trace, project_locations_json, is_truncated
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    g.fingerprint,
                    FINGERPRINT_VERSION,
                    g.runtime,
                    g.error_type,
                    g.normalized_message,
                    g.occurrences,
                    g.representative_trace,
                    json.dumps(g.project_locations),
                    1 if g.is_truncated else 0,
                ),
            )
    conn.close()
    return run_id


def query_historical_incidents(db_path: Path, limit: int = 20) -> List[dict]:
    if not db_path.exists():
        return []
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    with conn:
        # Fingerprint immutability contract (TSK-012): history only ever
        # aggregates rows written under the active fingerprint version, so a future
        # fingerprint_v2 can never rewrite or pollute v1 history.
        rows = conn.execute(
            """
            SELECT * FROM v_historical_incidents
            WHERE fingerprint_version = ?
            ORDER BY total_seen_count DESC
            LIMIT ?
            """,
            (FINGERPRINT_VERSION, limit),
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def query_recent_runs(db_path: Path, limit: int = 10) -> List[dict]:
    if not db_path.exists():
        return []
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    with conn:
        rows = conn.execute(
            """
            SELECT * FROM runs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def diff_runs(db_path: Path, run_id_a: int, run_id_b: int) -> dict:
    """Compare two historical runs and compute newly introduced, resolved, and persistent groups (TSK-024)."""
    if not db_path.exists():
        raise FileNotFoundError(f"Database not found at {db_path}")

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    with conn:
        run_a = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id_a,)).fetchone()
        run_b = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id_b,)).fetchone()
        if not run_a:
            conn.close()
            raise ValueError(f"Run ID {run_id_a} not found in database")
        if not run_b:
            conn.close()
            raise ValueError(f"Run ID {run_id_b} not found in database")

        inc_a = {
            r["fingerprint"]: dict(r)
            for r in conn.execute("SELECT * FROM incidents WHERE run_id = ?", (run_id_a,)).fetchall()
        }
        inc_b = {
            r["fingerprint"]: dict(r)
            for r in conn.execute("SELECT * FROM incidents WHERE run_id = ?", (run_id_b,)).fetchall()
        }
    conn.close()

    fps_a = set(inc_a.keys())
    fps_b = set(inc_b.keys())

    new_fps = fps_b - fps_a
    resolved_fps = fps_a - fps_b
    common_fps = fps_a & fps_b

    new_groups = [inc_b[fp] for fp in sorted(new_fps)]
    resolved_groups = [inc_a[fp] for fp in sorted(resolved_fps)]
    persistent_groups = []
    for fp in sorted(common_fps):
        item_a = inc_a[fp]
        item_b = inc_b[fp]
        persistent_groups.append({
            "fingerprint": fp,
            "runtime": item_b["runtime"],
            "error_type": item_b["error_type"],
            "normalized_message": item_b["normalized_message"],
            "occurrences_a": item_a["occurrences"],
            "occurrences_b": item_b["occurrences"],
            "delta_occurrences": item_b["occurrences"] - item_a["occurrences"],
        })

    return {
        "run_a": dict(run_a),
        "run_b": dict(run_b),
        "new": new_groups,
        "resolved": resolved_groups,
        "persistent": persistent_groups,
    }


def format_diff_report(diff_res: dict) -> str:
    """Format human-readable CLI report comparing two runs."""
    ra = diff_res["run_a"]
    rb = diff_res["run_b"]
    lines = [
        "Pra-Effect — Run Comparison (Diff)",
        f"Base Run #{ra['id']} ({ra['timestamp_utc']}) vs Target Run #{rb['id']} ({rb['timestamp_utc']})",
        "=" * 68,
        f"Base Run   : {ra['unique_groups']} groups, {ra['total_exceptions']} total exceptions",
        f"Target Run : {rb['unique_groups']} groups, {rb['total_exceptions']} total exceptions",
        "-" * 68,
        f"Summary: +{len(diff_res['new'])} NEW | -{len(diff_res['resolved'])} RESOLVED | ={len(diff_res['persistent'])} PERSISTENT",
        "=" * 68,
    ]

    if diff_res["new"]:
        lines.append("\n[+] NEW INCIDENT GROUPS (Introduced in Target Run):")
        for item in diff_res["new"]:
            lines.append(f"  + [{item['runtime'].upper()}] {item['error_type']} (#{item['fingerprint']})")
            lines.append(f"    Occurrences: {item['occurrences']}")
            if item.get("normalized_message"):
                lines.append(f"    Message    : {item['normalized_message']}")

    if diff_res["resolved"]:
        lines.append("\n[-] RESOLVED INCIDENT GROUPS (Cleared in Target Run):")
        for item in diff_res["resolved"]:
            lines.append(f"  - [{item['runtime'].upper()}] {item['error_type']} (#{item['fingerprint']})")
            lines.append(f"    Prior Occurrences: {item['occurrences']}")
            if item.get("normalized_message"):
                lines.append(f"    Prior Message    : {item['normalized_message']}")

    if diff_res["persistent"]:
        lines.append("\n[=] PERSISTENT GROUPS (Present in Both):")
        for item in diff_res["persistent"]:
            delta_sign = f"+{item['delta_occurrences']}" if item["delta_occurrences"] > 0 else f"{item['delta_occurrences']}"
            lines.append(
                f"  = [{item['runtime'].upper()}] {item['error_type']} (#{item['fingerprint']}) "
                f"({item['occurrences_a']} -> {item['occurrences_b']}, delta: {delta_sign})"
            )

    return "\n".join(lines)


def get_source_preview(file_path_str: str, target_line: int, src_dir: Optional[Path]) -> Optional[str]:
    """Read 5 lines of source context (target_line +/- 2) safely. (TSK-025)

    Guards against symlink traversal and escapes beyond src_dir.
    """
    if not src_dir or not file_path_str or target_line <= 0:
        return None

    try:
        resolved_src = src_dir.resolve()
        candidate = (src_dir / file_path_str).resolve()
        # Verify containment
        if os.path.commonpath([resolved_src, candidate]) != str(resolved_src):
            return None
        if not candidate.is_file():
            return None

        with open(candidate, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()

        total = len(all_lines)
        if target_line > total:
            return None

        start = max(1, target_line - 2)
        end = min(total, target_line + 2)

        preview_lines = []
        for i in range(start, end + 1):
            marker = " > " if i == target_line else "   "
            line_content = all_lines[i - 1].rstrip("\r\n")
            preview_lines.append(f"{marker}{i:4d} | {line_content}")

        return "\n".join(preview_lines)
    except Exception:
        return None


def generate_html_report(
    total_lines: int,
    total_exceptions: int,
    groups: Sequence[IncidentGroup],
    duration_s: float,
    src_dir: Optional[Path] = None,
) -> str:
    num_groups = len(groups)
    acr = (total_exceptions / num_groups) if num_groups > 0 else 0.0

    cards_html = []
    for idx, g in enumerate(groups, start=1):
        loc = ", ".join(g.project_locations) if g.project_locations else "unknown frame"

        # Check for source preview
        preview_html = ""
        if src_dir and g.project_locations:
            # First project location e.g. "app.py:42" or "src/Main.java:15"
            first_loc = g.project_locations[0]
            if ":" in first_loc:
                f_path, f_line = first_loc.rsplit(":", 1)
                if f_line.isdigit():
                    preview_text = get_source_preview(f_path, int(f_line), src_dir)
                    if preview_text:
                        preview_html = f"""
            <details class="source-preview" style="margin-top:0.5rem; background: #161b22; border: 1px solid var(--border); border-radius: 4px; padding: 0.5rem;">
                <summary style="cursor:pointer; font-weight:600; color:var(--text); font-size:0.85rem;">Source Context ({html.escape(first_loc)})</summary>
                <pre style="margin:0.5rem 0 0; font-family:monospace; font-size:0.8rem; overflow-x:auto;">{html.escape(preview_text)}</pre>
            </details>
            """

        cards_html.append(
            f"""
        <div class="incident-card" data-runtime="{html.escape(g.runtime)}" data-text="{html.escape((g.error_type + ' ' + g.normalized_message + ' ' + g.fingerprint).lower())}">
            <div class="card-header">
                <div>
                    <span class="badge badge-{html.escape(g.runtime)}">{html.escape(g.runtime.upper())}</span>
                    <span class="error-type">{html.escape(g.error_type)}</span>
                    <span class="fingerprint">#{html.escape(g.fingerprint)}</span>
                </div>
                <div class="occurrences"><strong>{g.occurrences:,}</strong> occurrences</div>
            </div>
            <div class="card-meta">
                <span><strong>Location:</strong> {html.escape(loc)}</span>
            </div>
            {f'<div class="card-message"><code>{html.escape(g.normalized_message)}</code></div>' if g.normalized_message else ''}
            {preview_html}
            <details class="trace-details">
                <summary>Stack Trace Excerpt <button type="button" class="btn-copy" onclick="copyTrace(this, event)">Copy Trace</button></summary>
                <pre class="trace-block">{html.escape(g.representative_trace)}</pre>
            </details>
        </div>
        """
        )

    all_cards = "\n".join(cards_html)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pra-Effect Analysis Report</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --surface-hover: #334155;
            --text: #f8fafc;
            --muted: #94a3b8;
            --border: #334155;
            --primary: #38bdf8;
            --accent-node: #22c55e;
            --accent-python: #3b82f6;
            --danger: #ef4444;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            padding: 2rem;
            line-height: 1.5;
        }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        header {{ margin-bottom: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem; }}
        h1 {{ font-size: 1.8rem; font-weight: 700; color: var(--primary); }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 1.5rem 0;
        }}
        .stat-card {{
            background: var(--surface);
            padding: 1rem;
            border-radius: 8px;
            border: 1px solid var(--border);
        }}
        .stat-label {{ font-size: 0.85rem; color: var(--muted); text-transform: uppercase; }}
        .stat-val {{ font-size: 1.6rem; font-weight: bold; margin-top: 0.25rem; }}
        .controls {{
            display: flex;
            gap: 1rem;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
        }}
        .search-box {{
            flex: 1;
            min-width: 260px;
            padding: 0.6rem 1rem;
            border-radius: 6px;
            border: 1px solid var(--border);
            background: var(--surface);
            color: var(--text);
            font-size: 0.95rem;
        }}
        .filter-select {{
            padding: 0.6rem 1rem;
            border-radius: 6px;
            border: 1px solid var(--border);
            background: var(--surface);
            color: var(--text);
            font-size: 0.95rem;
        }}
        .incident-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 1rem;
            padding: 1.25rem;
        }}
        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }}
        .badge {{
            font-size: 0.75rem;
            font-weight: 700;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        .badge-node {{ background: rgba(34, 197, 94, 0.2); color: var(--accent-node); border: 1px solid var(--accent-node); }}
        .badge-python {{ background: rgba(59, 130, 246, 0.2); color: var(--accent-python); border: 1px solid var(--accent-python); }}
        .badge-java {{ background: rgba(176, 114, 25, 0.2); color: #b07219; border: 1px solid #b07219; }}
        .badge-foreign {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }}
        .error-type {{ font-size: 1.1rem; font-weight: bold; margin-left: 0.5rem; }}
        .fingerprint {{ font-family: monospace; color: var(--muted); font-size: 0.85rem; margin-left: 0.5rem; }}
        .occurrences {{ font-size: 0.95rem; color: var(--primary); }}
        .card-meta {{ font-size: 0.85rem; color: var(--muted); margin: 0.4rem 0; }}
        .card-message {{
            background: rgba(0, 0, 0, 0.2);
            padding: 0.5rem;
            border-radius: 4px;
            font-size: 0.9rem;
            margin: 0.5rem 0;
            word-break: break-all;
        }}
        .trace-details {{ margin-top: 0.75rem; }}
        .trace-details summary {{
            cursor: pointer;
            font-size: 0.85rem;
            color: var(--muted);
            user-select: none;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .btn-copy {{
            background: var(--surface-hover);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 0.2rem 0.5rem;
            font-size: 0.75rem;
            border-radius: 4px;
            cursor: pointer;
        }}
        .btn-copy:hover {{ background: var(--primary); color: #000; }}
        .trace-block {{
            background: #090d16;
            padding: 0.75rem;
            border-radius: 6px;
            margin-top: 0.5rem;
            font-family: Consolas, Monaco, monospace;
            font-size: 0.82rem;
            overflow-x: auto;
            border: 1px solid #1e293b;
            white-space: pre-wrap;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Pra-Effect — Analysis Report</h1>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Lines Scanned</div>
                    <div class="stat-val">{total_lines:,}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Exceptions Found</div>
                    <div class="stat-val">{total_exceptions:,}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Unique Incidents</div>
                    <div class="stat-val">{num_groups:,}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Compression Ratio</div>
                    <div class="stat-val">{acr:.2f}x</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Duration</div>
                    <div class="stat-val">{duration_s*1000:.1f}ms</div>
                </div>
            </div>
        </header>

        <section class="controls">
            <input type="text" id="searchInput" class="search-box" placeholder="Search error type, message, or fingerprint..." oninput="filterIncidents()">
            <select id="runtimeFilter" class="filter-select" onchange="filterIncidents()">
                <option value="all">All Runtimes</option>
                <option value="python">Python Only</option>
                <option value="node">Node.js Only</option>
            </select>
        </section>

        <main id="incidentList">
            {all_cards}
        </main>

        <footer style="margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.8rem;">
            Generated by Pra-Effect. All log content is HTML-escaped.
            Fingerprint normalization (UUID/hex/ID) is <strong>not</strong> PII redaction —
            tokens, emails, or secrets inside log messages appear as-is. Share with care.
        </footer>
    </div>

    <script>
        function filterIncidents() {{
            const search = document.getElementById('searchInput').value.toLowerCase().trim();
            const runtime = document.getElementById('runtimeFilter').value;
            const cards = document.querySelectorAll('.incident-card');

            cards.forEach(card => {{
                const cardRuntime = card.getAttribute('data-runtime');
                const cardText = card.getAttribute('data-text');
                const matchesRuntime = (runtime === 'all' || cardRuntime === runtime);
                const matchesSearch = (!search || cardText.includes(search));

                if (matchesRuntime && matchesSearch) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}

        function copyTrace(btn, event) {{
            event.preventDefault();
            event.stopPropagation();
            const details = btn.closest('.trace-details');
            const pre = details.querySelector('pre');
            if (pre) {{
                navigator.clipboard.writeText(pre.innerText).then(() => {{
                    const orig = btn.innerText;
                    btn.innerText = 'Copied!';
                    setTimeout(() => {{ btn.innerText = orig; }}, 1500);
                }}).catch(() => {{
                    btn.innerText = 'Failed';
                }});
            }}
        }}
    </script>
</body>
</html>
"""


def format_terminal_report(
    total_lines: int,
    total_exceptions: int,
    groups: Sequence[IncidentGroup],
    duration_s: float,
) -> str:
    num_groups = len(groups)
    acr = (total_exceptions / num_groups) if num_groups > 0 else 0.0

    out = []
    out.append("Pra-Effect — Analysis Complete")
    out.append(f"Lines scanned:        {total_lines:,}")
    out.append(f"Exceptions found:     {total_exceptions:,}")
    out.append(f"Unique incident groups:{num_groups:,}")
    out.append(f"Actionable Comp Ratio:{acr:.2f}x")
    out.append(f"Duration:             {duration_s*1000:.1f}ms")
    out.append("")
    out.append("TOP INCIDENTS")
    out.append("=" * 60)

    for idx, g in enumerate(groups[:5], start=1):
        loc = ", ".join(g.project_locations) if g.project_locations else "unknown frame"
        out.append(f"#{idx} [{g.runtime.upper()}] {g.error_type} ({g.fingerprint})")
        out.append(f"    Occurrences: {g.occurrences:,} | {loc}")
        if g.normalized_message:
            out.append(f"    Message:     {g.normalized_message}")
        out.append("    Sample stack excerpt:")
        sample_lines = g.representative_trace.strip().splitlines()
        for sl in sample_lines[-3:]:
            out.append(f"      {sl.strip()}")
        out.append("-" * 60)

    if len(groups) > 5:
        out.append(f"... and {len(groups) - 5} more groups.")

    out.append("")
    out.append(
        "NOTE: fingerprint normalization (UUID/hex/ID) is NOT PII redaction — "
        "tokens, emails, or secrets inside log messages are shown as-is."
    )
    return "\n".join(out)


class PraEffectArgumentParser(argparse.ArgumentParser):
    def error(self, message: str):
        sys.stderr.write(f"Error: {message}\n")
        sys.exit(2)


def main(argv: Optional[Sequence[str]] = None) -> int:
    # v1.0.0 release-consistency: CLI version must match pyproject + tag.
    if argv and argv[0] == "--version":
        print(f"pra-effect {__version__}")
        return 0
    parser = PraEffectArgumentParser(description="Pra-Effect: Local Stack Trace Deduplication")
    parser.add_argument("--version", action="version", version=f"pra-effect {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    # Ingest
    ingest_p = subparsers.add_parser("ingest", help="Ingest log stream from STDIN")
    ingest_p.add_argument("--src", type=str, default=None, help="Project source directory")
    ingest_p.add_argument("--save", action="store_true", help="Save run into local SQLite history")
    ingest_p.add_argument("--db", type=str, default=None, help="Path to SQLite database file")
    ingest_p.add_argument("--html", type=str, default=None, help="Generate standalone interactive HTML report")
    ingest_p.add_argument("--max-input-mb", type=float, default=DEFAULT_MAX_INPUT_MB,
                          help="Input size backstop in MB (0 disables; streaming already bounds memory)")
    ingest_p.add_argument("--scrub-secrets", action="store_true",
                          help="Redact Bearer tokens, JWT, passwords, and API keys from outputs (TSK-023)")
    ingest_p.add_argument("--fail-if-groups-exceed", type=int, default=None,
                          help="CI Quality Gate: exit code 2 if unique incident groups exceed N (TSK-023)")

    # Scan
    scan_p = subparsers.add_parser("scan", help="Scan log file or directory")
    scan_p.add_argument("path", type=str, help="Path to file or directory")
    scan_p.add_argument(
        "--pattern",
        type=str,
        default="*.log,*.txt",
        help="Comma-separated glob patterns for directory scanning (default: *.log,*.txt)",
    )
    scan_p.add_argument("--src", type=str, default=None, help="Project source directory")
    scan_p.add_argument("--save", action="store_true", help="Save run into local SQLite history")
    scan_p.add_argument("--db", type=str, default=None, help="Path to SQLite database file")
    scan_p.add_argument("--html", type=str, default=None, help="Generate standalone interactive HTML report")
    scan_p.add_argument("--max-input-mb", type=float, default=DEFAULT_MAX_INPUT_MB,
                        help="Input size backstop in MB (0 disables; streaming already bounds memory)")
    scan_p.add_argument("--scrub-secrets", action="store_true",
                        help="Redact Bearer tokens, JWT, passwords, and API keys from outputs (TSK-023)")
    scan_p.add_argument("--fail-if-groups-exceed", type=int, default=None,
                        help="CI Quality Gate: exit code 2 if unique incident groups exceed N (TSK-023)")

    # History
    hist_p = subparsers.add_parser("history", help="View historical incident aggregation")
    hist_p.add_argument("--db", type=str, default=None, help="Path to SQLite database file")
    hist_p.add_argument("--limit", type=int, default=15, help="Number of records to show")

    # Diff (TSK-024)
    diff_p = subparsers.add_parser("diff", help="Compare two historical runs to see new, resolved, and persistent groups")
    diff_p.add_argument("run_a", type=int, help="Base run ID (older)")
    diff_p.add_argument("run_b", type=int, help="Target run ID (newer)")
    diff_p.add_argument("--db", type=str, default=None, help="Path to SQLite database file")
    diff_p.add_argument("--fail-on-new", action="store_true", help="CI gate: return exit code 2 if target run introduced new incident groups")

    args = parser.parse_args(argv)
    if not args.command:
        if not sys.stdin.isatty():
            cmd = "ingest"
            src_val = None
            save_val = False
            db_val = None
            html_val = None
            scrub_secrets_val = False
            fail_groups_threshold = None
        else:
            parser.print_help()
            return 2
    else:
        cmd = args.command
        src_val = getattr(args, "src", None)
        save_val = getattr(args, "save", False)
        db_val = getattr(args, "db", None)
        html_val = getattr(args, "html", None)
        scrub_secrets_val = getattr(args, "scrub_secrets", False)
        fail_groups_threshold = getattr(args, "fail_if_groups_exceed", None)

    cwd = Path.cwd()
    default_db = cwd / ".pra-effect" / "traces.db"
    db_path = Path(db_val) if db_val else default_db

    if cmd == "history":
        if not db_path.exists():
            print(f"No history found at: {db_path}")
            return 0
        incidents = query_historical_incidents(db_path, limit=getattr(args, "limit", 15))
        runs = query_recent_runs(db_path, limit=5)
        print("Pra-Effect — Historical Incident View")
        print(f"Database: {db_path}")
        print(f"Recent runs: {len(runs)}")
        print("=" * 60)
        for idx, inc in enumerate(incidents, start=1):
            print(
                f"#{idx} [{inc['runtime'].upper()}] {inc['error_type']} ({inc['fingerprint']})"
            )
            print(
                f"    Total occurrences: {inc['total_seen_count']} across {inc['total_runs_seen']} run(s)"
            )
            print(f"    First seen: {inc['first_seen_utc']} | Last seen: {inc['last_seen_utc']}")
            if inc["normalized_message"]:
                print(f"    Message:    {inc['normalized_message']}")
            print("-" * 60)
        return 0

    if cmd == "diff":
        if not db_path.exists():
            sys.stderr.write(f"Error: Database not found at {db_path}\n")
            return 1
        try:
            diff_res = diff_runs(db_path, args.run_a, args.run_b)
        except Exception as e:
            sys.stderr.write(f"Error: {e}\n")
            return 1
        print(format_diff_report(diff_res))
        if getattr(args, "fail_on_new", False) and len(diff_res["new"]) > 0:
            sys.stderr.write(f"\n[Pra-Effect Gate] Failed: {len(diff_res['new'])} new incident group(s) detected.\n")
            return 2
        return 0

    src_dir = Path(src_val) if src_val else cwd
    t_start = time.perf_counter()

    # DEC-016: --max-input-mb is a backstop on top of streaming, never a
    # substitute for it. 0 disables the cap.
    max_mb = getattr(args, "max_input_mb", DEFAULT_MAX_INPUT_MB)
    max_bytes = int(max_mb * 1024 * 1024) if max_mb and max_mb > 0 else None

    try:
        if cmd == "ingest":
            source = iter_stdin_lines()
        else:
            target = Path(args.path)
            if not target.exists():
                sys.stderr.write(f"Error: path not found {target}\n")
                return 1
            source = iter_scan_lines(target, args.pattern)
        total_lines, total_exceptions, groups = stream_analyze(
            source, cwd, src_dir, max_bytes, scrub_secrets=scrub_secrets_val
        )
    except (InputTooLargeError, ScanInputError) as e:
        sys.stderr.write(f"{e}\n")
        return 1
    except KeyboardInterrupt:
        # TSK-022 / v1.0.1: Graceful SIGINT exit (130) without unhandled Python traceback
        sys.stderr.write("\n[Pra-Effect] Interrupted by user\n")
        return 130
    except BrokenPipeError:
        # TSK-022 / v1.0.1: Standard UNIX pipe break (e.g. head -n)
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return 0

    duration_s = time.perf_counter() - t_start
    report = format_terminal_report(total_lines, total_exceptions, groups, duration_s)
    print(report)

    if save_val:
        run_id = save_run_to_db(
            db_path=db_path,
            command=cmd,
            total_lines=total_lines,
            total_exceptions=total_exceptions,
            duration_ms=duration_s * 1000.0,
            groups=groups,
        )
        print(f"\n[Pra-Effect] Run #{run_id} persisted to {db_path}")

    if html_val:
        html_out_path = Path(html_val)
        html_out_path.parent.mkdir(parents=True, exist_ok=True)
        html_content = generate_html_report(
            total_lines=total_lines,
            total_exceptions=total_exceptions,
            groups=groups,
            duration_s=duration_s,
            src_dir=src_dir,
        )
        html_out_path.write_text(html_content, encoding="utf-8")
        print(f"[Pra-Effect] Interactive HTML report saved to {html_out_path}")

    # TSK-023: CI quality gate check
    if fail_groups_threshold is not None and len(groups) > fail_groups_threshold:
        sys.stderr.write(
            f"\n[Pra-Effect CI Gate] Failure: unique incident groups ({len(groups)}) "
            f"exceed threshold ({fail_groups_threshold})\n"
        )
        return 2

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(0)
    except KeyboardInterrupt:
        sys.stderr.write("\n[Pra-Effect] Interrupted by user\n")
        sys.exit(130)
