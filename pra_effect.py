"""pra_effect.py - Core parser, fingerprinting, and CLI for Pra-Effect.
Zero external dependencies. Python standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import sqlite3
import sys
import time
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

FINGERPRINT_VERSION = "fingerprint_v1"
MAX_LINE_LENGTH = 4096
MAX_CONTINUATION_LINES = 5
MAX_INTERLEAVED_LINES = 2

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
    runtime: str  # "python" | "node"
    error_type: str
    original_message: str
    normalized_message: str
    frames: List[StackFrame]
    raw_text: str
    fingerprint: str = ""
    timestamp: Optional[str] = None
    is_truncated: bool = False

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


class TracebackParser:
    def __init__(self, cwd: Optional[Path] = None, src_dir: Optional[Path] = None):
        self.cwd = cwd or Path.cwd()
        self.src_dir = src_dir

    def parse_python_traces(self, text: str) -> List[ParsedTrace]:
        traces: List[ParsedTrace] = []
        raw_lines = text.splitlines()
        lines: List[str] = []
        lines_truncated: List[bool] = []
        for l in raw_lines:
            if len(l) > MAX_LINE_LENGTH:
                lines.append(l[:MAX_LINE_LENGTH])
                lines_truncated.append(True)
            else:
                lines.append(l)
                lines_truncated.append(False)

        i = 0
        n = len(lines)
        # DEC-011: cause tracebacks parked until their outer root traceback appears
        pending_causes: List[Tuple[ParsedTrace, str]] = []

        while i < n:
            line = lines[i]
            if RE_PY_TRACE_START.match(line.strip()):
                start_idx = i
                frames: List[StackFrame] = []
                trace_lines: List[str] = [lines[i]]
                interleaved_count = 0
                i += 1
                while i < n:
                    frame_match = RE_PY_FRAME.match(lines[i])
                    if frame_match:
                        interleaved_count = 0
                        trace_lines.append(lines[i])
                        raw_fpath, line_no, func_name = frame_match.groups()
                        norm_p, in_proj = normalize_frame_path(
                            raw_fpath, self.cwd, self.src_dir
                        )
                        frames.append(
                            StackFrame(
                                filepath=raw_fpath,
                                line_number=int(line_no),
                                function_name=func_name,
                                is_in_project=in_proj,
                                normalized_path=norm_p,
                            )
                        )
                        i += 1
                        # Indented source code line
                        if i < n and lines[i].startswith("    ") and not RE_PY_FRAME.match(lines[i]):
                            trace_lines.append(lines[i])
                            i += 1
                        continue

                    err_match = RE_PY_ERROR.match(lines[i].strip())
                    if err_match:
                        err_type = err_match.group(1)
                        raw_msg = err_match.group(2) or ""
                        trace_lines.append(lines[i])
                        i += 1
                        # Bounded multi-line collector (max 5 additional lines)
                        extra_lines = []
                        collected = 0
                        while (
                            i < n
                            and collected < MAX_CONTINUATION_LINES
                            and lines[i].strip()
                            and not RE_PY_TRACE_START.match(lines[i].strip())
                            and not RE_PY_FRAME.match(lines[i])
                            and not RE_PY_ERROR.match(lines[i].strip())
                            and not RE_NODE_ERROR_HEADER.match(lines[i].strip())
                            and not RE_CHAIN_MARKER.match(lines[i].strip())
                            and not RE_LOG_LEVEL_LINE.match(lines[i].strip())
                            and not RE_TIMESTAMP_LINE.match(lines[i].strip())
                        ):
                            extra_lines.append(lines[i].strip())
                            trace_lines.append(lines[i])
                            collected += 1
                            i += 1

                        if extra_lines:
                            raw_msg = (
                                raw_msg + " " + " ".join(extra_lines)
                                if raw_msg
                                else " ".join(extra_lines)
                            )

                        end_idx = i
                        raw_block = "\n".join(trace_lines)
                        if pending_causes:
                            # DEC-011: outermost exception owns the incident; causes ride along
                            # as diagnostic context only (never enter the fingerprint payload).
                            parts: List[str] = []
                            for cause_trace, marker_line in pending_causes:
                                parts.append(cause_trace.raw_text)
                                parts.append(marker_line)
                            parts.append(raw_block)
                            raw_block = "\n".join(parts)
                            pending_causes = []
                        norm_msg, is_trunc = normalize_message(raw_msg)
                        any_trunc = is_trunc or any(lines_truncated[start_idx:end_idx])
                        trace = ParsedTrace(
                            runtime="python",
                            error_type=err_type,
                            original_message=raw_msg,
                            normalized_message=norm_msg,
                            frames=frames,
                            raw_text=raw_block,
                            is_truncated=any_trunc,
                        )
                        trace.fingerprint = trace.compute_fingerprint()
                        traces.append(trace)
                        break

                    # Check for new trace start or node header -> abort candidate
                    if RE_PY_TRACE_START.match(lines[i].strip()) or RE_NODE_ERROR_HEADER.match(lines[i].strip()):
                        break

                    # Interleaving tolerance (Decision 1B: max 2 lines)
                    if interleaved_count < MAX_INTERLEAVED_LINES:
                        interleaved_count += 1
                        i += 1
                        continue
                    else:
                        # Exceeded tolerance, rewind to start_idx + 1 so outer loop can scan
                        i = start_idx + 1
                        break
            else:
                stripped = line.strip()
                if RE_CHAIN_MARKER.match(stripped) and traces:
                    # This completed traceback is a cause; hold it for the next (outer) traceback.
                    pending_causes.append((traces.pop(), stripped))
                i += 1

        # Log truncated mid-chain: keep parked causes as standalone traces instead of dropping them
        for cause_trace, _marker in pending_causes:
            traces.append(cause_trace)
        return traces

    def parse_node_traces(self, text: str) -> List[ParsedTrace]:
        traces: List[ParsedTrace] = []
        raw_lines = text.splitlines()
        lines: List[str] = []
        lines_truncated: List[bool] = []
        for l in raw_lines:
            if len(l) > MAX_LINE_LENGTH:
                lines.append(l[:MAX_LINE_LENGTH])
                lines_truncated.append(True)
            else:
                lines.append(l)
                lines_truncated.append(False)

        i = 0
        n = len(lines)

        while i < n:
            line_str = lines[i].strip()
            header_match = RE_NODE_ERROR_HEADER.match(line_str)
            if header_match:
                # Look ahead to see if the next non-empty line starts with 'at '
                peek = i + 1
                while peek < n and not lines[peek].strip():
                    peek += 1
                if peek < n and lines[peek].strip().startswith("at "):
                    err_type = header_match.group(1)
                    raw_msg = header_match.group(2) or ""
                    start_idx = i
                    frames: List[StackFrame] = []
                    trace_lines: List[str] = [lines[i]]
                    interleaved_count = 0
                    i = peek

                    while i < n:
                        line_cur = lines[i].strip()
                        if not line_cur:
                            i += 1
                            continue

                        f_match = RE_NODE_FRAME.match(line_cur)
                        if f_match:
                            interleaved_count = 0
                            trace_lines.append(lines[i])
                            fn_name, raw_fpath, line_no, _ = f_match.groups()
                            fn_name = fn_name or "<anonymous>"
                            norm_p, in_proj = normalize_frame_path(
                                raw_fpath, self.cwd, self.src_dir
                            )
                            frames.append(
                                StackFrame(
                                    filepath=raw_fpath,
                                    line_number=int(line_no),
                                    function_name=fn_name,
                                    is_in_project=in_proj,
                                    normalized_path=norm_p,
                                )
                            )
                            i += 1
                            continue

                        # Check if another trace header begins
                        if RE_NODE_ERROR_HEADER.match(line_cur) or RE_PY_TRACE_START.match(line_cur):
                            break

                        # Interleaving tolerance (Decision 1B: max 2 lines non-trace)
                        if interleaved_count < MAX_INTERLEAVED_LINES:
                            interleaved_count += 1
                            i += 1
                            continue
                        else:
                            break

                    raw_block = "\n".join(trace_lines)
                    norm_msg, is_trunc = normalize_message(raw_msg)
                    any_trunc = is_trunc or any(lines_truncated[start_idx:i])
                    trace = ParsedTrace(
                        runtime="node",
                        error_type=err_type,
                        original_message=raw_msg,
                        normalized_message=norm_msg,
                        frames=frames,
                        raw_text=raw_block,
                        is_truncated=any_trunc,
                    )
                    trace.fingerprint = trace.compute_fingerprint()
                    traces.append(trace)
                    continue
            i += 1
        return traces

    def parse_all(self, text: str) -> List[ParsedTrace]:
        py_traces = self.parse_python_traces(text)
        node_traces = self.parse_node_traces(text)
        return py_traces + node_traces


def group_traces(traces: Iterable[ParsedTrace]) -> List[IncidentGroup]:
    groups: dict[str, IncidentGroup] = {}
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


def generate_html_report(
    total_lines: int,
    total_exceptions: int,
    groups: Sequence[IncidentGroup],
    duration_s: float,
) -> str:
    num_groups = len(groups)
    acr = (total_exceptions / num_groups) if num_groups > 0 else 0.0

    cards_html = []
    for idx, g in enumerate(groups, start=1):
        loc = ", ".join(g.project_locations) if g.project_locations else "unknown frame"
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


def read_log_file(path: Path) -> Tuple[Optional[str], Optional[str]]:
    """Read one log file. Returns (text, None) on success or (None, skip_reason)."""
    try:
        data = path.read_bytes()
    except OSError as e:
        return None, f"unreadable ({e.strerror or e})"
    if b"\x00" in data[:8192]:
        return None, "binary content (NUL byte)"
    return data.decode("utf-8", errors="replace"), None


def read_scan_target(target: Path, pattern: str) -> Tuple[Optional[str], int, int]:
    """Read an explicit file or glob a directory (DEC-012).

    Returns (text, files_seen, files_read). text is None when an explicit file
    fails, or when a directory yielded zero readable files.
    """
    if target.is_file():
        text, reason = read_log_file(target)
        if text is None:
            sys.stderr.write(f"Error: cannot read {target}: {reason}\n")
            return None, 1, 0
        return text, 1, 1

    globs = [p.strip() for p in pattern.split(",") if p.strip()]
    seen: dict = {}
    for g in globs:
        for f in sorted(target.glob(f"**/{g}")):
            if f.is_file():
                seen[f] = None
    buf: List[str] = []
    read_ok = 0
    for f in seen:
        text, reason = read_log_file(f)
        if text is None:
            sys.stderr.write(f"[Pra-Effect] skipped {f}: {reason}\n")
            continue
        buf.append(text)
        read_ok += 1
    if read_ok == 0:
        sys.stderr.write(
            f"Error: no readable log files matched pattern '{pattern}' in {target}\n"
        )
        return None, len(seen), 0
    return "\n".join(buf), len(seen), read_ok


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = PraEffectArgumentParser(description="Pra-Effect: Local Stack Trace Deduplication")
    subparsers = parser.add_subparsers(dest="command")

    # Ingest
    ingest_p = subparsers.add_parser("ingest", help="Ingest log stream from STDIN")
    ingest_p.add_argument("--src", type=str, default=None, help="Project source directory")
    ingest_p.add_argument("--save", action="store_true", help="Save run into local SQLite history")
    ingest_p.add_argument("--db", type=str, default=None, help="Path to SQLite database file")
    ingest_p.add_argument("--html", type=str, default=None, help="Generate standalone interactive HTML report")

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

    # History
    hist_p = subparsers.add_parser("history", help="View historical incident aggregation")
    hist_p.add_argument("--db", type=str, default=None, help="Path to SQLite database file")
    hist_p.add_argument("--limit", type=int, default=15, help="Number of records to show")

    args = parser.parse_args(argv)
    if not args.command:
        if not sys.stdin.isatty():
            cmd = "ingest"
            src_val = None
            save_val = False
            db_val = None
            html_val = None
        else:
            parser.print_help()
            return 2
    else:
        cmd = args.command
        src_val = getattr(args, "src", None)
        save_val = getattr(args, "save", False)
        db_val = getattr(args, "db", None)
        html_val = getattr(args, "html", None)

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

    src_dir = Path(src_val) if src_val else cwd
    t_start = time.perf_counter()

    raw_text = ""
    if cmd == "ingest":
        raw_text = sys.stdin.read()
    elif cmd == "scan":
        target = Path(args.path)
        if not target.exists():
            sys.stderr.write(f"Error: path not found {target}\n")
            return 1
        raw_text, _seen, _read = read_scan_target(target, args.pattern)
        if raw_text is None:
            return 1

    t_parser = TracebackParser(cwd=cwd, src_dir=src_dir)
    traces = t_parser.parse_all(raw_text)
    groups = group_traces(traces)
    duration_s = time.perf_counter() - t_start

    total_lines = len(raw_text.splitlines())
    report = format_terminal_report(total_lines, len(traces), groups, duration_s)
    print(report)

    if save_val:
        run_id = save_run_to_db(
            db_path=db_path,
            command=cmd,
            total_lines=total_lines,
            total_exceptions=len(traces),
            duration_ms=duration_s * 1000.0,
            groups=groups,
        )
        print(f"\n[Pra-Effect] Run #{run_id} persisted to {db_path}")

    if html_val:
        html_out_path = Path(html_val)
        html_out_path.parent.mkdir(parents=True, exist_ok=True)
        html_content = generate_html_report(
            total_lines=total_lines,
            total_exceptions=len(traces),
            groups=groups,
            duration_s=duration_s,
        )
        html_out_path.write_text(html_content, encoding="utf-8")
        print(f"[Pra-Effect] Interactive HTML report saved to {html_out_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
