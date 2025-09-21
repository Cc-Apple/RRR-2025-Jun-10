# -*- coding: utf-8 -*-
"""
KABUKI-INV — RTCR Deep FUKABORI Pipeline (friend set) v1.0
Author: GPT-5 Thinking (assistant)
User: Tajima (構文支配者)

Contract (per user request):
- Do *not* emit interim narrative reports.
- Only Python code and tables may appear in-room.
- Actual output/tables are produced *only* when the user explicitly says "output" (or calls the run functions below).
- This script prepares a reproducible pipeline to FUKABORI (deep-dive) the uploaded friend RTCR and related logs,
  cross-referencing the infection date 2025-07-12.

Uploaded artifacts (per this room):
- /mnt/data/PHOTO-2025-08-07-19-52-24 (1).zip
- /mnt/data/spotlightknowledged.cpu_resource-2025-07-31-231436.zip
- /mnt/data/RTCReporting_messageLog_2025-08-30-06-25-32.zip

What this script does (when you call run_* functions):
1) Extract all ZIPs into structured folders under /mnt/data/friend_ingest/ .
2) Index every discovered file with path, size, SHA-256, mtimes; parse timestamps from filename/content.
3) Parse .ips / Analytics / RTCR logs to structured rows (bug_type, incident_id, process, pid, os_version, exception, etc.).
4) Parse image EXIF (if available) and compute SHA-256 for all images; attach EXIF DateTimeOriginal.
5) Build a canonical TIMELINE (DataFrame) across *all* sources; align against infection date 2025-07-12 (UTC+7),
   and compute day_offset and time_distance.
6) Produce standard tables (but only when you call the emit functions):
   A) overview_per_log
   B) combined_process_list
   C) parse_errors
   D) daily_stats
   E) rtcr_focus (RTCR-only slice)
   F) align_2025_07_12_window (±7 days slice around infection date)
7) Optionally write CSVs to /mnt/data/friend_ingest/exports/ and return DataFrames to the notebook for display.

Usage (no output happens until you explicitly call emit_*):
    from pathlib import Path
    p = Pipeline()
    p.prepare()                  # extracts ZIPs, indexes files, parses logs (quiet)
    dfs = p.emit_tables()        # returns dict of DataFrames (and writes CSVs if write_csv=True)
    # or, for timeline-only slice around 2025-07-12:
    window = p.emit_alignment_window(days=7)

All timestamps are normalized to Asia/Ho_Chi_Minh (UTC+07:00) where possible.
"""

from __future__ import annotations
import os
import io
import re
import json
import csv
import sys
import hashlib
import zipfile
import plistlib
import traceback
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple

try:
    import pandas as pd
except Exception:
    raise

# PIL is optional (for EXIF on images). If missing, image EXIF will be skipped.
try:
    from PIL import Image, ExifTags
    PIL_OK = True
except Exception:
    PIL_OK = False

TZ_VN = timezone(timedelta(hours=7))
INFECTION_DATE = datetime(2025, 7, 12, 0, 0, 0, tzinfo=TZ_VN)

ARTIFACTS = [
    Path("/mnt/data/PHOTO-2025-08-07-19-52-24 (1).zip"),
    Path("/mnt/data/spotlightknowledged.cpu_resource-2025-07-31-231436.zip"),
    Path("/mnt/data/RTCReporting_messageLog_2025-08-30-06-25-32.zip"),
]

OUTDIR = Path("/mnt/data/friend_ingest").resolve()
EXTRACT_DIR = OUTDIR / "extracted"
EXPORTS_DIR = OUTDIR / "exports"
EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
EXPORTS_DIR.mkdir(parents=True, exist_ok=True)

# ------------------------------
# Helpers
# ------------------------------

def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

FILENAME_TS_PATTERNS = [
    # Common patterns e.g., 2025-07-31-231436, 2025-08-30-06-25-32, etc.
    (re.compile(r"(20\d{2})[-_](\d{2})[-_](\d{2})[-_](\d{2})[-_]?(\d{2})[-_]?(\d{2})"), "%Y-%m-%d-%H-%M-%S"),
    (re.compile(r"(20\d{2})(\d{2})(\d{2})[T_\-]?(\d{2})(\d{2})(\d{2})"), "%Y%m%d%H%M%S"),
]

def parse_timestamp_from_name(name: str) -> Optional[datetime]:
    base = Path(name).name
    for pat, fmt in FILENAME_TS_PATTERNS:
        m = pat.search(base)
        if m:
            # normalize digits
            parts = m.groups()
            digits = "-".join(parts[:3]) + "-" + ":".join(parts[3:])
            # try multiple fmts safely
            for fmt_try in ("%Y-%m-%d-%H-%M-%S", "%Y-%m-%d-%H:%M:%S"):
                try:
                    dt = datetime.strptime(digits, fmt_try).replace(tzinfo=TZ_VN)
                    return dt
                except Exception:
                    pass
    return None

# iOS .ips may be JSON or plist-like text. Try JSON first, then plist, then regex fallback.

def parse_ips_text(txt: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    # Try JSON
    try:
        j = json.loads(txt)
        if isinstance(j, dict):
            data.update(j)
            return data
    except Exception:
        pass
    # Try plist
    try:
        p = plistlib.loads(txt.encode('utf-8'))
        if isinstance(p, dict):
            data.update(p)
            return data
    except Exception:
        pass
    # Regex fallback (very loose)
    # Matches: key: value  and  "key" = value; style
    for line in txt.splitlines():
        kv = re.match(r"\s*([A-Za-z0-9_\-\.]+)\s*[:=]\s*(.+)$", line)
        if kv:
            k, v = kv.group(1), kv.group(2).strip()
            data[k] = v
    return data

# Extract key fields from parsed structure

def extract_ips_fields(meta: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    out['bug_type'] = meta.get('bug_type') or meta.get('bugType') or meta.get('BugType')
    out['incident_id'] = meta.get('incident_id') or meta.get('incidentId') or meta.get('Incident')
    out['timestamp_raw'] = meta.get('timestamp') or meta.get('date') or meta.get('Timestamp')
    out['os_version'] = meta.get('os_version') or meta.get('osVersion') or meta.get('OSVersion')
    # Common process fields
    out['process'] = (meta.get('process') or meta.get('proc_name') or meta.get('Process') or
                      meta.get('com.apple.thread') or meta.get('CFBundleExecutable'))
    out['pid'] = meta.get('pid') or meta.get('Pid') or meta.get('PID')
    out['exception_type'] = meta.get('exception_type') or meta.get('ExceptionType')
    out['exception_subtype'] = meta.get('exception_subtype') or meta.get('ExceptionSubtype')
    out['termination'] = meta.get('termination') or meta.get('Termination')
    out['signal'] = meta.get('termination_signal') or meta.get('Signal')
    return out

# Normalize timestamp string to datetime with TZ_VN when possible

def normalize_any_timestamp(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    s = s.strip()
    # Try strict formats first
    fmts = [
        "%Y-%m-%d %H:%M:%S.%f %z",
        "%Y-%m-%d %H:%M:%S %z",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ]
    for f in fmts:
        try:
            dt = datetime.strptime(s, f)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=TZ_VN)
            else:
                dt = dt.astimezone(TZ_VN)
            return dt
        except Exception:
            pass
    # ISO general
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=TZ_VN)
        else:
            dt = dt.astimezone(TZ_VN)
        return dt
    except Exception:
        pass
    return None

# Parse RTCR message log (generic). Accepts JSON/plist/text lines.

def parse_rtcr_text(txt: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    # JSON lines?
    try:
        j = json.loads(txt)
        if isinstance(j, list):
            for e in j:
                if isinstance(e, dict):
                    rows.append(e)
            return rows
        if isinstance(j, dict):
            rows.append(j)
            return rows
    except Exception:
        pass
    # plist dict or array
    try:
        p = plistlib.loads(txt.encode('utf-8'))
        if isinstance(p, list):
            for e in p:
                if isinstance(e, dict):
                    rows.append(e)
        elif isinstance(p, dict):
            rows.append(p)
        if rows:
            return rows
    except Exception:
        pass
    # Fallback: parse lines like "YYYY-mm-dd HH:MM:SS ... RTCR ..."
    TS = re.compile(r"(20\d{2}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[\+\-]\d{2}:?\d{2})?)")
    for line in txt.splitlines():
        m = TS.search(line)
        if m:
            t = m.group(1)
            dt = normalize_any_timestamp(t)
        else:
            dt = None
        rows.append({"timestamp": t if m else None, "timestamp_dt": dt, "raw": line})
    return rows

# ------------------------------
# Core Pipeline
# ------------------------------

class Pipeline:
    def __init__(self):
        self.extract_dir = EXTRACT_DIR
        self.exports_dir = EXPORTS_DIR
        self.index_rows: List[Dict[str, Any]] = []
        self.parsed_rows: List[Dict[str, Any]] = []
        self.parse_errors: List[Dict[str, Any]] = []

    # 1) Extract all zip artifacts
    def _extract_all(self) -> None:
        for z in ARTIFACTS:
            if not z.exists():
                continue
            target = self.extract_dir / z.stem
            target.mkdir(parents=True, exist_ok=True)
            try:
                with zipfile.ZipFile(z, 'r') as zf:
                    zf.extractall(target)
            except Exception:
                self.parse_errors.append({"stage": "extract", "path": str(z), "error": traceback.format_exc()})

    # 2) Walk & index
    def _index_files(self) -> None:
        for p in self.extract_dir.rglob('*'):
            if p.is_file():
                try:
                    size = p.stat().st_size
                    sha = sha256_file(p)
                    ts_from_name = parse_timestamp_from_name(p.name)
                    self.index_rows.append({
                        "path": str(p),
                        "name": p.name,
                        "ext": p.suffix.lower(),
                        "size": size,
                        "sha256": sha,
                        "mtime": datetime.fromtimestamp(p.stat().st_mtime, tz=TZ_VN),
                        "ts_from_name": ts_from_name,
                    })
                except Exception:
                    self.parse_errors.append({"stage": "index", "path": str(p), "error": traceback.format_exc()})

    # 3) Parse known types
    def _parse_known(self) -> None:
        for row in self.index_rows:
            p = Path(row["path"])            
            ext = row["ext"]
            try:
                if ext in {".ips", ".log", ".txt", ".json", ".plist"}:
                    txt = p.read_text(errors='replace')
                    # Heuristic: RTCR bundle name hints
                    if "RTCReporting" in str(p) or "RTCR" in txt or "RTCReporting" in txt:
                        rtcr_rows = parse_rtcr_text(txt)
                        for e in rtcr_rows:
                            out = {"source": "RTCR", "path": str(p)}
                            # map common fields
                            ts = e.get("timestamp") or e.get("time") or e.get("date")
                            dt = normalize_any_timestamp(ts)
                            out.update({
                                "timestamp": ts,
                                "timestamp_dt": dt or row.get("ts_from_name"),
                                "raw": e.get("raw") or json.dumps(e, ensure_ascii=False)[:2000],
                            })
                            self.parsed_rows.append(out)
                    else:
                        meta = parse_ips_text(txt)
                        fields = extract_ips_fields(meta)
                        dt = normalize_any_timestamp(fields.get("timestamp_raw"))
                        out = {
                            "source": "IPS/LOG",
                            "path": str(p),
                            **fields,
                            "timestamp_dt": dt or row.get("ts_from_name"),
                        }
                        self.parsed_rows.append(out)
                elif ext in {".jpg", ".jpeg", ".png", ".heic"}:
                    # image hashing was done in index; add EXIF
                    exif_dt = None
                    if PIL_OK:
                        try:
                            with Image.open(p) as im:
                                exif = im.getexif() or {}
                                # map tag names
                                tagmap = {ExifTags.TAGS.get(k, k): v for k, v in exif.items()}
                                dtorig = tagmap.get('DateTimeOriginal') or tagmap.get('DateTime')
                                if isinstance(dtorig, str):
                                    # EXIF: 'YYYY:MM:DD HH:MM:SS'
                                    try:
                                        exif_dt = datetime.strptime(dtorig, "%Y:%m:%d %H:%M:%S").replace(tzinfo=TZ_VN)
                                    except Exception:
                                        pass
                        except Exception:
                            self.parse_errors.append({"stage": "image_exif", "path": str(p), "error": traceback.format_exc()})
                    self.parsed_rows.append({
                        "source": "IMAGE",
                        "path": str(p),
                        "timestamp_dt": exif_dt or row.get("ts_from_name"),
                        "bug_type": None,
                        "incident_id": None,
                        "process": None,
                        "pid": None,
                    })
                else:
                    # Unknown file — still place on timeline using name-ts or mtime
                    self.parsed_rows.append({
                        "source": "OTHER",
                        "path": str(p),
                        "timestamp_dt": row.get("ts_from_name") or row.get("mtime"),
                    })
            except Exception:
                self.parse_errors.append({"stage": "parse", "path": str(p), "error": traceback.format_exc()})

    def prepare(self) -> None:
        """Run extract + index + parse (quiet)."""
        self._extract_all()
        self._index_files()
        self._parse_known()

    # ---------- table emitters (only run when explicitly requested) ----------

    def _timeline_df(self) -> pd.DataFrame:
        df = pd.DataFrame(self.parsed_rows)
        if df.empty:
            # Even if parsing yielded nothing, fall back to index rows
            base = pd.DataFrame(self.index_rows)
            if base.empty:
                return pd.DataFrame(columns=["timestamp_dt", "source", "path"])            
            df = base.assign(source="INDEX", timestamp_dt=base["ts_from_name"].fillna(base["mtime"]))[["timestamp_dt", "source", "path"]]
        # normalize timestamps
        if "timestamp_dt" not in df:
            df["timestamp_dt"] = None
        # derive alignment columns
        df["timestamp_dt"] = pd.to_datetime(df["timestamp_dt"], errors='coerce')
        df = df.sort_values("timestamp_dt")
        df["infection_date"] = INFECTION_DATE
        df["time_delta_sec"] = (df["timestamp_dt"] - INFECTION_DATE).dt.total_seconds()
        df["day_offset"] = (df["time_delta_sec"] / 86400.0).round(3)
        return df

    def emit_tables(self, write_csv: bool = True) -> Dict[str, pd.DataFrame]:
        df = self._timeline_df()
        # A) Overview per log
        overview_cols = [
            "timestamp_dt", "source", "path", "bug_type", "incident_id", "process", "pid", "os_version", "exception_type", "exception_subtype", "termination", "signal"
        ]
        overview = df[overview_cols].copy() if set(overview_cols).issubset(df.columns) else df.copy()

        # B) Combined process list
        procs = df.loc[df["process"].notna(), ["timestamp_dt", "process", "pid", "source", "path"]].copy() if "process" in df else pd.DataFrame(columns=["timestamp_dt","process","pid","source","path"])

        # C) Parse errors as a table
        err = pd.DataFrame(self.parse_errors)

        # D) Daily stats
        daily = df.copy()
        daily['date'] = daily['timestamp_dt'].dt.tz_convert(TZ_VN).dt.date if pd.api.types.is_datetime64_any_dtype(daily['timestamp_dt']) else None
        daily_stats = daily.groupby('date', dropna=True).size().reset_index(name='count') if 'date' in daily else pd.DataFrame(columns=['date','count'])

        # E) RTCR focus
        rtcr_focus = df[df['source'] == 'RTCR'].copy() if 'source' in df else pd.DataFrame()

        # F) Alignment window ±7 days
        align = self.emit_alignment_window(days=7, write_csv=False)

        tables = {
            "overview_per_log": overview,
            "combined_process_list": procs,
            "parse_errors": err,
            "daily_stats": daily_stats,
            "rtcr_focus": rtcr_focus,
            "align_2025_07_12_window": align,
        }

        if write_csv:
            for name, d in tables.items():
                try:
                    d.to_csv(self.exports_dir / f"{name}.csv", index=False)
                except Exception:
                    self.parse_errors.append({"stage": "csv_write", "table": name, "error": traceback.format_exc()})
        return tables

    def emit_alignment_window(self, days: int = 7, write_csv: bool = False) -> pd.DataFrame:
        df = self._timeline_df()
        if df.empty:
            return df
        lo = INFECTION_DATE - timedelta(days=days)
        hi = INFECTION_DATE + timedelta(days=days)
        m = (df['timestamp_dt'] >= lo) & (df['timestamp_dt'] <= hi)
        win = df.loc[m].copy()
        if write_csv:
            try:
                win.to_csv(self.exports_dir / f"alignment_window_±{days}d.csv", index=False)
            except Exception:
                self.parse_errors.append({"stage": "csv_write", "table": "alignment_window", "error": traceback.format_exc()})
        return win

    def emit_index_dump(self, write_csv: bool = True) -> pd.DataFrame:
        idx = pd.DataFrame(self.index_rows)
        if write_csv:
            try:
                idx.to_csv(self.exports_dir / "index_inventory.csv", index=False)
            except Exception:
                self.parse_errors.append({"stage": "csv_write", "table": "index_inventory", "error": traceback.format_exc()})
        return idx

# End of script
