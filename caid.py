#!/usr/bin/env python3
"""
Import CAID hash JSON files into a SQLite database.

Usage: python import_caid.py [--db caid.db] [--dir ./json_files]

JSON files from https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/nsrl-download/non-rds-hash
"""

import argparse
import json
import re
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


DDL_TABLE = """
CREATE TABLE IF NOT EXISTS caid_hashes (
    filetype TEXT NOT NULL,
    md5      TEXT NOT NULL,
    sha1     TEXT NOT NULL,
    size     INTEGER NOT NULL,
    category INTEGER NOT NULL
);
"""

DDL_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_caid_hashes_md5      ON caid_hashes(md5);
CREATE INDEX IF NOT EXISTS idx_caid_hashes_sha1     ON caid_hashes(sha1);
CREATE INDEX IF NOT EXISTS idx_caid_hashes_size     ON caid_hashes(size);
CREATE INDEX IF NOT EXISTS idx_caid_hashes_size_md5_sha1 ON caid_hashes(size, md5, sha1);
"""

FILETYPE_RE = re.compile(r"NSRL-CAID-(.+)\.json$", re.IGNORECASE)

INSERT_SQL = """
    INSERT INTO caid_hashes (filetype, md5, sha1, size, category)
    VALUES (?, ?, ?, ?, ?)
"""


def filetype_from_path(path: Path) -> str:
    m = FILETYPE_RE.search(path.name)
    return m.group(1).upper() if m else path.stem


def iter_records(data: dict):
    for entry in data.get("value", []):
        md5  = entry.get("MD5",  "").strip()
        sha1 = entry.get("SHA1", "").strip()
        if not md5 or not sha1:
            continue
        try:
            size = int(entry.get("MediaSize", 0))
        except (ValueError, TypeError):
            size = 0
        try:
            category = int(entry.get("Category", 0))
        except (ValueError, TypeError):
            category = 0
        yield md5, sha1, size, category


def parse_file(path: Path) -> tuple[str, list, float]:
    """Parse a JSON file and return (name, rows, elapsed_seconds)."""
    t0 = time.perf_counter()
    filetype = filetype_from_path(path)
    with open(path, encoding="utf-8-sig") as fh:
        data = json.load(fh)
    rows = [
        (filetype, md5, sha1, size, category)
        for md5, sha1, size, category in iter_records(data)
    ]
    return path.name, rows, time.perf_counter() - t0


def fmt(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(int(seconds), 60)
    return f"{m}m{s:02d}s"


def main():
    ap = argparse.ArgumentParser(description="Import CAID JSON → SQLite")
    ap.add_argument("--db",       default="caid.db", help="Output SQLite file")
    ap.add_argument("--dir",      default=".",        help="Directory containing JSON files")
    ap.add_argument("--workers",  type=int, default=None, help="Parser threads (default: cpu count)")
    ap.add_argument("--no-sync",  action="store_true",    help="PRAGMA synchronous=OFF (faster, less safe)")
    args = ap.parse_args()

    json_dir = Path(args.dir)
    files = sorted(json_dir.glob("NSRL-CAID-*.json"))
    if not files:
        print(f"No NSRL-CAID-*.json files found in {json_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(files)} file(s) in {json_dir}")
    t_total = time.perf_counter()

    # ── DB setup ────────────────────────────────────────────────────────────
    t0 = time.perf_counter()
    conn = sqlite3.connect(args.db)
    conn.execute("PRAGMA page_size    = 8192")
    conn.execute("PRAGMA cache_size   = -131072")   # 128 MB
    conn.execute("PRAGMA temp_store   = MEMORY")
    conn.execute(f"PRAGMA synchronous = {'OFF' if args.no_sync else 'NORMAL'}")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.executescript(DDL_TABLE)
    print(f"DB init:      {fmt(time.perf_counter() - t0)}")

    # ── Parallel parse ───────────────────────────────────────────────────────
    print(f"\nParsing ({args.workers or 'auto'} workers)...")
    t0 = time.perf_counter()
    all_rows: list[tuple] = []
    errors: list[str] = []

    col_name = 42
    col_rows =  9

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(parse_file, p): p for p in files}
        for future in as_completed(futures):
            try:
                name, rows, elapsed = future.result()
                all_rows.extend(rows)
                print(f"  {name:<{col_name}} {len(rows):>{col_rows},} rows  {fmt(elapsed):>6}")
            except Exception as exc:
                path = futures[future]
                errors.append(f"{path.name}: {exc}")
                print(f"  ERROR {path.name}: {exc}", file=sys.stderr)

    t_parse = time.perf_counter() - t0
    print(f"Parse total:  {fmt(t_parse)}  ({len(all_rows):,} rows)")

    if not all_rows:
        print("Nothing to insert.", file=sys.stderr)
        conn.close()
        sys.exit(1)

    # ── Insert ───────────────────────────────────────────────────────────────
    print(f"\nInserting {len(all_rows):,} rows...")
    t0 = time.perf_counter()
    conn.executemany(INSERT_SQL, all_rows)
    conn.commit()
    t_insert = time.perf_counter() - t0
    rate = len(all_rows) / t_insert if t_insert > 0 else 0
    print(f"Insert total: {fmt(t_insert)}  ({rate:,.0f} rows/s)")

    # ── Index build ──────────────────────────────────────────────────────────
    print("\nBuilding indexes...")
    t0 = time.perf_counter()
    conn.executescript(DDL_INDEXES)
    t_index = time.perf_counter() - t0
    print(f"Index total:  {fmt(t_index)}")

    conn.close()

    # ── Summary ──────────────────────────────────────────────────────────────
    t_elapsed = time.perf_counter() - t_total
    db_size = Path(args.db).stat().st_size / (1024 ** 2)
    print(f"""
┌─────────────────────────────────────────┐
│  Import complete                        │
├─────────────────────────────────────────┤
│  Files:    {len(files) - len(errors):>6} processed, {len(errors):>2} error(s)     │
│  Rows:     {len(all_rows):>12,}               │
│  DB size:  {db_size:>10.1f} MB                 │
├─────────────────────────────────────────┤
│  Parse:    {fmt(t_parse):>10}                   │
│  Insert:   {fmt(t_insert):>10}                   │
│  Index:    {fmt(t_index):>10}                   │
│  Total:    {fmt(t_elapsed):>10}                   │
└─────────────────────────────────────────┘""")

    if errors:
        print("\nErrors:")
        for e in errors:
            print(f"  {e}", file=sys.stderr)


if __name__ == "__main__":
    main()