#!/usr/bin/env python3
"""
Tamper-Evident Logging System
Pipeline: source file -> convert -> clean JSON -> logger -> chained log

Step 1 — convert:  reads any .txt / .csv / .json file and writes a
                   normalized intermediate JSON file (one object per line).
Step 2 — import:   reads the normalized JSON and chains every entry
                   into the tamper-evident log with SHA-256 / HMAC-SHA-256.

You can also run both steps in one shot with the 'ingest' command.
"""

import argparse
import csv
import hashlib
import hmac
import json
import os
import re
import sys
from datetime import datetime, timezone


# ─── Constants ────────────────────────────────────────────────────────────────

GENESIS_HASH = "0" * 64
LOG_FILE     = "tamper_evident.log"

# Common patterns found in real-world plain-text log files
_TXT_PATTERNS = [
    # nginx / apache combined:  127.0.0.1 - - [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 200 1234
    (re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" (?P<status>\d+) (?P<size>\S+)'
    ), "HTTP_ACCESS"),

    # syslog:  Jan 15 10:23:45 hostname sshd[1234]: message
    (re.compile(
        r'(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>\S+):\s+(?P<msg>.+)'
    ), "SYSLOG"),

    # ISO timestamp + level:  2024-01-15T10:23:45 ERROR [service] message
    (re.compile(
        r'(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\s+(?P<level>DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL)\s*(?:\[(?P<svc>[^\]]+)\])?\s*(?P<msg>.+)'
    ), lambda m: m.group("level")),

    # Windows event-style:  2024-01-15 10:23:45,123 INFO message
    (re.compile(
        r'(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[,.]?\d*)\s+(?P<level>DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL)\s+(?P<msg>.+)'
    ), lambda m: m.group("level")),
]


# ─── Hashing ──────────────────────────────────────────────────────────────────

def compute_hash(payload: dict, prev_hash: str, secret: str | None = None) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True) + prev_hash
    if secret:
        return hmac.new(secret.encode(), raw.encode(), hashlib.sha256).hexdigest()
    return hashlib.sha256(raw.encode()).hexdigest()


# ─── Logger ───────────────────────────────────────────────────────────────────

def _last_hash(log_file: str) -> str:
    if not os.path.exists(log_file):
        return GENESIS_HASH
    with open(log_file, "r") as f:
        last = None
        for line in f:
            line = line.strip()
            if line:
                last = line
    if last is None:
        return GENESIS_HASH
    return json.loads(last)["hash"]


def append_log(event: str, data: dict | str, log_file: str = LOG_FILE,
               secret: str | None = None) -> dict:
    prev_hash = _last_hash(log_file)
    timestamp = datetime.now(timezone.utc).isoformat()
    payload   = {"timestamp": timestamp, "event": event, "data": data}
    cur_hash  = compute_hash(payload, prev_hash, secret)
    entry     = {**payload, "prev_hash": prev_hash, "hash": cur_hash}
    with open(log_file, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


# ─── Converter ────────────────────────────────────────────────────────────────
# Converts any source file into a normalized NDJSON file.
# Each output line is:  {"event": "...", "data": {...}}
# The logger then reads this clean JSON — no format ambiguity.

def _parse_txt_line(line: str) -> tuple[str, dict]:
    """
    Try each known log pattern. If a pattern matches, extract named groups
    as the data dict. Falls back to raw line if nothing matches.
    """
    for pattern, event_src in _TXT_PATTERNS:
        m = pattern.match(line)
        if m:
            event = event_src(m) if callable(event_src) else event_src
            data  = {k: v for k, v in m.groupdict().items() if v is not None}
            return event, data
    # no pattern matched — store raw line
    return "LINE", {"raw": line}


def convert_file(source_path: str, output_path: str) -> int:
    """
    Read source_path (any supported format), write normalized NDJSON to
    output_path. Returns the number of records written.
    """
    ext = os.path.splitext(source_path)[1].lower()

    if not os.path.exists(source_path):
        raise FileNotFoundError(f"Source file not found: {source_path}")

    records = []  # list of (event, data) tuples

    # ── Plain text ─────────────────────────────────────────────────────────────
    if ext == ".txt":
        with open(source_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.strip():
                    event, data = _parse_txt_line(line)
                    records.append((event, data))

    # ── CSV ────────────────────────────────────────────────────────────────────
    elif ext == ".csv":
        with open(source_path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                row   = {k.strip(): v.strip() for k, v in row.items() if k}
                # coerce numeric strings to numbers
                row   = _coerce_types(row)
                event = row.pop("event", row.pop("type", row.pop("level", "CSV_ROW")))
                records.append((str(event), row))

    # ── JSON / NDJSON ──────────────────────────────────────────────────────────
    elif ext == ".json":
        with open(source_path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read().strip()

        # try full JSON array
        parsed_ok = False
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                for item in data:
                    records.append(_extract_json_record(item))
                parsed_ok = True
        except json.JSONDecodeError:
            pass

        # fallback: one object per line (NDJSON)
        if not parsed_ok:
            for line in raw.splitlines():
                line = line.strip()
                if line:
                    try:
                        item = json.loads(line)
                        records.append(_extract_json_record(item))
                    except json.JSONDecodeError:
                        records.append(("PARSE_ERROR", {"raw": line}))

    else:
        raise ValueError(f"Unsupported file type '{ext}'. Use .txt, .csv, or .json")

    # write normalized NDJSON
    with open(output_path, "w", encoding="utf-8") as out:
        for event, data in records:
            out.write(json.dumps({"event": event, "data": data}) + "\n")

    return len(records)


def _extract_json_record(item) -> tuple[str, any]:
    """Pull event key from a JSON object; keep remaining fields as data."""
    if isinstance(item, dict):
        item  = dict(item)
        event = item.pop("event",
                item.pop("type",
                item.pop("level",
                item.pop("severity", "JSON_ENTRY"))))
        return str(event), item
    return "JSON_ENTRY", item


def _coerce_types(row: dict) -> dict:
    """Convert numeric strings in a CSV row to int/float."""
    out = {}
    for k, v in row.items():
        if v == "":
            out[k] = None
            continue
        try:
            out[k] = int(v)
            continue
        except ValueError:
            pass
        try:
            out[k] = float(v)
            continue
        except ValueError:
            pass
        out[k] = v
    return out


# ─── Importer (normalized JSON -> chained log) ────────────────────────────────

def import_normalized(ndjson_path: str, log_file: str = LOG_FILE,
                      secret: str | None = None) -> list[dict]:
    """
    Read a normalized NDJSON file produced by convert_file() and append
    every record to the tamper-evident log. Returns list of appended entries.
    """
    if not os.path.exists(ndjson_path):
        raise FileNotFoundError(f"Normalized file not found: {ndjson_path}")

    appended = []
    with open(ndjson_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            entry  = append_log(record["event"], record["data"],
                                 log_file=log_file, secret=secret)
            appended.append(entry)
    return appended


# ─── Verifier ─────────────────────────────────────────────────────────────────

def load_logs(log_file: str = LOG_FILE) -> list[dict]:
    if not os.path.exists(log_file):
        return []
    entries = []
    with open(log_file, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def verify_chain(log_file: str = LOG_FILE, secret: str | None = None) -> dict:
    logs = load_logs(log_file)
    if not logs:
        return {"status": "ok", "total": 0, "first_tampered": None,
                "affected": [], "results": []}

    results        = []
    first_tampered = None
    affected       = []

    for i, entry in enumerate(logs):
        expected_prev = GENESIS_HASH if i == 0 else logs[i - 1]["hash"]
        payload       = {"timestamp": entry["timestamp"],
                         "event":     entry["event"],
                         "data":      entry["data"]}
        recomputed    = compute_hash(payload, expected_prev, secret)
        hash_ok       = recomputed == entry["hash"]
        prev_ok       = entry["prev_hash"] == expected_prev

        if not hash_ok or not prev_ok:
            if first_tampered is None:
                first_tampered = i
            affected.append(i)
            status_str = "TAMPERED" if i == first_tampered else "CHAIN_BROKEN"
        else:
            status_str = "OK"

        results.append({
            "index":       i,
            "event":       entry["event"],
            "timestamp":   entry["timestamp"],
            "status":      status_str,
            "hash_match":  hash_ok,
            "prev_match":  prev_ok,
            "stored_hash": entry["hash"],
            "recomputed":  recomputed,
        })

    overall = "ok" if first_tampered is None else "tampered"
    return {"status": overall, "total": len(logs),
            "first_tampered": first_tampered,
            "affected": affected, "results": results}


# ─── Pretty printing ──────────────────────────────────────────────────────────

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def _c(text, color): return f"{color}{text}{RESET}"
def _short(h):       return h[:16] + "..."


def print_entry(entry: dict, label: str = "") -> None:
    tag   = f"[{label}] " if label else ""
    idx   = entry.get("index", "?")
    event = entry["event"]
    print(f"\n{_c(f'{tag}Log #{idx}  -  {event}', BOLD)}")
    print(f"  timestamp : {entry['timestamp']}")
    print(f"  data      : {json.dumps(entry['data'])}")
    print(f"  prev_hash : {_c(_short(entry['prev_hash']), CYAN)}")
    print(f"  hash      : {_c(_short(entry['hash']), CYAN)}")


def print_report(report: dict, verbose: bool = False) -> None:
    total = report["total"]
    print(f"\n{'='*60}")
    print(f"  {_c('INTEGRITY VERIFICATION REPORT', BOLD)}")
    print(f"{'='*60}")
    print(f"  Total entries   : {total}")

    if total == 0:
        print(f"  {_c('Log file is empty.', YELLOW)}")
        return

    if report["status"] == "ok":
        print(f"  Status          : {_c('OK  CHAIN INTACT', GREEN)}")
        print(f"  All {total} entr{'y' if total==1 else 'ies'} verified successfully.\n")
    else:
        ft       = report["first_tampered"]
        affected = report["affected"]
        print(f"  Status          : {_c('TAMPERING DETECTED', RED)}")
        print(f"\n  {_c(f'Tampering detected at log #{ft}', RED)}")
        if len(affected) > 1:
            broken = [i for i in affected if i != ft]
            print(f"  {_c(f'Chain broken between log #{ft} and log #{ft+1}', YELLOW)}")
            print(f"  {_c(f'Affected entries: {broken}', YELLOW)}")

    if verbose:
        print(f"\n{'-'*60}")
        print(f"  {'#':<5} {'EVENT':<18} {'STATUS':<16} {'HASH MATCH':<12} PREV MATCH")
        print(f"{'-'*60}")
        for r in report["results"]:
            st    = r["status"]
            color = GREEN if st == "OK" else (RED if st == "TAMPERED" else YELLOW)
            hm    = _c("OK", GREEN) if r["hash_match"] else _c("FAIL", RED)
            pm    = _c("OK", GREEN) if r["prev_match"] else _c("FAIL", RED)
            print(f"  {r['index']:<5} {r['event']:<18} {_c(st, color):<25} {hm:<14} {pm}")
        print()


# ─── CLI handlers ─────────────────────────────────────────────────────────────

def cli_convert(args):
    source = args.source
    output = args.output or (os.path.splitext(source)[0] + "_normalized.json")
    ext    = os.path.splitext(source)[1].lower()

    print(f"\n  Converting {_c(source, CYAN)}  ({ext[1:].upper()} -> NDJSON)")

    try:
        count = convert_file(source, output)
    except (FileNotFoundError, ValueError) as e:
        print(_c(f"  Error: {e}", RED)); sys.exit(1)

    print(f"  Output      : {_c(output, CYAN)}")
    print(f"  Records     : {_c(str(count), GREEN)}")
    print(f"\n  {_c(f'{count} records normalized successfully.', GREEN)}")
    print(f"  Run:  python tamper_evident_log.py import {output}")


def cli_import(args):
    source = args.source
    print(f"\n  Importing {_c(source, CYAN)}  (normalized NDJSON)")
    print(f"  Destination : {_c(args.file, CYAN)}\n")

    try:
        entries = import_normalized(source, log_file=args.file, secret=args.secret)
    except (FileNotFoundError, ValueError) as e:
        print(_c(f"  Error: {e}", RED)); sys.exit(1)

    if not entries:
        print(_c("  No entries found in the normalized file.", YELLOW)); return

    total_now = sum(1 for _ in open(args.file))
    start_idx = total_now - len(entries)
    for i, entry in enumerate(entries):
        entry["index"] = start_idx + i
        print_entry(entry, label="IMPORTED")

    print(f"\n  {_c(f'{len(entries)} entries imported and chained successfully.', GREEN)}")


def cli_ingest(args):
    """Convert + import in one shot."""
    source     = args.source
    normalized = os.path.splitext(source)[0] + "_normalized.json"
    ext        = os.path.splitext(source)[1].lower()

    print(f"\n  [1/2] Converting {_c(source, CYAN)}  ({ext[1:].upper()} -> NDJSON)")
    try:
        count = convert_file(source, normalized)
    except (FileNotFoundError, ValueError) as e:
        print(_c(f"  Error: {e}", RED)); sys.exit(1)
    print(f"  {_c(str(count), GREEN)} records normalized -> {_c(normalized, CYAN)}")

    print(f"\n  [2/2] Importing into {_c(args.file, CYAN)}\n")
    try:
        entries = import_normalized(normalized, log_file=args.file, secret=args.secret)
    except (FileNotFoundError, ValueError) as e:
        print(_c(f"  Error: {e}", RED)); sys.exit(1)

    total_now = sum(1 for _ in open(args.file))
    start_idx = total_now - len(entries)
    for i, entry in enumerate(entries):
        entry["index"] = start_idx + i
        print_entry(entry, label="INGESTED")

    print(f"\n  {_c(f'Done. {len(entries)} entries chained into {args.file}', GREEN)}")


def cli_add(args):
    try:
        data = json.loads(args.data) if args.data else {}
    except json.JSONDecodeError:
        data = args.data

    entry = append_log(event=args.event, data=data,
                       log_file=args.file, secret=args.secret)
    idx        = sum(1 for _ in open(args.file)) - 1
    entry["index"] = idx
    print_entry(entry, label="APPENDED")
    print(f"\n  {_c('Entry appended successfully', GREEN)}")


def cli_verify(args):
    report = verify_chain(log_file=args.file, secret=args.secret)
    print_report(report, verbose=args.verbose)
    sys.exit(0 if report["status"] == "ok" else 1)


def cli_show(args):
    logs = load_logs(args.file)
    if not logs:
        print(_c("Log file is empty or does not exist.", YELLOW)); return
    for i, entry in enumerate(logs):
        entry["index"] = i
        print_entry(entry)


def cli_tamper(args):
    logs = load_logs(args.file)
    if not logs:
        print(_c("No logs found.", YELLOW)); return
    idx = args.index
    if idx < 0 or idx >= len(logs):
        print(_c(f"Index {idx} out of range (0-{len(logs)-1}).", RED)); return

    try:
        new_data = json.loads(args.data)
    except json.JSONDecodeError:
        new_data = args.data

    print(f"\n{_c('TAMPERING LOG ENTRY (simulation)', RED)}")
    print(f"  Entry    : #{idx} - {logs[idx]['event']}")
    print(f"  Old data : {json.dumps(logs[idx]['data'])}")
    print(f"  New data : {json.dumps(new_data)}")
    logs[idx]["data"] = new_data

    with open(args.file, "w") as f:
        for entry in logs:
            f.write(json.dumps({k: v for k, v in entry.items() if k != "index"}) + "\n")

    print(f"\n  {_c('Entry tampered. Run verify to detect it.', RED)}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Tamper-Evident Logging System - convert -> chain",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
two-step pipeline:
  python tamper_evident_log.py convert server.log.txt
  python tamper_evident_log.py import  server.log_normalized.json

one-shot:
  python tamper_evident_log.py ingest  server.log.txt
  python tamper_evident_log.py ingest  events.csv
  python tamper_evident_log.py ingest  logs.json

other commands:
  python tamper_evident_log.py add USER_LOGIN '{"user":"alice"}'
  python tamper_evident_log.py verify --verbose
  python tamper_evident_log.py show
  python tamper_evident_log.py tamper 2 '{"user":"mallory"}'

with HMAC:
  python tamper_evident_log.py ingest logs.json --secret mykey
  python tamper_evident_log.py verify --secret mykey
        """
    )
    parser.add_argument("--file",   default=LOG_FILE, help="output log file path")
    parser.add_argument("--secret", default=None,     help="HMAC secret key")

    sub = parser.add_subparsers(dest="command", required=True)

    # convert
    p_conv = sub.add_parser("convert", help="convert source file to normalized NDJSON")
    p_conv.add_argument("source",           help="source file (.txt, .csv, .json)")
    p_conv.add_argument("--output", "-o",   help="output NDJSON path (default: <source>_normalized.json)")
    p_conv.set_defaults(func=cli_convert)

    # import
    p_imp = sub.add_parser("import", help="import a normalized NDJSON file into the chain")
    p_imp.add_argument("source", help="normalized NDJSON file from 'convert'")
    p_imp.set_defaults(func=cli_import)

    # ingest (convert + import in one shot)
    p_ing = sub.add_parser("ingest", help="convert + import in one shot")
    p_ing.add_argument("source", help="source file (.txt, .csv, .json)")
    p_ing.set_defaults(func=cli_ingest)

    # add
    p_add = sub.add_parser("add", help="append a single entry manually")
    p_add.add_argument("event")
    p_add.add_argument("data", nargs="?", default="{}")
    p_add.set_defaults(func=cli_add)

    # verify
    p_ver = sub.add_parser("verify", help="verify chain integrity")
    p_ver.add_argument("--verbose", "-v", action="store_true")
    p_ver.set_defaults(func=cli_verify)

    # show
    p_show = sub.add_parser("show", help="display all log entries")
    p_show.set_defaults(func=cli_show)

    # tamper
    p_tamp = sub.add_parser("tamper", help="[DEMO] mutate an entry without rehashing")
    p_tamp.add_argument("index", type=int)
    p_tamp.add_argument("data")
    p_tamp.set_defaults(func=cli_tamper)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
