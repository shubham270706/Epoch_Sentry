"""
Epoch Sentry - Zeek conn.log ingestion daemon.

Tails a Zeek conn.log (optionally enriched with a dns_query_entropy field by
enrich_dns.zeek), parses new lines as they're written, and pushes them into
SQLite for the Streamlit dashboard to read.

Design notes / fixes vs. the original version:
  - Keeps ONE sqlite connection open for the life of the process instead of
    open/close per row. That was the biggest perf risk for anything beyond
    a toy demo (one disk round-trip per packet flow).
  - Commits are batched (time- or count-based) instead of per-row, which
    also means we don't fsync on every single line.
  - Detects log rotation/truncation (Zeek rotates conn.log periodically) by
    watching file size; if the file shrinks, we reopen it from the top
    instead of silently going idle forever.
  - Malformed lines are logged and skipped instead of crashing the daemon.
  - WAL mode is turned on so the Streamlit reader doesn't get locked out
    while we're writing.
  - Storage is bounded even though capture runs indefinitely: rows older
    than RETENTION_HOURS (and anything beyond MAX_ROWS) are purged on a
    timer, followed by an incremental vacuum + WAL checkpoint so the
    freed space is actually returned to the OS rather than just marked
    free inside sentry_logs.db. On the Zeek side, local_capture.zeek
    rotates conn.log frequently and deletes each rotated file immediately
    (see that file's comments), so raw packets/flows never accumulate as
    files — SQLite (with its own cap) is the only durable store.
"""

import sqlite3
import time
import os
import signal
import logging


class _Stop(Exception):
    """Raised from the SIGTERM handler so the main loop can flush + exit
    cleanly instead of being killed mid-write. capture_controller.py stops
    this process with SIGTERM (not SIGKILL) specifically so this runs."""


def _handle_sigterm(signum, frame):
    raise _Stop()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "sentry_logs.db")
ZEEK_LOG_PATH = os.path.join(BASE_DIR, "conn.log")

BATCH_SIZE = 25          # flush after this many buffered rows
BATCH_INTERVAL_SEC = 1.0  # ...or after this long, whichever comes first

# --- Storage retention -------------------------------------------------
# Endless capture + an unbounded table is exactly the "storing packets is
# resource exhaustive" problem this daemon needs to avoid. Both knobs are
# environment-overridable so the operator can tune retention without
# touching code.
RETENTION_HOURS = float(os.environ.get("EPOCH_SENTRY_RETENTION_HOURS", "24"))
MAX_ROWS = int(os.environ.get("EPOCH_SENTRY_MAX_ROWS", "200000"))
RETENTION_CHECK_INTERVAL_SEC = 60.0

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("epoch_sentry.daemon")

INSERT_SQL = """
    INSERT INTO live_conn (
        uid, orig_h, resp_h, resp_p, duration,
        orig_bytes, resp_bytes, orig_pkts, resp_pkts,
        conn_state, dns_query_entropy
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    # Only takes effect on a brand-new DB file, but costs nothing to set
    # unconditionally: lets incremental_vacuum() below actually shrink the
    # file on disk instead of just freeing pages Sqlite keeps for reuse.
    conn.execute("PRAGMA auto_vacuum=INCREMENTAL;")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS live_conn (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            uid TEXT,
            orig_h TEXT,
            resp_h TEXT,
            resp_p INTEGER,
            duration REAL,
            orig_bytes REAL,
            resp_bytes REAL,
            orig_pkts INTEGER,
            resp_pkts INTEGER,
            conn_state TEXT,
            dns_query_entropy REAL
        )
    ''')
    # Indices matter once this table has more than a few thousand rows.
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_live_conn_ts ON live_conn(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_live_conn_resp_h ON live_conn(resp_h);")
    conn.commit()
    return conn


def _to_int(value, default=0):
    try:
        return int(float(value))
    except (ValueError, TypeError):
        return default


def _to_float(value, default=0.0):
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def parse_line(line, cols):
    parts = line.rstrip("\n").split('\t')
    if len(parts) < len(cols):
        return None
    row = dict(zip(cols, parts))
    for k, v in row.items():
        if v == '-':
            row[k] = 0
    return (
        str(row.get('uid', 'UNKNOWN')),
        str(row.get('id.orig_h', '0.0.0.0')),
        str(row.get('id.resp_h', '0.0.0.0')),
        _to_int(row.get('id.resp_p', 0)),
        _to_float(row.get('duration', 0.0)),
        _to_float(row.get('orig_bytes', 0.0)),
        _to_float(row.get('resp_bytes', 0.0)),
        _to_int(row.get('orig_pkts', 0)),
        _to_int(row.get('resp_pkts', 0)),
        str(row.get('conn_state', 'SF')),
        _to_float(row.get('dns_query_entropy', 0.0)),
    ), row


def trim_retention(db_conn, cursor):
    """Bound the live_conn table so it never grows without limit.

    Two independent caps, either of which can trigger a delete:
      - age: rows older than RETENTION_HOURS
      - count: keep only the newest MAX_ROWS rows

    Followed by an incremental vacuum + WAL checkpoint so the space is
    actually reclaimed on disk rather than left as free pages inside the
    (still large) sentry_logs.db file.
    """
    cursor.execute(
        "DELETE FROM live_conn WHERE timestamp < datetime('now', ?)",
        (f"-{RETENTION_HOURS} hours",),
    )
    cursor.execute(
        "DELETE FROM live_conn WHERE id NOT IN "
        "(SELECT id FROM live_conn ORDER BY id DESC LIMIT ?)",
        (MAX_ROWS,),
    )
    deleted = cursor.rowcount
    db_conn.commit()

    # Return freed pages to the OS and checkpoint WAL so the -wal file
    # doesn't grow unbounded either.
    cursor.execute("PRAGMA incremental_vacuum;")
    cursor.execute("PRAGMA wal_checkpoint(TRUNCATE);")
    db_conn.commit()

    if deleted:
        log.info(f"Retention trim: purged rows beyond "
                  f"{RETENTION_HOURS}h / {MAX_ROWS} rows.")


def _read_header(f):
    """Advance f past the Zeek TSV header and return the #fields column list."""
    cols = []
    while True:
        line = f.readline()
        if line.startswith("#fields"):
            cols = line.strip().split('\t')[1:]
            return cols
        if not line:
            time.sleep(1)


def run_daemon():
    signal.signal(signal.SIGTERM, _handle_sigterm)
    db_conn = init_db()
    cursor = db_conn.cursor()
    log.info(f"Epoch Sentry daemon initialized. Monitoring: {ZEEK_LOG_PATH}")

    while not os.path.exists(ZEEK_LOG_PATH):
        log.info("Waiting for Zeek to generate conn.log...")
        time.sleep(2)

    log.info("Log file detected. Starting real-time ingestion loop...")

    f = open(ZEEK_LOG_PATH, "r")
    cols = _read_header(f)
    f.seek(0, os.SEEK_END)
    last_pos = f.tell()

    buffer = []
    last_flush = time.time()
    last_retention_check = time.time()

    def flush():
        nonlocal buffer, last_flush
        if buffer:
            cursor.executemany(INSERT_SQL, buffer)
            db_conn.commit()
            buffer = []
        last_flush = time.time()

    try:
        while True:
            line = f.readline()

            if not line:
                # Check for log rotation: if the underlying file is now
                # smaller than where we are, Zeek rotated/truncated it.
                try:
                    if os.path.getsize(ZEEK_LOG_PATH) < last_pos:
                        log.warning("conn.log appears rotated/truncated, reopening.")
                        f.close()
                        f = open(ZEEK_LOG_PATH, "r")
                        cols = _read_header(f)
                        last_pos = f.tell()
                        continue
                except FileNotFoundError:
                    pass

                if buffer and (time.time() - last_flush) > BATCH_INTERVAL_SEC:
                    flush()

                if (time.time() - last_retention_check) > RETENTION_CHECK_INTERVAL_SEC:
                    trim_retention(db_conn, cursor)
                    last_retention_check = time.time()

                time.sleep(0.1)
                continue

            last_pos = f.tell()

            if line.startswith("#"):
                continue

            try:
                parsed, raw_row = parse_line(line, cols)
            except Exception as e:
                log.warning(f"Skipping malformed line ({e}): {line.strip()[:120]}")
                continue

            if parsed is None:
                continue

            buffer.append(parsed)
            log.info(f"Flow queued: {raw_row.get('id.orig_h')} -> "
                      f"{raw_row.get('id.resp_h')}:{raw_row.get('id.resp_p')}")

            if len(buffer) >= BATCH_SIZE or (time.time() - last_flush) > BATCH_INTERVAL_SEC:
                flush()

            # Also checked here (not just in the idle branch above) so
            # retention trimming still happens under sustained, high-volume
            # traffic that never leaves the flow-processing hot path.
            if (time.time() - last_retention_check) > RETENTION_CHECK_INTERVAL_SEC:
                trim_retention(db_conn, cursor)
                last_retention_check = time.time()
    except (KeyboardInterrupt, _Stop):
        log.info("Shutting down, flushing remaining buffer...")
        flush()
    finally:
        f.close()
        db_conn.close()


if __name__ == "__main__":
    run_daemon()