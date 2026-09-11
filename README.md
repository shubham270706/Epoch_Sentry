# Epoch Sentry

AI-based detection of cyber threats in unidirectional IP traffic (SIH25145).

## File layout (only what's essential — and why)

| File | Role |
|---|---|
| `app.py` | Streamlit dashboard: capture control, threat feed, telemetry, analytics. |
| `capture_controller.py` | Starts/stops Zeek + the ingestion daemon as tracked background processes. This is what the sidebar's single Start/Stop button calls. |
| `local_capture.zeek` | The **only** Zeek entry script you run. Loads `enrich_dns.zeek` and disables every default log stream except `conn.log`, since that's the only one anything here reads. |
| `enrich_dns.zeek` | Adds `dns_query_entropy` directly onto `conn.log` (max entropy seen across DNS queries on a connection — a DGA/tunneling signal). |
| `zeek_daemon.py` | Tails `conn.log`, batches inserts into `sentry_logs.db` (SQLite), and enforces storage retention (see below). |
| `data/epoch_sentry_model.pkl` | Trained classifier (bring your own — not included here). |

Nothing else from a stock Zeek deployment is needed for this pipeline. `local_capture.zeek`
switches off `dns.log`, `http.log`, `ssl.log`, `x509.log`, `files.log`, `weird.log`,
`notice.log`, `software.log`, and the rest of the default bundle — they cost disk and I/O
for signal this dashboard doesn't consume. If a future version starts reading TLS metadata
(the `sni_entropy` / `cipher_encoded` placeholder features already in `app.py`), re-enable
`SSL::LOG` and `X509::LOG` in `local_capture.zeek` and extend `zeek_daemon.py`'s ingestion —
nothing else needs to change.

## Setup

```bash
pip install -r requirements.txt
```

Zeek itself needs raw-socket capture rights. The recommended one-time setup (so you don't
have to run Streamlit as root):

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which zeek)
```

Then just run the dashboard normally:

```bash
streamlit run app.py
```

## Using it

Everything is driven from the **Capture control** panel at the top of the sidebar:

1. Pick an interface (`any` captures on every interface and is the safe default).
2. Click **▶ Start capture**. This launches Zeek (reading `local_capture.zeek`) and
   `zeek_daemon.py` in the background and returns immediately — the dashboard doesn't block
   while capture runs.
3. Capture runs **indefinitely** — no packet count or time limit — until you click
   **■ Stop capture**. Both processes are tracked by PID in `capture_run/capture_state.json`,
   so the button reflects the true running state even across dashboard reloads; if a process
   died outside the tool (crash, `kill -9`, reboot), the panel detects the stale PID and
   resets to "not running" instead of getting stuck.

If Zeek fails to start (wrong interface name, missing capture permission), the panel shows
Zeek's actual stderr instead of failing silently — check `capture_run/zeek_stderr.log` for
the full history.

## Storage: bounded even though capture never stops on its own

Packet/flow capture is exactly the kind of workload that quietly fills a disk if left
unattended, so two independent mechanisms keep it bounded:

- **On the Zeek side:** `local_capture.zeek` rotates `conn.log` every 10 minutes and deletes
  each rotated file the instant Zeek finishes writing it (via a rotation post-processor). At
  most ~10 minutes of raw flow log ever sits on disk. This is safe because `zeek_daemon.py`
  tails the file by open file descriptor — on Linux, an open fd keeps reading a file's data
  fine even after it's unlinked, so nothing is lost between "Zeek deletes it" and "the daemon
  finishes reading it."
- **On the SQLite side:** every 60 seconds, `zeek_daemon.py` purges rows older than
  `EPOCH_SENTRY_RETENTION_HOURS` (default 24h) and caps the table at `EPOCH_SENTRY_MAX_ROWS`
  (default 200,000 rows), then runs an incremental vacuum + WAL checkpoint so the freed space
  is actually returned to disk. Override either via environment variable before starting the
  dashboard, e.g.:

  ```bash
  EPOCH_SENTRY_RETENTION_HOURS=6 EPOCH_SENTRY_MAX_ROWS=50000 streamlit run app.py
  ```

No raw packets (`.pcap`) are ever written — Zeek is run without `-w`, so it only ever
produces the flow-level `conn.log` text records described above.

## Known limitations (also shown live in the dashboard footer)

- `sni_entropy` and `cipher_encoded` are placeholder-valued — TLS/SSL metadata isn't ingested
  yet, so those two model features don't currently contribute to predictions.
- `byte_ratio` / `conn_state` were designed assuming bidirectional TCP handshakes; on a
  genuinely unidirectional link (near-zero response bytes) their signal is weaker and worth
  revisiting against one-way-traffic-specific features.
# Epoch_Sentry
