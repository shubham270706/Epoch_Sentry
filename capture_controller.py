"""
Epoch Sentry - capture process controller.

Owns the "single button" start/stop lifecycle the dashboard exposes:
start() launches Zeek (reading local_capture.zeek) and zeek_daemon.py as
two tracked subprocesses that run indefinitely against a live interface;
stop() shuts them both down.

Why a state file instead of just keeping subprocess.Popen handles in
Streamlit's session_state: Streamlit reruns the whole script on every
interaction and (with auto-refresh on) on a timer, but it's still the same
server process for a given session, so a Popen handle *could* survive in
session_state. It does NOT survive a Streamlit server restart, a different
browser tab/session, or the analyst hitting Stop from another machine that
shares this box, and stale handles left over from a crash would be
invisible. A small JSON state file plus PID verification against /proc
survives all of that and is the same pattern zeek_daemon.py's SQLite file
already uses for durability.
"""

import json
import os
import signal
import subprocess
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RUN_DIR = os.path.join(BASE_DIR, "capture_run")
STATE_PATH = os.path.join(RUN_DIR, "capture_state.json")
ZEEK_SCRIPT = os.path.join(BASE_DIR, "local_capture.zeek")
DAEMON_SCRIPT = os.path.join(BASE_DIR, "zeek_daemon.py")

ZEEK_STDERR_LOG = os.path.join(RUN_DIR, "zeek_stderr.log")
DAEMON_STDOUT_LOG = os.path.join(RUN_DIR, "daemon_stdout.log")

STARTUP_GRACE_SEC = 0.4   # ceiling to let zeek fail fast on bad iface/perms
STARTUP_POLL_SEC = 0.1     # how often we check during that ceiling
DAEMON_GRACE_SEC = 0.2     # same idea, for the (much lighter) daemon process
TERM_TIMEOUT_SEC = 4.0     # ceiling after SIGTERM before SIGKILL
TERM_POLL_SEC = 0.1        # how often we check during that ceiling


class CaptureError(RuntimeError):
    """Raised when start()/stop() can't do what was asked; message is
    meant to be shown directly to the analyst in the UI."""


# ---------------------------------------------------------------------
# PID bookkeeping
# ---------------------------------------------------------------------
def _read_state():
    if not os.path.exists(STATE_PATH):
        return None
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _write_state(state):
    os.makedirs(RUN_DIR, exist_ok=True)
    tmp_path = STATE_PATH + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(state, f)
    os.replace(tmp_path, STATE_PATH)  # atomic on POSIX


def _clear_state():
    try:
        os.remove(STATE_PATH)
    except FileNotFoundError:
        pass


def _cmdline_of(pid):
    """Best-effort process command line via /proc (Linux). Returns ''
    if unavailable (process gone, non-Linux, permission denied) rather
    than raising - callers treat '' as 'can't verify'."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().decode(errors="replace").replace("\x00", " ")
    except OSError:
        return ""


def _pid_matches(pid, expect_substr):
    """True if pid is alive AND (where we can check) its cmdline still
    looks like the process we launched - guards against a stale state
    file pointing at a PID the OS has since reused for something else."""
    try:
        os.kill(pid, 0)  # signal 0: existence/permission check only
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, just owned by someone else - trust the PID
    cmdline = _cmdline_of(pid)
    if not cmdline:
        return True  # couldn't verify (e.g. non-Linux) - trust the PID
    return expect_substr in cmdline


# ---------------------------------------------------------------------
# Public status
# ---------------------------------------------------------------------
def status():
    """Returns a dict describing current capture state. Self-heals: if
    the recorded PIDs are dead/mismatched (e.g. the box rebooted, or a
    process was kill -9'd outside this tool), clears the stale state and
    reports not-running rather than lying to the UI forever."""
    state = _read_state()
    if not state:
        return {"running": False}

    zeek_ok = _pid_matches(state.get("zeek_pid", -1), "zeek")
    daemon_ok = _pid_matches(state.get("daemon_pid", -1), "zeek_daemon.py")

    if not (zeek_ok and daemon_ok):
        _clear_state()
        return {"running": False, "note": "previous capture process had died; state reset"}

    return {
        "running": True,
        "interface": state.get("interface"),
        "started_at": state.get("started_at"),
        "zeek_pid": state.get("zeek_pid"),
        "daemon_pid": state.get("daemon_pid"),
    }


# ---------------------------------------------------------------------
# Interfaces available to capture on
# ---------------------------------------------------------------------
def list_interfaces():
    """Best-effort local network interface list (Linux /proc/net/dev, no
    extra dependency). Always includes 'any' (Zeek/libpcap's pseudo-
    interface that captures on all interfaces) as a safe default choice."""
    names = ["any"]
    try:
        with open("/proc/net/dev") as f:
            lines = f.readlines()[2:]  # skip the two header lines
        for line in lines:
            iface = line.split(":")[0].strip()
            if iface and iface != "lo":
                names.append(iface)
    except OSError:
        pass
    return names


# ---------------------------------------------------------------------
# Start / stop
# ---------------------------------------------------------------------
def _died_within(proc, window_sec):
    """Poll proc every STARTUP_POLL_SEC for up to window_sec, returning
    True as soon as it's observed dead (fast exit on the common failure
    case: bad interface/permissions usually kills these within <100ms),
    or False once the window elapses with it still alive. Trading a
    short window for lower start() latency: a crash slower than the
    window won't be caught here, but the next status() call self-heals
    against it (see status() above) - the UI catches up within one
    rerun instead of every start() paying the full ceiling up front."""
    deadline = time.time() + window_sec
    while time.time() < deadline:
        if proc.poll() is not None:
            return True
        time.sleep(STARTUP_POLL_SEC)
    return proc.poll() is not None


def start(interface):
    current = status()
    if current["running"]:
        return current

    os.makedirs(RUN_DIR, exist_ok=True)

    zeek_bin = _which("zeek") or _which("zeekctl")
    if zeek_bin is None:
        raise CaptureError(
            "`zeek` was not found on PATH. Install Zeek and make sure the "
            "user running this dashboard can invoke it before starting a capture."
        )

    # Zeek needs raw-socket capture rights. Prefer the box already having
    # `setcap cap_net_raw,cap_net_admin=eip $(which zeek)` applied (so
    # neither Zeek nor this dashboard need to run as root); if that wasn't
    # done, Zeek will fail fast below and we surface its stderr.
    # cwd=BASE_DIR (not RUN_DIR): Zeek writes conn.log into its working
    # directory, and that must be BASE_DIR because zeek_daemon.py looks
    # for conn.log next to itself (BASE_DIR), regardless of the daemon's
    # own cwd. RUN_DIR is only used for this controller's own bookkeeping
    # files (state json, captured stderr/stdout).
    with open(ZEEK_STDERR_LOG, "ab") as zeek_log:
        zeek_proc = subprocess.Popen(
            [zeek_bin, "-i", interface, ZEEK_SCRIPT],
            cwd=BASE_DIR,
            stdout=zeek_log,
            stderr=subprocess.STDOUT,
            start_new_session=True,  # survives this Streamlit process restarting
        )

    if _died_within(zeek_proc, STARTUP_GRACE_SEC):
        tail = _tail(ZEEK_STDERR_LOG, 40)
        raise CaptureError(
            f"zeek exited immediately (interface `{interface}`). This is almost "
            f"always missing capture permissions or a bad interface name. "
            f"Try `sudo setcap cap_net_raw,cap_net_admin=eip $(which zeek)` "
            f"once, then retry without sudo. Last output:\n{tail}"
        )

    with open(DAEMON_STDOUT_LOG, "ab") as daemon_log:
        daemon_proc = subprocess.Popen(
            [sys.executable, DAEMON_SCRIPT],
            cwd=BASE_DIR,
            stdout=daemon_log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    if _died_within(daemon_proc, DAEMON_GRACE_SEC):
        _terminate_all([zeek_proc.pid])
        tail = _tail(DAEMON_STDOUT_LOG, 40)
        raise CaptureError(f"zeek_daemon.py exited immediately:\n{tail}")

    _write_state({
        "zeek_pid": zeek_proc.pid,
        "daemon_pid": daemon_proc.pid,
        "interface": interface,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    })
    return status()


def stop():
    state = _read_state()
    if not state:
        return {"running": False}

    pids = [pid for pid in (state.get("zeek_pid"), state.get("daemon_pid")) if pid]
    _terminate_all(pids)

    _clear_state()
    return {"running": False}


def _process_finished(pid):
    """True once pid is actually gone. Prefers os.waitpid(WNOHANG) so we
    properly reap processes we're the parent of - os.kill(pid, 0) alone
    reports a zombie (exited but not yet reaped) as still "alive"
    forever, which is exactly the bug that made stop() always burn the
    full TERM_TIMEOUT_SEC ceiling even though Zeek/the daemon exit
    almost instantly after SIGTERM. Falls back to a plain existence
    check for pids we aren't the parent of (e.g. tracked via the state
    file after this controller process itself restarted)."""
    try:
        reaped_pid, _ = os.waitpid(pid, os.WNOHANG)
        if reaped_pid == pid:
            return True
        if reaped_pid == 0:
            return False  # still running, and we ARE its parent
    except ChildProcessError:
        pass  # not our child - fall through to a plain existence check
    try:
        os.kill(pid, 0)
        return False
    except ProcessLookupError:
        return True


def _terminate_all(pids):
    """Send SIGTERM to every pid immediately (not one at a time), then
    poll all of them together and SIGKILL whichever are still alive once
    TERM_TIMEOUT_SEC elapses. This is the main latency fix for stop():
    the previous version waited out the full timeout for the first
    process before even signaling the second, which could double the
    worst-case wait. In practice Zeek and the daemon both exit within a
    fraction of a second of SIGTERM (confirmed in zeek_stderr.log —
    "received termination signal" appears immediately), so the common
    case here is just the poll interval, not the ceiling."""
    alive = set()
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
            alive.add(pid)
        except ProcessLookupError:
            pass

    deadline = time.time() + TERM_TIMEOUT_SEC
    while alive and time.time() < deadline:
        for pid in list(alive):
            if _process_finished(pid):
                alive.discard(pid)
        if alive:
            time.sleep(TERM_POLL_SEC)

    for pid in alive:  # anything still standing after the ceiling: force it
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


# ---------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------
def _which(binary):
    for d in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(d, binary)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _tail(path, n_lines):
    try:
        with open(path, "r", errors="replace") as f:
            return "".join(f.readlines()[-n_lines:])
    except OSError:
        return "(no log output captured)"