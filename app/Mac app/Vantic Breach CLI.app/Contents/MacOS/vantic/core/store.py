"""
Engagement Store - one SQLite DB per engagement

~/.vantic/engagements/<name>/data.db holds targets, services, findings
and run history. Thread-safe via thread-local connections (WAL mode).
Tools dual-write: store + their existing CSV/JSON exports.
"""

import json
import os
import sqlite3
import threading
from datetime import datetime

VANTIC_HOME = os.path.join(os.path.expanduser("~"), ".vantic")
ENGAGE_DIR = os.path.join(VANTIC_HOME, "engagements")
ACTIVE_FILE = os.path.join(VANTIC_HOME, "active_engagement")

SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
  id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL,
  client TEXT, start_date TEXT, end_date TEXT, auth_ref TEXT,
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scopes (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('cidr','domain','url','host')),
  value TEXT NOT NULL, allowed INTEGER NOT NULL DEFAULT 1,
  UNIQUE(engagement_id, kind, value));
CREATE TABLE IF NOT EXISTS targets (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL REFERENCES engagements(id),
  kind TEXT CHECK (kind IN ('host','domain','url','service')),
  value TEXT NOT NULL, group_name TEXT,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  UNIQUE(engagement_id, kind, value));
CREATE TABLE IF NOT EXISTS services (
  id INTEGER PRIMARY KEY,
  target_id INTEGER NOT NULL REFERENCES targets(id),
  port INTEGER NOT NULL, protocol TEXT NOT NULL DEFAULT 'tcp',
  state TEXT DEFAULT 'open', service_name TEXT, banner TEXT,
  source_tool TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  UNIQUE(target_id, port, protocol));
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL REFERENCES engagements(id),
  fingerprint TEXT NOT NULL,
  family TEXT NOT NULL, title TEXT NOT NULL,
  severity TEXT CHECK (severity IN ('info','low','medium','high','critical')),
  cvss_vector TEXT, cvss_score REAL,
  target TEXT, port INTEGER,
  evidence TEXT, remediation TEXT, status TEXT DEFAULT 'open',
  tool TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  UNIQUE(engagement_id, fingerprint));
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER REFERENCES engagements(id),
  tool TEXT NOT NULL, argv TEXT NOT NULL, started_at TEXT NOT NULL,
  finished_at TEXT, exit_code INTEGER, stats TEXT);
CREATE TABLE IF NOT EXISTS checkpoints (
  run_id INTEGER PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE,
  wordlist TEXT, offset INTEGER, updated_at TEXT);
CREATE TABLE IF NOT EXISTS notes (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL, target TEXT, body TEXT,
  created_at TEXT NOT NULL);
"""

_LOCAL = threading.local()
_lock = threading.RLock()


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------- engagement management ----------

def list_engagements():
    if not os.path.isdir(ENGAGE_DIR):
        return []
    out = []
    for name in sorted(os.listdir(ENGAGE_DIR)):
        db = os.path.join(ENGAGE_DIR, name, "data.db")
        if os.path.isfile(db):
            out.append(name)
    return out


def active_engagement():
    override = getattr(_LOCAL, "override", None)
    if override:
        return override
    try:
        with open(ACTIVE_FILE) as f:
            name = f.read().strip()
        if name and name in list_engagements():
            return name
    except OSError:
        pass
    return None


def set_override(name):
    """One-shot engagement override (per process, not persisted)."""
    _LOCAL.override = name


def set_active(name):
    """Set (or clear, with None) the active engagement."""
    with _lock:
        if name is None:
            try:
                os.unlink(ACTIVE_FILE)
            except OSError:
                pass
            return
        os.makedirs(os.path.join(ENGAGE_DIR, name), exist_ok=True)
        with open(ACTIVE_FILE, "w") as f:
            f.write(name)
        _migrate(name)


def db_path(name=None):
    name = name or active_engagement()
    if not name:
        return None
    return os.path.join(ENGAGE_DIR, name, "data.db")


def _migrate(name):
    path = db_path(name)
    con = sqlite3.connect(path, timeout=5)
    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.executescript(SCHEMA)
        with con:
            con.execute(
                "INSERT OR IGNORE INTO engagements (name, created_at) VALUES (?, ?)",
                (name, _now()))
        version = con.execute("PRAGMA user_version").fetchone()[0]
        # Future migrations switch on version here.
    finally:
        con.close()


def create(name, client=None, auth_ref=None, start=None, end=None):
    os.makedirs(os.path.join(ENGAGE_DIR, name), exist_ok=True)
    _migrate(name)
    if client or auth_ref or start or end:
        con = _connect(name)
        with con:
            con.execute(
                "UPDATE engagements SET client=?, auth_ref=?, start_date=?, end_date=? "
                "WHERE name=?", (client, auth_ref, start, end, name))
    return name


def metadata(name=None):
    name = name or active_engagement()
    if not name:
        return None
    con = _connect(name)
    row = con.execute(
        "SELECT name, client, start_date, end_date, auth_ref, created_at "
        "FROM engagements WHERE name=?", (name,)).fetchone()
    if not row:
        return None
    keys = ["name", "client", "start_date", "end_date", "auth_ref", "created_at"]
    return dict(zip(keys, row))


def is_active():
    return active_engagement() is not None


# ---------- connections ----------

def _connect(name=None):
    """Thread-local connection to the active engagement DB (WAL, busy-wait)."""
    name = name or active_engagement()
    if not name:
        return None
    cache = getattr(_LOCAL, "cons", None)
    if cache is None:
        cache = _LOCAL.cons = {}
    if name not in cache:
        path = os.path.join(ENGAGE_DIR, name, "data.db")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        con = sqlite3.connect(path, timeout=5)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA busy_timeout=5000")
        con.executescript(SCHEMA)
        cache[name] = con
    return cache[name]


def close_all():
    for con in getattr(_LOCAL, "cons", {}).values():
        try:
            con.close()
        except Exception:
            pass
    _LOCAL.cons = {}


# ---------- scope ----------

def set_scope(entries, name=None):
    """entries: [(kind, value, allowed)] - replaces the whole scope table."""
    name = name or active_engagement()
    if not name:
        return
    con = _connect(name)
    eid = con.execute("SELECT id FROM engagements WHERE name=?", (name,)).fetchone()[0]
    with con:
        con.execute("DELETE FROM scopes WHERE engagement_id=?", (eid,))
        con.executemany(
            "INSERT OR REPLACE INTO scopes (engagement_id, kind, value, allowed) "
            "VALUES (?,?,?,?)", [(eid, k, v, a) for k, v, a in entries])


def get_scope(name=None):
    con = _connect(name)
    if not con:
        return []
    name = name or active_engagement()
    rows = con.execute(
        "SELECT kind, value, allowed FROM scopes s JOIN engagements e "
        "ON s.engagement_id = e.id WHERE e.name=?", (name,)).fetchall()
    return [(k, v, bool(a)) for k, v, a in rows]


# ---------- recorders ----------

def _engagement_id(con, name=None):
    name = name or active_engagement()
    row = con.execute("SELECT id FROM engagements WHERE name=?", (name,)).fetchone()
    return row[0] if row else None


def record_target(value, kind="host", group_name=None):
    con = _connect()
    if not con:
        return None
    eid = _engagement_id(con)
    if eid is None:
        return None
    with con:
        con.execute(
            "INSERT INTO targets (engagement_id, kind, value, group_name, first_seen, last_seen) "
            "VALUES (?,?,?,?,?,?) ON CONFLICT(engagement_id, kind, value) "
            "DO UPDATE SET last_seen=excluded.last_seen",
            (eid, kind, value, group_name, _now(), _now()))
    return con.execute(
        "SELECT id FROM targets WHERE engagement_id=? AND kind=? AND value=?",
        (eid, kind, value)).fetchone()[0]


def record_service(host, port, service_name=None, banner=None, protocol="tcp",
                   source_tool="vantic"):
    con = _connect()
    if not con:
        return
    tid = record_target(host, "host")
    if tid is None:
        return
    with con:
        con.execute(
            "INSERT INTO services (target_id, port, protocol, state, service_name, "
            "banner, source_tool, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(target_id, port, protocol) DO UPDATE SET "
            "last_seen=excluded.last_seen, service_name=COALESCE(excluded.service_name, services.service_name), "
            "banner=COALESCE(excluded.banner, services.banner)",
            (tid, port, protocol, "open", service_name, banner, source_tool, _now(), _now()))


def add_finding(finding):
    """Insert-or-refresh a Finding (dedup by fingerprint)."""
    con = _connect()
    if not con:
        return
    eid = _engagement_id(con)
    if eid is None:
        return
    if finding.target:
        record_target(finding.target, "host")
    with con:
        con.execute(
            "INSERT INTO findings (engagement_id, fingerprint, family, title, severity, "
            "cvss_vector, cvss_score, target, port, evidence, remediation, status, tool, "
            "first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(engagement_id, fingerprint) DO UPDATE SET "
            "last_seen=excluded.last_seen, evidence=excluded.evidence",
            (eid, finding.fingerprint, finding.family, finding.title, finding.severity,
             finding.cvss_vector, finding.cvss_score, finding.target, finding.port,
             finding.evidence, finding.remediation, finding.status, finding.tool,
             _now(), _now()))


# ---------- runs ----------

def run_start(tool, argv):
    con = _connect()
    if not con:
        return None
    eid = _engagement_id(con)
    cur = con.execute(
        "INSERT INTO runs (engagement_id, tool, argv, started_at) VALUES (?,?,?,?)",
        (eid, tool, " ".join(argv), _now()))
    con.commit()
    return cur.lastrowid


def run_finish(run_id, exit_code=0, stats=None):
    con = _connect()
    if not con or run_id is None:
        return
    with con:
        con.execute(
            "UPDATE runs SET finished_at=?, exit_code=?, stats=? WHERE id=?",
            (_now(), exit_code, json.dumps(stats) if stats else None, run_id))


def run_list(limit=25):
    con = _connect()
    if not con:
        return []
    rows = con.execute(
        "SELECT id, tool, argv, started_at, finished_at, exit_code "
        "FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    keys = ["id", "tool", "argv", "started_at", "finished_at", "exit_code"]
    return [dict(zip(keys, r)) for r in rows]


def run_get(run_id):
    con = _connect()
    if not con:
        return None
    row = con.execute(
        "SELECT id, tool, argv, started_at, finished_at, exit_code, stats "
        "FROM runs WHERE id=?", (run_id,)).fetchone()
    if not row:
        return None
    keys = ["id", "tool", "argv", "started_at", "finished_at", "exit_code", "stats"]
    d = dict(zip(keys, row))
    if d["stats"]:
        try:
            d["stats"] = json.loads(d["stats"])
        except (ValueError, TypeError):
            pass
    return d


# ---------- checkpoints (dir/creds resume) ----------

def checkpoint(run_id, wordlist, offset):
    con = _connect()
    if not con or run_id is None:
        return
    with con:
        con.execute(
            "INSERT INTO checkpoints (run_id, wordlist, offset, updated_at) VALUES (?,?,?,?) "
            "ON CONFLICT(run_id) DO UPDATE SET offset=excluded.offset, "
            "wordlist=excluded.wordlist, updated_at=excluded.updated_at",
            (run_id, wordlist, offset, _now()))


def checkpoint_get(run_id):
    con = _connect()
    if not con:
        return None
    row = con.execute(
        "SELECT wordlist, offset FROM checkpoints WHERE run_id=?", (run_id,)).fetchone()
    return (row[0], row[1]) if row else None


# ---------- report/diff queries ----------

def findings_all():
    con = _connect()
    if not con:
        return []
    rows = con.execute(
        "SELECT family, title, severity, cvss_vector, cvss_score, target, port, "
        "evidence, remediation, status, tool, first_seen, last_seen "
        "FROM findings ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
        "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, family, title").fetchall()
    keys = ["family", "title", "severity", "cvss_vector", "cvss_score", "target",
            "port", "evidence", "remediation", "status", "tool", "first_seen", "last_seen"]
    return [dict(zip(keys, r)) for r in rows]


def services_all():
    con = _connect()
    if not con:
        return []
    rows = con.execute(
        "SELECT t.value, s.port, s.protocol, s.service_name, s.banner, s.source_tool "
        "FROM services s JOIN targets t ON s.target_id = t.id "
        "ORDER BY t.value, s.port").fetchall()
    keys = ["host", "port", "protocol", "service_name", "banner", "source_tool"]
    return [dict(zip(keys, r)) for r in rows]


def targets_all():
    con = _connect()
    if not con:
        return []
    rows = con.execute(
        "SELECT kind, value, group_name, first_seen, last_seen FROM targets "
        "ORDER BY kind, value").fetchall()
    keys = ["kind", "value", "group_name", "first_seen", "last_seen"]
    return [dict(zip(keys, r)) for r in rows]
