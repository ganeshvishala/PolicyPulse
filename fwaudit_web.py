"""fwaudit_web.py - web front end for fwaudit (PolicyPulse).

Python 3.8+ standard library only. Uses the audit engine in fwaudit.py
(kept network-free); only this file opens a network port.

  python fwaudit_web.py                      local use: http://127.0.0.1:8765
  python fwaudit_web.py --host 0.0.0.0 --cert c.pem --key k.pem
                                             intranet server (HTTPS)
  python fwaudit_web.py adduser NAME --role reviewer
  python fwaudit_web.py users

Roles: viewer < analyst < reviewer < admin
  viewer   read runs, results and download reports
  analyst  + upload files, run audits, propose overrides, QA checks
  reviewer + approve / reject overrides (never their own)
  admin    + manage users

Data (runs, uploads, overrides, audit trail) is stored in
fwaudit_web_data/ next to this file (change with --data).
"""

import argparse
import collections
import datetime
import getpass
import hashlib
import hmac
import io
import json
import os
import random
import re
import secrets
import shutil
import ssl
import sys
import threading
import time
import traceback
import zipfile
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import fwaudit as fa
import fwaudit_web_ui as ui

WEB_VERSION = "1.0.0"
ROLES = ("viewer", "analyst", "reviewer", "admin")
MAX_UPLOAD = 60 * 1024 * 1024
MAX_JSON = 1024 * 1024
SESSION_HOURS = 10
UPLOAD_KINDS = ("algosec", "rfc", "smax")
_RUN_ID = re.compile(r'^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$')


def _now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _role_ok(role, need):
    return ROLES.index(role) >= ROLES.index(need)


def _safe_name(name):
    name = os.path.basename((name or "").replace("\\", "/"))
    name = re.sub(r'[^A-Za-z0-9._ ()+\-]', "_", name).strip(" .")
    if not name or name.startswith("~$"):
        return ""
    return name[:150]


def _write_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, default=str)
    os.replace(tmp, path)


def _read_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


class Store(object):
    """All persistent state of the web app."""

    def __init__(self, root, cfg_path=None):
        self.root = os.path.abspath(root)
        self.cfg_path = cfg_path
        os.makedirs(os.path.join(self.root, "runs"), exist_ok=True)
        self.users_path = os.path.join(self.root, "users.json")
        self.ov_path = os.path.join(self.root, "overrides.json")
        self.trail_path = os.path.join(self.root, "audit_trail.jsonl")
        self.lock = threading.RLock()
        self.running = {}

    # --- config ---
    def cfg(self):
        return fa.load_config(self.cfg_path)

    # --- users ---
    def users(self):
        return _read_json(self.users_path, {})

    def add_user(self, name, password, role, by="setup"):
        name = (name or "").strip()
        if not re.match(r'^[A-Za-z0-9._@\-]{2,64}$', name):
            raise fa.AuditError("User name: 2-64 letters, digits or . _ @ -")
        if role not in ROLES:
            raise fa.AuditError("Role must be one of %s" % ", ".join(ROLES))
        if len(password or "") < 10:
            raise fa.AuditError("Password must be at least 10 characters.")
        with self.lock:
            us = self.users()
            salt, h = fa._hash_pw(password)
            prev = us.get(name, {})
            us[name] = {"salt": salt, "hash": h, "role": role,
                        "created": prev.get("created", _now()),
                        "updated": _now()}
            _write_json(self.users_path, us)
        self.trail(by, "user.save", {"user": name, "role": role})

    def del_user(self, name, by):
        with self.lock:
            us = self.users()
            if name not in us:
                raise fa.AuditError("No such user")
            admins = [u for u, r in us.items() if r.get("role") == "admin"]
            if us[name].get("role") == "admin" and len(admins) <= 1:
                raise fa.AuditError("Cannot remove the last admin.")
            del us[name]
            _write_json(self.users_path, us)
        self.trail(by, "user.delete", {"user": name})

    def check_password(self, name, password):
        rec = self.users().get(name)
        if not rec:
            fa._hash_pw(password or "x")  # same time as a real check
            return None
        _, h = fa._hash_pw(password or "", rec["salt"])
        return rec.get("role") if hmac.compare_digest(h, rec["hash"]) else None

    # --- audit trail ---
    def trail(self, user, action, details=None, ip=""):
        rec = {"at": _now(), "user": user, "ip": ip, "action": action,
               "details": details or {}}
        with self.lock:
            with open(self.trail_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, default=str) + "\n")

    def read_trail(self, limit=500):
        try:
            with open(self.trail_path, "r", encoding="utf-8") as f:
                lines = f.readlines()[-limit:]
        except OSError:
            return []
        out = []
        for ln in reversed(lines):
            try:
                out.append(json.loads(ln))
            except ValueError:
                pass
        return out

    # --- overrides ---
    def overrides(self):
        return fa.load_overrides(self.ov_path)

    def save_overrides(self, data):
        fa.save_overrides(data, self.ov_path)

    # --- runs ---
    def run_dir(self, rid):
        if not _RUN_ID.match(rid or ""):
            raise fa.AuditError("bad run id")
        d = os.path.join(self.root, "runs", rid)
        if not os.path.isdir(d):
            raise fa.AuditError("run not found")
        return d

    def new_run(self, user, label=""):
        rid = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(3)
        d = os.path.join(self.root, "runs", rid)
        for k in UPLOAD_KINDS:
            os.makedirs(os.path.join(d, "in", k), exist_ok=True)
        meta = {"id": rid, "label": label[:80], "created_by": user,
                "created_at": _now(), "status": "draft", "log": [],
                "versions": 0, "summary": None, "report_date": ""}
        _write_json(os.path.join(d, "meta.json"), meta)
        self.trail(user, "run.create", {"run": rid})
        return meta

    def meta(self, rid):
        return _read_json(os.path.join(self.run_dir(rid), "meta.json"), {})

    def save_meta(self, rid, meta):
        _write_json(os.path.join(self.run_dir(rid), "meta.json"), meta)

    def list_runs(self):
        base = os.path.join(self.root, "runs")
        out = []
        for rid in sorted(os.listdir(base), reverse=True):
            if _RUN_ID.match(rid):
                m = _read_json(os.path.join(base, rid, "meta.json"), None)
                if m:
                    m = dict(m)
                    m.pop("log", None)
                    m["files"] = self.input_files(rid)
                    out.append(m)
        return out

    def input_files(self, rid):
        d = os.path.join(self.run_dir(rid), "in")
        res = {}
        for k in UPLOAD_KINDS:
            items = []
            for dp, _, fs in os.walk(os.path.join(d, k)):
                for f in sorted(fs):
                    p = os.path.join(dp, f)
                    items.append({"name": os.path.relpath(p, os.path.join(d, k)).replace("\\", "/"),
                                  "size": os.path.getsize(p)})
            res[k] = items
        return res

    def results(self, rid):
        return _read_json(os.path.join(self.run_dir(rid), "results.json"), None)

    def qa(self, rid):
        return _read_json(os.path.join(self.run_dir(rid), "qa.json"), {})

    def save_qa(self, rid, data):
        _write_json(os.path.join(self.run_dir(rid), "qa.json"), data)

    # --- running an audit ---
    def start(self, rid, user, report_date=""):
        with self.lock:
            if rid in self.running:
                raise fa.AuditError("This run is already in progress.")
            meta = self.meta(rid)
            files = self.input_files(rid)
            if not files["algosec"]:
                raise fa.AuditError("Upload at least one AlgoSec report.")
            meta["status"] = "running"
            meta["log"] = []
            meta["started_by"] = user
            meta["started_at"] = _now()
            if report_date:
                meta["report_date"] = report_date
            self.save_meta(rid, meta)
            t = threading.Thread(target=self._worker, args=(rid, user), daemon=True)
            self.running[rid] = t
            t.start()
        self.trail(user, "run.start", {"run": rid, "version": meta["versions"] + 1})

    def _worker(self, rid, user):
        d = self.run_dir(rid)
        log = []

        def progress(msg):
            log.append("%s  %s" % (datetime.datetime.now().strftime("%H:%M:%S"), msg))
            with self.lock:
                m = self.meta(rid)
                m["log"] = log[-300:]
                self.save_meta(rid, m)

        try:
            cfg = self.cfg()
            meta = self.meta(rid)
            ver = meta.get("versions", 0) + 1
            out = os.path.join(d, "out", "v%d" % ver)
            os.makedirs(out, exist_ok=True)
            rdate = meta.get("report_date") or None
            if rdate and re.match(r'^\d{4}-\d{2}-\d{2}$', rdate):
                rdate = datetime.datetime.strptime(rdate, "%Y-%m-%d").strftime("%d-%m-%Y")
            smax = os.path.join(d, "in", "smax")
            has_rfc = bool(os.listdir(os.path.join(d, "in", "rfc")))
            ctx, outs = fa.run_audit(
                [os.path.join(d, "in", "algosec")],
                os.path.join(d, "in", "rfc") if has_rfc else None,
                out, cfg, rdate, progress=progress,
                smax_path=smax if os.listdir(smax) else None,
                operator=user, record_job=False,
                overrides_path=self.ov_path if os.path.isfile(self.ov_path) else "",
            )
            res = fa.results_to_dict(ctx)
            for cu in res.get("input_custody", []) + res.get("output_custody", []):
                cu.pop("path", None)  # do not show server paths to viewers
            res["rules"] = [dict(r, file=os.path.basename(r.get("file") or "")) for r in res["rules"]]
            res["outputs"] = [os.path.relpath(p, d).replace("\\", "/") for p in outs]
            res["version"] = ver
            _write_json(os.path.join(d, "results.json"), res)
            with self.lock:
                m = self.meta(rid)
                m.update({
                    "status": "done", "versions": ver, "finished_at": _now(),
                    "report_date": res["report_date"],
                    "summary": {
                        "rules": len(res["rules"]), "status": res["status"],
                        "counts": res["counts"], "tool_counts": res["tool_counts"],
                        "confidence": res["confidence_counts"],
                        "overrides": res["overrides"],
                    },
                })
                m["log"] = log[-300:]
                self.save_meta(rid, m)
            self.trail(user, "run.done", {"run": rid, "version": ver, "status": res["status"],
                                          "counts": res["counts"]})
        except Exception as e:
            detail = str(e) if isinstance(e, fa.AuditError) else "Unexpected error: %s" % e
            log.append(detail)
            fa.log.error("web run %s failed:\n%s", rid, traceback.format_exc())
            with self.lock:
                m = self.meta(rid)
                m["status"] = "failed"
                m["error"] = detail
                m["log"] = log[-300:]
                self.save_meta(rid, m)
            self.trail(user, "run.failed", {"run": rid, "error": detail})
        finally:
            with self.lock:
                self.running.pop(rid, None)


def qa_sample(results, percent, seed):
    """Random, repeatable share of NO rules for a human re-check."""
    pool = [r["uid"] for r in results["rules"] if r["status"] == "NO"]
    if not pool or percent <= 0:
        return []
    n = max(1, int(round(len(pool) * percent / 100.0)))
    rnd = random.Random(seed)
    return sorted(rnd.sample(pool, min(n, len(pool))))


class Sessions(object):
    def __init__(self):
        self.s = {}
        self.fails = collections.defaultdict(list)
        self.lock = threading.Lock()

    def create(self, user, role):
        tok = secrets.token_urlsafe(32)
        with self.lock:
            self.s[tok] = {"user": user, "role": role,
                           "exp": time.time() + SESSION_HOURS * 3600}
        return tok

    def get(self, tok):
        with self.lock:
            rec = self.s.get(tok or "")
            if rec and rec["exp"] > time.time():
                return rec
            self.s.pop(tok or "", None)
        return None

    def drop(self, tok):
        with self.lock:
            self.s.pop(tok or "", None)

    def drop_user(self, user):
        with self.lock:
            for k in [k for k, v in self.s.items() if v["user"] == user]:
                del self.s[k]

    def blocked(self, ip):
        with self.lock:
            now = time.time()
            self.fails[ip] = [t for t in self.fails[ip] if now - t < 300]
            return len(self.fails[ip]) >= 5

    def fail(self, ip):
        with self.lock:
            self.fails[ip].append(time.time())


class ApiError(Exception):
    def __init__(self, code, msg):
        Exception.__init__(self, msg)
        self.code, self.msg = code, msg


def make_handler(store, sessions, tls=False):

    class H(BaseHTTPRequestHandler):
        server_version = "PolicyPulse/" + WEB_VERSION
        sys_version = ""

        def log_message(self, fmt, *args):
            fa.log.info("web %s %s", self.client_address[0], fmt % args)

        # --- plumbing ---
        def _headers(self, code, ctype, length, extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(length))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data:; style-src 'self';"
                " script-src 'self'; frame-ancestors 'none'; base-uri 'none';"
                " form-action 'self'",
            )
            if tls:
                self.send_header("Strict-Transport-Security", "max-age=31536000")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()

        def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
            if isinstance(body, (dict, list)):
                body = json.dumps(body, default=str).encode("utf-8")
            elif isinstance(body, str):
                body = body.encode("utf-8")
            self._headers(code, ctype, len(body), extra)
            if self.command != "HEAD":
                self.wfile.write(body)

        def _cookie_token(self):
            c = cookies.SimpleCookie()
            try:
                c.load(self.headers.get("Cookie", ""))
            except cookies.CookieError:
                return None
            m = c.get("pp_session")
            return m.value if m else None

        def _session(self):
            return sessions.get(self._cookie_token())

        def _need(self, role):
            s = self._session()
            if not s:
                raise ApiError(401, "Please sign in.")
            if s["user"] not in store.users():
                sessions.drop_user(s["user"])
                raise ApiError(401, "Please sign in.")
            if not _role_ok(s["role"], role):
                raise ApiError(403, "Your role (%s) cannot do this; %s needed." % (s["role"], role))
            return s

        def _body(self, limit=MAX_JSON):
            n = int(self.headers.get("Content-Length") or 0)
            if n > limit:
                raise ApiError(413, "Upload too large (max %d MB)." % (limit // (1024 * 1024)))
            return self.rfile.read(n) if n else b""

        def _json(self):
            try:
                d = json.loads(self._body().decode("utf-8") or "{}")
            except ValueError:
                raise ApiError(400, "Bad JSON")
            if not isinstance(d, dict):
                raise ApiError(400, "Bad JSON")
            return d

        def _csrf(self):
            if self.headers.get("X-PP") != "1":
                raise ApiError(403, "Missing request header.")
            origin = self.headers.get("Origin")
            if origin:
                host = self.headers.get("Host", "")
                if urlparse(origin).netloc != host:
                    raise ApiError(403, "Cross-site request refused.")

        def _ip(self):
            return self.client_address[0]

        # --- dispatch ---
        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def do_DELETE(self):
            self._dispatch("DELETE")

        def _dispatch(self, method):
            u = urlparse(self.path)
            path, q = u.path, parse_qs(u.query)
            try:
                if method == "GET" and path in ("/", "/index.html"):
                    return self._send(200, ui.INDEX_HTML, "text/html; charset=utf-8")
                if method == "GET" and path == "/app.js":
                    return self._send(200, ui.APP_JS, "application/javascript; charset=utf-8")
                if method == "GET" and path == "/app.css":
                    return self._send(200, ui.APP_CSS, "text/css; charset=utf-8")
                if method == "GET" and path == "/favicon.ico":
                    return self._send(204, b"", "image/x-icon")
                if not path.startswith("/api/"):
                    raise ApiError(404, "Not found")
                if method != "GET":
                    self._csrf()
                return self._api(method, path[5:].strip("/").split("/"), q)
            except ApiError as e:
                return self._send(e.code, {"error": e.msg})
            except fa.AuditError as e:
                return self._send(400, {"error": str(e)})
            except Exception:
                fa.log.error("web error:\n%s", traceback.format_exc())
                return self._send(500, {"error": "Internal error (see fwaudit.log)."})

        def _api(self, method, parts, q):
            p0 = parts[0] if parts else ""
            # --- auth ---
            if p0 == "login" and method == "POST":
                ip = self._ip()
                if sessions.blocked(ip):
                    raise ApiError(429, "Too many failed sign-ins. Wait 5 minutes.")
                d = self._json()
                user = (d.get("user") or "").strip()
                role = store.check_password(user, d.get("password") or "")
                if not role:
                    sessions.fail(ip)
                    store.trail(user, "login.failed", ip=ip)
                    raise ApiError(401, "Wrong user name or password.")
                tok = sessions.create(user, role)
                store.trail(user, "login", ip=ip)
                ck = "pp_session=%s; Path=/; HttpOnly; SameSite=Strict%s; Max-Age=%d" % (
                    tok, "; Secure" if tls else "", SESSION_HOURS * 3600)
                return self._send(200, {"user": user, "role": role}, extra={"Set-Cookie": ck})
            if p0 == "logout" and method == "POST":
                s = self._session()
                sessions.drop(self._cookie_token())
                if s:
                    store.trail(s["user"], "logout", ip=self._ip())
                return self._send(200, {"ok": True},
                                  extra={"Set-Cookie": "pp_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})
            if p0 == "me" and method == "GET":
                s = self._need("viewer")
                cfg = store.cfg()
                return self._send(200, {
                    "user": s["user"], "role": s["role"], "version": fa.VERSION,
                    "web_version": WEB_VERSION,
                    "require_approval": (cfg.get("review") or {}).get("require_approval", True),
                    "reasons": list(fa.OVERRIDE_REASONS),
                    "statuses": list(fa.FINAL_STATUSES),
                })
            if p0 == "me" and len(parts) > 1 and parts[1] == "password" and method == "POST":
                s = self._need("viewer")
                d = self._json()
                if not store.check_password(s["user"], d.get("old") or ""):
                    raise ApiError(400, "Current password is wrong.")
                store.add_user(s["user"], d.get("new") or "", store.users()[s["user"]]["role"], by=s["user"])
                return self._send(200, {"ok": True})
            # --- dashboard ---
            if p0 == "dashboard":
                self._need("viewer")
                return self._send(200, self._dashboard())
            # --- runs ---
            if p0 == "runs":
                return self._runs(method, parts[1:], q)
            # --- overrides ---
            if p0 == "overrides":
                return self._overrides(method, parts[1:])
            if p0 == "trail":
                self._need("reviewer")
                return self._send(200, store.read_trail())
            if p0 == "users":
                return self._users(method, parts[1:])
            raise ApiError(404, "Unknown API")

        # --- dashboard ---
        def _dashboard(self):
            runs = [r for r in store.list_runs() if r.get("status") == "done"]
            ovs = store.overrides()["overrides"]
            reasons = collections.Counter(o.get("reason") for o in ovs if o.get("state") == "approved")
            pending = sum(1 for o in ovs if o.get("state") == "proposed")
            qa_ok = qa_bad = 0
            for r in runs[:60]:
                for rec in store.qa(r["id"]).values():
                    if rec.get("verdict") == "correct":
                        qa_ok += 1
                    elif rec.get("verdict") == "wrong":
                        qa_bad += 1
            trend = []
            for r in reversed(runs[:30]):
                s = r.get("summary") or {}
                trend.append({"id": r["id"], "date": r.get("report_date"),
                              "counts": s.get("counts", {}), "tool_counts": s.get("tool_counts", {}),
                              "rules": s.get("rules", 0)})
            latest = runs[0] if runs else None
            fp_rate = None
            if latest:
                s = latest.get("summary") or {}
                flagged = s.get("tool_counts", {}).get("YES", 0) + s.get("tool_counts", {}).get("REVIEW", 0)
                applied = (s.get("overrides") or {}).get("applied", 0)
                fp_rate = round(100.0 * applied / flagged, 1) if flagged else 0.0
            return {"latest": latest, "trend": trend, "reasons": reasons.most_common(),
                    "pending": pending, "overrides_total": len(ovs),
                    "qa": {"correct": qa_ok, "wrong": qa_bad,
                           "accuracy": round(100.0 * qa_ok / (qa_ok + qa_bad), 1) if (qa_ok + qa_bad) else None},
                    "fp_rate": fp_rate, "runs": len(runs)}

        # --- runs ---
        def _runs(self, method, parts, q):
            if not parts or not parts[0]:
                if method == "GET":
                    self._need("viewer")
                    return self._send(200, store.list_runs())
                if method == "POST":
                    s = self._need("analyst")
                    d = self._json()
                    return self._send(200, store.new_run(s["user"], d.get("label") or ""))
                raise ApiError(405, "Method not allowed")
            rid = parts[0]
            store.run_dir(rid)
            sub = parts[1] if len(parts) > 1 else ""
            if sub == "" and method == "GET":
                self._need("viewer")
                m = store.meta(rid)
                m["files"] = store.input_files(rid)
                m["running"] = rid in store.running
                return self._send(200, m)
            if sub == "" and method == "DELETE":
                s = self._need("admin")
                if rid in store.running:
                    raise ApiError(409, "Run in progress")
                shutil.rmtree(store.run_dir(rid))
                store.trail(s["user"], "run.delete", {"run": rid}, self._ip())
                return self._send(200, {"ok": True})
            if sub == "upload" and method == "POST":
                s = self._need("analyst")
                if store.meta(rid).get("status") == "running":
                    raise ApiError(409, "Run in progress")
                kind = (q.get("kind") or [""])[0]
                if kind not in UPLOAD_KINDS:
                    raise ApiError(400, "kind must be algosec, rfc or smax")
                name = _safe_name((q.get("name") or [""])[0])
                folder = _safe_name((q.get("folder") or [""])[0])
                if not name:
                    raise ApiError(400, "Bad file name")
                low = name.lower()
                if not (low.endswith((".xlsx", ".xlsm", ".csv")) or "." not in name):
                    raise ApiError(400, "%s: only .xlsx, .xlsm, .csv (or extensionless RFC files)" % name)
                data = self._body(MAX_UPLOAD)
                if low.endswith((".xlsx", ".xlsm")) or "." not in name:
                    if not zipfile.is_zipfile(io.BytesIO(data)):
                        raise ApiError(400, "%s is not an Excel .xlsx workbook" % name)
                dest = os.path.join(store.run_dir(rid), "in", kind)
                if folder and kind == "rfc" and fa.find_rfc_number(folder):
                    dest = os.path.join(dest, folder)
                    os.makedirs(dest, exist_ok=True)
                with open(os.path.join(dest, name), "wb") as f:
                    f.write(data)
                store.trail(s["user"], "run.upload", {"run": rid, "kind": kind, "file": name,
                                                      "sha256": hashlib.sha256(data).hexdigest()}, self._ip())
                return self._send(200, {"ok": True, "name": name, "size": len(data)})
            if sub == "file" and method == "DELETE":
                s = self._need("analyst")
                kind = (q.get("kind") or [""])[0]
                rel = (q.get("name") or [""])[0]
                if kind not in UPLOAD_KINDS:
                    raise ApiError(400, "bad kind")
                base = os.path.realpath(os.path.join(store.run_dir(rid), "in", kind))
                p = os.path.realpath(os.path.join(base, rel))
                if not p.startswith(base + os.sep) or not os.path.isfile(p):
                    raise ApiError(404, "No such file")
                os.remove(p)
                store.trail(s["user"], "run.remove_file", {"run": rid, "kind": kind, "file": rel}, self._ip())
                return self._send(200, {"ok": True})
            if sub == "start" and method == "POST":
                s = self._need("analyst")
                d = self._json()
                rd = (d.get("report_date") or "").strip()
                if rd and not re.match(r'^\d{4}-\d{2}-\d{2}$', rd):
                    raise ApiError(400, "report_date must be YYYY-MM-DD")
                store.start(rid, s["user"], rd)
                return self._send(200, {"ok": True})
            if sub == "results" and method == "GET":
                self._need("viewer")
                res = store.results(rid)
                if res is None:
                    raise ApiError(404, "No results yet")
                cfg = store.cfg()
                pct = float((cfg.get("review") or {}).get("qa_sample_percent", 5))
                res["qa_sample"] = qa_sample(res, pct, rid)
                res["qa"] = store.qa(rid)
                ovs = store.overrides()["overrides"]
                by_fp = collections.defaultdict(list)
                for o in ovs:
                    by_fp[o.get("fingerprint")].append(o)
                for r in res["rules"]:
                    r["override_history"] = by_fp.get(r["fingerprint"], [])
                return self._send(200, res)
            if sub == "qa" and method == "POST":
                s = self._need("analyst")
                d = self._json()
                uid = str(d.get("uid"))
                verdict = d.get("verdict")
                if verdict not in ("correct", "wrong", ""):
                    raise ApiError(400, "verdict must be correct or wrong")
                res = store.results(rid) or {"rules": []}
                if not any(str(r["uid"]) == uid for r in res["rules"]):
                    raise ApiError(404, "No such rule")
                with store.lock:
                    qa = store.qa(rid)
                    if verdict:
                        qa[uid] = {"verdict": verdict, "by": s["user"], "at": _now(),
                                   "comment": (d.get("comment") or "")[:1000]}
                    else:
                        qa.pop(uid, None)
                    store.save_qa(rid, qa)
                store.trail(s["user"], "qa.mark", {"run": rid, "uid": uid, "verdict": verdict}, self._ip())
                return self._send(200, {"ok": True})
            if sub == "download" and method == "GET":
                self._need("viewer")
                rel = (q.get("path") or [""])[0]
                base = os.path.realpath(os.path.join(store.run_dir(rid), "out"))
                p = os.path.realpath(os.path.join(store.run_dir(rid), rel))
                if not p.startswith(base + os.sep) or not os.path.isfile(p):
                    raise ApiError(404, "No such file")
                with open(p, "rb") as f:
                    data = f.read()
                ctype = ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                         if p.endswith(".xlsx") else "application/octet-stream")
                return self._send(200, data, ctype, {
                    "Content-Disposition": 'attachment; filename="%s"' % os.path.basename(p)})
            if sub == "evidence" and method == "GET":
                s = self._need("viewer")
                data = self._evidence(rid)
                store.trail(s["user"], "run.evidence_pack", {"run": rid,
                                                             "sha256": hashlib.sha256(data).hexdigest()}, self._ip())
                return self._send(200, data, "application/zip", {
                    "Content-Disposition": 'attachment; filename="Evidence_%s.zip"' % rid})
            raise ApiError(404, "Unknown run API")

        def _evidence(self, rid):
            d = store.run_dir(rid)
            res = store.results(rid)
            if res is None:
                raise ApiError(404, "No results yet")
            buf = io.BytesIO()
            manifest = []
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                def add(arc, data):
                    z.writestr(arc, data)
                    manifest.append("%s  %s" % (hashlib.sha256(data).hexdigest(), arc))
                for rel in res.get("outputs", []):
                    p = os.path.join(d, rel)
                    if os.path.isfile(p):
                        with open(p, "rb") as f:
                            add("reports/" + os.path.basename(p), f.read())
                add("results.json", json.dumps(res, indent=1, default=str).encode("utf-8"))
                add("run_meta.json", json.dumps(store.meta(rid), indent=1, default=str).encode("utf-8"))
                add("qa_checks.json", json.dumps(store.qa(rid), indent=1).encode("utf-8"))
                add("overrides_snapshot.json", json.dumps(store.overrides(), indent=1).encode("utf-8"))
                trail = [t for t in store.read_trail(5000) if (t.get("details") or {}).get("run") == rid]
                add("audit_trail.json", json.dumps(trail, indent=1).encode("utf-8"))
                z.writestr("SHA256SUMS.txt", "\n".join(manifest) + "\n")
            return buf.getvalue()

        # --- overrides ---
        def _overrides(self, method, parts):
            if not parts or not parts[0]:
                if method == "GET":
                    self._need("viewer")
                    return self._send(200, store.overrides())
                if method == "POST":
                    s = self._need("analyst")
                    d = self._json()
                    rid = d.get("run") or ""
                    res = store.results(rid) or {"rules": []}
                    rule = next((r for r in res["rules"] if str(r["uid"]) == str(d.get("uid"))), None)
                    if rule is None:
                        raise ApiError(404, "Rule not found in that run")
                    if len((d.get("comment") or "").strip()) < 5:
                        raise ApiError(400, "Write the evidence / reason in the comment.")
                    cfg = store.cfg()
                    need = (cfg.get("review") or {}).get("require_approval", True)
                    rec = fa.override_record(
                        rule["tab"], rule["name"], rule["change_type"], rule["fingerprint"],
                        d.get("final_status") or "", d.get("reason") or "",
                        (d.get("comment") or "")[:2000], s["user"],
                        "proposed" if need else "approved", d.get("expires") or "")
                    rec["run"] = rid
                    rec["tool_status"] = rule.get("tool_status")
                    with store.lock:
                        data = store.overrides()
                        data["overrides"].append(rec)
                        store.save_overrides(data)
                    store.trail(s["user"], "override.propose", {"run": rid, "id": rec["id"], "rule": rule["name"],
                                                                "tab": rule["tab"], "final": rec["final_status"],
                                                                "reason": rec["reason"]}, self._ip())
                    return self._send(200, rec)
                raise ApiError(405, "Method not allowed")
            oid, action = parts[0], (parts[1] if len(parts) > 1 else "")
            if method != "POST" or action not in ("approve", "reject", "revoke"):
                raise ApiError(404, "Unknown override API")
            s = self._need("reviewer" if action in ("approve", "reject") else "analyst")
            d = self._json()
            with store.lock:
                data = store.overrides()
                ov = next((o for o in data["overrides"] if o.get("id") == oid), None)
                if ov is None:
                    raise ApiError(404, "No such override")
                if action in ("approve", "reject"):
                    if ov.get("state") != "proposed":
                        raise ApiError(409, "Only proposed overrides can be %sd." % action)
                    if ov.get("by", "").lower() == s["user"].lower():
                        raise ApiError(403, "Maker-checker: you cannot %s your own override." % action)
                if action == "revoke":
                    if ov.get("state") not in ("approved", "proposed"):
                        raise ApiError(409, "Nothing to revoke.")
                    if ov.get("by", "").lower() != s["user"].lower() and not _role_ok(s["role"], "reviewer"):
                        raise ApiError(403, "Only the proposer or a reviewer can revoke.")
                now = _now()
                if action == "approve":
                    ov["state"], ov["approved_by"], ov["approved_at"] = "approved", s["user"], now
                else:
                    ov["state"] = "rejected" if action == "reject" else "revoked"
                    ov["closed_by"], ov["closed_at"] = s["user"], now
                ov["closed_note"] = (d.get("note") or "")[:500]
                store.save_overrides(data)
            store.trail(s["user"], "override." + action, {"id": oid, "rule": ov.get("rule"),
                                                          "tab": ov.get("tab"), "run": ov.get("run")}, self._ip())
            return self._send(200, ov)

        # --- users ---
        def _users(self, method, parts):
            s = self._need("admin")
            if method == "GET":
                us = store.users()
                return self._send(200, [{"user": u, "role": r.get("role"), "created": r.get("created"),
                                         "updated": r.get("updated")} for u, r in sorted(us.items())])
            if method == "POST":
                d = self._json()
                store.add_user(d.get("user"), d.get("password"), d.get("role"), by=s["user"])
                sessions.drop_user((d.get("user") or "").strip())
                return self._send(200, {"ok": True})
            if method == "DELETE" and parts:
                if parts[0] == s["user"]:
                    raise ApiError(400, "You cannot delete yourself.")
                store.del_user(parts[0], s["user"])
                sessions.drop_user(parts[0])
                return self._send(200, {"ok": True})
            raise ApiError(405, "Method not allowed")

    return H


def build_server(host, port, data_dir, cfg_path=None, cert=None, key=None):
    store = Store(data_dir, cfg_path)
    sessions = Sessions()
    tls = bool(cert and key)
    srv = ThreadingHTTPServer((host, port), make_handler(store, sessions, tls))
    srv.daemon_threads = True
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv, store


def _prompt_admin(store):
    print("No users yet. Create the first admin account.")
    if not sys.stdin.isatty():
        print("Run:  python fwaudit_web.py adduser <name> --role admin")
        return False
    name = input("Admin user name: ").strip()
    pw = getpass.getpass("Password (min 10 chars): ")
    if pw != getpass.getpass("Repeat password: "):
        print("Passwords do not match.")
        return False
    store.add_user(name, pw, "admin")
    return True


def main(argv=None):
    p = argparse.ArgumentParser(prog="fwaudit_web.py", description="PolicyPulse web front end for fwaudit")
    p.add_argument("--host", default="127.0.0.1", help="address to listen on (default 127.0.0.1 = this PC only)")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--data", default=os.path.join(fa.tool_dir(), "fwaudit_web_data"), help="data folder")
    p.add_argument("--config", help="fwaudit config JSON")
    p.add_argument("--cert", help="TLS certificate (PEM) for HTTPS")
    p.add_argument("--key", help="TLS private key (PEM)")
    sub = p.add_subparsers(dest="cmd")
    a = sub.add_parser("adduser", help="add or update a user (password asked, or from stdin)")
    a.add_argument("name")
    a.add_argument("--role", default="analyst", choices=ROLES)
    a.add_argument("--password-stdin", action="store_true")
    sub.add_parser("users", help="list users")
    args = p.parse_args(argv)
    store = Store(args.data, args.config)
    if args.cmd == "adduser":
        if args.password_stdin:
            pw = sys.stdin.readline().rstrip("\n")
        else:
            pw = getpass.getpass("Password for %s (min 10 chars): " % args.name)
        try:
            store.add_user(args.name, pw, args.role)
        except fa.AuditError as e:
            print(e)
            return 2
        print("Saved user %s (%s)." % (args.name, args.role))
        return 0
    if args.cmd == "users":
        for u, r in sorted(store.users().items()):
            print("%-24s %s" % (u, r.get("role")))
        return 0
    cfg = fa.load_config(args.config)
    fa.setup_logging(cfg, console=False)
    if not store.users() and not _prompt_admin(store):
        return 2
    if args.host not in ("127.0.0.1", "localhost", "::1") and not (args.cert and args.key):
        print("WARNING: listening on %s without HTTPS. Passwords and reports cross the network"
              " in clear text. Use --cert and --key on a shared server." % args.host)
    srv, _ = build_server(args.host, args.port, args.data, args.config, args.cert, args.key)
    scheme = "https" if args.cert and args.key else "http"
    print("PolicyPulse web %s (engine %s) on %s://%s:%d  - data: %s  - Ctrl+C to stop"
          % (WEB_VERSION, fa.VERSION, scheme, args.host, args.port, os.path.abspath(args.data)))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("Stopped.")
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
