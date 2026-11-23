"""End-to-end test of the web API: users, upload, run, overrides with
maker-checker, re-run, evidence pack and basic security checks.

    python tests/test_web.py
"""
import http.cookiejar
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import fwaudit as fa  # noqa: E402
import fwaudit_web as web  # noqa: E402

FAILS = []


def check(label, cond):
    print("%s %s" % ("PASS" if cond else "FAIL", label))
    if not cond:
        FAILS.append(label)


class Client(object):
    def __init__(self, base):
        self.base = base
        self.op = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(self, method, path, body=None, raw=None, header=True):
        data, headers = None, {}
        if header:
            headers["X-PP"] = "1"
        if raw is not None:
            data = raw
            headers["Content-Type"] = "application/octet-stream"
        elif body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            r = self.op.open(req)
            code, payload = r.status, r.read()
        except urllib.error.HTTPError as e:
            code, payload = e.code, e.read()
        try:
            return code, json.loads(payload.decode())
        except ValueError:
            return code, payload


def main():
    fa.setup_logging(console=False)
    tmp = tempfile.mkdtemp(prefix="pp_web_")
    try:
        samples = os.path.join(tmp, "samples")
        os.makedirs(samples)
        fa._sample(samples)
        data = os.path.join(tmp, "data")
        srv, store = web.build_server("127.0.0.1", 0, data)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = "http://127.0.0.1:%d" % port
        store.add_user("admin1", "admin-password-1", "admin")
        store.add_user("ana", "analyst-password", "analyst")
        store.add_user("rev", "reviewer-password", "reviewer")
        store.add_user("view", "viewer-password", "viewer")

        anon = Client(base)
        code, _ = anon.call("GET", "/api/runs")
        check("API needs sign-in", code == 401)
        code, html = anon.call("GET", "/")
        check("index page served", code == 200 and b"app.js" in html)
        code, d = anon.call("POST", "/api/login", {"user": "ana", "password": "wrong"})
        check("wrong password refused", code == 401)

        ana, rev, view = Client(base), Client(base), Client(base)
        check("analyst signs in", ana.call("POST", "/api/login", {"user": "ana", "password": "analyst-password"})[0] == 200)
        check("reviewer signs in", rev.call("POST", "/api/login", {"user": "rev", "password": "reviewer-password"})[0] == 200)
        check("viewer signs in", view.call("POST", "/api/login", {"user": "view", "password": "viewer-password"})[0] == 200)
        code, _ = ana.call("POST", "/api/runs", {"label": "x"}, header=False)
        check("POST without X-PP header refused (CSRF)", code == 403)
        check("viewer cannot create run", view.call("POST", "/api/runs", {"label": "x"})[0] == 403)

        code, run = ana.call("POST", "/api/runs", {"label": "Selftest data"})
        rid = run["id"]
        check("run created", code == 200 and rid)
        for f in sorted(os.listdir(samples)):
            p = os.path.join(samples, f)
            kind = "rfc" if f.startswith("RFC") else "algosec"
            with open(p, "rb") as fh:
                code, _ = ana.call("POST", "/api/runs/%s/upload?kind=%s&name=%s" % (rid, kind, f), raw=fh.read())
            if code != 200:
                check("upload " + f, False)
        code, d = ana.call("POST", "/api/runs/%s/upload?kind=rfc&name=evil.xlsx" % rid, raw=b"not a zip")
        check("non-Excel upload refused", code == 400)
        code, d = ana.call("POST", "/api/runs/%s/upload?kind=rfc&name=..%%2F..%%2Fx.xlsx" % rid, raw=b"PK")
        check("path traversal in name neutralised", code in (400,) and not os.path.exists(os.path.join(data, "x.xlsx")))
        code, m = ana.call("GET", "/api/runs/" + rid)
        check("uploads listed", len(m["files"]["algosec"]) == 2 and len(m["files"]["rfc"]) >= 6)

        def run_and_wait():
            code, d = ana.call("POST", "/api/runs/%s/start" % rid, {"report_date": "2026-11-08"})
            if code != 200:
                return code, d
            for _ in range(200):
                time.sleep(0.1)
                code, m = ana.call("GET", "/api/runs/" + rid)
                if m["status"] in ("done", "failed") and not m.get("running"):
                    return 200, m
            return 0, {}

        code, m = run_and_wait()
        check("audit run completes", code == 200 and m["status"] == "done")
        code, res = view.call("GET", "/api/runs/%s/results" % rid)
        check("results readable by viewer", code == 200 and len(res["rules"]) == 9)
        by = dict((r["name"], r) for r in res["rules"] if r["name"] == "RFC900000002-1" and r["status"] == "YES")
        target = list(by.values())[0]
        check("rule has explanation and evidence", target["explain"] and target["evidence"] and target["confidence"])
        check("server paths hidden", all("path" not in c for c in res["input_custody"]))

        code, d = view.call("POST", "/api/overrides", {"run": rid, "uid": target["uid"], "final_status": "NO",
                                                       "reason": fa.OVERRIDE_REASONS[0], "comment": "nope"})
        check("viewer cannot propose override", code == 403)
        code, d = ana.call("POST", "/api/overrides", {"run": rid, "uid": target["uid"], "final_status": "NO",
                                                      "reason": fa.OVERRIDE_REASONS[0], "comment": ""})
        check("override needs a comment", code == 400)
        code, ov = ana.call("POST", "/api/overrides", {"run": rid, "uid": target["uid"], "final_status": "NO",
                                                       "reason": fa.OVERRIDE_REASONS[0],
                                                       "comment": "1521 approved in RFC900000099 Sr 2"})
        check("analyst proposes override", code == 200 and ov["state"] == "proposed")
        code, d = ana.call("POST", "/api/overrides/%s/approve" % ov["id"], {})
        check("analyst cannot approve (role)", code == 403)
        store.add_user("ana2", "analyst2-password", "reviewer")
        selfc = Client(base)
        selfc.call("POST", "/api/login", {"user": "ana2", "password": "analyst2-password"})
        code, ov2 = selfc.call("POST", "/api/overrides", {"run": rid, "uid": target["uid"], "final_status": "NO",
                                                          "reason": fa.OVERRIDE_REASONS[1], "comment": "own one test"})
        code, d = selfc.call("POST", "/api/overrides/%s/approve" % ov2["id"], {})
        check("reviewer cannot approve own override (maker-checker)", code == 403)
        selfc.call("POST", "/api/overrides/%s/revoke" % ov2["id"], {})
        code, d = rev.call("POST", "/api/overrides/%s/approve" % ov["id"], {})
        check("other reviewer approves", code == 200 and d["state"] == "approved")

        code, m = run_and_wait()
        code, res2 = ana.call("GET", "/api/runs/%s/results" % rid)
        t2 = [r for r in res2["rules"] if r["uid"] == target["uid"]][0]
        check("re-run applies approved override", t2["status"] == "NO" and t2["tool_status"] == "YES" and res2["version"] == 2)

        sample = res2["qa_sample"]
        check("QA sample drawn from NO rules", len(sample) >= 1)
        code, _ = ana.call("POST", "/api/runs/%s/qa" % rid, {"uid": sample[0], "verdict": "correct"})
        check("QA mark saved", code == 200)
        code, dash = view.call("GET", "/api/dashboard")
        check("dashboard shows QA accuracy and override reasons",
              dash["qa"]["accuracy"] == 100.0 and dash["reasons"] and dash["latest"]["id"] == rid)

        out = [o for o in res2["outputs"] if "RFC_Audit" in o][0]
        code, blob = view.call("GET", "/api/runs/%s/download?path=%s" % (rid, out))
        check("report download", code == 200 and isinstance(blob, bytes) and blob[:2] == b"PK")
        code, d = view.call("GET", "/api/runs/%s/download?path=in/algosec/%s" % (rid, os.listdir(samples)[0]))
        check("download limited to outputs", code == 404)
        code, blob = view.call("GET", "/api/runs/%s/evidence" % rid)
        z = zipfile.ZipFile(io.BytesIO(blob))
        names = z.namelist()
        check("evidence pack has reports, results, trail and checksums",
              "SHA256SUMS.txt" in names and "results.json" in names and "audit_trail.json" in names
              and any(n.startswith("reports/") for n in names))
        code, trail = rev.call("GET", "/api/trail")
        acts = set(t["action"] for t in trail)
        check("audit trail records actions", {"login", "run.upload", "override.propose", "override.approve", "run.done"} <= acts)
        check("viewer cannot read trail", view.call("GET", "/api/trail")[0] == 403)
        bad = Client(base)
        for _ in range(5):
            bad.call("POST", "/api/login", {"user": "x", "password": "y"})
        check("sign-in lockout after 5 failures", bad.call("POST", "/api/login", {"user": "ana", "password": "analyst-password"})[0] == 429)
        srv.shutdown()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("WEB TEST %s (%d failed)" % ("PASSED" if not FAILS else "FAILED", len(FAILS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
