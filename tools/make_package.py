"""Build the ready-to-run download package.

    python tools/make_package.py            -> dist/PolicyPulse-<version>-<commit>.zip

The ZIP holds the three .py files, README, double-click start files for
Windows and a VERSION.txt with the commit, date and SHA-256 of each file,
so a tester always knows exactly which build they have.
"""
import datetime
import hashlib
import os
import re
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = ["fwaudit.py", "fwaudit_web.py", "fwaudit_web_ui.py", "README.md"]
EXTRA_DIRS = ["tests", "docs/screenshots"]

START_FILES = {
    "1_Desktop_window.bat": "@echo off\r\ncd /d \"%~dp0\"\r\npython fwaudit.py\r\nif errorlevel 1 pause\r\n",
    "2_Web_version.bat": (
        "@echo off\r\ncd /d \"%~dp0\"\r\n"
        "echo Starting PolicyPulse web on http://127.0.0.1:8765  (Ctrl+C to stop)\r\n"
        "start \"\" http://127.0.0.1:8765\r\npython fwaudit_web.py\r\npause\r\n"
    ),
    "3_Selftest.bat": "@echo off\r\ncd /d \"%~dp0\"\r\npython fwaudit.py selftest\r\npython tests\\test_web.py\r\npause\r\n",
    "start_web.sh": "#!/bin/sh\ncd \"$(dirname \"$0\")\"\nexec python3 fwaudit_web.py \"$@\"\n",
}


def _git(*args):
    try:
        return subprocess.check_output(["git"] + list(args), cwd=ROOT, stderr=subprocess.DEVNULL).decode().strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def version():
    with open(os.path.join(ROOT, "fwaudit.py"), encoding="utf-8") as f:
        m = re.search(r'^VERSION = "([^"]+)"', f.read(), re.M)
    return m.group(1) if m else "0"


def build(out_dir=None):
    out_dir = out_dir or os.path.join(ROOT, "dist")
    os.makedirs(out_dir, exist_ok=True)
    sha = os.environ.get("GITHUB_SHA", "")[:7] or _git("rev-parse", "--short", "HEAD") or "local"
    branch = os.environ.get("GITHUB_REF_NAME", "") or _git("rev-parse", "--abbrev-ref", "HEAD")
    ver = version().replace("-single", "")
    name = "PolicyPulse-%s-%s" % (ver, sha)
    path = os.path.join(out_dir, name + ".zip")
    entries = []
    for f in FILES:
        entries.append((f, os.path.join(ROOT, f)))
    for d in EXTRA_DIRS:
        for dp, _, fs in os.walk(os.path.join(ROOT, d)):
            for f in sorted(fs):
                if f.endswith((".pyc",)) or "__pycache__" in dp:
                    continue
                full = os.path.join(dp, f)
                entries.append((os.path.relpath(full, ROOT).replace("\\", "/"), full))
    lines = [
        "PolicyPulse %s" % ver,
        "Commit : %s (%s)" % (sha, branch or "?"),
        "Built  : %s UTC" % datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M"),
        "Needs  : Python 3.8+ (Windows: python.org installer, tick 'Add to PATH')",
        "",
        "Start  : 1_Desktop_window.bat | 2_Web_version.bat | 3_Selftest.bat",
        "",
        "SHA-256 of the files:",
    ]
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for arc, full in entries:
            with open(full, "rb") as fh:
                data = fh.read()
            z.writestr(name + "/" + arc, data)
            lines.append("  %s  %s" % (hashlib.sha256(data).hexdigest(), arc))
        for arc, text in START_FILES.items():
            z.writestr(name + "/" + arc, text)
        z.writestr(name + "/VERSION.txt", "\r\n".join(lines) + "\r\n")
    return path


if __name__ == "__main__":
    p = build(sys.argv[1] if len(sys.argv) > 1 else None)
    print(p)
