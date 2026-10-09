"""
app.py - web page for the UAE PDPL scanner (pdpl_scanner.py must be in the same folder).
Local test : python app.py            then open http://localhost:8000
Server     : gunicorn app:app --bind 0.0.0.0:8000 --workers 1 --threads 8
Login      : set APP_PASSWORD (and optionally APP_USER) to require a username and password.
Proxy      : set SCAN_PROXY=http://user:pass@host:port to scan through a UAE IP address.
Speed      : set SCAN_PARALLEL=1 on a server with 2 GB+ memory to run the Accept and Reject sessions side by side
             (default "auto" turns it on only when 1.5 GB+ is available; 0 forces one session at a time).
"""
import hmac
import ipaddress
import json
import os
import re
import socket
import threading
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from functools import wraps
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlparse

from flask import Flask, Response, abort, redirect, render_template_string, request, send_from_directory, url_for

import pdpl_scanner as ps

APP_USER = os.environ.get("APP_USER", "team")
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
REPORTS = Path(__file__).resolve().parent / ps.OUTPUT_DIR
REPORTS.mkdir(parents=True, exist_ok=True)
OPTS = SimpleNamespace(headful=False, proxy=os.environ.get("SCAN_PROXY") or None, no_reject=False,
                       max_pages=4, settle=3000, timeout=30000, parallel=None)
GRADE_COLOUR = {"A": "#067647", "B": "#4d7c0f", "C": "#b54708", "D": "#c4320a", "F": "#b42318"}

app = Flask(__name__)
executor = ThreadPoolExecutor(max_workers=1)      # one scan at a time; others wait in a queue
jobs, lock = {}, threading.Lock()


def protected(view):
    """Ask for the shared username/password when APP_PASSWORD is set."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if APP_PASSWORD:
            au = request.authorization
            ok = au is not None and hmac.compare_digest((au.username or "").encode(), APP_USER.encode()) \
                and hmac.compare_digest((au.password or "").encode(), APP_PASSWORD.encode())
            if not ok:
                return Response("Login required", 401, {"WWW-Authenticate": 'Basic realm="PDPL Scanner"'})
        return view(*args, **kwargs)
    return wrapper


def public_url(raw):
    """Normalise the address and refuse internal/private targets."""
    u = raw.strip()
    if not re.match(r"^https?://", u, re.I):
        u = "https://" + u
    p = urlparse(u)
    if p.scheme not in ("http", "https") or not p.hostname or "." not in p.hostname:
        raise ValueError("Please enter a valid website address, e.g. https://example.ae")
    try:
        infos = socket.getaddrinfo(p.hostname, None)
    except socket.gaierror:
        raise ValueError("That website could not be found. Check the spelling of the address.")
    for info in infos:
        if not ipaddress.ip_address(info[4][0].split("%")[0]).is_global:
            raise ValueError("Internal or private network addresses cannot be scanned.")
    return u


def scan_job(job_id):
    job = jobs[job_id]
    c = job["client"]
    job.update(status="running", started=time.time())
    t0 = time.time()
    try:
        sc = ps.Scan(c, OPTS)
        sc.collect()
        sc.analyse()
        r = sc.report()
        slug = re.sub(r"[^A-Za-z0-9]+", "_", c["company"]).strip("_")[:40] or "client"
        stem = slug + "_UAE_PDPL_Report_" + datetime.now().strftime("%Y-%m-%d_%H%M") + "_" + job_id[:6]
        (REPORTS / (stem + ".json")).write_text(
            json.dumps({"client": c, "report": r}, indent=2, ensure_ascii=False, default=list), encoding="utf-8")
        ps.to_pdf(ps.render(r, c), REPORTS / (stem + ".pdf"),
                  c["company"] + " | UAE PDPL website readiness | " + c["prepared_by"])
        job.update(status="done", pdf=stem + ".pdf", json=stem + ".json",
                   score=r["score"], grade=r["grade"], counts=r["counts"], duration=int(time.time() - t0))
        print("scan done", c["url"], "in", job["duration"], "s", r.get("timings"), flush=True)
    except Exception as ex:
        traceback.print_exc()
        job.update(status="failed", error=(str(ex).splitlines() or [type(ex).__name__])[0][:300])


def recent_reports(limit=25):
    files = sorted(REPORTS.glob("*.pdf"), key=lambda f: f.stat().st_mtime, reverse=True)[:limit]
    return [{"name": f.name, "when": datetime.fromtimestamp(f.stat().st_mtime).strftime("%d %b %Y %H:%M")} for f in files]


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>UAE PDPL Scanner</title>{% if refresh %}<meta http-equiv="refresh" content="4">{% endif %}
<style>
body{margin:0;font:15px/1.5 -apple-system,'Segoe UI',Roboto,Arial,sans-serif;background:#f5f7fa;color:#101828}
main{max-width:760px;margin:0 auto;padding:32px 20px}
.card{background:#fff;border:1px solid #e4e7ec;border-radius:12px;padding:24px;margin-bottom:20px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:0 0 10px}.muted{color:#667085;font-size:14px}
label{display:block;font-weight:600;font-size:14px;margin:14px 0 4px}.req{color:#b42318}
input,textarea{width:100%;padding:10px 12px;border:1px solid #d0d5dd;border-radius:8px;font:inherit;box-sizing:border-box}
textarea{min-height:70px}
.btn{display:inline-block;background:#175cd3;color:#fff;border:1px solid #175cd3;border-radius:8px;padding:10px 18px;
font:inherit;font-weight:600;text-decoration:none;cursor:pointer;margin:16px 8px 0 0}
.ghost{background:#fff;color:#175cd3}
.err{background:#fef3f2;border:1px solid #fecdca;color:#b42318;padding:10px 12px;border-radius:8px}
.score{font-size:44px;font-weight:800}.grade{display:inline-block;color:#fff;border-radius:8px;padding:4px 12px;font-weight:700;margin-left:12px}
table{width:100%;border-collapse:collapse;font-size:14px}td{padding:8px 0;border-bottom:1px solid #f2f4f7}
.spin{width:20px;height:20px;border:3px solid #d0d5dd;border-top-color:#175cd3;border-radius:50%;display:inline-block;
animation:s 1s linear infinite;vertical-align:middle;margin-right:8px}@keyframes s{to{transform:rotate(360deg)}}
</style></head><body><main>
{% if view == 'home' %}
<div class="card"><h1>UAE PDPL Website Scanner</h1>
<div class="muted">Checks a public website against Federal Decree-Law No. 45 of 2021 and creates a client-ready PDF.
A scan usually takes under a minute. Only scan websites you are engaged to assess.</div>
{% if error %}<p class="err">{{ error }}</p>{% endif %}
<form method="post" action="{{ url_for('start_scan') }}">
{% for key, label, required in fields %}
<label for="{{ key }}">{{ label }}{% if required %} <span class="req">*</span>{% endif %}</label>
{% if key == 'notes' %}<textarea id="{{ key }}" name="{{ key }}">{{ values.get(key, '') }}</textarea>
{% else %}<input id="{{ key }}" name="{{ key }}" value="{{ values.get(key, '') }}"{% if required %} required{% endif %}{% if key == 'email' %} type="email"{% endif %}>{% endif %}
{% endfor %}
<button class="btn" type="submit">Run scan</button>
</form></div>
<div class="card"><h2>Recent reports</h2>
{% if recent %}<table>{% for r in recent %}<tr><td><a href="{{ url_for('report_file', name=r.name) }}" target="_blank">{{ r.name }}</a></td>
<td class="muted" style="text-align:right">{{ r.when }}</td></tr>{% endfor %}</table>
{% else %}<p class="muted">No reports yet.</p>{% endif %}</div>
{% else %}
<div class="card"><h1>{{ job.client.company }}</h1><div class="muted">{{ job.client.url }}</div>
{% if job.status == 'queued' %}<p><span class="spin"></span>Waiting in the queue ({{ position }} scan(s) ahead). This page refreshes by itself.</p>
{% elif job.status == 'running' %}<p><span class="spin"></span>Scanning... {{ elapsed }} seconds so far (usually 20-60). This page refreshes by itself.</p>
{% elif job.status == 'failed' %}<p class="err">Scan failed: {{ job.error }}</p><a class="btn" href="{{ url_for('home') }}">Try again</a>
{% else %}
<p><span class="score">{{ job.score }}</span><span class="muted">/100</span><span class="grade" style="background:{{ colour }}">Grade {{ job.grade }}</span></p>
<p class="muted">Critical {{ job.counts.critical }} &middot; High {{ job.counts.high }} &middot; Medium {{ job.counts.medium }} &middot; Low {{ job.counts.low }}{% if job.duration %} &middot; Scan took {{ job.duration }} s{% endif %}</p>
<a class="btn" href="{{ url_for('report_file', name=job.pdf) }}" target="_blank">Open PDF</a>
<a class="btn ghost" href="{{ url_for('report_file', name=job.pdf, download=1) }}">Download PDF</a>
<a class="btn ghost" href="{{ url_for('report_file', name=job.json, download=1) }}">Download JSON</a>
<a class="btn ghost" href="{{ url_for('home') }}">Scan another website</a>
{% endif %}</div>
{% endif %}
</main></body></html>"""


@app.get("/health")
def health():
    return "ok"


@app.get("/")
@protected
def home():
    return render_template_string(PAGE, view="home", fields=ps.FIELDS, values={"prepared_by": ps.BRAND},
                                  recent=recent_reports(), error=None, refresh=False)


@app.post("/scan")
@protected
def start_scan():
    values = {k: (request.form.get(k) or "").strip()[:500] for k, _, _ in ps.FIELDS}
    try:
        if not values["company"]:
            raise ValueError("Client company name is required.")
        values["url"] = public_url(values["url"])
    except ValueError as ex:
        return render_template_string(PAGE, view="home", fields=ps.FIELDS, values=values,
                                      recent=recent_reports(), error=str(ex), refresh=False), 400
    values["prepared_by"] = values["prepared_by"] or ps.BRAND
    job_id = uuid.uuid4().hex
    with lock:
        jobs[job_id] = {"id": job_id, "status": "queued", "client": values, "created": time.time()}
        if len(jobs) > 300:                                   # forget the oldest finished jobs
            for old in sorted(jobs.values(), key=lambda j: j["created"])[:50]:
                if old["status"] in ("done", "failed"):
                    jobs.pop(old["id"], None)
    executor.submit(scan_job, job_id)
    return redirect(url_for("job_page", job_id=job_id))


@app.get("/job/<job_id>")
@protected
def job_page(job_id):
    job = jobs.get(job_id)
    if not job:
        abort(404)
    with lock:
        position = sum(1 for j in jobs.values() if j["status"] == "queued" and j["created"] < job["created"])
    elapsed = int(time.time() - job.get("started", time.time()))
    return render_template_string(PAGE, view="job", job=job, position=position, elapsed=elapsed,
                                  colour=GRADE_COLOUR.get(job.get("grade"), "#475467"),
                                  refresh=job["status"] in ("queued", "running"))


@app.get("/reports/<path:name>")
@protected
def report_file(name):
    return send_from_directory(REPORTS, name, as_attachment=request.args.get("download") == "1")


if __name__ == "__main__":
    print("Open http://localhost:8000 in your browser. Press Ctrl+C to stop.")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), threaded=True)