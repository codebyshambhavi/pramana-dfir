"""Role 4 / T12: run the CASE-DEMO-IST demo against a live backend over HTTP and save every response verbatim.

Usage:
    demo_run.py full <evidence_dir> <out_dir>   whole demo: seed, run A, tamper, verify, run B, diff
    demo_run.py seed <evidence_dir> <out_dir>   only case + uploads + run A (the state the live UI demo starts from)

Backend URL: $PRAMANA_API (default http://127.0.0.1:8000). Tamper needs the backend started with DEMO_MODE=1.
Each step is timed; the whole run must finish within $DEMO_BUDGET_SECONDS (default 100) or the script fails.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import httpx

BASE = os.getenv("PRAMANA_API", "http://127.0.0.1:8000")
BUDGET = float(os.getenv("DEMO_BUDGET_SECONDS", "100"))
CASE = "CASE-DEMO-IST"
TZ = "Asia/Kolkata"
# Upload order fixes the evidence IDs: browser_history.csv is always EVID-002.
FILES = [
    "endpoint_system_log.csv",
    "browser_history.csv",
    "phone_chat.json",
    "vpn_authentication.csv",
    "backup_scheduler.csv",
]

mode, EVIDENCE_DIR, OUT = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
if mode not in {"full", "seed"}:
    raise SystemExit(__doc__)

client = httpx.Client(base_url=BASE, timeout=60)
log: list[dict] = []
timings: list[dict] = []


def save(name: str, data) -> None:
    (OUT / f"{name}.json").write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def call(method: str, path: str, name: str | None = None, **kw):
    r = client.request(method, path, **kw)
    log.append({"method": method, "path": path, "status": r.status_code})
    if r.status_code >= 400:
        raise SystemExit(f"{method} {path} -> {r.status_code}: {r.text[:500]}")
    data = r.json()
    if name:
        save(name, data)
    return data


class step:
    def __init__(self, name: str):
        self.name = name

    def __enter__(self):
        self.t0 = time.perf_counter()

    def __exit__(self, *exc):
        seconds = round(time.perf_counter() - self.t0, 3)
        timings.append({"step": self.name, "seconds": seconds})
        print(f"  {seconds:7.2f}s  {self.name}", flush=True)


for _ in range(90):
    try:
        if client.get("/health").status_code == 200:
            break
    except httpx.HTTPError:
        pass
    time.sleep(1)
else:
    raise SystemExit(f"backend at {BASE} did not become healthy")

OUT.mkdir(parents=True, exist_ok=True)
start = time.perf_counter()

with step("create case + upload 5 files"):
    call("POST", "/cases", json={"name": "CASE-DEMO-IST (T9 demo scenario)", "case_id": CASE})
    uploads = []
    for name in FILES:
        with open(EVIDENCE_DIR / name, "rb") as fh:
            uploads.append(call("POST", f"/cases/{CASE}/evidence", files={"file": (name, fh)}))
    save("uploads", uploads)

with step("read evidence, events, integrity"):
    call("GET", f"/cases/{CASE}/evidence", "evidence_before")
    call("GET", f"/cases/{CASE}/events", "events")
    call("GET", f"/cases/{CASE}/integrity", "integrity_before")

with step("run A"):
    a = call("POST", f"/cases/{CASE}/runs", "run_a_created", json={"assumptions": {"case_timezone": TZ}})["run_id"]
    details_a = call("GET", f"/runs/{a}", "run_a")

if mode == "full":
    with step("verify run A + claim lineage"):
        call("POST", f"/runs/{a}/verify", "run_a_verify")
        save("run_a_lineage", {c["claim_id"]: call("GET", f"/runs/{a}/claims/{c['claim_id']}/lineage") for c in details_a["claims"]})

    browser = next(u for u in uploads if u["filename"] == "browser_history.csv")
    with step(f"tamper + verify {browser['evidence_id']}"):
        call("POST", f"/evidence/{browser['evidence_id']}/simulate-tamper", "tamper")
        call("POST", f"/evidence/{browser['evidence_id']}/verify", "verify_after_tamper", json={"actor": "PRAMANA T12 demo"})
        call("GET", f"/cases/{CASE}/integrity", "integrity_after")
        call("GET", f"/cases/{CASE}/evidence", "evidence_after")
        call("GET", f"/runs/{a}", "run_a_after_quarantine")

    with step("run B (parent A) + lineage"):
        b = call("POST", f"/cases/{CASE}/runs", "run_b_created", json={"assumptions": {"case_timezone": TZ}, "parent_run_id": a})["run_id"]
        details_b = call("GET", f"/runs/{b}", "run_b")
        save("run_b_lineage", {c["claim_id"]: call("GET", f"/runs/{b}/claims/{c['claim_id']}/lineage") for c in details_b["claims"]})
        call("GET", f"/cases/{CASE}/runs", "runs")

    with step("diff A -> B"):
        call("GET", f"/runs/{a}/diff/{b}", "diff_a_b")

total = round(time.perf_counter() - start, 3)
save("requests", log)
(OUT / "_timings.json").write_text(json.dumps({"mode": mode, "total_seconds": total, "budget_seconds": BUDGET, "steps": timings}, indent=2) + "\n", encoding="utf-8")
print(f"  {total:7.2f}s  total ({mode}, budget {BUDGET:.0f}s, {len(log)} requests, run A {a})")
if total > BUDGET:
    raise SystemExit(f"demo took {total}s, over the {BUDGET}s budget")
