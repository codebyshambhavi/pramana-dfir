"""Role 4 / T12: check a CASE-DEMO-IST run made by demo_run.py full. Usage: validate_recording.py <run_dir> <repo_root>"""
import hashlib
import json
import sys
from pathlib import Path

R, REPO = Path(sys.argv[1]), Path(sys.argv[2])
sys.path[:0] = [str(REPO / "evidence-engine"), str(REPO)]
J = lambda n: json.loads((R / f"{n}.json").read_text(encoding="utf-8"))
results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))


reqs = J("requests")
check("all HTTP calls 2xx", all(200 <= r["status"] < 300 for r in reqs), f"{len(reqs)} requests")

# 1. Real parser output: re-parse the same files directly and compare with what the API stored.
from parsers import parse_evidence  # noqa: E402
uploads, events = J("uploads"), J("events")
ev_dir = REPO / "bench/scenarios/CASE-DEMO-IST/evidence"
direct_total = 0
for u in uploads:
    path = ev_dir / u["filename"]
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    direct = parse_evidence(str(path), "CASE-DEMO-IST")
    direct_total += len(direct)
    stored = [e for e in events if e["evidence_id"] == u["evidence_id"]]
    same = sorted((e["timestamp"][:19], e["action"], e.get("actor"), e.get("object")) for e in direct) == \
        sorted((e["timestamp"][:19], e["action"], e.get("actor"), e.get("object")) for e in stored)
    check(f"{u['filename']}: intake sha256 = file sha256", u["sha256"] == sha)
    check(f"{u['filename']}: API events == direct parse", same and u["events_created"] == len(direct),
          f"api={u['events_created']} direct={len(direct)}")
check("events carry parser_version", all(e.get("parser_version") for e in events),
      f"versions={sorted({e.get('parser_version') for e in events})}")
print(f"       total events: api={len(events)} direct={direct_total}")

# 2. Run A: claims, edges, lineage are tied to real events and evidence hashes.
a, b = J("run_a"), J("run_b")
ev_ids = {e["event_id"] for e in events}
ev_by_id = {e["event_id"]: e for e in events}
sha_by_evid = {u["evidence_id"]: u["sha256"] for u in uploads}
check("run A manifest == all 5 ACTIVE evidence with intake hashes",
      {(m["evidence_id"], m["sha256"]) for m in a["manifest"]["evidence"]} == set(sha_by_evid.items()))
edges = [e for c in a["claims"] for e in c["edges"]]
check("every claim has at least one edge", all(c["edges"] for c in a["claims"]), f"{len(a['claims'])} claims")
check("every event edge points at a stored event",
      all(e["ref_id"] in ev_ids for e in edges if e["ref_kind"] == "event"),
      f"{sum(e['ref_kind'] == 'event' for e in edges)} event edges")
lin_a = J("run_a_lineage")
check("lineage recorded for every run A claim", set(lin_a) == {c["claim_id"] for c in a["claims"]})
lin_ok = all(
    ev["evidence_sha256"] == sha_by_evid.get(ev["evidence_id"]) and ev_by_id[ev["event_id"]]["evidence_id"] == ev["evidence_id"]
    for lin in lin_a.values() for ev in lin["events"]
)
check("lineage resolves to the right evidence and intake sha256", lin_ok)
v = J("run_a_verify")
check("run A reproducible (POST /runs/{id}/verify)", v["verified"] and v["persisted_ranking_hash"] == v["recomputed_ranking_hash"],
      f"ranking_hash={v['persisted_ranking_hash'][:16]}")
check("run A snapshot authoritative", a["snapshot_status"] == "AUTHORITATIVE_DB", a["snapshot_status"])
print("       run A claims:", [(c["type"], c["status"], c["grade"]) for c in a["claims"]])
print("       run A hypotheses:", [(h["rank"], h["id"], h["name"], h["status"]) for h in a["ranked_hypotheses"]], "outcome:", a["outcome"])
states = sorted({(h["id"], ev["category"], ev["state"]) for h in a["ranked_hypotheses"] for ev in h["evaluations"]})
print("       matrix states present:", sorted({s for _, _, s in states}))
print("       H2 matrix:", [(ev["item_id"], ev["category"], ev["state"]) for h in a["ranked_hypotheses"] if h["id"] == "H2" for ev in h["evaluations"]])
rec = a["reconstruction"]
print("       reconstruction:", rec and rec["hypothesis_id"], [(s["stage_name"], s["status"], s["relationship_to_previous"]) for s in (rec or {}).get("stages", [])])
print("       h0 residual events:", a["h0_residual"] and a["h0_residual"]["unassigned_event_count"], "| next-best:", len(a["next_best_evidence"]))

# 3. Tamper -> quarantine -> invalidation -> run B -> diff.
t, vr = J("tamper"), J("verify_after_tamper")
browser = next(u for u in uploads if u["filename"] == "browser_history.csv")
check("tamper changed the stored file hash", t["tampered_sha256"] != t["intake_sha256"] == browser["sha256"])
check("tamper alone does not change status", t["status"] == "ACTIVE", t["status"])
check("verify after tamper: MISMATCH -> QUARANTINED",
      vr["outcome"] == "MISMATCH" and vr["status"] == "QUARANTINED" and vr["observed_sha256"] == t["tampered_sha256"],
      f"{vr['previous_status']} -> {vr['status']} ({vr['outcome']})")
ib, ia = J("integrity_before"), J("integrity_after")
check("integrity intact before, not after", ib["intact"] and not ia["intact"],
      f"after by_status={ia['summary']['by_status']}")
check("intake sha256 unchanged after quarantine",
      next(e for e in J("evidence_after") if e["evidence_id"] == browser["evidence_id"])["sha256"] == browser["sha256"])
aq = J("run_a_after_quarantine")
check("run A becomes INVALIDATED", aq["validity"] == "INVALIDATED", "; ".join(aq["invalidation_reasons"]))
check("run A content unchanged (write-once)", aq["ranking_hash"] == a["ranking_hash"] and len(aq["claims"]) == len(a["claims"]))
check("run B manifest excludes the quarantined file",
      {m["evidence_id"] for m in b["manifest"]["evidence"]} == set(sha_by_evid) - {browser["evidence_id"]})
check("run B parent is run A", b["parent_run_id"] == a["run_id"])
d = J("diff_a_b")
check("diff: evidence removed == quarantined file", [e["evidence_id"] for e in d["evidence_diff"]["removed"]] == [browser["evidence_id"]])
removed = d["claims_diff"]["removed_claims"]
dep = lambda cid: any(ev["evidence_id"] == browser["evidence_id"] for ev in lin_a[cid]["events"])
check("diff: every removed claim depended on the quarantined file", removed and all(dep(c["claim_id"]) for c in removed),
      f"removed={[c['type'] for c in removed]}")
kept = [c for c in a["claims"] if c["claim_key"] not in {r["claim_key"] for r in removed}]
check("diff: claims not depending on it were kept", all(not dep(c["claim_id"]) for c in kept), f"kept={[c['type'] for c in kept]}")
print("       hypothesis changes:", [(h["hypothesis_id"], h.get("old_status"), h.get("new_status"), h.get("old_rank"), h.get("new_rank")) for h in d["hypothesis_diffs"]])
print("       stage changes:", d["stage_changes"])
print("       root cause:", d["root_cause_analysis"][:400])
print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
