"""Role 4 / T12: check that a fresh demo run matches the committed recording (the backup).

Usage: compare.py <recorded_dir> <run_dir>

Run IDs, custody times and stored file names are random per run, so they are left out. Everything the demo shows
is compared: hashes, events, claims, hypothesis ranking, tamper/verify outcome, quarantine, invalidation and the diff.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def summary(d: Path) -> dict:
    J = lambda n: json.loads((d / f"{n}.json").read_text(encoding="utf-8"))
    claims = lambda run: sorted((c["type"], c["status"], c["grade"]) for c in run["claims"])
    hyps = lambda run: [(h["rank"], h["id"], h["status"]) for h in run["ranked_hypotheses"]]
    stages = lambda run: [(s["stage_name"], s["status"], s["relationship_to_previous"]) for s in (run.get("reconstruction") or {}).get("stages", [])]
    a, b, aq, diff = J("run_a"), J("run_b"), J("run_a_after_quarantine"), J("diff_a_b")
    tamper, verify = J("tamper"), J("verify_after_tamper")
    return {
        "uploads": [(u["filename"], u["evidence_id"], u["sha256"], u["events_created"]) for u in J("uploads")],
        "events": sorted((e["evidence_id"], e["timestamp"], e["source"], e["action"], e.get("actor"), e.get("object")) for e in J("events")),
        "integrity_before": J("integrity_before")["intact"],
        "run_a.ranking_hash": a["ranking_hash"],
        "run_a.outcome": a["outcome"],
        "run_a.hypotheses": hyps(a),
        "run_a.claims": claims(a),
        "run_a.reconstruction": stages(a),
        "run_a.manifest": sorted((m["evidence_id"], m["sha256"]) for m in a["manifest"]["evidence"]),
        "run_a.verified": J("run_a_verify")["verified"],
        "tamper": (tamper["evidence_id"], tamper["intake_sha256"], tamper["tampered_sha256"], tamper["status"]),
        "verify_after_tamper": (verify["outcome"], verify["previous_status"], verify["status"], verify["observed_sha256"]),
        "integrity_after": (J("integrity_after")["intact"], J("integrity_after")["summary"]["by_status"]),
        "run_a.after_quarantine": (aq["validity"], aq["ranking_hash"]),
        "run_b.ranking_hash": b["ranking_hash"],
        "run_b.hypotheses": hyps(b),
        "run_b.claims": claims(b),
        "run_b.manifest": sorted((m["evidence_id"], m["sha256"]) for m in b["manifest"]["evidence"]),
        "diff.evidence_removed": [e["evidence_id"] for e in diff["evidence_diff"]["removed"]],
        "diff.claims_removed": sorted(c["type"] for c in diff["claims_diff"]["removed_claims"]),
        "diff.hypotheses": [(h["hypothesis_id"], h.get("old_status"), h.get("new_status"), h.get("old_rank"), h.get("new_rank")) for h in diff["hypothesis_diffs"]],
        "diff.stages": diff["stage_changes"],
    }


recorded, fresh = summary(Path(sys.argv[1])), summary(Path(sys.argv[2]))
bad = [k for k in recorded if json.dumps(recorded[k], default=list) != json.dumps(fresh[k], default=list)]
for key in recorded:
    print(f"[{'FAIL' if key in bad else 'PASS'}] matches recording: {key}")
print(f"\n{len(recorded) - len(bad)}/{len(recorded)} fields match the recording")
sys.exit(1 if bad else 0)
