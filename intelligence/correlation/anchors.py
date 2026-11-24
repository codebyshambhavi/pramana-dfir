"""Validated direct anchors and bounded, indexed candidate generation.

Candidate generation only narrows comparisons; it never asserts a relationship.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

from .fields import ResolvedField, resolve_field
from .registry import Registry

_BLOCKED_INTEGRITY = {"MISMATCH", "MISSING", "CUSTODY_BROKEN", "QUARANTINED", "REMOVED"}

@dataclass(frozen=True)
class AnchorResult:
    parameter_id: str
    status: str  # ANCHORED / REJECTED / NO_MATCH
    anchor_type: str
    value_reference: str | None
    source_event_ids: tuple[str, str]
    evidence_refs: tuple[str | None, str | None]
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {"parameter_id": self.parameter_id, "status": self.status, "anchor_type": self.anchor_type,
                "value_reference": self.value_reference, "source_event_ids": list(self.source_event_ids),
                "evidence_refs": list(self.evidence_refs), "explanation": self.explanation}


def _event_id(e: Mapping[str, Any]) -> str:
    return str(e.get("event_id") or "")


def _field(e: Mapping[str, Any], name: str, evidence_context=None) -> ResolvedField:
    return resolve_field(e, name, evidence_context=evidence_context)


def _integrity_ok(e: Mapping[str, Any], evidence_context=None) -> tuple[bool, str]:
    f = _field(e, "prov.integrity", evidence_context)
    status = str(f.value or "MISSING").upper()
    return status not in _BLOCKED_INTEGRITY, status


def evaluate_anchor(parameter, a: Mapping[str, Any], b: Mapping[str, Any], *, evidence_context=None) -> AnchorResult:
    method = parameter.extraction["method"]
    ids = (_event_id(a), _event_id(b))
    refs = (a.get("artifact_ref") or a.get("evidence_id"), b.get("artifact_ref") or b.get("evidence_id"))
    def result(status, explanation, value=None):
        digest = hashlib.sha256(str(value).encode()).hexdigest()[:16] if value is not None else None
        return AnchorResult(parameter.parameter_id, status, method, digest, ids, refs, explanation)
    ok_a, int_a = _integrity_ok(a, evidence_context); ok_b, int_b = _integrity_ok(b, evidence_context)
    if parameter.extraction.get("block_on_integrity") and (not ok_a or not ok_b):
        return result("REJECTED", f"Anchor blocked by evidence integrity ({int_a}, {int_b}).")
    fields = parameter.source_fields
    if method == "ANCHOR_EXACT":
        field_name = next((x for x in fields if x != "prov.integrity"), None)
        if field_name == "file.sha256":
            vals_a = [_field(a, "file.sha256", evidence_context).value]
            vals_b = [_field(b, "file.sha256", evidence_context).value]
            vals_a += list(_field(a, "attachment.sha256", evidence_context).value or ())
            vals_b += list(_field(b, "attachment.sha256", evidence_context).value or ())
            vals_a = [x for x in vals_a if x]; vals_b = [x for x in vals_b if x]
            common = sorted(set(vals_a) & set(vals_b))
            if common:
                if len(common[0]) != int(parameter.extraction.get("hash_length", 64)):
                    return result("REJECTED", "Hash has the wrong cryptographic length.")
                return result("ANCHORED", "Both events reference identical validated SHA-256 content.", common[0])
            return result("NO_MATCH", "No identical valid SHA-256 content hash was found.")
        fa, fb = _field(a, field_name, evidence_context), _field(b, field_name, evidence_context)
        va, vb = fa.value, fb.value
        if not va or not vb: return result("NO_MATCH", "A required direct identifier is missing.")
        if field_name == "message.id" and (not isinstance(va, str) or not isinstance(vb, str) or "@" not in va or "@" not in vb):
            return result("REJECTED", "Message identifier is not a validated RFC-style Message-ID.")
        if va == vb: return result("ANCHORED", "Exact validated identifier match.", va)
        return result("NO_MATCH", "Direct identifiers do not match.")
    if method == "ANCHOR_REFERENCE":
        ida = _field(a, "message.id", evidence_context).value; idb = _field(b, "message.id", evidence_context).value
        ra = _field(a, "message.references", evidence_context).value or (); rb = _field(b, "message.references", evidence_context).value or ()
        if ida and (ida in rb or idb in ra):
            return result("ANCHORED", "An explicit RFC message reference connects the two messages.", ida if ida in rb else idb)
        return result("NO_MATCH", "No explicit message-reference edge was found.")
    if method in ("ANCHOR_SCOPED_EXACT",):
        field_name = "thread.id" if parameter.parameter_id == "ANCHOR_THREAD_ID" else "net.session_id"
        va, vb = _field(a, field_name, evidence_context).value, _field(b, field_name, evidence_context).value
        if not va or not vb: return result("NO_MATCH", "Scoped identifier is missing.")
        if va != vb: return result("NO_MATCH", "Scoped identifiers differ.")
        scopes = parameter.extraction.get("scope_fields", [])
        mode = parameter.extraction.get("scope_mode", "ALL")
        pairs = [(s, _field(a, s, evidence_context).value, _field(b, s, evidence_context).value) for s in scopes]
        if mode == "ALL":
            if any(x is None or y is None or x != y for _, x, y in pairs):
                return result("REJECTED", "Identifier matches but required scope does not.")
        else:
            first = next(((s, x, y) for s, x, y in pairs if x is not None and y is not None), None)
            if first is None or first[1] != first[2]:
                return result("REJECTED", "Identifier matches but no valid shared scope is established.")
        return result("ANCHORED", "Exact identifier match within its required scope.", va)
    return result("NO_MATCH", "Unsupported anchor method.")


def evaluate_anchors(a: Mapping[str, Any], b: Mapping[str, Any], registry: Registry, *, evidence_context=None) -> list[AnchorResult]:
    out=[]
    for p in registry.for_pair(a.get("source"), b.get("source"), relationship_class="PRIMARY"):
        r=evaluate_anchor(p,a,b,evidence_context=evidence_context)
        if r.status != "NO_MATCH": out.append(r)
    return out


def _index_values(event: Mapping[str, Any], index: str) -> tuple[str, ...]:
    mapping = {
        "file_hash": ("file.sha256",), "attachment_hash": ("attachment.sha256",),
        "message_id": ("message.id",), "message_reference": ("message.references",),
        "thread_id": ("thread.id",), "session_id": ("net.session_id",),
        "account": ("account.id",), "email": ("actor.email",), "username": ("actor.username",),
        "domain": ("net.domain", "content.url_domains"), "ip": ("net.ip",),
        "device": ("device.id",), "actor_device": ("actor.normalized", "device.id"),
        "filename": ("file.name", "attachment.names"),
    }
    vals=[]
    for f in mapping.get(index, ()):
        v=resolve_field(event,f).value
        if isinstance(v,(list,tuple,set)): vals.extend(map(str,v))
        elif v is not None: vals.append(str(v))
    return tuple(sorted(set(vals)))


def generate_candidate_pairs(events: Sequence[Mapping[str, Any]], registry: Registry, *,
                             max_bucket_size: int | None = None, window_seconds: float | None = None) -> tuple[list[tuple[Mapping[str, Any], Mapping[str, Any]]], dict[str, Any]]:
    """Generate deterministic candidate pairs from configured indexes and time windows."""
    cfg=registry.candidate_generation
    max_bucket_size=int(max_bucket_size or cfg.get("max_bucket_size",50))
    windows=cfg.get("windows_seconds",{}); window_seconds=float(window_seconds or windows.get("default",600))
    buckets: dict[tuple[str,str,str],list[int]]=defaultdict(list)
    for i,e in enumerate(events):
        case_scope = str(e.get("case_id") or "")
        for index in cfg.get("indexes",[]):
            for value in _index_values(e,index): buckets[(case_scope,index,value)].append(i)
    pairs:set[tuple[int,int]]=set(); skipped=[]
    for (case_scope,index,value),members in sorted(buckets.items()):
        members=sorted(set(members),key=lambda i:(_event_id(events[i]),i))
        if len(members)>max_bucket_size:
            skipped.append({"case_id":case_scope,"index":index,"value_hash":hashlib.sha256(value.encode()).hexdigest()[:12],"bucket_size":len(members),"reason":"MAX_BUCKET_SIZE"}); continue
        for x,pos in enumerate(members):
            for j in members[x+1:]: pairs.add((min(pos,j),max(pos,j)))
    # Time-window candidate index: sorted sliding window, not unrestricted all-pairs.
    timed=[]
    for i,e in enumerate(events):
        try:
            ts=datetime.fromisoformat(str(e.get("timestamp")).replace("Z","+00:00"))
            if ts.tzinfo: ts=ts.astimezone(timezone.utc).replace(tzinfo=None)
            timed.append((ts,i))
        except (ValueError,TypeError): pass
    timed.sort(key=lambda x:(x[0],_event_id(events[x[1]])))
    left=0
    for right,(ts,idx) in enumerate(timed):
        while left<right and (ts-timed[left][0]).total_seconds()>window_seconds: left+=1
        for k in range(left,right):
            other=timed[k][1]
            if events[idx].get("case_id")==events[other].get("case_id"):
                pairs.add((min(idx,other),max(idx,other)))
    result=[]
    for i,j in sorted(pairs,key=lambda ij:(_event_id(events[ij[0]]),_event_id(events[ij[1]]))):
        a,b=events[i],events[j]
        if a.get("case_id") != b.get("case_id"): continue
        if registry.for_pair(a.get("source"),b.get("source")):
            result.append((a,b))
    return result,{"candidate_pair_count":len(result),"bucket_count":len(buckets),"skipped_buckets":skipped,
                   "max_bucket_size":max_bucket_size,"time_window_seconds":window_seconds}
