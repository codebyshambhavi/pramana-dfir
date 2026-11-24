"""Registry-driven feature, reliability and contradiction evaluation."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse

from ..correlate import _hub_factor
from ..timeline import SourceClock
from .fields import ResolvedField, resolve_field
from .registry import Parameter, Registry

@dataclass(frozen=True)
class Signal:
    parameter_id: str
    role: str
    status: str
    value: float | None
    raw_value: float | None = None
    reliability: float | None = None
    contribution: float | None = None
    details: Mapping[str, Any] | None = None

    def to_dict(self):
        return {"parameter_id":self.parameter_id,"role":self.role,"status":self.status,"value":self.value,
                "raw_value":self.raw_value,"reliability":self.reliability,"contribution":self.contribution,
                "details":dict(self.details or {})}


def _tokens(value: Any, strip_prefixes=()) -> set[str]:
    text=str(value or "").casefold().strip()
    for prefix in strip_prefixes:
        if text.startswith(prefix): text=text[len(prefix):].strip()
    return {t for t in re.findall(r"[a-z0-9]+",text) if t not in {"the","a","an","and","or","to","of","in","on","is","are","this","that","by","for","with","it","as","at","be","from"}}


def _as_set(v: Any) -> set[str]:
    if v is None: return set()
    if isinstance(v,(list,tuple,set)): return {str(x).casefold() for x in v if x is not None}
    return {str(v).casefold()}


def _parent_domain(x: str) -> str:
    host=urlparse(x if "://" in x else "//"+x).hostname or x
    labels=host.casefold().strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels)>=2 else host.casefold()


def _filename_stem(x: str) -> str:
    name=x.replace("\\","/").rsplit("/",1)[-1].casefold()
    name=re.sub(r"\.[^.]+$","",name)
    name=re.sub(r"(?:[_ -]v\d+|[_ -]final|\s*\(\d+\)|[_ -]copy)$","",name)
    return name.strip()


def _get_pair_fields(a,b,fields,clocks=None,evidence_context=None):
    return [(resolve_field(a,x,source_clock=(clocks or {}).get(a.get("source")),evidence_context=evidence_context),
             resolve_field(b,y,source_clock=(clocks or {}).get(b.get("source")),evidence_context=evidence_context)) for x,y in fields]


def _feature_value(p: Parameter,a: Mapping[str,Any],b: Mapping[str,Any], *, registry: Registry,
                   clocks=None,evidence_context=None,reference_data=None) -> tuple[float|None,str,dict[str,Any]]:
    em=p.extraction; method=em["method"]; details={}
    if method=="EXACT_MATCH":
        f=p.source_fields[0]; x=resolve_field(a,f,evidence_context=evidence_context).value; y=resolve_field(b,f,evidence_context=evidence_context).value
        if x is None or y is None:return None,"UNAVAILABLE",details
        return (1.0 if x==y else 0.0),"EVALUATED",{"field":f}
    if method=="SET_INTERSECTION":
        scores=[]; overlaps=[]
        for fa,fb in em.get("pairs",[]):
            x=resolve_field(a,fa,evidence_context=evidence_context).value; y=resolve_field(b,fb,evidence_context=evidence_context).value
            sx,sy=_as_set(x),_as_set(y)
            if not sx or not sy: continue
            tx,ty=sx,sy
            transform=em.get("transform")
            if transform=="parent_domain": tx={_parent_domain(z) for z in sx};ty={_parent_domain(z) for z in sy}
            elif transform=="filename_stem": tx={_filename_stem(z) for z in sx};ty={_filename_stem(z) for z in sy}
            overlap=tx&ty
            if em.get("exclude_exact_overlap") and sx&sy: continue
            if overlap:
                scores.append(1.0);overlaps.extend(sorted(overlap))
        if not scores:return (0.0,"EVALUATED",details) if all(resolve_field(a,f,evidence_context=evidence_context).value is not None or resolve_field(b,f,evidence_context=evidence_context).value is not None for f in p.source_fields) else (None,"UNAVAILABLE",details)
        return max(scores),"EVALUATED",{"overlap_count":len(set(overlaps)),"overlap_values_hashes":[__import__('hashlib').sha256(x.encode()).hexdigest()[:12] for x in sorted(set(overlaps))]}
    if method=="SET_CONTAINS":
        x=resolve_field(a,p.source_fields[0],evidence_context=evidence_context).value;y=resolve_field(b,p.source_fields[1],evidence_context=evidence_context).value
        if x is None or y is None:return None,"UNAVAILABLE",details
        return (1.0 if str(x).casefold() in _as_set(y) or str(y).casefold() in _as_set(x) else 0.0),"EVALUATED",details
    if method=="TOKEN_JACCARD":
        f=p.source_fields[0];x=resolve_field(a,f,evidence_context=evidence_context).value;y=resolve_field(b,f,evidence_context=evidence_context).value
        if not x or not y:return None,"UNAVAILABLE",details
        tx=_tokens(x,em.get("strip_prefixes",()));ty=_tokens(y,em.get("strip_prefixes",()))
        return (len(tx&ty)/len(tx|ty) if tx|ty else 0.0),"EVALUATED",{"token_intersection":len(tx&ty),"token_union":len(tx|ty)}
    if method in ("TIME_SEPARATION","INTERVAL_OVERLAP"):
        x=resolve_field(a,"time.interval",source_clock=(clocks or {}).get(a.get("source"))).value
        y=resolve_field(b,"time.interval",source_clock=(clocks or {}).get(b.get("source"))).value
        if x is None or y is None:return None,"UNAVAILABLE",details
        if method=="INTERVAL_OVERLAP":
            overlap=x.overlaps(y)
            point_a=x.lo==x.hi;point_b=y.lo==y.hi
            if em.get("require_point_difference") and point_a and point_b:return 0.0,"EVALUATED",{"overlap":overlap,"uncertainty_driven":False}
            return (1.0 if overlap else 0.0),"EVALUATED",{"overlap":overlap,"uncertainty_driven":overlap and not(point_a and point_b)}
        delta=0.0 if x.overlaps(y) else min(abs((x.hi-y.lo).total_seconds()),abs((y.hi-x.lo).total_seconds()))
        window=float(em.get("window_seconds",registry.candidate_generation.get("windows_seconds",{}).get("default",600)))
        return max(0.0,1.0-delta/window),"EVALUATED",{"separation_seconds":delta,"window_seconds":window}
    if method in ("ORDERED_ACTIONS","ORDERED_ACTIONS_VIOLATION"):
        aa=resolve_field(a,"event.action").value;bb=resolve_field(b,"event.action").value
        ta=resolve_field(a,"time.interval",source_clock=(clocks or {}).get(a.get("source"))).value
        tb=resolve_field(b,"time.interval",source_clock=(clocks or {}).get(b.get("source"))).value
        if not aa or not bb or ta is None or tb is None:return None,"UNAVAILABLE",details
        pairs={tuple(x) for x in registry.reference_data.get("ordered_action_pairs",[])}
        if (aa,bb) in pairs: earlier,later=ta,tb
        elif (bb,aa) in pairs: earlier,later=tb,ta
        else:return 0.0,"EVALUATED",{"ordered_pair":False}
        violation=earlier.lo>later.hi
        compatible=earlier.hi<=later.lo
        if method=="ORDERED_ACTIONS_VIOLATION":return (1.0 if violation else 0.0),"EVALUATED",{"definite_violation":violation}
        return (1.0 if compatible else 0.0),"EVALUATED",{"definitely_ordered":compatible,"ambiguous":not(compatible or violation)}
    if method=="ALIAS_MAPPED":
        vals=[]
        for f in p.source_fields:
            vals.extend([resolve_field(a,f).value,resolve_field(b,f).value])
        vals={str(v).casefold() for v in vals if v}
        groups=(reference_data or registry.reference_data).get("alias_groups",[])
        for group in groups:
            members={str(x).casefold() for x in group.get("members",[])}
            if len(vals&members)>=2:return 1.0,"EVALUATED",{"alias_group":group.get("group_id")}
        if groups and vals:return 0.0,"EVALUATED",{"reason":"No shared analyst-approved alias group."}
        return None,"UNAVAILABLE",{"reason":"No analyst-approved alias group is configured."}
    if method=="ENDPOINT_PAIR":
        sa=resolve_field(a,"net.src_ip").value;da=resolve_field(a,"net.dst_ip").value
        sb=resolve_field(b,"net.src_ip").value;db=resolve_field(b,"net.dst_ip").value
        if not all((sa,da,sb,db)):return None,"UNAVAILABLE",details
        pa=(sa,da);pb=(sb,db)
        return (1.0 if pa==pb or pa==(db,sb) else 0.0),"EVALUATED",{}
    if method=="CONFLICT_CHECK":
        triggered=[];available=False
        for check in em["checks"]:
            keys_a=[resolve_field(a,f).value for f in check["key_fields"]];keys_b=[resolve_field(b,f).value for f in check["key_fields"]]
            facts_a=[resolve_field(a,f).value for f in check["fact_fields"]];facts_b=[resolve_field(b,f).value for f in check["fact_fields"]]
            if any(v is None for v in keys_a+keys_b+facts_a+facts_b):continue
            available=True
            if keys_a==keys_b:
                mismatch=False
                for x,y in zip(facts_a,facts_b):
                    if isinstance(x,datetime) and isinstance(y,datetime):mismatch=abs((x-y).total_seconds())>float(check.get("tolerance_seconds",0))
                    else:mismatch=x!=y
                    if mismatch:break
                if mismatch:triggered.append(check["label"])
        if not available:return None,"UNAVAILABLE",details
        return (1.0 if triggered else 0.0),"EVALUATED",{"triggered_checks":triggered}
    if method=="IDENTITY_CONFLICT":
        found=False
        for f in p.source_fields:
            x=resolve_field(a,f).value;y=resolve_field(b,f).value
            if x is not None and y is not None:
                found=True
                if x!=y:return 1.0,"EVALUATED",{"conflicting_field":f}
        return (0.0,"EVALUATED",{}) if found else (None,"UNAVAILABLE",{})
    return None,"UNAVAILABLE",{"reason":f"Unsupported method {method}"}


def _factor_value(p: Parameter,event: Mapping[str,Any], *, registry: Registry, clocks=None,evidence_context=None) -> tuple[float|None,str,dict[str,Any]]:
    em=p.extraction;method=em["method"];field=p.source_fields[0]
    f=resolve_field(event,field,source_clock=(clocks or {}).get(event.get("source")),evidence_context=evidence_context);v=f.value
    if method=="FIELD_QUALITY_MAP":
        if v is None:return em.get("default"),"UNAVAILABLE",{"field":field}
        if str(v) in em.get("block_values",[]):return 0.0,"BLOCKED",{"field":field,"value":v}
        result=em.get("map",{}).get(str(v),em.get("default"))
        return (float(result),"EVALUATED",{"field":field}) if result is not None else (None,"UNAVAILABLE",{"field":field})
    if method=="FIELD_UNIT_VALUE":
        if v is None:return None,"UNAVAILABLE",{"field":field}
        return float(v),"EVALUATED",{"field":field}
    if method=="FIELD_COMPLETENESS":
        present=sum(resolve_field(event,x,evidence_context=evidence_context).present for x in p.source_fields)
        completeness=present/len(p.source_fields)
        penalty_factor=float(em.get("missing_penalty_factor",1.0))
        adjusted=1.0-(1.0-completeness)*penalty_factor
        return adjusted,"EVALUATED",{"present":present,"total":len(p.source_fields),"raw_completeness":completeness,"missing_penalty_factor":penalty_factor}
    if method=="CLOCK_UNCERTAINTY":
        sec=float(v or 0);window=float(em["window_seconds"])
        return max(0.0,1.0-sec/window),"EVALUATED",{"uncertainty_seconds":sec,"window_seconds":window}
    return None,"UNAVAILABLE",{}


def evaluate_reliability(p: Parameter,a: Mapping[str,Any],b: Mapping[str,Any], *, registry: Registry,clocks=None,evidence_context=None) -> Signal:
    vals=[]; unavailable=[]; blocked=[]; details={}
    for ev in (a,b):
        v,status,d=_factor_value(p,ev,registry=registry,clocks=clocks,evidence_context=evidence_context)
        if status=="BLOCKED":blocked.append(d)
        elif v is None:
            policy=p.missing_policy["policy"]
            if policy=="ZERO_CONTRIBUTION":v=1.0
            elif policy=="EXPLICIT_PENALTY":v=1.0-float(p.missing_policy["penalty"])
            else:unavailable.append(d)
        if v is not None:vals.append(float(v))
    if blocked:return Signal(p.parameter_id,p.role,"BLOCKED",0.0,details={"blocked":blocked})
    if unavailable:return Signal(p.parameter_id,p.role,"UNAVAILABLE",None,details={"unavailable":unavailable})
    if not vals:return Signal(p.parameter_id,p.role,"UNAVAILABLE",None)
    combine=p.spec.get("combine") or "MIN"
    value=(vals[0]*vals[1] if combine=="PRODUCT" and len(vals)==2 else min(vals))
    return Signal(p.parameter_id,p.role,"EVALUATED",max(0,min(1,value)),details={"event_factors":vals})


def evaluate_parameter(p: Parameter,a: Mapping[str,Any],b: Mapping[str,Any], *, registry: Registry,clocks=None,evidence_context=None,reference_data=None) -> Signal:
    if p.role=="RELIABILITY_FACTOR":return evaluate_reliability(p,a,b,registry=registry,clocks=clocks,evidence_context=evidence_context)
    value,status,details=_feature_value(p,a,b,registry=registry,clocks=clocks,evidence_context=evidence_context,reference_data=reference_data)
    raw_value=value
    if value is not None:
        rule=p.normalisation; kind=rule.get("kind")
        if kind=="UNIT_FLOOR":
            floor=float(rule["floor"]); value=0.0 if value<floor else (value-floor)/(1.0-floor)
        elif kind=="UNIT_RESCALE":
            value=float(rule["min_factor"])+(1.0-float(rule["min_factor"]))*value
        value=max(0.0,min(1.0,float(value)))
    return Signal(p.parameter_id,p.role,status,value,raw_value=raw_value,details=details)


def evaluate_features(a: Mapping[str,Any],b: Mapping[str,Any],registry: Registry, *, clocks=None,evidence_context=None,reference_data=None) -> list[Signal]:
    return [evaluate_parameter(p,a,b,registry=registry,clocks=clocks,evidence_context=evidence_context,reference_data=reference_data)
            for p in registry.for_pair(a.get("source"),b.get("source"),relationship_class="SECONDARY")]
