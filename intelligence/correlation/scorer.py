"""Deterministic registry-driven secondary scoring and contribution accounting."""
from __future__ import annotations

import hashlib
from collections import Counter
from typing import Any, Mapping, Sequence

from ..correlate import _hub_factor
from .features import Signal, evaluate_parameter, evaluate_reliability
from .fields import resolve_field
from .registry import Parameter, Registry


def _event_counter_value(event: Mapping[str,Any], counter: str):
    field={"ip":"net.ip","device":"device.id","domain":"net.domain","account":"account.id",
           "filename":"file.name","port":"net.dst_port","user_agent":"net.user_agent"}.get(counter)
    if not field:return None
    v=resolve_field(event,field).value
    if isinstance(v,(list,tuple,set)):return tuple(str(x) for x in v)
    return (str(v),) if v is not None else None


def _collision_penalty(p: Parameter,a: Mapping[str,Any],b: Mapping[str,Any],raw: float,reliability: float,
                       registry: Registry,events: Sequence[Mapping[str,Any]]|None) -> tuple[float,dict[str,Any]]:
    rule=p.collision_rule
    if not rule or raw<=0:return 0.0,{}
    if rule["kind"]=="COMMON_VALUE":
        common={str(x).casefold() for x in registry.reference_data.get("common_values",{}).get(rule["list"],[])}
        values=set()
        for field in p.source_fields:
            va=resolve_field(a,field).value;vb=resolve_field(b,field).value
            values.update(str(x).casefold() for v in (va,vb) for x in (v if isinstance(v,(list,tuple,set)) else [v]) if x is not None)
        hits=sorted(values&common)
        if not hits:return 0.0,{}
        # Compute the clean signal with common values removed, rather than
        # treating an overlap containing one common value as wholly generic.
        method=p.extraction["method"]
        clean=0.0
        if method=="SET_INTERSECTION":
            for fa,fb in p.extraction.get("pairs",[]):
                xa=resolve_field(a,fa).value; xb=resolve_field(b,fb).value
                sa={str(x).casefold() for x in (xa if isinstance(xa,(list,tuple,set)) else [xa]) if x is not None}
                sb={str(x).casefold() for x in (xb if isinstance(xb,(list,tuple,set)) else [xb]) if x is not None}
                if p.extraction.get("transform")=="parent_domain":
                    from .features import _parent_domain
                    sa={_parent_domain(x) for x in sa}; sb={_parent_domain(x) for x in sb}
                elif p.extraction.get("transform")=="filename_stem":
                    from .features import _filename_stem
                    sa={_filename_stem(x) for x in sa}; sb={_filename_stem(x) for x in sb}
                if p.extraction.get("exclude_exact_overlap") and sa & sb: continue
                overlap=(sa & sb)-common
                if overlap: clean=1.0; break
        elif method=="TOKEN_JACCARD":
            from .features import _tokens
            va=resolve_field(a,field).value; vb=resolve_field(b,field).value
            ta=_tokens(va,p.extraction.get("strip_prefixes",()))-common
            tb=_tokens(vb,p.extraction.get("strip_prefixes",()))-common
            clean=len(ta&tb)/len(ta|tb) if ta|tb else 0.0
            nr=p.normalisation
            if nr.get("kind")=="UNIT_FLOOR":
                floor=float(nr["floor"]); clean=0.0 if clean<floor else (clean-floor)/(1-floor)
        penalty_factor=float(rule["penalty_factor"])
        applied=clean+penalty_factor*(raw-clean)
        amount=max(0.0,(raw-applied)*float(p.weight or 0)*reliability)
        return amount,{"kind":"COMMON_VALUE","matched_count":len(hits),"matched_value_hashes":[hashlib.sha256(x.encode()).hexdigest()[:12] for x in hits],"value_raw":raw,"value_clean":clean,"value_applied":applied,"penalty_factor":penalty_factor}
    if rule["kind"]=="HUB_COUNT":
        if not events:return 0.0,{"kind":"HUB_COUNT","unavailable":True}
        counter=rule["counter"];vals_a=_event_counter_value(a,counter);vals_b=_event_counter_value(b,counter)
        common_values=set(vals_a or ())&set(vals_b or ())
        if not common_values:return 0.0,{}
        threshold=int(registry.candidate_generation.get("hub_thresholds",{}).get(counter,3))
        max_count=max(sum(v in (_event_counter_value(e,counter) or ()) for e in events) for v in common_values)
        factor=_hub_factor(max_count,threshold)
        amount=float(p.weight or 0)*reliability*raw*(1.0-factor)
        return amount,{"kind":"HUB_COUNT","count":max_count,"threshold":threshold,"hub_factor":factor}
    return 0.0,{}


def score_pair(a: Mapping[str,Any],b: Mapping[str,Any],registry: Registry, *, events: Sequence[Mapping[str,Any]]|None=None,
               clocks=None,evidence_context=None) -> dict[str,Any]:
    """Score a pair; result contains full signal-level accounting and review classification."""
    params=registry.for_pair(a.get("source"),b.get("source"),relationship_class="SECONDARY")
    factor_params={p.parameter_id:p for p in params if p.role=="RELIABILITY_FACTOR"}
    factor_signals={pid:evaluate_reliability(p,a,b,registry=registry,clocks=clocks,evidence_context=evidence_context)
                    for pid,p in factor_params.items()}
    contributions=[];counter_signals=[];unavailable=[];blocked=[];positive_total=0.0;negative_total=0.0
    for p in params:
        if p.role=="RELIABILITY_FACTOR":continue
        sig=evaluate_parameter(p,a,b,registry=registry,clocks=clocks,evidence_context=evidence_context)
        if sig.status=="BLOCKED":blocked.append(sig.to_dict());continue
        if sig.status=="UNAVAILABLE" or sig.value is None:
            unavailable.append(p.parameter_id)
            if p.missing_policy["policy"]=="EXPLICIT_PENALTY":
                penalty=float(p.missing_policy["penalty"])*float(p.weight or 0)
                negative_total+=penalty
                contributions.append({"parameter_id":p.parameter_id,"kind":"missing_value_penalty","amount":-penalty,"status":"UNAVAILABLE"})
            continue
        if p.role=="CONTRADICTION":
            amount=float(p.weight or 0)*float(sig.value)
            if amount:
                negative_total+=amount
                counter_signals.append({"parameter_id":p.parameter_id,"value":sig.value,"details":dict(sig.details or {})})
                contributions.append({"parameter_id":p.parameter_id,"kind":"contradiction","value":sig.value,"weight":p.weight,"amount":-amount,"details":dict(sig.details or {})})
            continue
        rr=p.reliability_rule or {}; factors=[]; factor_missing=[]
        for pid in rr.get("factors",[]):
            fs=factor_signals.get(pid)
            if fs is None or fs.value is None:
                factor_missing.append(pid)
            else:factors.append(float(fs.value))
        if factor_missing:
            # Factor policies are handled in evaluate_reliability; UNAVAILABLE factors
            # are excluded rather than silently converted into a mismatch.
            unavailable.extend(factor_missing)
        reliability=(__import__('math').prod(factors) if rr.get("combine")=="PRODUCT" else (min(factors) if factors else 1.0))
        reliability=max(float(rr.get("floor",0.0)),min(1.0,reliability))
        raw=float(sig.value); weight=float(p.weight or 0.0)
        amount=weight*raw*reliability
        collision,collision_details=_collision_penalty(p,a,b,raw,reliability,registry,events)
        applied=max(0.0,amount-collision)
        positive_total+=applied
        contributions.append({"parameter_id":p.parameter_id,"kind":"feature","value":raw,"weight":weight,
                              "reliability":reliability,"raw_contribution":amount,"collision_penalty":collision,
                              "contribution":applied,"details":dict(sig.details or {}),"collision":collision_details})
        if collision:
            negative_total+=collision
            contributions.append({"parameter_id":p.parameter_id,"kind":"collision_penalty","amount":-collision,"details":collision_details})
    raw_score=positive_total-negative_total
    score=max(float(registry.score_model.get("clamp_min",0)),min(float(registry.score_model.get("clamp_max",1)),raw_score))
    status="HIGH_CONFIDENCE" if score>=registry.t_high else ("ANALYST_REVIEW" if score>=registry.t_review else "BELOW_THRESHOLD")
    return {"score":round(score,12),"raw_score":round(raw_score,12),"status":status,
            "thresholds":{"T_HIGH":registry.t_high,"T_REVIEW":registry.t_review,"status":"PROVISIONAL" if registry.is_provisional else "CALIBRATED"},
            "positive_contribution":round(positive_total,12),"negative_contribution":round(negative_total,12),
            "feature_contributions":contributions,"counter_signals":counter_signals,
            "unavailable_parameters":sorted(set(unavailable)),"blocked_parameters":blocked,
            "reliability_factors":{k:v.to_dict() for k,v in factor_signals.items()},
            "registry_version":registry.registry_version,"registry_hash":registry.registry_hash,
            "config_version":registry.config_version,"calibration_status":registry.calibration_status}
