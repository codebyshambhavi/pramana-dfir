"""Tests for defensible source coverage semantics in T7 Hypothesis Engine.

Verifies:
1. Source events before and after the expected interval -> demonstrably covered.
2. Source events only before the interval -> UNOBSERVABLE (0 penalty).
3. Source events only after the interval -> UNOBSERVABLE (0 penalty).
4. Explicit case-level source coverage declaration -> demonstrably covered.
5. Coverage gaps exceeding allowed bound (>2 hours) -> UNOBSERVABLE (0 penalty).
6. Different source kinds (audit, scheduler, system_log, auth, network).
7. Missing source entirely -> UNOBSERVABLE (0 penalty).
"""

from datetime import datetime, timedelta, timezone
import pytest

from intelligence.hyp.engine import (
    STATE_MISSING,
    STATE_UNOBSERVABLE,
    _source_demonstrably_covered,
    compute_source_coverage,
    evaluate_hypotheses,
    HypothesisTemplate,
    TemplateItem,
    TemplateConstraint,
)


def _ev(event_id: str, source: str, timestamp_str: str, action: str = "read") -> dict:
    return {
        "event_id": event_id,
        "source": source,
        "action": action,
        "timestamp": timestamp_str,
        "actor": "alice",
        "device": "srv-01",
    }


def _make_test_template(req_source_kind: str) -> HypothesisTemplate:
    return HypothesisTemplate(
        id="H99",
        kind="test_hyp",
        name="Test Hypothesis",
        description="Testing source coverage",
        stages=["stage1"],
        requires=[
            TemplateItem(
                id="H99-REQ-1",
                stage="stage1",
                description="Required test evidence",
                claim_type="ACTOR_DEVICE_CONSISTENT",
                source_kind=req_source_kind,
                weight=1.0,
                critical=True,
            )
        ],
        expects=[
            TemplateItem(
                id="H99-EXP-1",
                stage="stage1",
                description="Expected test evidence",
                claim_type="SAME_OBJECT_FLOW",
                source_kind=req_source_kind,
                weight=1.0,
            )
        ],
        forbids=[],
        constraints=[],
    )


# --- 1. Source events before and after expected interval ---

def test_coverage_events_before_and_after_interval():
    """Events span the entire target window within gap bound -> covered."""
    # Target interval: 10:00 to 12:00
    target_window = (
        datetime(2026, 10, 18, 10, 0, 0),
        datetime(2026, 10, 18, 12, 0, 0),
    )
    # Events at 09:50 (before start within 30m bound), 11:00 (middle), and 12:10 (after end within 30m bound)
    events = [
        _ev("E1", "system_log", "2026-10-18T09:50:00Z"),
        _ev("E2", "system_log", "2026-10-18T11:00:00Z"),
        _ev("E3", "system_log", "2026-10-18T12:10:00Z"),
    ]
    cov = compute_source_coverage(events)
    assert _source_demonstrably_covered("system_log", cov, target_window=target_window) is True

    # Evaluated hypothesis should produce MISSING (with penalty) when expected evidence is absent
    tmpl = _make_test_template("system_log")
    res = evaluate_hypotheses(
        claims=[],
        events=events,
        assumptions={"target_window": target_window},
        templates=[tmpl],
    )
    h = res.ranked_hypotheses[0]
    exp_eval = next(e for e in h.evaluations if e.category == "expects")
    assert exp_eval.state == STATE_MISSING
    assert exp_eval.disconfirmation_penalty > 0.0


# --- 2. Source events only before the interval ---

def test_coverage_events_only_before_interval():
    """Events end well before target interval -> UNOBSERVABLE, penalty 0.0."""
    target_window = (
        datetime(2026, 10, 18, 10, 0, 0),
        datetime(2026, 10, 18, 12, 0, 0),
    )
    # Events stop at 08:30 (more than 30m before 10:00)
    events = [
        _ev("E1", "system_log", "2026-10-18T08:00:00Z"),
        _ev("E2", "system_log", "2026-10-18T08:30:00Z"),
    ]
    cov = compute_source_coverage(events)
    assert _source_demonstrably_covered("system_log", cov, target_window=target_window) is False

    tmpl = _make_test_template("system_log")
    res = evaluate_hypotheses(
        claims=[],
        events=events,
        assumptions={"target_window": target_window},
        templates=[tmpl],
    )
    h = res.ranked_hypotheses[0]
    exp_eval = next(e for e in h.evaluations if e.category == "expects")
    assert exp_eval.state == STATE_UNOBSERVABLE
    assert exp_eval.disconfirmation_penalty == 0.0


# --- 3. Source events only after the interval ---

def test_coverage_events_only_after_interval():
    """Events begin well after target interval -> UNOBSERVABLE, penalty 0.0."""
    target_window = (
        datetime(2026, 10, 18, 10, 0, 0),
        datetime(2026, 10, 18, 12, 0, 0),
    )
    # Events start at 13:30 (more than 30m after 12:00)
    events = [
        _ev("E1", "system_log", "2026-10-18T13:30:00Z"),
        _ev("E2", "system_log", "2026-10-18T14:00:00Z"),
    ]
    cov = compute_source_coverage(events)
    assert _source_demonstrably_covered("system_log", cov, target_window=target_window) is False

    tmpl = _make_test_template("system_log")
    res = evaluate_hypotheses(
        claims=[],
        events=events,
        assumptions={"target_window": target_window},
        templates=[tmpl],
    )
    h = res.ranked_hypotheses[0]
    exp_eval = next(e for e in h.evaluations if e.category == "expects")
    assert exp_eval.state == STATE_UNOBSERVABLE
    assert exp_eval.disconfirmation_penalty == 0.0


# --- 4. Explicit coverage declaration ---

def test_coverage_explicit_declaration():
    """Explicit declaration marks interval covered even if event log is sparse or missing."""
    target_window = (
        datetime(2026, 10, 18, 10, 0, 0),
        datetime(2026, 10, 18, 12, 0, 0),
    )
    # No events from scheduler at all
    events = [
        _ev("E1", "system_log", "2026-10-18T10:00:00Z"),
    ]
    cov = compute_source_coverage(events)
    # Without declaration, scheduler is not covered
    assert _source_demonstrably_covered("scheduler", cov, target_window=target_window) is False

    # With explicit declaration spanning window
    decls = [
        {
            "source_kind": "scheduler",
            "window_start": "2026-10-18T09:00:00Z",
            "window_end": "2026-10-18T13:00:00Z",
        }
    ]
    assert _source_demonstrably_covered(
        "scheduler",
        cov,
        target_window=target_window,
        explicit_declarations=decls,
    ) is True

    tmpl = _make_test_template("scheduler")
    res = evaluate_hypotheses(
        claims=[],
        events=events,
        assumptions={
            "target_window": target_window,
            "source_coverage": decls,
        },
        templates=[tmpl],
    )
    h = res.ranked_hypotheses[0]
    exp_eval = next(e for e in h.evaluations if e.category == "expects")
    assert exp_eval.state == STATE_MISSING
    assert exp_eval.disconfirmation_penalty > 0.0


# --- 5. Coverage gaps exceeding allowed bound (> 2 hours) ---

def test_coverage_gap_exceeding_bound():
    """Events exist before and after, but with a 4-hour gap between them -> UNOBSERVABLE."""
    target_window = (
        datetime(2026, 10, 18, 8, 0, 0),
        datetime(2026, 10, 18, 14, 0, 0),
    )
    # E1 at 08:00, E2 at 13:00 (5 hour internal gap > max allowed 2 hours)
    events = [
        _ev("E1", "system_log", "2026-10-18T08:00:00Z"),
        _ev("E2", "system_log", "2026-10-18T13:30:00Z"),
    ]
    cov = compute_source_coverage(events)
    assert _source_demonstrably_covered("system_log", cov, target_window=target_window) is False

    tmpl = _make_test_template("system_log")
    res = evaluate_hypotheses(
        claims=[],
        events=events,
        assumptions={"target_window": target_window},
        templates=[tmpl],
    )
    h = res.ranked_hypotheses[0]
    exp_eval = next(e for e in h.evaluations if e.category == "expects")
    assert exp_eval.state == STATE_UNOBSERVABLE
    assert exp_eval.disconfirmation_penalty == 0.0


# --- 6. Different source kinds ---

@pytest.mark.parametrize("kind", ["audit", "scheduler", "system_log", "auth", "network"])
def test_coverage_different_source_kinds(kind: str):
    """Normalized source kinds correctly recognized across varying raw inputs."""
    target_window = (
        datetime(2026, 10, 18, 10, 0, 0),
        datetime(2026, 10, 18, 11, 0, 0),
    )
    raw_source_map = {
        "audit": "audit_log.csv",
        "scheduler": "cron_tasks.log",
        "system_log": "syslog_var.log",
        "auth": "auth_events.json",
        "network": "pcap_trace.pcap",
    }
    events = [
        _ev("E1", raw_source_map[kind], "2026-10-18T10:00:00Z"),
        _ev("E2", raw_source_map[kind], "2026-10-18T10:30:00Z"),
        _ev("E3", raw_source_map[kind], "2026-10-18T11:00:00Z"),
    ]
    cov = compute_source_coverage(events)
    assert _source_demonstrably_covered(kind, cov, target_window=target_window) is True


# --- 7. Missing source entirely ---

def test_coverage_missing_source_entirely():
    """Source completely unrepresented in ingested evidence is strictly UNOBSERVABLE (0 penalty)."""
    events = [
        _ev("E1", "browser.csv", "2026-10-18T10:00:00Z"),
    ]
    cov = compute_source_coverage(events)
    assert _source_demonstrably_covered("scheduler", cov) is False
    assert _source_demonstrably_covered("audit", cov) is False

    tmpl = _make_test_template("scheduler")
    res = evaluate_hypotheses(
        claims=[],
        events=events,
        templates=[tmpl],
    )
    h = res.ranked_hypotheses[0]
    exp_eval = next(e for e in h.evaluations if e.category == "expects")
    assert exp_eval.state == STATE_UNOBSERVABLE
    assert exp_eval.disconfirmation_penalty == 0.0
    req_eval = next(e for e in h.evaluations if e.category == "requires")
    assert req_eval.state == STATE_UNOBSERVABLE
    assert req_eval.disconfirmation_penalty == 0.0
