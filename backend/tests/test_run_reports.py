"""Role 3: immutable run-based PDF reports.

Covers generation from a completed run, the 10 mandatory sections, persistence and hashes,
versioning, case/run isolation, invalidated and snapshot-less runs, write-once guards,
download-time SHA-256 verification, no correlation recomputation, and the legacy endpoint.
"""
from __future__ import annotations

import hashlib
import io
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pdfminer.high_level import extract_text
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.models import CaseReport, ImmutableRecordError
from app.db.runs import create_analysis_run
from app.reports.run_report import SECTION_TITLES, UNAVAILABLE_FIELDS

EVIDENCE_DIR = Path(__file__).resolve().parents[2] / "datasets" / "sample_case_001" / "evidence"
FILES = ("browser_history.csv", "system_log.csv", "chat_export.json")


def _case_with_run(client: TestClient, case_id: str, files: tuple[str, ...] = FILES) -> tuple[str, list[str]]:
    res = client.post("/cases", json={"name": f"Report test {case_id}", "case_id": case_id, "owner": "Test Investigator",
                                      "scope": "laptop-01, Jan 2026"})
    assert res.status_code == 201, res.text
    evidence_ids = []
    for name in files:
        up = client.post(f"/cases/{case_id}/evidence", files={"file": (name, (EVIDENCE_DIR / name).read_bytes())})
        assert up.status_code == 201, up.text
        evidence_ids.append(up.json()["evidence_id"])
    run = client.post(f"/cases/{case_id}/runs")
    assert run.status_code == 201, run.text
    return run.json()["run_id"], evidence_ids


def _pdf_text(data: bytes) -> str:
    return " ".join(extract_text(io.BytesIO(data)).split())


def test_generate_persists_report_with_hashes_and_all_sections(client: TestClient) -> None:
    run_id, _ = _case_with_run(client, "CASE-R1")

    res = client.post(f"/cases/CASE-R1/runs/{run_id}/reports", json={"generated_by": "Reviewer One"})
    assert res.status_code == 201, res.text
    meta = res.json()
    assert meta["report_id"].startswith("RPT-")
    assert (meta["case_id"], meta["run_id"], meta["report_version"]) == ("CASE-R1", run_id, 1)
    assert meta["storage_ref"] == f"db:case_report/{meta['report_id']}"
    assert meta["review_status"] == "PENDING_REVIEW"
    assert meta["generated_by"] == "Reviewer One"
    assert meta["generated_at"].endswith("+00:00")
    assert len(meta["sha256"]) == 64 and len(meta["content_hash"]) == 64
    assert "pdf_bytes" not in meta

    pdf = client.get(f"/cases/CASE-R1/reports/{meta['report_id']}/pdf")
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content.startswith(b"%PDF")
    assert hashlib.sha256(pdf.content).hexdigest() == meta["sha256"] == pdf.headers["x-report-sha256"]
    assert len(pdf.content) == meta["size_bytes"]

    body = _pdf_text(pdf.content)
    for title in SECTION_TITLES:
        assert title in body, f"missing section: {title}"
    assert "Pending review" in body
    assert run_id in body and meta["report_id"] in body
    assert meta["content_hash"] in body.replace(" ", "")
    # Teammate-owned fields are printed as unavailable, not invented.
    assert "Unavailable: the correlation parameter registry exists" in body
    assert "not recorded with this run (correlation engine, Shambhavi)" in body
    assert "registry is not implemented" not in body
    assert "Unavailable: source coverage is a stub table" in body


def test_second_report_of_same_run_is_a_new_version_with_same_content_hash(client: TestClient) -> None:
    run_id, _ = _case_with_run(client, "CASE-R2")
    first = client.post(f"/cases/CASE-R2/runs/{run_id}/reports").json()
    second = client.post(f"/cases/CASE-R2/runs/{run_id}/reports").json()
    assert second["report_version"] == 2
    assert second["report_id"] != first["report_id"]
    assert second["content_hash"] == first["content_hash"]

    listed = client.get("/cases/CASE-R2/reports").json()
    assert {r["report_id"] for r in listed} == {first["report_id"], second["report_id"]}
    assert all("pdf_bytes" not in r for r in listed)
    assert client.get(f"/cases/CASE-R2/reports/{first['report_id']}").json()["report_version"] == 1


def test_report_only_uses_manifest_evidence(client: TestClient) -> None:
    run_id, evidence_ids = _case_with_run(client, "CASE-R3", files=("browser_history.csv", "system_log.csv"))
    # Uploaded after the run: must not appear in that run's report.
    late = client.post("/cases/CASE-R3/evidence", files={"file": ("chat_export.json", (EVIDENCE_DIR / "chat_export.json").read_bytes())})
    assert late.status_code == 201
    late_id = late.json()["evidence_id"]

    meta = client.post(f"/cases/CASE-R3/runs/{run_id}/reports").json()
    body = _pdf_text(client.get(f"/cases/CASE-R3/reports/{meta['report_id']}/pdf").content)
    for ev_id in evidence_ids:
        assert ev_id in body
    assert late_id not in body


def test_case_and_run_isolation(client: TestClient) -> None:
    run_a, _ = _case_with_run(client, "CASE-IA")
    run_b, _ = _case_with_run(client, "CASE-IB", files=("system_log.csv",))
    report_a = client.post(f"/cases/CASE-IA/runs/{run_a}/reports").json()["report_id"]

    # Run of case A requested through case B, and vice versa.
    assert client.post(f"/cases/CASE-IB/runs/{run_a}/reports").status_code == 404
    assert client.post(f"/cases/CASE-IA/runs/{run_b}/reports").status_code == 404
    # Report of case A requested through case B.
    assert client.get(f"/cases/CASE-IB/reports/{report_a}").status_code == 404
    assert client.get(f"/cases/CASE-IB/reports/{report_a}/pdf").status_code == 404
    assert report_a not in {r["report_id"] for r in client.get("/cases/CASE-IB/reports").json()}
    # Unknown case / run / report.
    assert client.post(f"/cases/CASE-NOPE/runs/{run_a}/reports").status_code == 404
    assert client.post("/cases/CASE-IA/runs/RUN-NOPE/reports").status_code == 404
    assert client.get("/cases/CASE-IA/reports/RPT-NOPE/pdf").status_code == 404
    assert client.get("/cases/CASE-NOPE/reports").status_code == 404


def test_invalidated_run_is_rejected(client: TestClient) -> None:
    run_id, evidence_ids = _case_with_run(client, "CASE-INV")
    assert client.post(f"/evidence/{evidence_ids[0]}/remove", json={"reason": "test"}).status_code == 200

    res = client.post(f"/cases/CASE-INV/runs/{run_id}/reports")
    assert res.status_code == 409
    assert "invalidated" in res.json()["detail"]
    assert client.get("/cases/CASE-INV/reports").json() == []


def test_run_without_authoritative_snapshot_is_rejected(client: TestClient, db_session: Session) -> None:
    _case_with_run(client, "CASE-NOSNAP", files=("system_log.csv",))
    run = create_analysis_run(db_session, "CASE-NOSNAP", engine_version="test@1", assumptions={"case_timezone": "UTC"})
    db_session.commit()

    res = client.post(f"/cases/CASE-NOSNAP/runs/{run.run_id}/reports")
    assert res.status_code == 409
    assert "authoritative" in res.json()["detail"]


def test_reports_are_write_once(client: TestClient, db_session: Session) -> None:
    run_id, _ = _case_with_run(client, "CASE-WO", files=("system_log.csv",))
    report_id = client.post(f"/cases/CASE-WO/runs/{run_id}/reports").json()["report_id"]

    report = db_session.get(CaseReport, report_id)
    report.generated_by = "someone else"
    with pytest.raises(ImmutableRecordError):
        db_session.flush()
    db_session.rollback()

    report = db_session.get(CaseReport, report_id)
    db_session.delete(report)
    with pytest.raises(ImmutableRecordError):
        db_session.flush()
    db_session.rollback()

    # Database triggers block raw SQL as well.
    with pytest.raises(Exception, match="write-once"):
        db_session.execute(text("UPDATE case_report SET sha256 = 'x' WHERE report_id = :r"), {"r": report_id})
    db_session.rollback()
    with pytest.raises(Exception, match="write-once"):
        db_session.execute(text("DELETE FROM case_report WHERE report_id = :r"), {"r": report_id})
    db_session.rollback()


def test_database_rejects_report_for_run_of_another_case(client: TestClient, db_session: Session) -> None:
    run_a, _ = _case_with_run(client, "CASE-DA", files=("system_log.csv",))
    client.post("/cases", json={"name": "Other", "case_id": "CASE-DB"})
    with pytest.raises(Exception, match="same case"):
        db_session.execute(
            text(
                "INSERT INTO case_report (report_id, case_id, run_id, report_version, report_format, generator_version, "
                "generated_at, content_hash, sha256, size_bytes, storage_ref, pdf_bytes) VALUES "
                "('RPT-X', 'CASE-DB', :run, 1, 'pdf', 'x', '2026-11-24 00:00:00', 'h', 's', 1, 'db:x', x'00')"
            ),
            {"run": run_a},
        )
    db_session.rollback()


def test_download_fails_when_stored_bytes_do_not_match_sha256(client: TestClient, db_session: Session) -> None:
    run_id, _ = _case_with_run(client, "CASE-TAMPER", files=("system_log.csv",))
    report_id = client.post(f"/cases/CASE-TAMPER/runs/{run_id}/reports").json()["report_id"]

    # Simulate storage-level tampering: bypass the write-once trigger the way an attacker with DB access would.
    db_session.execute(text("DROP TRIGGER trg_case_report_no_update"))
    db_session.execute(text("UPDATE case_report SET pdf_bytes = :b WHERE report_id = :r"), {"b": b"%PDF-tampered", "r": report_id})
    db_session.commit()
    db_session.expire_all()

    res = client.get(f"/cases/CASE-TAMPER/reports/{report_id}/pdf")
    assert res.status_code == 500
    assert "integrity check" in res.json()["detail"]


def test_generation_does_not_recompute_correlations(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    run_id, _ = _case_with_run(client, "CASE-NORECOMP", files=("system_log.csv", "browser_history.csv"))

    def forbidden(*args, **kwargs):
        raise AssertionError("report generation must not recompute analysis")

    import sys

    import app.routers.claims as claims_router
    import app.services.runs as runs_service
    import intelligence

    # intelligence/__init__ re-exports a function named `correlate`, which shadows the submodule attribute.
    intel_correlate = sys.modules["intelligence.correlate"]
    intel_claims = sys.modules["intelligence.claims"]

    for target in (intel_correlate, intelligence, claims_router):
        monkeypatch.setattr(target, "correlate_events", forbidden)
    for target in (intel_claims, intelligence, claims_router, runs_service):
        if hasattr(target, "generate_claims"):
            monkeypatch.setattr(target, "generate_claims", forbidden)
    monkeypatch.setattr(runs_service, "evaluate_hypotheses", forbidden)

    assert client.post(f"/cases/CASE-NORECOMP/runs/{run_id}/reports").status_code == 201


def test_legacy_case_report_endpoint_still_works(client: TestClient) -> None:
    _case_with_run(client, "CASE-LEGACY", files=("system_log.csv",))
    res = client.get("/cases/CASE-LEGACY/report", params={"format": "pdf"})
    assert res.status_code == 200
    assert res.content.startswith(b"%PDF")


def test_unavailable_markers_cover_every_teammate_gap() -> None:
    # Each documented gap has explicit wording; none is an empty or placeholder value.
    for key in ("correlation_registry_version", "scoring_thresholds", "relationship_score", "relationship_type",
                "clock_uncertainty", "source_coverage", "inaccessible_sources", "reviewer_identity"):
        assert UNAVAILABLE_FIELDS[key].startswith("Unavailable: ")
    # Owners named in the gaps match code ownership; no stale role numbers.
    for key in ("correlation_registry_version", "scoring_thresholds", "relationship_score", "relationship_type"):
        assert UNAVAILABLE_FIELDS[key].endswith("(correlation engine, Shambhavi).")
    assert UNAVAILABLE_FIELDS["source_coverage"].endswith("(Niharika, T7/T8).")
    assert UNAVAILABLE_FIELDS["inaccessible_sources"].endswith("(evidence acquisition/provenance, Anupriya).")
    assert not any("(Role " in text for text in UNAVAILABLE_FIELDS.values())
