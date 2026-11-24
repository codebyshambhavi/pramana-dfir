"""Role 3: Reports router.

Endpoints:
- GET /cases/{id}/report?format=pdf: Download investigator-reviewed PDF report (legacy, built live)
- POST /cases/{case_id}/runs/{run_id}/reports: Generate an immutable report from a completed run
- GET /cases/{case_id}/reports: List immutable reports of a case
- GET /cases/{case_id}/reports/{report_id}: Report metadata
- GET /cases/{case_id}/reports/{report_id}/pdf: Download after SHA-256 verification
"""
from __future__ import annotations

import uuid
from datetime import timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models import Case, CaseReport, utc_now
from app.db.session import get_db
from app.reports.export_pdf import generate_case_pdf_report
from app.reports.run_report import (
    REPORT_GENERATOR_VERSION,
    ReportInputError,
    build_report_content,
    content_hash,
    load_report_inputs,
    render_report_pdf,
    sha256_hex,
)

router = APIRouter(tags=["reports"])


@router.get(
    "/cases/{id}/report",
    summary="Download the investigator-reviewed report",
    responses={
        200: {
            "content": {"application/pdf": {}},
            "description": "Downloadable PDF forensic report",
        }
    },
)
def get_case_report(
    id: str,
    format: str = Query("pdf", description="Report format, currently only 'pdf' is supported"),
    db: Session = Depends(get_db),
) -> Response:
    """Generate and return forensic case report PDF aligned with BSA Section 63."""
    if format.lower() != "pdf":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported format '{format}'. Only 'pdf' is supported.",
        )

    case = db.query(Case).filter(Case.case_id == id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{id}' not found",
        )

    pdf_bytes = generate_case_pdf_report(case, db)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="pramana_case_{id}_report.pdf"',
            "Content-Type": "application/pdf",
        },
    )


# ---------------------------------------------------------------------------------------------------
# Role 3: immutable reports generated from one completed analysis run.
#
#   POST /cases/{case_id}/runs/{run_id}/reports        generate and persist a report (201)
#   GET  /cases/{case_id}/reports                      list report metadata for the case
#   GET  /cases/{case_id}/reports/{report_id}          one report's metadata
#   GET  /cases/{case_id}/reports/{report_id}/pdf      download; SHA-256 is re-verified first
#
# Every lookup is scoped by case_id on the server: a run or report of another case is answered with
# 404, exactly like a missing one. The legacy GET /cases/{id}/report above is unchanged.
# ---------------------------------------------------------------------------------------------------


class ReportCreateRequest(BaseModel):
    generated_by: str | None = Field(
        None, max_length=255, description="Self-declared name of the person generating the report (no authentication yet)"
    )


def _case_or_404(db: Session, case_id: str) -> Case:
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_id}' not found")
    return case


def _report_or_404(db: Session, case_id: str, report_id: str) -> CaseReport:
    _case_or_404(db, case_id)
    report = db.get(CaseReport, report_id)
    if report is None or report.case_id != case_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Report '{report_id}' not found in case '{case_id}'")
    return report


@router.post(
    "/cases/{case_id}/runs/{run_id}/reports",
    status_code=status.HTTP_201_CREATED,
    summary="Generate an immutable PDF report from a completed analysis run",
)
def create_run_report(
    case_id: str,
    run_id: str,
    payload: ReportCreateRequest | None = None,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Build the PDF from the run, its authoritative snapshot, stored claims/edges and manifest evidence.

    409 when the run is invalidated (manifest evidence removed, quarantined or changed) or has no
    authoritative database snapshot. Nothing is recomputed.
    """
    try:
        inputs = load_report_inputs(db, case_id, run_id)
    except ReportInputError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    content = build_report_content(inputs)
    c_hash = content_hash(content)
    report_id = f"RPT-{uuid.uuid4().hex[:12].upper()}"
    version = db.query(CaseReport).filter(CaseReport.run_id == run_id).count() + 1
    generated_at = utc_now()
    generated_by = (payload.generated_by.strip() or None) if payload and payload.generated_by else None

    meta = {
        "report_id": report_id,
        "report_version": version,
        "generated_at": generated_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generated_by": generated_by,
        "content_hash": c_hash,
    }
    pdf = render_report_pdf(content, meta)

    report = CaseReport(
        report_id=report_id,
        case_id=case_id,
        run_id=run_id,
        report_version=version,
        report_format="pdf",
        generator_version=REPORT_GENERATOR_VERSION,
        generated_at=generated_at,
        generated_by=generated_by,
        content_hash=c_hash,
        sha256=sha256_hex(pdf),
        size_bytes=len(pdf),
        storage_ref=f"db:case_report/{report_id}",
        pdf_bytes=pdf,
    )
    db.add(report)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Another report for this run was generated at the same time; retry to get the next version",
        ) from exc
    db.refresh(report)
    return report.to_dict()


@router.get("/cases/{case_id}/reports", summary="List immutable reports of a case (metadata only)")
def list_case_reports(case_id: str, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    _case_or_404(db, case_id)
    reports = (
        db.query(CaseReport)
        .filter(CaseReport.case_id == case_id)
        .order_by(CaseReport.generated_at.desc(), CaseReport.report_version.desc())
        .all()
    )
    return [r.to_dict() for r in reports]


@router.get("/cases/{case_id}/reports/{report_id}", summary="Metadata of one immutable report")
def get_case_report_metadata(case_id: str, report_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    return _report_or_404(db, case_id, report_id).to_dict()


@router.get(
    "/cases/{case_id}/reports/{report_id}/pdf",
    summary="Download an immutable report after re-verifying its SHA-256",
    responses={200: {"content": {"application/pdf": {}}, "description": "The stored PDF"}},
)
def download_case_report(case_id: str, report_id: str, db: Session = Depends(get_db)) -> Response:
    report = _report_or_404(db, case_id, report_id)
    data = bytes(report.pdf_bytes or b"")
    actual = sha256_hex(data)
    if actual != report.sha256 or len(data) != report.size_bytes:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report '{report_id}' failed its integrity check: stored PDF bytes do not match the recorded SHA-256",
        )
    return Response(
        content=data,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="pramana_{case_id}_{report_id}_v{report.report_version}.pdf"',
            "X-Report-Id": report.report_id,
            "X-Report-SHA256": report.sha256,
            "X-Report-Content-Hash": report.content_hash,
            "Cache-Control": "no-store",
        },
    )
