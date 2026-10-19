"""Role 3: Reports router.

Endpoint:
- GET /cases/{id}/report?format=pdf: Download investigator-reviewed PDF report
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.db.models import Case
from app.db.session import get_db
from app.reports.export_pdf import generate_case_pdf_report

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
