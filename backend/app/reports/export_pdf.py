"""Role 3: PDF Forensic Report Generator aligned with BSA Section 63.

Contents:
- Case summary & metadata
- BSA Section 63 certificate alignment statement & non-legal certificate disclaimer
- Evidence acquisition table with SHA-256 hashes and intake timestamps
- Cryptographic chain-of-custody log and verification status
- Investigator-approved findings with evidence linkage and confidence
- Lead investigator sign-off and approval section
"""
from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.db.models import Case, CustodyEntry, Evidence, FindingModel
from app.db.session import verify_custody_log


def generate_case_pdf_report(case: Case, db: Any) -> bytes:
    """Generate professional forensic PDF report for a case."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#1A202C"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#4A5568"),
        spaceAfter=12,
    )
    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#2B6CB0"),
        spaceBefore=14,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#2D3748"),
    )
    code_style = ParagraphStyle(
        "CodeText",
        parent=styles["Normal"],
        fontSize=7,
        leading=9,
        fontName="Courier",
        textColor=colors.HexColor("#2D3748"),
    )
    disclaimer_style = ParagraphStyle(
        "Disclaimer",
        parent=styles["Italic"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#744210"),
    )

    story: list[Any] = []

    # Title & Subtitle
    story.append(Paragraph("PRAMANA DIGITAL FORENSIC INVESTIGATION REPORT", title_style))
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(
        Paragraph(
            f"Case ID: <b>{case.case_id}</b> &nbsp;|&nbsp; Case Name: <b>{case.name}</b> &nbsp;|&nbsp; Generated: {now_str}",
            subtitle_style,
        )
    )
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2B6CB0"), spaceAfter=10))

    # Legal Disclaimer / BSA Section 63 Alignment Notice
    disclaimer_html = (
        "<b>LEGAL & COMPLIANCE NOTICE:</b> The digital artifact fields in this report "
        "are structured and aligned with electronic evidence admissibility requirements under "
        "<b>Section 63 of the Bharatiya Sakshya Adhiniyam (BSA), 2023</b> "
        "(identifying source device, intake timing, cryptographic SHA-256 verification, and continuous chain of custody). "
        "<br/><i>IMPORTANT DISCLAIMER: This automated report is an investigative forensic summary produced by Pramana. "
        "The report itself does not constitute a certified legal certificate under Section 63 of BSA 2023 and must be signed "
        "and certified by the competent forensic examiner or authorized officer.</i>"
    )
    disclaimer_table = Table(
        [[Paragraph(disclaimer_html, disclaimer_style)]],
        colWidths=[530],
    )
    disclaimer_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEFCBF")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#D69E2E")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ])
    )
    story.append(disclaimer_table)
    story.append(Spacer(1, 10))

    # Section 1: Evidence Acquisition & Cryptographic Hash
    story.append(Paragraph("1. Digital Evidence Identification & Acquisition Table", section_heading))
    story.append(
        Paragraph(
            "Aligned with BSA Section 63 certificate fields (device artifact identification, SHA-256 digest, and timestamp):",
            body_style,
        )
    )
    story.append(Spacer(1, 4))

    evidence_items = case.evidence_items or []
    if evidence_items:
        evidence_data: list[list[Any]] = [
            [
                Paragraph("<b>Evidence ID</b>", body_style),
                Paragraph("<b>Filename</b>", body_style),
                Paragraph("<b>SHA-256 Hash</b>", body_style),
                Paragraph("<b>Intake Time (UTC)</b>", body_style),
                Paragraph("<b>Size</b>", body_style),
            ]
        ]
        for ev in evidence_items:
            intake_str = ev.intake_time.strftime("%Y-%m-%d %H:%M:%S") if ev.intake_time else "N/A"
            evidence_data.append([
                Paragraph(ev.evidence_id, body_style),
                Paragraph(ev.filename, body_style),
                Paragraph(ev.sha256, code_style),
                Paragraph(intake_str, body_style),
                Paragraph(f"{ev.size_bytes} B", body_style),
            ])

        ev_table = Table(evidence_data, colWidths=[65, 110, 205, 100, 50])
        ev_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EDF2F7")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(ev_table)
    else:
        story.append(Paragraph("<i>No evidence items registered for this case.</i>", body_style))

    story.append(Spacer(1, 10))

    # Section 2: Chain of Custody & Cryptographic Verification
    story.append(Paragraph("2. Cryptographic Chain-of-Custody Log", section_heading))
    story.append(
        Paragraph(
            "Every custody event is append-only and cryptographically hash-chained to detect tampering:",
            body_style,
        )
    )
    story.append(Spacer(1, 4))

    custody_entries: list[CustodyEntry] = []
    for ev in evidence_items:
        custody_entries.extend(ev.custody_entries or [])

    if custody_entries:
        custody_data: list[list[Any]] = [
            [
                Paragraph("<b>Evidence ID</b>", body_style),
                Paragraph("<b>Actor</b>", body_style),
                Paragraph("<b>Action</b>", body_style),
                Paragraph("<b>Timestamp (UTC)</b>", body_style),
                Paragraph("<b>Chain Status</b>", body_style),
            ]
        ]
        for entry in custody_entries:
            is_valid, _ = verify_custody_log(db, entry.evidence_id)
            status_text = "<font color='green'><b>VERIFIED</b></font>" if is_valid else "<font color='red'><b>TAMPERED</b></font>"
            t_str = entry.time.strftime("%Y-%m-%d %H:%M:%S") if entry.time else "N/A"
            custody_data.append([
                Paragraph(entry.evidence_id, body_style),
                Paragraph(entry.actor, body_style),
                Paragraph(entry.action, body_style),
                Paragraph(t_str, body_style),
                Paragraph(status_text, body_style),
            ])

        custody_table = Table(custody_data, colWidths=[80, 100, 120, 120, 110])
        custody_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EDF2F7")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(custody_table)
    else:
        story.append(Paragraph("<i>No custody entries logged.</i>", body_style))

    story.append(Spacer(1, 10))

    # Section 3: Forensic Findings (Approved and Pending)
    story.append(Paragraph("3. Forensic Findings & Evidence Lineage", section_heading))
    findings = case.findings or []
    if findings:
        findings_data: list[list[Any]] = [
            [
                Paragraph("<b>ID</b>", body_style),
                Paragraph("<b>Type</b>", body_style),
                Paragraph("<b>Status</b>", body_style),
                Paragraph("<b>Confidence</b>", body_style),
                Paragraph("<b>Claim & Evidence Lineage</b>", body_style),
            ]
        ]
        for f in findings:
            status_color = "green" if f.status == "approved" else ("red" if f.status == "rejected" else "orange")
            status_html = f"<font color='{status_color}'><b>{f.status.upper()}</b></font>"
            cited_events = ", ".join(f.evidence_event_ids or [])
            claim_html = f"<b>Claim:</b> {f.claim}<br/><b>Events:</b> {cited_events}"
            if f.reasoning:
                claim_html += f"<br/><b>Reasoning:</b> {f.reasoning}"

            findings_data.append([
                Paragraph(f.finding_id, body_style),
                Paragraph(f.type.capitalize(), body_style),
                Paragraph(status_html, body_style),
                Paragraph(f"{int(f.confidence * 100)}%", body_style),
                Paragraph(claim_html, body_style),
            ])

        findings_table = Table(findings_data, colWidths=[60, 80, 75, 65, 250])
        findings_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EDF2F7")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(findings_table)
    else:
        story.append(Paragraph("<i>No findings generated yet.</i>", body_style))

    story.append(Spacer(1, 14))

    # Section 4: Examiner Certification Sign-off Section
    story.append(Paragraph("4. Forensic Examiner & Reviewer Sign-Off", section_heading))
    sign_data = [
        [
            Paragraph("<b>Investigating Forensic Examiner:</b>", body_style),
            Paragraph("<b>Reviewing Lead Officer:</b>", body_style),
        ],
        [
            Paragraph("Name: _______________________________", body_style),
            Paragraph("Name: _______________________________", body_style),
        ],
        [
            Paragraph("Designation / Badge: ___________________", body_style),
            Paragraph("Designation / Badge: ___________________", body_style),
        ],
        [
            Paragraph("Signature: __________________________", body_style),
            Paragraph("Signature: __________________________", body_style),
        ],
        [
            Paragraph("Date: _______________________________", body_style),
            Paragraph("Date: _______________________________", body_style),
        ],
    ]
    sign_table = Table(sign_data, colWidths=[265, 265])
    sign_table.setStyle(
        TableStyle([
            ("LINEABOVE", (0, 0), (-1, 0), 1, colors.HexColor("#CBD5E0")),
            ("LINEBELOW", (0, -1), (-1, -1), 1, colors.HexColor("#CBD5E0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
    )
    story.append(sign_table)

    doc.build(story)
    return buffer.getvalue()
