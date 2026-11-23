import type { Recording } from "../../api/recorded/loadRecording";

type ReportLine = { text: string; size?: number; bold?: boolean; color?: string; gap?: number };

const PAGE_WIDTH = 612;
const PAGE_HEIGHT = 792;
const MARGIN = 42;
const CONTENT_WIDTH = PAGE_WIDTH - MARGIN * 2;
const BODY_SIZE = 9;

const textValue = (value: unknown, fallback = "Not recorded") =>
  typeof value === "string" || typeof value === "number" || typeof value === "boolean" ? String(value) : fallback;

const shortHash = (value: unknown) => {
  const hash = textValue(value, "");
  return hash.length > 24 ? `${hash.slice(0, 12)}...${hash.slice(-8)}` : hash || "Not recorded";
};

const safeText = (value: string) => value.replace(/[^\x20-\x7e]/g, "?");
const pdfEscape = (value: string) => safeText(value).replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
const encodePdfText = (value: string) => new TextEncoder().encode(value);

function wrap(text: string, size: number, width = CONTENT_WIDTH) {
  const limit = Math.max(12, Math.floor(width / (size * 0.52)));
  const words = safeText(text).split(/\s+/);
  const lines: string[] = [];
  let current = "";
  for (const word of words) {
    if (!word) continue;
    if (word.length > limit) {
      if (current) lines.push(current);
      for (let i = 0; i < word.length; i += limit) lines.push(word.slice(i, i + limit));
      current = "";
    } else if (!current) current = word;
    else if (`${current} ${word}`.length <= limit) current += ` ${word}`;
    else {
      lines.push(current);
      current = word;
    }
  }
  if (current) lines.push(current);
  return lines.length ? lines : [""];
}

class PdfPage {
  readonly commands: string[] = [];
  y = PAGE_HEIGHT - MARGIN;

  text(value: string, size = BODY_SIZE, bold = false, color = "0.16 0.20 0.26") {
    const font = bold ? "F2" : "F1";
    this.commands.push(`BT /${font} ${size} Tf ${color} rg ${MARGIN} ${this.y.toFixed(2)} Td (${pdfEscape(value)}) Tj ET`);
    this.y -= size + 4;
  }

  wrapped(value: string, size = BODY_SIZE, bold = false, gap = 2) {
    for (const line of wrap(value, size)) this.text(line, size, bold);
    this.y -= gap;
  }

  heading(value: string) {
    this.y -= 7;
    this.text(value, 13, true, "0.07 0.31 0.58");
    this.commands.push(`0.07 0.31 0.58 RG 1.2 w ${MARGIN} ${this.y + 3} m ${PAGE_WIDTH - MARGIN} ${this.y + 3} l S`);
    this.y -= 8;
  }

  rule() {
    this.commands.push(`0.80 0.84 0.88 RG 0.5 w ${MARGIN} ${this.y} m ${PAGE_WIDTH - MARGIN} ${this.y} l S`);
    this.y -= 8;
  }

  table(headers: string[], rows: string[][], widths: number[], pages: PdfPage[]) {
    let page: PdfPage = this;
    const drawRow = (cells: string[], header: boolean) => {
      const wrapped = cells.map((cell, index) => wrap(cell, 7.5, widths[index] - 8));
      const height = Math.max(...wrapped.map(lines => lines.length)) * 10 + 8;
      if (page.y - height < MARGIN + 24) return false;
      page.commands.push(`0.93 0.95 0.97 rg ${MARGIN} ${page.y - height + 2} ${widths.reduce((a, b) => a + b, 0)} ${height} re f`);
      page.commands.push(`0.72 0.77 0.83 RG 0.45 w ${MARGIN} ${page.y - height + 2} m ${MARGIN + widths.reduce((a, b) => a + b, 0)} ${page.y - height + 2} l S`);
      let x = MARGIN;
      wrapped.forEach((lines, index) => {
        lines.forEach((line, lineIndex) => {
          page.commands.push(`BT /${header ? "F2" : "F1"} 7.5 Tf 0.16 0.20 0.26 rg ${x + 4} ${page.y - 11 - lineIndex * 10} Td (${pdfEscape(line)}) Tj ET`);
        });
        x += widths[index];
      });
      page.y -= height;
      return true;
    };

    if (!drawRow(headers, true)) {
      page = new PdfPage();
      pages.push(page);
      page.text("Table continued", 8, true, "0.29 0.34 0.41");
      drawRow(headers, true);
    }
    for (const row of rows) {
      if (!drawRow(row, false)) {
        page = new PdfPage();
        pages.push(page);
        page.text("Table continued", 8, true, "0.29 0.34 0.41");
        drawRow(headers, true);
        drawRow(row, false);
      }
    }
    page.y -= 6;
  }
}

function addSection(pages: PdfPage[], title: string, lines: ReportLine[]) {
  let page = pages[pages.length - 1];
  if (page.y < 150) {
    page = new PdfPage();
    pages.push(page);
  }
  page.heading(title);
  for (const line of lines) {
    if (page.y < MARGIN + 45) {
      page = new PdfPage();
      pages.push(page);
      page.heading(`${title} (continued)`);
    }
    page.wrapped(line.text, line.size ?? BODY_SIZE, line.bold ?? false, line.gap ?? 2);
  }
}

function evidenceIdsForClaim(recording: Recording, claimId: string) {
  const lineage = recording.runALineage[claimId];
  return [...new Set((lineage?.events ?? []).map(event => event.evidence_id).filter(Boolean))].join(", ") || "No linked evidence";
}

function readableEvidenceDiff(diff: Recording["diffAB"]["evidence_diff"]) {
  const removed = diff.removed.map(item => `${item.evidence_id} (${shortHash(item.sha256)})`).join(", ") || "None";
  const added = diff.added.map(item => `${item.evidence_id} (${shortHash(item.sha256)})`).join(", ") || "None";
  return [
    ["Evidence removed or quarantined", removed],
    ["Evidence added", added]
  ];
}

function readableClaimDiff(diff: Recording["diffAB"]["claims_diff"]) {
  return [
    ["Claims added", `${diff.added_count}: ${diff.added_claims.map(claim => `${claim.type} (${claim.status}, grade ${claim.grade})`).join("; ") || "None"}`],
    ["Claims removed", `${diff.removed_count}: ${diff.removed_claims.map(claim => `${claim.type} (${claim.status}, grade ${claim.grade})`).join("; ") || "None"}`],
    ["Claims modified", `${diff.modified_count}: ${diff.modified_claims.map(claim => `${claim.type} ${claim.old_status} -> ${claim.new_status}, grade ${claim.old_grade} -> ${claim.new_grade}`).join("; ") || "None"}`],
    ["Claims unchanged", textValue(diff.unchanged_count, "Not recorded")]
  ];
}

function readableHypothesisDiffs(diff: Recording["diffAB"]["hypothesis_diffs"]) {
  return diff.map(item =>
    "transition" in item
      ? [item.hypothesis_id, "Unavailable", item.transition, item.transition, "Unavailable", "Hypothesis exists in only one run"]
      : [
          item.hypothesis_id,
          item.name,
          `${item.old_rank} -> ${item.new_rank}`,
          `${item.old_status} -> ${item.new_status}`,
          `${item.old_score} -> ${item.new_score}`,
          item.item_state_shifts.map(shift => `${shift.item_id}: ${shift.old_state} -> ${shift.new_state}`).join("; ") || "No item state changes"
        ]
  );
}

function buildPages(recording: Recording) {
  const pages = [new PdfPage()];
  const firstEvent = recording.events.slice().sort((a, b) => a.timestamp.localeCompare(b.timestamp))[0];
  const lastEvent = recording.events.slice().sort((a, b) => b.timestamp.localeCompare(a.timestamp))[0];
  const evidenceAfter = recording.evidenceAfter;
  const custody = recording.evidenceBefore.flatMap(item => item.custody.map(entry => ({ evidenceId: item.evidence_id, entry: entry as Record<string, unknown> })));

  const cover = pages[0];
  cover.text("PRAMANA DIGITAL FORENSIC INVESTIGATION REPORT", 18, true, "0.07 0.31 0.58");
  cover.text(`Case ID: ${recording.caseId}`, 11, true);
  cover.text("Recorded investigation snapshot", 10, false, "0.29 0.34 0.41");
  cover.rule();
  cover.wrapped("This report is generated locally from the bundled recorded investigation data. It is a deterministic investigator support document, not a live database report or a legal certificate.", 9);

  addSection(pages, "1. Case summary", [
    { text: `Case ID: ${recording.caseId}`, bold: true },
    { text: `Recorded source commit: ${recording.sourceCommit}` },
    { text: `Evidence period: ${firstEvent?.timestamp ?? "Not recorded"} to ${lastEvent?.timestamp ?? "Not recorded"}` },
    { text: `Investigation events: ${recording.events.length}; evidence items: ${recording.evidenceBefore.length}` },
    { text: `Run A: ${recording.runA.run_id} (${recording.runA.outcome ?? "Not recorded"}); Run B: ${recording.runB.run_id} (${recording.runB.outcome ?? "Not recorded"})` },
    { text: `Recorded assumptions: ${Object.entries(recording.runA.manifest.assumptions).map(([key, value]) => `${key}=${textValue(value)}`).join(", ") || "None recorded"}` }
  ]);

  const evidenceRows = evidenceAfter.map(item => [
    item.evidence_id,
    item.filename,
    textValue(item.status, "Not recorded"),
    shortHash(item.sha256),
    textValue(item.intake_time)
  ]);
  let page = pages[pages.length - 1];
  page.heading("2. Evidence inventory");
  page.table(["ID", "Filename", "Status", "SHA-256", "Intake (UTC)"], evidenceRows, [54, 170, 72, 130, 106], pages);

  const custodyRows = custody.map(({ evidenceId, entry }) => [
    evidenceId,
    textValue(entry.actor),
    textValue(entry.action),
    textValue(entry.time ?? entry.timestamp)
  ]);
  page = pages[pages.length - 1];
  page.heading("3. Chain of custody");
  page.wrapped("Custody entries below are reproduced from the recorded intake response. No new custody event is created by this report.");
  page.table(["Evidence", "Actor", "Action", "Recorded time"], custodyRows, [60, 170, 190, 112], pages);

  const timelineGroups = new Map<string, { evidenceId: string; source: string; action: string; count: number; first: string; last: string; refs: string[] }>();
  for (const event of recording.events.slice().sort((a, b) => a.timestamp.localeCompare(b.timestamp))) {
    const key = `${event.evidence_id}:${event.action}`;
    const current = timelineGroups.get(key);
    if (current) {
      current.count += 1;
      current.last = event.timestamp;
      if (current.refs.length < 3) current.refs.push(event.event_id.slice(-15));
    } else {
      timelineGroups.set(key, {
        evidenceId: event.evidence_id,
        source: event.source,
        action: event.action,
        count: 1,
        first: event.timestamp,
        last: event.timestamp,
        refs: [event.event_id.slice(-15)]
      });
    }
  }
  const timelineRows = [...timelineGroups.values()].map(group => [
    group.first,
    group.last,
    group.evidenceId,
    group.source,
    group.action,
    `${group.count} event${group.count === 1 ? "" : "s"}; refs ${group.refs.join(", ")}`
  ]);
  page = pages[pages.length - 1];
  if (page.y < 300) {
    page = new PdfPage();
    pages.push(page);
  }
  page.heading("4. Investigation timeline");
  page.wrapped(`Complete timeline summary: ${recording.events.length} normalized events are represented in ${timelineRows.length} chronological evidence/action groups. Each group preserves its first and last timestamp, event count, and representative event references; repetitive raw events are grouped to keep the report concise.`);
  page.table(["First timestamp", "Last timestamp", "Evidence", "Source", "Action", "Group summary"], timelineRows, [92, 92, 58, 55, 92, 143], pages);

  const claimRows = recording.runA.claims.map(claim => [
    claim.claim_id,
    claim.type,
    `${claim.status} / grade ${claim.grade}`,
    evidenceIdsForClaim(recording, claim.claim_id)
  ]);
  page = pages[pages.length - 1];
  page.heading("5. Findings and corroborated claims");
  page.wrapped("The recorded snapshot contains engine claims rather than investigator-approved live findings. Each claim below is kept with its recorded status and lineage references.");
  page.table(["Claim", "Type", "Recorded result", "Evidence references"], claimRows, [100, 105, 105, 222], pages);

  const hypothesisRows = recording.runA.ranked_hypotheses.map(h => [
    `${h.rank}. ${h.id}`,
    h.name,
    h.status,
    `score ${h.inconsistency_score}; ${h.supporting_claim_ids.length} supporting claims`
  ]);
  page = pages[pages.length - 1];
  if (page.y < 190) {
    page = new PdfPage();
    pages.push(page);
  }
  page.heading("6. Hypotheses and supporting evidence");
  page.table(["Rank", "Hypothesis", "Status", "Recorded support"], hypothesisRows, [72, 180, 90, 190], pages);
  page = pages[pages.length - 1];
  page.wrapped("Ground-truth discrepancy: the benchmark identifies H1 (Insider Exfiltration) as the expected leading hypothesis, while the recorded engine result ranks H2 (Sanctioned Backup) as LEADING. This report preserves both results and does not silently correct the engine output.", 9, true);
  page.wrapped("The recording also preserves the engine distinction between MISSING and UNOBSERVABLE: H2-EXP-2 is recorded as UNOBSERVABLE where the benchmark expected MISSING.", 9);

  page = pages[pages.length - 1];
  if (page.y < 240) {
    page = new PdfPage();
    pages.push(page);
  }
  page.heading("7. Run comparison");
  page.wrapped(`Run A ${recording.diffAB.run_a_id} is compared with Run B ${recording.diffAB.run_b_id}.`);
  page.table(["Evidence comparison", "Recorded result"], readableEvidenceDiff(recording.diffAB.evidence_diff), [190, 342], pages);
  page = pages[pages.length - 1];
  page.table(["Claim comparison", "Recorded result"], readableClaimDiff(recording.diffAB.claims_diff), [190, 342], pages);
  page = pages[pages.length - 1];
  page.table(["Hypothesis", "Name", "Rank A -> B", "Status A -> B", "Score A -> B", "Item changes"], readableHypothesisDiffs(recording.diffAB.hypothesis_diffs), [55, 115, 65, 92, 72, 153], pages);
  page = pages[pages.length - 1];
  page.wrapped(`Stage changes: ${recording.diffAB.stage_changes.length ? recording.diffAB.stage_changes.map(change => `${change.stage_name}: ${change.old_status} -> ${change.new_status}`).join("; ") : "None recorded."}`);
  page.wrapped(`Root cause analysis: ${recording.diffAB.root_cause_analysis}`);

  const before = recording.integrityBefore;
  const after = recording.integrityAfter;
  addSection(pages, "8. Integrity verification and quarantine", [
    { text: `Before tamper simulation: ${before.intact ? "intact" : "not intact"}; ${before.summary.total} evidence items checked; ${before.summary.broken_custody_chains} broken custody chains.` },
    { text: `Tamper simulation: ${recording.tamper.evidence_id}; recorded tampered SHA-256 ${shortHash(recording.tamper.tampered_sha256)}.` },
    { text: `Verification result: ${recording.verifyAfterTamper.evidence_id} -> ${recording.verifyAfterTamper.outcome}; status ${recording.verifyAfterTamper.previous_status} to ${recording.verifyAfterTamper.status}.` },
    { text: `After quarantine: ${after.intact ? "intact" : "not intact"}; quarantined evidence ${after.summary.by_status.QUARANTINED ?? 0}; run A validity ${recording.runAAfterQuarantine.validity}.` }
  ]);

  addSection(pages, "9. Conclusion and limitations", [
    { text: `The recorded engine result is ${recording.runA.ranked_hypotheses[0]?.id ?? "not recorded"} (${recording.runA.ranked_hypotheses[0]?.name ?? "not recorded"}) for Run A, while Run B is ${recording.runB.outcome ?? "not recorded"} after EVID-002 was quarantined.` },
    { text: "This report contains only values present in the recorded fixtures. It does not infer missing evidence, confidence, timestamps, investigator approvals, or legal conclusions." },
    { text: "The PDF is generated locally from the frontend recording and is independent of backend persistence. It is not a Section 63 certificate and requires review by the responsible investigator or examiner." }
  ]);
  return pages;
}

export function buildRecordedReportPdf(recording: Recording) {
  const pages = buildPages(recording);
  const objects: string[] = [];
  const addObject = (value: string) => {
    objects.push(value);
    return objects.length;
  };
  const font = addObject("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
  const boldFont = addObject("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>");
  const pageIds: number[] = [];
  const contentIds: number[] = [];
  pages.forEach((page, index) => {
    const footer = `BT /F1 8 Tf 0.35 0.39 0.45 rg ${MARGIN} 24 Td (PRAMANA - ${pdfEscape(recording.caseId)}    Page ${index + 1} of ${pages.length}) Tj ET`;
    const stream = `${page.commands.join("\n")}\n${footer}`;
    const streamLength = encodePdfText(stream).length;
    contentIds.push(addObject(`<< /Length ${streamLength} >>\nstream\n${stream}\nendstream`));
    pageIds.push(0);
  });
  const pagesId = addObject("<< /Type /Pages /Kids [] /Count 0 >>");
  pages.forEach((_, index) => {
    pageIds[index] = addObject(`<< /Type /Page /Parent ${pagesId} 0 R /MediaBox [0 0 ${PAGE_WIDTH} ${PAGE_HEIGHT}] /Resources << /Font << /F1 ${font} 0 R /F2 ${boldFont} 0 R >> >> /Contents ${contentIds[index]} 0 R >>`);
  });
  objects[pagesId - 1] = `<< /Type /Pages /Kids [${pageIds.map(id => `${id} 0 R`).join(" ")}] /Count ${pageIds.length} >>`;
  const catalog = addObject(`<< /Type /Catalog /Pages ${pagesId} 0 R >>`);
  const header = encodePdfText("%PDF-1.4\n");
  const chunks: Uint8Array[] = [header];
  let byteOffset = header.length;
  const offsets = [0];
  objects.forEach((object, index) => {
    const bytes = encodePdfText(`${index + 1} 0 obj\n${object}\nendobj\n`);
    offsets.push(byteOffset);
    chunks.push(bytes);
    byteOffset += bytes.length;
  });
  const xref = byteOffset;
  const xrefText = [`xref`, `0 ${objects.length + 1}`, `0000000000 65535 f `, ...offsets.slice(1).map(offset => `${String(offset).padStart(10, "0")} 00000 n `), `trailer`, `<< /Size ${objects.length + 1} /Root ${catalog} 0 R >>`, `startxref`, String(xref), "%%EOF"].join("\n");
  const xrefBytes = encodePdfText(xrefText);
  chunks.push(xrefBytes);
  const pdf = new Uint8Array(byteOffset + xrefBytes.length);
  let cursor = 0;
  for (const chunk of chunks) {
    pdf.set(chunk, cursor);
    cursor += chunk.length;
  }
  return new Blob([pdf], { type: "application/pdf" });
}
