// Role 4: joins findings to the events and evidence they cite. Everything is a lookup over loaded records;
// nothing is inferred beyond the IDs a finding lists.
import type { CaseEvent, EvidenceItem, Finding, FindingLineage } from "../../api/types";

export interface CaseIndex {
  eventById: Map<string, CaseEvent>;
  evidenceById: Map<string, EvidenceItem>;
}

export const buildIndex = (events: CaseEvent[] | null, evidence: EvidenceItem[] | null): CaseIndex => ({
  eventById: new Map(events?.map(e => [e.event_id, e])),
  evidenceById: new Map(evidence?.map(e => [e.evidence_id, e]))
});

/** Evidence IDs a finding rests on, through its cited events, in citation order. */
export const evidenceIdsFor = (finding: Finding, index: CaseIndex) => [
  ...new Set(finding.evidence_event_ids.map(id => index.eventById.get(id)?.evidence_id).filter((id): id is string => Boolean(id)))
];

/** The lineage the backend would return, built from loaded records (used in demo mode). */
export function lineageFromIndex(finding: Finding, index: CaseIndex): FindingLineage {
  const events = finding.evidence_event_ids
    .map(id => index.eventById.get(id))
    .filter((e): e is CaseEvent => Boolean(e))
    .map(e => ({ event_id: e.event_id, artifact_ref: e.artifact_ref, evidence_id: e.evidence_id }));
  const evidence = [...new Set(events.map(e => e.evidence_id))]
    .map(id => index.evidenceById.get(id))
    .filter((e): e is EvidenceItem => Boolean(e))
    .map(e => ({ evidence_id: e.evidence_id, filename: e.filename, sha256: e.sha256 }));
  return { finding_id: finding.finding_id, events, evidence };
}

export const TYPE_LABEL: Record<Finding["type"], string> = {
  contradiction: "Contradiction",
  anomaly: "Anomaly",
  correlation: "Correlation",
  hypothesis: "Hypothesis"
};
