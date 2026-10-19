// Role 4: response types taken from contracts/openapi.yaml. Only fields the contract documents are listed.

/** One item of GET /cases/{id}/evidence. */
export interface EvidenceItem {
  evidence_id: string;
  filename: string;
  sha256: string;
  /** ISO 8601 date-time. */
  intake_time: string;
  /** The contract does not define an entry's shape yet; its example is an empty array. */
  custody: unknown[];
}

/** 201 response of POST /cases/{id}/evidence. */
export interface EvidenceUploadResult {
  evidence_id: string;
  filename: string;
  sha256: string;
  events_created: number;
}

/** One item of GET /cases/{id}/events; fields from contracts/event.schema.json. */
export interface CaseEvent {
  event_id: string;
  case_id: string;
  evidence_id: string;
  artifact_ref: string;
  sha256: string;
  /** ISO 8601 date-time. */
  timestamp: string;
  source: "browser" | "chat" | "log" | "pcap" | "image";
  action: string;
  device?: string | null;
  actor?: string | null;
  object?: string | null;
  ip?: string | null;
  location?: { lat: number; lon: number } | null;
  raw?: Record<string, unknown>;
}

export interface FindingAlternative {
  claim: string;
  confidence: number;
  needed_evidence?: string[];
}

/** One item of GET /cases/{id}/findings; fields from contracts/finding.schema.json. */
export interface Finding {
  finding_id: string;
  case_id: string;
  type: "contradiction" | "anomaly" | "correlation" | "hypothesis";
  claim: string;
  /** 0 to 1. */
  confidence: number;
  evidence_event_ids: string[];
  reasoning?: string;
  alternatives?: FindingAlternative[];
  needs_human_review: boolean;
  status?: "pending" | "approved" | "rejected";
}

/** GET /cases/{id}/graph. */
export interface CaseGraph {
  nodes: { id: string; type: string }[];
  edges: { source: string; target: string; action: string }[];
}

/** GET /findings/{id}/lineage: the finding's cited events, their evidence and SHA-256. */
export interface FindingLineage {
  finding_id: string;
  events: { event_id: string; artifact_ref: string; evidence_id: string }[];
  evidence: { evidence_id: string; filename: string; sha256: string }[];
}

/** 200 response of PATCH /findings/{id}. */
export interface FindingStatusUpdate {
  finding_id: string;
  status: "pending" | "approved" | "rejected";
}
