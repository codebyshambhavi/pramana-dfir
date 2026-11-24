// Role 4: response types taken from contracts/openapi.yaml. Only fields the contract documents are listed.

/** One item of GET /cases/{id}/evidence. */
export interface EvidenceItem {
  evidence_id: string;
  filename: string;
  sha256: string;
  /** ISO 8601 date-time. */
  intake_time: string;
  /** Evidence lifecycle status (T3). Rows are never deleted; REMOVED is a status. */
  status?: EvidenceStatus;
  /** ISO 8601 date-time of the last successful re-hash, or null. */
  verified_at?: string | null;
  verify_state?: VerifyState | null;
  /** The contract does not define an entry's shape yet; its example is an empty array. */
  custody: unknown[];
}

/** 201 response of POST /cases/{id}/evidence. */
export type EvidenceStatus = "ACTIVE" | "QUARANTINED" | "REMOVED";
/** Outcome of the most recent re-verification; null until first verified. */
export type VerifyState = "MATCH" | "MISMATCH" | "MISSING" | "CUSTODY_BROKEN";

/** One item of GET /cases/{id}/integrity (read-only; does not re-hash). */
export interface EvidenceIntegrity {
  evidence_id: string;
  filename: string;
  /** Intake SHA-256; never changes. */
  sha256: string;
  status: EvidenceStatus;
  verified_at: string | null;
  verify_state: VerifyState | null;
  custody_entries: number;
  custody_chain_valid: boolean;
  custody_message: string;
  last_custody_action: string | null;
}

/** Response of GET /cases/{id}/integrity. */
export interface CaseIntegrity {
  case_id: string;
  checked_at: string;
  /** True when nothing is QUARANTINED and every custody chain verifies. */
  intact: boolean;
  summary: {
    total: number;
    by_status: Record<EvidenceStatus, number>;
    by_verify_state: Record<VerifyState, number>;
    never_verified: number;
    broken_custody_chains: number;
  };
  evidence: EvidenceIntegrity[];
}

/** Response of POST /evidence/{id}/verify. */
export interface VerificationResult {
  evidence_id: string;
  outcome: VerifyState;
  match: boolean;
  verify_state: VerifyState;
  previous_status: EvidenceStatus;
  status: EvidenceStatus;
  intake_sha256: string;
  observed_sha256: string | null;
  custody_chain_valid: boolean;
  custody_message: string;
  verified_at: string | null;
  custody_entry: unknown;
}

export interface EvidenceUploadResult {
  evidence_id: string;
  filename: string;
  sha256: string;
  events_created: number;
}

/** 200 response of POST /cases/{id}/analyze. */
export interface AnalyzeResponse {
  findings_created: number;
  run_id: string | null;
  claims_created: number;
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
  /** Event v1.1 (optional). Persisted by the backend since T3; absent on events stored earlier. */
  parser_version?: string;
  tz_assumption?: string;
  family?: string;
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

/** GET /findings/{id}/reviews: append-only investigator decision history. */
export interface FindingReviewDecision {
  review_id: string;
  finding_id: string;
  decision: "approved" | "rejected";
  reviewer_label: string;
  reviewer_identity_type: "self_declared";
  rationale: string;
  decided_at: string;
}

/** 200 response of PATCH /findings/{id}. */
export interface FindingStatusUpdate {
  finding_id: string;
  status: "approved" | "rejected";
  review: {
    review_id: string;
    finding_id: string;
    decision: "approved" | "rejected";
    reviewer_label: string;
    reviewer_identity_type: "self_declared";
    rationale: string;
    decided_at: string;
  };
}

// ---------------------------------------------------------------------------------------------------------------
// T4 evidence state changes (contracts/openapi.yaml: EvidenceStateChange, TamperSimulation).

/** 200 response of POST /evidence/{id}/remove. */
export interface EvidenceStateChange {
  evidence_id: string;
  previous_status: EvidenceStatus;
  status: EvidenceStatus;
  custody_entry: unknown;
}

/** 200 response of POST /evidence/{id}/simulate-tamper (404 unless the backend runs with DEMO_MODE=1). */
export interface TamperSimulation {
  evidence_id: string;
  demo: boolean;
  intake_sha256: string;
  tampered_sha256: string;
  status: EvidenceStatus;
  custody_entry: unknown;
}

// ---------------------------------------------------------------------------------------------------------------
// Role 3 case workflow (contracts/openapi.yaml: CaseResponse, CaseCreateRequest, CaseUpdateRequest).

/** Workflow summary, not a forensic conclusion. The API sets OPEN, CLOSED and REOPENED today. */
export type CaseStatus =
  | "DRAFT"
  | "OPEN"
  | "EVIDENCE_COLLECTED"
  | "ANALYSIS_IN_PROGRESS"
  | "ANALYSIS_COMPLETE"
  | "REPORT_GENERATED"
  | "REVIEWED"
  | "CLOSED"
  | "INGESTION_FAILED"
  | "ANALYSIS_FAILED"
  | "REPORT_FAILED"
  | "REOPENED";

/** GET /cases item, GET /cases/{id}, and the response of every case write. */
export interface CaseSummary {
  case_id: string;
  name: string;
  description: string | null;
  scope: string | null;
  tags: string[];
  /** Self-declared until authentication exists. */
  owner: string | null;
  status: CaseStatus;
  created_at: string;
  updated_at: string | null;
  closed_at: string | null;
  evidence_count: number;
  finding_count: number;
  run_count: number;
}

/** POST /cases body. case_id is generated by the server when omitted. */
export interface CaseCreateInput {
  name: string;
  case_id?: string;
  description?: string;
  scope?: string;
  tags?: string[];
  owner?: string;
}

/** PATCH /cases/{id} body: only the fields present are changed. */
export type CaseUpdateInput = Partial<Pick<CaseSummary, "name" | "description" | "scope" | "tags" | "owner">>;

// ---------------------------------------------------------------------------------------------------------------
// Role 3 immutable run-based reports (contracts/openapi.yaml: CaseReportResponse, ReportCreateRequest).

/** Metadata of a write-once report. The PDF itself comes from GET /cases/{case_id}/reports/{report_id}/pdf. */
export interface CaseReport {
  report_id: string;
  case_id: string;
  run_id: string;
  /** 1 for the first report of a run, then 2, 3, ... */
  report_version: number;
  report_format: "pdf";
  generator_version: string;
  generated_at: string;
  /** Self-declared until authentication exists. */
  generated_by: string | null;
  /** SHA-256 of the canonical report content; equal for reports of the same run. */
  content_hash: string;
  /** SHA-256 of the PDF bytes; the server re-verifies it before every download. */
  sha256: string;
  size_bytes: number;
  storage_ref: string;
  review_status: "PENDING_REVIEW";
}

// Role 3 reviewer decisions on a saved report (contracts/openapi.yaml: ReportDecisionCreateRequest,
// ReportDecisionResponse). Append-only: the last item of the history is the current decision.

export type ReportDecisionValue = "APPROVE" | "REJECT" | "INCONCLUSIVE";

export interface ReportDecision {
  decision_id: string;
  case_id: string;
  report_id: string;
  decision: ReportDecisionValue;
  rationale: string;
  /** Typed by the reviewer; not a verified identity (no authentication yet). */
  reviewer_label: string;
  reviewer_identity_type: "self_declared";
  identity_verified: false;
  decided_at: string;
}

export interface ReportDecisionInput {
  decision: ReportDecisionValue;
  rationale: string;
  reviewer_label: string;
}
