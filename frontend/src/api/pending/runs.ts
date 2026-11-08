// Role 4 / T11: T7/T8 analysis runs, claims, lineage and run diffs. PENDING OPENAPI SCHEMA.
//
// contracts/openapi.yaml lists these paths but documents no response bodies, so nothing here is a confirmed
// contract. The types are copied field for field from the backend merged at a6e9ffd:
//   backend/app/services/runs.py   execute_analysis_run, get_run_details, verify_run_reproducibility, diff_runs
//   backend/app/db/models.py       AnalysisRun.to_dict, Claim.to_dict, ClaimEdge.to_dict, CLAIM_* enums
//   backend/app/db/claims.py       claim_lineage
//   intelligence/hyp/engine.py     RankedHypothesis, ItemEvaluation, ResidualH0, NextBestEvidence
//   intelligence/hyp/reconstruct.py StageReconstruction, NarrativeReconstruction
// Nested values the UI does not read are typed `unknown`. Each fetch checks a few key fields and throws ApiError
// when they are absent instead of rendering partial data.
//
// Keep everything run-related in this module. When Role 3 publishes response schemas, move the types into
// api/types.ts and the functions into api/client.ts, and delete this file.
import { ApiError, postJson, request } from "../client";

const enc = encodeURIComponent;
const isString = (value: unknown): value is string => typeof value === "string";
const isRecord = (data: unknown): data is Record<string, unknown> => data !== null && typeof data === "object" && !Array.isArray(data);
const isObjectArray = (data: unknown): data is Record<string, unknown>[] => Array.isArray(data) && data.every(isRecord);

// ----- Types -----

export type ClaimType =
  | "SAME_OBJECT_FLOW"
  | "OFFHOURS_SESSION"
  | "ACTOR_DEVICE_CONSISTENT"
  | "LOCATION_CONFLICT"
  | "NO_RECORD_IN_COVERED_WINDOW"
  | "SESSION_ORIGIN_MISMATCH";
export type ClaimStatus = "ASSERTED" | "CORROBORATED" | "CONTESTED" | "REFUTED" | "ASSUMED";
/** Evidence grade, A strongest. A category, not a probability. */
export type ClaimGrade = "A" | "B" | "C";
export type EdgeRole = "SUPPORTS" | "CONTRADICTS";

/** One claim edge: a claim rests on an event or on another claim of the same run. */
export interface ClaimEdge {
  run_id: string;
  claim_id: string;
  ref_kind: "event" | "claim";
  ref_id: string;
  role: EdgeRole;
  weight: number | null;
  reason_code: string | null;
  family: string | null;
}

/** Claim.to_dict(); GET /runs/{run_id}/claims/{claim_id} and GET /cases/{case_id}/runs/{run_id}/claims items. */
export interface Claim {
  claim_id: string;
  claim_key: string;
  run_id: string;
  case_id: string;
  type: ClaimType;
  params: Record<string, unknown>;
  status: ClaimStatus;
  grade: ClaimGrade;
  rule_id: string;
  rule_version: string;
  assumptions_hash: string;
}

/** Claims inside GET /runs/{id} also carry their edges. */
export interface RunClaim extends Claim {
  edges: ClaimEdge[];
}

/** GET /runs/{run_id}/claims/{claim_id}/lineage: claim -> edges -> events -> evidence intake SHA-256, recursive. */
export interface ClaimLineage {
  claim: Claim;
  events: {
    event_id: string;
    role: EdgeRole;
    family: string | null;
    artifact_ref: string | null;
    evidence_id: string | null;
    evidence_sha256: string | null;
  }[];
  /** A sub-claim either carries its own lineage or, when already visited, `cycle: true`. */
  claims: ({ claim_id: string; role: EdgeRole; lineage: ClaimLineage } | { claim_id: string; role: EdgeRole; cycle: true })[];
}

export type HypothesisStatus = "LEADING" | "VIABLE" | "WEAKENED" | "REFUTED" | "UNDETERMINED";
export type ItemCategory = "requires" | "expects" | "forbids" | "constraint";
/** MISSING: the source covered the window and the record is absent (penalized). UNOBSERVABLE: the source did not
 *  cover the window (neutral, never penalized). */
export type ItemState = "SATISFIED" | "VIOLATED" | "MISSING" | "UNOBSERVABLE" | "NEUTRAL";

/** One cell of the required/expected/forbidden matrix (ItemEvaluation). */
export interface ItemEvaluation {
  item_id: string;
  category: ItemCategory;
  stage: string;
  claim_type: string;
  state: ItemState;
  description: string;
  matched_claim_ids: string[];
  witness_family: string | null;
  disconfirmation_penalty: number;
  diagnostic: boolean;
  rationale: string;
  assumed_claim_ids: string[];
}

export interface RankedHypothesis {
  id: string;
  kind: string;
  name: string;
  description: string;
  status: HypothesisStatus;
  /** Disconfirmation score; lower ranks higher. Not a confidence or probability. */
  inconsistency_score: number;
  rank: number;
  evaluations: ItemEvaluation[];
  supporting_claim_ids: string[];
  hard_violations_count: number;
  missing_expected_count: number;
  unobservable_count: number;
}

/** Events no hypothesis stage accounts for. Never ranked. */
export interface ResidualH0 {
  id: string;
  name: string;
  description: string;
  unassigned_event_count: number;
  unassigned_event_ids: string[];
}

export interface NextBestEvidence {
  evidence_needed: string;
  source_kind: string;
  distinguishes: string[];
  rationale: string;
  priority: "HIGH" | "MEDIUM" | "LOW";
}

export type StageStatus = "SUPPORTED" | "GAP";
export type StageRelationship = "FIRST_STAGE" | "PRECEDES" | "CONCURRENT_OR_OVERLAPPING" | "OUT_OF_ORDER" | "UNPROVEN" | "GAP_DETECTED";

export interface StageReconstruction {
  stage_name: string;
  status: StageStatus;
  /** ISO 8601 bounds of the stage, or null for a GAP. */
  time_window: { lo: string | null; hi: string | null } | null;
  relationship_to_previous: StageRelationship;
  /** Subset of claim fields (claim_id, type, params, status, grade, edges). */
  claims: Partial<RunClaim>[];
  raw_events: Record<string, unknown>[];
}

export interface NarrativeReconstruction {
  hypothesis_id: string;
  hypothesis_name: string;
  status: string;
  stages: StageReconstruction[];
  background_activity_count: number;
  background_activity_event_ids: string[];
  residual_h0_count: number;
  residual_h0_event_ids: string[];
  narrative_summary: string;
}

/** The evidence a run was computed over: ACTIVE evidence IDs with their intake SHA-256, plus assumptions. */
export interface RunManifest {
  evidence: { evidence_id: string; sha256: string }[];
  assumptions: Record<string, unknown>;
}

/** AnalysisRun.to_dict(); items of GET /cases/{case_id}/runs. */
export interface RunSummary {
  run_id: string;
  case_id: string;
  parent_run_id: string | null;
  manifest: RunManifest;
  assumptions_hash: string;
  engine_version: string;
  parser_versions: { known: string[]; unknown_evidence_ids: string[] };
  ranking_hash: string;
  created_at: string | null;
}

/** Fields shared by the POST /cases/{id}/runs response and GET /runs/{id}. */
interface RunResultBase {
  run_id: string;
  case_id: string;
  parent_run_id: string | null;
  engine_version: string;
  assumptions_hash: string;
  manifest: RunManifest;
  claims_count: number;
  ranking_hash: string;
  template_hash: string;
  ranked_hypotheses: RankedHypothesis[];
  h0_residual: ResidualH0 | null;
  reconstruction: NarrativeReconstruction | null;
  next_best_evidence: NextBestEvidence[];
  outcome: "LEADING" | "UNDETERMINED" | "REFUTED" | null;
  created_at: string | null;
}

/** 201 response of POST /cases/{case_id}/runs. */
export type RunCreated = RunResultBase;

export type SnapshotStatus = "AUTHORITATIVE_DB" | "EPHEMERAL_LOCAL_FALLBACK" | "UNAVAILABLE";

/** GET /runs/{run_id} and GET /cases/{case_id}/runs/{run_id}. */
export interface RunDetails extends RunResultBase {
  parser_versions: { known: string[]; unknown_evidence_ids: string[] };
  /** INVALIDATED once evidence in the manifest is gone or no longer ACTIVE. */
  validity: "VALID" | "INVALIDATED";
  is_valid: boolean;
  invalidation_reasons: string[];
  ranking_hash_verified: boolean | null;
  snapshot_available: boolean;
  snapshot_status: SnapshotStatus;
  snapshot_source: string | null;
  snapshot_authoritative: boolean;
  snapshot_warning?: string;
  claims: RunClaim[];
  /** Present only with ?verify=true. */
  verification?: RunVerification;
  historical_replay?: unknown;
  current_state_comparison?: RunVerification["current_state_comparison"];
}

/** POST /runs/{run_id}/verify: recomputes the run without changing it. */
export interface RunVerification {
  verified: boolean;
  persisted_ranking_hash: string;
  recomputed_ranking_hash: string;
  diverged: boolean;
  divergence_details: string[];
  snapshot_available: boolean;
  snapshot_authoritative: boolean;
  snapshot_status: SnapshotStatus;
  ranking_hash_verified: boolean;
  historical_replay: unknown;
  current_state_comparison: {
    diverged: boolean;
    events_identical: boolean;
    templates_identical: boolean;
    current_ranking_hash: string;
    divergence_reasons: string[];
    event_drift_detected: boolean;
    event_drift_details: unknown[];
  };
}

/** One hypothesis in a run diff: either compared across both runs, or present in only one. */
export type HypothesisDiff =
  | {
      hypothesis_id: string;
      name: string;
      old_rank: number;
      new_rank: number;
      old_status: HypothesisStatus;
      new_status: HypothesisStatus;
      old_score: number;
      new_score: number;
      score_delta: number;
      item_state_shifts: { item_id: string; old_state: ItemState; new_state: ItemState; old_penalty: number; new_penalty: number }[];
      changed: boolean;
    }
  | { hypothesis_id: string; transition: "DROPPED" | "INTRODUCED" };

/** GET /runs/{run_a_id}/diff/{run_b_id}: claims are matched by claim_key. */
export interface RunDiff {
  run_a_id: string;
  run_b_id: string;
  evidence_diff: {
    added: { evidence_id: string; sha256: string }[];
    removed: { evidence_id: string; sha256: string }[];
  };
  claims_diff: {
    added_count: number;
    added_claims: RunClaim[];
    removed_count: number;
    removed_claims: RunClaim[];
    modified_count: number;
    modified_claims: {
      claim_key: string;
      type: ClaimType;
      params: Record<string, unknown>;
      old_status: ClaimStatus;
      new_status: ClaimStatus;
      old_grade: ClaimGrade;
      new_grade: ClaimGrade;
    }[];
    unchanged_count: number;
  };
  hypothesis_diffs: HypothesisDiff[];
  stage_changes: { stage_name: string; old_status: StageStatus; new_status: StageStatus }[];
  root_cause_notes: string[];
  root_cause_analysis: string;
}

// ----- Client -----


const isRunPayload = (data: unknown): data is Record<string, unknown> =>
  isRecord(data) && isString(data.run_id) && isString(data.ranking_hash) && Array.isArray(data.ranked_hypotheses);

/** POST /cases/{case_id}/runs: creates a write-once run. 422 when the case has no ACTIVE evidence. */
export async function createRun(
  caseId: string,
  body: { engine_version?: string; assumptions?: Record<string, unknown>; parent_run_id?: string } = {},
  signal?: AbortSignal
): Promise<RunCreated> {
  const data = await postJson<unknown>(`/cases/${enc(caseId)}/runs`, body, signal);
  if (!isRunPayload(data)) throw new ApiError("The created run did not match the backend's run shape.");
  return data as unknown as RunCreated;
}

/** GET /cases/{case_id}/runs, newest first. */
export async function listRuns(caseId: string, signal?: AbortSignal): Promise<RunSummary[]> {
  const data = await request<unknown>(`/cases/${enc(caseId)}/runs`, { signal });
  if (!isObjectArray(data) || !data.every(r => isString(r.run_id) && isString(r.ranking_hash)))
    throw new ApiError("The run list did not match the backend's run shape.");
  return data as unknown as RunSummary[];
}

/** GET /runs/{run_id}; `verify` also recomputes the run and attaches the result. */
export async function getRun(runId: string, options: { verify?: boolean } = {}, signal?: AbortSignal): Promise<RunDetails> {
  const suffix = options.verify ? "?verify=true" : "";
  const data = await request<unknown>(`/runs/${enc(runId)}${suffix}`, { signal });
  if (!isRunPayload(data) || !Array.isArray(data.claims)) throw new ApiError("The run did not match the backend's run shape.");
  return data as unknown as RunDetails;
}

/** POST /runs/{run_id}/verify: recomputes from the run's inputs without changing the run. */
export function verifyRun(runId: string, signal?: AbortSignal): Promise<RunVerification> {
  return postJson<RunVerification>(`/runs/${enc(runId)}/verify`, undefined, signal);
}

/** GET /runs/{a}/diff/{b}: claims matched by claim_key, plus ranking and stage changes and their cause. */
export async function diffRuns(runAId: string, runBId: string, signal?: AbortSignal): Promise<RunDiff> {
  const data = await request<unknown>(`/runs/${enc(runAId)}/diff/${enc(runBId)}`, { signal });
  if (!isRecord(data) || !isRecord(data.claims_diff) || !Array.isArray(data.hypothesis_diffs))
    throw new ApiError("The run diff did not match the backend's diff shape.");
  return data as unknown as RunDiff;
}

/** GET /cases/{case_id}/runs/{run_id}/claims */
export async function listRunClaims(caseId: string, runId: string, signal?: AbortSignal): Promise<Claim[]> {
  const data = await request<unknown>(`/cases/${enc(caseId)}/runs/${enc(runId)}/claims`, { signal });
  if (!isObjectArray(data) || !data.every(c => isString(c.claim_id) && isString(c.claim_key)))
    throw new ApiError("The claim list did not match the backend's claim shape.");
  return data as unknown as Claim[];
}

/** GET /runs/{run_id}/claims/{claim_id} */
export function getClaim(runId: string, claimId: string, signal?: AbortSignal): Promise<Claim> {
  return request<Claim>(`/runs/${enc(runId)}/claims/${enc(claimId)}`, { signal });
}

/** GET /runs/{run_id}/claims/{claim_id}/lineage: down to each evidence intake SHA-256. */
export async function getClaimLineage(runId: string, claimId: string, signal?: AbortSignal): Promise<ClaimLineage> {
  const data = await request<unknown>(`/runs/${enc(runId)}/claims/${enc(claimId)}/lineage`, { signal });
  if (!isRecord(data) || !isRecord(data.claim) || !Array.isArray(data.events) || !Array.isArray(data.claims))
    throw new ApiError("The claim lineage did not match the backend's lineage shape.");
  return data as unknown as ClaimLineage;
}
