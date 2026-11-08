// Role 4 / T11: the recorded CASE-DEMO-IST run (real backend responses; see README.md for provenance).
// The `Loose<T>` checks below make tsc verify every recorded file against our API types: all required fields are
// present with the right primitive types. Enum-valued fields are widened to `string` because JSON imports infer
// `string`, not literal unions.
import type { CaseEvent, CaseIntegrity, EvidenceItem, EvidenceUploadResult, TamperSimulation, VerificationResult } from "../../types";
import type { ClaimLineage, RunCreated, RunDetails, RunDiff, RunSummary, RunVerification } from "../../pending/runs";
import diffAB from "./diff_a_b.json";
import events from "./events.json";
import evidenceAfter from "./evidence_after.json";
import evidenceBefore from "./evidence_before.json";
import integrityAfter from "./integrity_after.json";
import integrityBefore from "./integrity_before.json";
import runA from "./run_a.json";
import runAAfterQuarantine from "./run_a_after_quarantine.json";
import runACreated from "./run_a_created.json";
import runALineage from "./run_a_lineage.json";
import runAVerify from "./run_a_verify.json";
import runB from "./run_b.json";
import runBCreated from "./run_b_created.json";
import runBLineage from "./run_b_lineage.json";
import runs from "./runs.json";
import tamper from "./tamper.json";
import uploads from "./uploads.json";
import verifyAfterTamper from "./verify_after_tamper.json";

type Loose<T> = T extends string
  ? string
  : T extends number
    ? number
    : T extends boolean
      ? boolean
      : T extends (infer U)[]
        ? Loose<U>[]
        : T extends object
          ? { [K in keyof T]: Loose<T[K]> }
          : T;

// Compile-time shape checks only; nothing here runs.
const checks = {
  uploads: uploads satisfies Loose<EvidenceUploadResult>[],
  evidenceBefore: evidenceBefore satisfies Loose<EvidenceItem>[],
  evidenceAfter: evidenceAfter satisfies Loose<EvidenceItem>[],
  events: events satisfies Loose<CaseEvent>[],
  integrityBefore: integrityBefore satisfies Loose<CaseIntegrity>,
  integrityAfter: integrityAfter satisfies Loose<CaseIntegrity>,
  tamper: tamper satisfies Loose<TamperSimulation>,
  verifyAfterTamper: verifyAfterTamper satisfies Loose<VerificationResult>,
  runACreated: runACreated satisfies Loose<RunCreated>,
  runBCreated: runBCreated satisfies Loose<RunCreated>,
  runA: runA satisfies Loose<RunDetails>,
  runAAfterQuarantine: runAAfterQuarantine satisfies Loose<RunDetails>,
  runB: runB satisfies Loose<RunDetails>,
  runAVerify: runAVerify satisfies Loose<RunVerification>,
  runs: runs satisfies Loose<RunSummary>[],
  runALineage: runALineage satisfies Record<string, Loose<ClaimLineage>>,
  runBLineage: runBLineage satisfies Record<string, Loose<ClaimLineage>>,
  diffAB: diffAB satisfies Loose<RunDiff>
};
void checks;

/** The recorded run, typed. Run A is before the tamper; run B is after EVID-002 (browser_history.csv) was quarantined. */
export const RECORDED_CASE_DEMO_IST = {
  caseId: "CASE-DEMO-IST",
  sourceCommit: "a6e9ffd",
  uploads: uploads as EvidenceUploadResult[],
  evidenceBefore: evidenceBefore as unknown as EvidenceItem[],
  evidenceAfter: evidenceAfter as unknown as EvidenceItem[],
  events: events as unknown as CaseEvent[],
  integrityBefore: integrityBefore as unknown as CaseIntegrity,
  integrityAfter: integrityAfter as unknown as CaseIntegrity,
  tamper: tamper as unknown as TamperSimulation,
  verifyAfterTamper: verifyAfterTamper as unknown as VerificationResult,
  runs: runs as unknown as RunSummary[],
  runA: runA as unknown as RunDetails,
  runAVerify: runAVerify as unknown as RunVerification,
  runAAfterQuarantine: runAAfterQuarantine as unknown as RunDetails,
  runALineage: runALineage as unknown as Record<string, ClaimLineage>,
  runB: runB as unknown as RunDetails,
  runBLineage: runBLineage as unknown as Record<string, ClaimLineage>,
  diffAB: diffAB as unknown as RunDiff
} as const;
