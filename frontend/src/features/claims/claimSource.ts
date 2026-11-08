// Role 4 / T11: data for the Claim Inspector. Like features/hypotheses/runSource.ts, this is the only place the
// inspector touches T7/T8.
//   recorded: lineage, events and evidence saved with the CASE-DEMO-IST recording. A claim with no recorded lineage
//             is reported as unavailable; nothing is rebuilt or substituted.
//   api:      GET /runs/{run}/claims/{claim}/lineage (pending OpenAPI schema, via api/pending/runs.ts), plus the
//             documented GET /cases/{id}/events and /evidence for event details and file names.
import { useEffect, useState } from "react";
import { listEvents, listEvidence } from "../../api/client";
import { getClaimLineage, type ClaimLineage } from "../../api/pending/runs";
import { loadRecording } from "../../api/recorded/loadRecording";
import type { CaseEvent, EvidenceItem } from "../../api/types";
import type { Section } from "../dashboard/dashboardData";
import type { LoadedRun } from "../hypotheses/runSource";

const RECORDING_FAILED = "The recorded run could not be loaded.";

export function useClaimLineage(loaded: LoadedRun, claimId: string | null) {
  const [state, setState] = useState<Section<ClaimLineage>>({ status: "loading" });
  const { origin, run } = loaded;

  useEffect(() => {
    if (!claimId) return undefined;
    const controller = new AbortController();
    setState({ status: "loading" });
    if (origin === "recorded") {
      loadRecording()
        .then(rec => {
          if (controller.signal.aborted) return;
          const byRun: Record<string, Record<string, ClaimLineage>> = { [rec.runA.run_id]: rec.runALineage, [rec.runB.run_id]: rec.runBLineage };
          const lineage = byRun[run.run_id]?.[claimId];
          setState(lineage ? { status: "ready", data: lineage } : { status: "error", message: "No lineage was recorded for this claim." });
        })
        .catch(() => !controller.signal.aborted && setState({ status: "error", message: RECORDING_FAILED }));
      return () => controller.abort();
    }
    getClaimLineage(run.run_id, claimId, controller.signal)
      .then(data => !controller.signal.aborted && setState({ status: "ready", data }))
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        setState({ status: "error", message: error instanceof Error ? error.message : "Lineage unavailable" });
      });
    return () => controller.abort();
  }, [origin, run.run_id, claimId]);

  return state;
}

export interface CaseRecords {
  eventById: Map<string, CaseEvent>;
  evidenceById: Map<string, EvidenceItem>;
}

/** Event details and evidence file names for the run's case. Optional: lineage still shows IDs and hashes without them. */
export function useCaseRecords(loaded: LoadedRun) {
  const [state, setState] = useState<Section<CaseRecords>>({ status: "loading" });
  const { origin, run } = loaded;

  useEffect(() => {
    const index = (events: CaseEvent[], evidence: EvidenceItem[]): CaseRecords => ({
      eventById: new Map(events.map(e => [e.event_id, e])),
      evidenceById: new Map(evidence.map(e => [e.evidence_id, e]))
    });
    const controller = new AbortController();
    setState({ status: "loading" });
    if (origin === "recorded") {
      // Evidence as it stood when run A was created (before the tamper); used for file names only.
      loadRecording()
        .then(rec => !controller.signal.aborted && setState({ status: "ready", data: index(rec.events, rec.evidenceBefore) }))
        .catch(() => !controller.signal.aborted && setState({ status: "error", message: RECORDING_FAILED }));
      return () => controller.abort();
    }
    Promise.all([listEvents(run.case_id, {}, controller.signal), listEvidence(run.case_id, controller.signal)])
      .then(([events, evidence]) => !controller.signal.aborted && setState({ status: "ready", data: index(events, evidence) }))
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        setState({ status: "error", message: error instanceof Error ? error.message : "Case records unavailable" });
      });
    return () => controller.abort();
  }, [origin, run.case_id]);

  return state;
}
