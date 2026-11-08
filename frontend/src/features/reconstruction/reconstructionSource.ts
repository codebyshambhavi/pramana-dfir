// Role 4 / T11: where the Reconstruction view gets its data. The only place that view touches T8.
// The reconstruction is part of the run (GET /runs/{id} → `reconstruction`), so this reuses the run loader:
//   demo: run A of the recorded CASE-DEMO-IST run (api/recorded/case-demo-ist).
//   api:  newest run for the case, through api/pending/runs.ts (no OpenAPI response schema yet).
// When a run has no reconstruction, the reason is passed on as-is; no stages are built here.
import type { NarrativeReconstruction } from "../../api/pending/runs";
import type { Section } from "../dashboard/dashboardData";
import { useLatestRun, type LoadedRun } from "../hypotheses/runSource";
import type { EvidenceSourceKind } from "../vault/evidenceSource";

export type ReconstructionResult =
  | { kind: "no-run" }
  | { kind: "unavailable"; loaded: LoadedRun; reason: string }
  | { kind: "ready"; loaded: LoadedRun; reconstruction: NarrativeReconstruction };

export function useReconstruction(kind: EvidenceSourceKind, caseId: string, runId: string | null = null): { state: Section<ReconstructionResult>; reload: () => void } {
  const { state, reload } = useLatestRun(kind, caseId, runId);
  if (state.status !== "ready") return { state, reload };
  const loaded = state.data;
  if (!loaded) return { state: { status: "ready", data: { kind: "no-run" } }, reload };
  const { reconstruction, snapshot_status } = loaded.run;
  if (!reconstruction)
    return {
      state: {
        status: "ready",
        data: {
          kind: "unavailable",
          loaded,
          reason:
            snapshot_status === "UNAVAILABLE"
              ? "This run's analysis snapshot is unavailable, so its reconstruction cannot be shown."
              : "The backend returned no reconstruction for this run."
        }
      },
      reload
    };
  return { state: { status: "ready", data: { kind: "ready", loaded, reconstruction } }, reload };
}
