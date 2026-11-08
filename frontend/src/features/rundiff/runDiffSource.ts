// Role 4 / T11: where the Run diff view gets its data. The only place that view touches T8.
//   demo: the recorded CASE-DEMO-IST diff of run A → run B (B was created after EVID-002 was quarantined), both runs,
//         and the evidence list recorded after the quarantine. Only that pair was recorded; any other pair is refused.
//   api:  GET /runs/{a}/diff/{b} and GET /runs/{a}, /runs/{b} (pending OpenAPI schema, via api/pending/runs.ts), plus
//         the documented GET /cases/{id}/evidence for file names and current status. Without explicit IDs, B is the
//         newest run and A its parent_run_id (or else the run before it).
// Nothing here computes a diff; the comparison is the backend's.
import { useEffect, useState } from "react";
import { listEvidence } from "../../api/client";
import { diffRuns, getRun, listRuns, type RunDetails, type RunDiff, type RunSummary } from "../../api/pending/runs";
import { loadRecording } from "../../api/recorded/loadRecording";
import type { EvidenceItem } from "../../api/types";
import type { Section } from "../dashboard/dashboardData";
import type { LoadedRun } from "../hypotheses/runSource";
import type { EvidenceSourceKind } from "../vault/evidenceSource";

export type RunDiffResult =
  | { kind: "insufficient"; runs: RunSummary[] }
  | {
      kind: "ready";
      a: LoadedRun;
      b: LoadedRun;
      diff: RunDiff;
      /** Evidence of the case as it stands now (recorded: after the quarantine); null if it could not be loaded. */
      evidence: EvidenceItem[] | null;
      /** Runs available to compare (live only). */
      runs: RunSummary[];
    };

/** Default pair for a newest-first run list: newest as B, its parent (or the next newest) as A. */
export function defaultPair(runs: RunSummary[]): [string, string] | null {
  if (runs.length < 2) return null;
  const b = runs[0];
  const parent = b.parent_run_id && runs.some(r => r.run_id === b.parent_run_id) ? b.parent_run_id : runs[1].run_id;
  return [parent, b.run_id];
}

export function useRunDiff(kind: EvidenceSourceKind, caseId: string, runA: string | null, runB: string | null) {
  const [state, setState] = useState<Section<RunDiffResult>>({ status: "loading" });
  const [version, setVersion] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    const signal = controller.signal;
    setState({ status: "loading" });

    if (kind === "demo") {
      loadRecording()
        .then(REC => {
          if (signal.aborted) return;
          if ((runA || runB) && (runA !== REC.runA.run_id || runB !== REC.runB.run_id)) {
            setState({ status: "error", message: `Only ${REC.runA.run_id} → ${REC.runB.run_id} was recorded for CASE-DEMO-IST.` });
            return;
          }
          setState({
            status: "ready",
            data: {
              kind: "ready",
              // Run A as read back after the quarantine: same content, validity now INVALIDATED (matches the diff's moment).
              a: { run: REC.runAAfterQuarantine, origin: "recorded" },
              b: { run: REC.runB, origin: "recorded" },
              diff: REC.diffAB,
              evidence: REC.evidenceAfter,
              runs: []
            }
          });
        })
        .catch(() => !signal.aborted && setState({ status: "error", message: "The recorded run could not be loaded." }));
      return () => controller.abort();
    }

    (async () => {
      const runs = await listRuns(caseId, signal);
      const pair: [string, string] | null = runA && runB ? [runA, runB] : defaultPair(runs);
      if (!pair) return { kind: "insufficient" as const, runs };
      const [a, b] = pair;
      const [diff, runADetails, runBDetails, evidence] = await Promise.all([
        diffRuns(a, b, signal),
        getRun(a, {}, signal),
        getRun(b, {}, signal),
        listEvidence(caseId, signal).catch(() => null)
      ]);
      const toLoaded = (run: RunDetails): LoadedRun => ({ run, origin: "api" });
      return { kind: "ready" as const, a: toLoaded(runADetails), b: toLoaded(runBDetails), diff, evidence, runs };
    })()
      .then(data => !signal.aborted && setState({ status: "ready", data }))
      .catch((error: unknown) => {
        if (signal.aborted) return;
        setState({ status: "error", message: error instanceof Error ? error.message : "Run diff unavailable" });
      });
    return () => controller.abort();
  }, [kind, caseId, runA, runB, version]);

  return { state, reload: () => setVersion(v => v + 1) };
}
