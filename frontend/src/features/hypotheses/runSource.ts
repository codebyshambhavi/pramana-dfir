// Role 4 / T11: where the run-based views (Hypotheses, Claims, Reconstruction) get their analysis run. This is the only
// place they touch T7/T8.
//   demo: a run from the CASE-DEMO-IST recording (real backend output, see api/recorded/case-demo-ist/README.md).
//         Run A (before the tamper) by default; run B when asked for by ID. Any other ID is reported as not recorded.
//   api:  the requested run (GET /runs/{id}), or the newest run for the case (GET /cases/{id}/runs, then GET /runs/{id}).
//         These endpoints have no OpenAPI response schema yet, so they go through api/pending/runs.ts, which checks key
//         fields and throws on anything else.
import { useEffect, useState } from "react";
import { getRun, listRuns, type RunDetails } from "../../api/pending/runs";
import { loadRecording } from "../../api/recorded/loadRecording";
import type { Section } from "../dashboard/dashboardData";
import type { EvidenceSourceKind } from "../vault/evidenceSource";

export interface LoadedRun {
  run: RunDetails;
  /** "recorded": a saved CASE-DEMO-IST run; "api": fetched from the backend just now. */
  origin: "recorded" | "api";
}

export function useLatestRun(kind: EvidenceSourceKind, caseId: string, runId: string | null = null) {
  const [state, setState] = useState<Section<LoadedRun | null>>({ status: "loading" });
  const [version, setVersion] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setState({ status: "loading" });
    if (kind === "demo" || kind === "recorded") {
      loadRecording()
        .then(rec => {
          if (controller.signal.aborted) return;
          const runs: Record<string, RunDetails> = { [rec.runA.run_id]: rec.runA, [rec.runB.run_id]: rec.runB };
          const run = runId ? runs[runId] : rec.runA;
          setState(run ? { status: "ready", data: { run, origin: "recorded" } } : { status: "error", message: `Run ${runId} is not in the CASE-DEMO-IST recording.` });
        })
        .catch(() => !controller.signal.aborted && setState({ status: "error", message: "The recorded run could not be loaded." }));
      return () => controller.abort();
    }
    const load = runId
      ? getRun(runId, {}, controller.signal)
      : listRuns(caseId, controller.signal).then(runs => (runs.length ? getRun(runs[0].run_id, {}, controller.signal) : null));
    load
      .then(run => !controller.signal.aborted && setState({ status: "ready", data: run ? { run, origin: "api" } : null }))
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        setState({ status: "error", message: error instanceof Error ? error.message : "Runs unavailable" });
      });
    return () => controller.abort();
  }, [kind, caseId, runId, version]);

  return { state, reload: () => setVersion(v => v + 1) };
}
