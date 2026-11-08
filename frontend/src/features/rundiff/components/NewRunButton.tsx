// Role 4 / T12: create a new analysis run from the UI (live API only).
// POST /cases/{id}/runs with parent_run_id = the newest run and the parent's own assumptions, so the only thing that
// can differ between the two runs is the case's current ACTIVE evidence (e.g. after a quarantine). The backend builds
// the run; nothing is computed here.
import { useState } from "react";
import { createRun, getRun } from "../../../api/pending/runs";

export default function NewRunButton({
  caseId,
  parentRunId,
  onCreated
}: {
  caseId: string;
  parentRunId: string | null;
  onCreated: (parentRunId: string | null, runId: string) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      const assumptions = parentRunId ? (await getRun(parentRunId)).manifest.assumptions : undefined;
      const run = await createRun(caseId, { assumptions, parent_run_id: parentRunId ?? undefined });
      onCreated(parentRunId, run.run_id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not create the run.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <button
        type="button"
        onClick={create}
        disabled={busy}
        title={parentRunId ? `New run over the current ACTIVE evidence, parent ${parentRunId}` : "New run over the current ACTIVE evidence"}
        className="rounded-md border border-trace/40 px-2.5 py-1.5 text-[12.5px] text-trace-soft transition hover:bg-trace/10 disabled:opacity-50"
      >
        {busy ? "Running analysis…" : "New run from current evidence"}
      </button>
      {error && (
        <span role="alert" className="text-[12.5px] text-alert-soft">
          {error}
        </span>
      )}
    </span>
  );
}
