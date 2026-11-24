// Role 3: immutable run-based reports for the active case (live API only).
//
// Lists the case's completed analysis runs (GET /cases/{id}/runs; a run row exists only once the run has
// finished), generates a write-once report from the selected run (POST /cases/{id}/runs/{run}/reports), lists
// the saved reports (GET /cases/{id}/reports) and downloads each one after checking its SHA-256. Everything shown
// comes from those responses. The server rejects invalidated runs and runs without an authoritative snapshot;
// that message is shown as returned.
//
// Each saved report also carries its reviewer decisions (GET/POST /cases/{id}/reports/{report}/decisions). They
// are append-only and separate from the PDF, which stays immutable and still reads "Pending review"; the badge
// shows the latest decision. Reviewer names are self-declared (no authentication yet).
import { useCallback, useEffect, useMemo, useState } from "react";
import { Alert, Check, Copy, Refresh, ReportIcon } from "../../components/console/icons";
import {
  ApiError,
  createReportDecision,
  createRunReport,
  downloadCaseReportPdf,
  listCaseReports,
  listReportDecisions,
} from "../../api/client";
import type { CaseReport, ReportDecision, ReportDecisionValue } from "../../api/types";
import { listRuns, type RunSummary } from "../../api/pending/runs";
import { formatTimestamp, Stamp, useDisplayZone } from "../../lib/time";

type Load<T> = { status: "loading" } | { status: "error"; message: string; missingRoute: boolean } | { status: "ready"; data: T };
type GenerateState = { status: "idle" } | { status: "saving" } | { status: "error"; message: string } | { status: "done"; report: CaseReport };

const primaryButton =
  "inline-flex items-center gap-2 rounded-lg bg-alert px-4 py-2.5 text-[13.5px] font-medium text-white shadow-[0_0_18px_rgba(239,43,60,0.35)] transition hover:bg-[#ff3a4a] disabled:cursor-not-allowed disabled:opacity-45 disabled:shadow-none";
const secondaryButton =
  "inline-flex items-center gap-1.5 rounded-lg border border-white/12 px-3 py-1.5 text-[12.5px] text-soft transition hover:border-white/25 hover:text-white disabled:cursor-not-allowed disabled:opacity-50";
const field =
  "w-full rounded-lg border border-white/10 bg-black/20 px-3 py-2 text-[13px] text-white placeholder:text-soft/40 focus:border-trace/50 focus:outline-none disabled:opacity-60";

const message = (error: unknown) => (error instanceof Error ? error.message : "The request failed.");
const isAbort = (error: unknown) => error instanceof DOMException && error.name === "AbortError";
/** FastAPI answers an unknown route with detail "Not Found"; a missing case says "Case '…' not found". */
const isMissingRoute = (error: unknown) => error instanceof ApiError && error.status === 404 && error.message.endsWith(": Not Found");

function ErrorNote({ text, missingRoute, what }: { text: string; missingRoute: boolean; what: string }) {
  return (
    <p role="alert" className="flex gap-2 rounded-lg border border-alert/30 bg-alert/[0.06] px-3 py-2.5 text-[12.5px] text-soft">
      <Alert size={15} className="mt-px shrink-0 text-alert" />
      <span>
        {missingRoute ? `This backend does not provide ${what} yet. ` : ""}
        <span className="text-soft/75">{text}</span>
      </span>
    </p>
  );
}

function CopyHash({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      aria-label={`Copy ${label}`}
      onClick={() => {
        navigator.clipboard?.writeText(value).then(
          () => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          },
          () => undefined
        );
      }}
      className="shrink-0 rounded p-1 text-soft/60 hover:text-white"
    >
      {copied ? <Check size={13} /> : <Copy size={13} />}
    </button>
  );
}

const DECISION_STYLE: Record<ReportDecisionValue, { label: string; badge: string }> = {
  APPROVE: { label: "Approved", badge: "border-teal-400/40 text-teal-200" },
  REJECT: { label: "Rejected", badge: "border-alert/45 text-red-200" },
  INCONCLUSIVE: { label: "Inconclusive", badge: "border-sky-300/40 text-sky-100/90" },
};
const DECISION_OPTIONS: { value: ReportDecisionValue; label: string }[] = [
  { value: "APPROVE", label: "Approve" },
  { value: "REJECT", label: "Reject" },
  { value: "INCONCLUSIVE", label: "Inconclusive" },
];

/** Latest decision, or "Pending review" when none has been recorded. */
function StatusBadge({ history }: { history: Load<ReportDecision[]> }) {
  if (history.status === "loading") {
    return <span className="rounded-full border border-white/12 px-2 py-0.5 text-[11px] text-soft/60">Loading review…</span>;
  }
  if (history.status === "error") {
    return <span className="rounded-full border border-white/12 px-2 py-0.5 text-[11px] text-soft/60">Review status unavailable</span>;
  }
  const latest = history.data[history.data.length - 1];
  if (!latest) {
    return <span className="rounded-full border border-amber-300/35 px-2 py-0.5 text-[11px] text-amber-100/90">Pending review</span>;
  }
  const style = DECISION_STYLE[latest.decision];
  return <span className={`rounded-full border px-2 py-0.5 text-[11px] ${style.badge}`}>{style.label}</span>;
}

type SubmitState = { status: "idle" } | { status: "saving" } | { status: "error"; message: string } | { status: "done" };

function DecisionPanel({
  report,
  history,
  onReload,
}: {
  report: CaseReport;
  history: Load<ReportDecision[]>;
  onReload: () => Promise<void>;
}) {
  const [decision, setDecision] = useState<ReportDecisionValue | "">("");
  const [reviewer, setReviewer] = useState("");
  const [rationale, setRationale] = useState("");
  const [submit, setSubmit] = useState<SubmitState>({ status: "idle" });
  const [touched, setTouched] = useState(false);

  const problems = [
    decision ? "" : "Choose a decision.",
    reviewer.trim() ? "" : "Enter your name.",
    rationale.trim() ? "" : "Enter a rationale.",
  ].filter(Boolean);
  const saving = submit.status === "saving";

  const send = async () => {
    setTouched(true);
    if (problems.length > 0 || !decision) return;
    setSubmit({ status: "saving" });
    try {
      await createReportDecision(report.case_id, report.report_id, {
        decision,
        reviewer_label: reviewer.trim(),
        rationale: rationale.trim(),
      });
      setDecision("");
      setRationale("");
      setTouched(false);
      setSubmit({ status: "done" });
      await onReload();
    } catch (error) {
      setSubmit({ status: "error", message: message(error) });
    }
  };

  return (
    <div className="mt-4 border-t border-white/[0.06] pt-3">
      <p className="text-[12px] font-semibold tracking-[0.08em] text-soft/70 uppercase">Reviewer decisions</p>

      {history.status === "loading" && <p className="mt-2 text-[12.5px] text-soft/60">Loading decision history…</p>}
      {history.status === "error" && (
        <div className="mt-2 space-y-2">
          <ErrorNote text={history.message} missingRoute={history.missingRoute} what="reviewer decisions" />
          <button type="button" onClick={() => void onReload()} className={secondaryButton}>
            <Refresh size={13} /> Retry
          </button>
        </div>
      )}
      {history.status === "ready" && history.data.length === 0 && (
        <p className="mt-2 text-[12.5px] text-soft/60">No decision recorded yet. This report is pending review.</p>
      )}
      {history.status === "ready" && history.data.length > 0 && (
        <ol className="mt-2 space-y-2">
          {history.data.map((d, i) => (
            <li key={d.decision_id} className="rounded-lg border border-white/[0.06] bg-black/10 px-3 py-2 text-[12.5px]">
              <p className="flex flex-wrap items-center gap-x-2 gap-y-1">
                <span className={`rounded-full border px-2 py-0.5 text-[11px] ${DECISION_STYLE[d.decision].badge}`}>
                  {DECISION_STYLE[d.decision].label}
                </span>
                {i === history.data.length - 1 && <span className="text-[11px] text-soft/60">current</span>}
                <span className="text-soft/80">
                  {d.reviewer_label} <span className="text-soft/50">(self-declared, not verified)</span>
                </span>
                <span className="text-soft/50">
                  · <Stamp iso={d.decided_at} seconds />
                </span>
              </p>
              <p className="mt-1 break-words whitespace-pre-wrap text-soft/85">{d.rationale}</p>
              <p className="mt-1 font-mono text-[10.5px] text-soft/40">{d.decision_id}</p>
            </li>
          ))}
        </ol>
      )}

      <form
        className="mt-3 space-y-2"
        noValidate
        onSubmit={event => {
          event.preventDefault();
          void send();
        }}
      >
        <fieldset disabled={saving} className="flex flex-wrap gap-2">
          <legend className="sr-only">Decision</legend>
          {DECISION_OPTIONS.map(option => (
            <button
              key={option.value}
              type="button"
              aria-pressed={decision === option.value}
              onClick={() => setDecision(option.value)}
              className={`${secondaryButton} ${decision === option.value ? `${DECISION_STYLE[option.value].badge} bg-white/[0.04]` : ""}`}
            >
              {option.label}
            </button>
          ))}
        </fieldset>
        <label className="block text-[12px] text-soft/70">
          Reviewer name (self-declared, not verified)
          <input
            value={reviewer}
            onChange={e => setReviewer(e.target.value)}
            maxLength={120}
            disabled={saving}
            required
            placeholder="Your name"
            className={`${field} mt-1`}
          />
        </label>
        <label className="block text-[12px] text-soft/70">
          Rationale
          <textarea
            value={rationale}
            onChange={e => setRationale(e.target.value)}
            maxLength={10000}
            rows={3}
            disabled={saving}
            required
            placeholder="What you checked and why you reached this decision"
            className={`${field} mt-1`}
          />
        </label>
        {touched && problems.length > 0 && (
          <p role="alert" className="text-[12px] text-red-200/90">
            {problems.join(" ")}
          </p>
        )}
        {submit.status === "error" && <ErrorNote text={submit.message} missingRoute={false} what="" />}
        {submit.status === "done" && <p className="text-[12px] text-teal-200/90">Decision recorded. Earlier decisions are kept.</p>}
        <div className="flex flex-wrap items-center gap-3">
          <button type="submit" disabled={saving} className={secondaryButton}>
            {saving ? "Recording…" : "Record decision"}
          </button>
          <span className="text-[11.5px] text-soft/50">Decisions are append-only; the PDF is not changed.</span>
        </div>
      </form>
    </div>
  );
}

function ReportRow({ report, isNew }: { report: CaseReport; isNew: boolean }) {
  const [download, setDownload] = useState<{ status: "idle" | "busy" } | { status: "error"; message: string }>({ status: "idle" });
  const [history, setHistory] = useState<Load<ReportDecision[]>>({ status: "loading" });

  const loadHistory = useCallback(
    async (signal?: AbortSignal) => {
      // Keep showing the current history while a refresh after submission is in flight.
      setHistory(current => (current.status === "ready" ? current : { status: "loading" }));
      try {
        const data = await listReportDecisions(report.case_id, report.report_id, signal);
        setHistory({ status: "ready", data });
      } catch (error) {
        if (!isAbort(error)) setHistory({ status: "error", message: message(error), missingRoute: isMissingRoute(error) });
      }
    },
    [report.case_id, report.report_id]
  );

  useEffect(() => {
    const controller = new AbortController();
    void loadHistory(controller.signal);
    return () => controller.abort();
  }, [loadHistory]);

  const save = async () => {
    setDownload({ status: "busy" });
    try {
      const blob = await downloadCaseReportPdf(report);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${report.case_id}-${report.report_id}-v${report.report_version}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      setDownload({ status: "idle" });
    } catch (error) {
      setDownload({ status: "error", message: message(error) });
    }
  };

  return (
    <li className={`rounded-xl border p-4 ${isNew ? "border-teal-400/40 bg-teal-400/[0.04]" : "border-white/[0.08] bg-white/[0.02]"}`}>
      <div className="flex flex-wrap items-start gap-x-4 gap-y-3">
        <div className="min-w-0 flex-1">
          <p className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-[14px] text-white">
            <span className="font-mono text-[13px]">{report.report_id}</span>
            <span className="rounded-full border border-trace/35 px-2 py-0.5 text-[11px] text-trace-soft">v{report.report_version}</span>
            <StatusBadge history={history} />
            {isNew && <span className="text-[11px] font-semibold tracking-[0.08em] text-teal-200 uppercase">New</span>}
          </p>
          <dl className="mt-2 grid gap-x-5 gap-y-1 text-[12.5px] sm:grid-cols-[auto_minmax(0,1fr)]">
            <dt className="text-soft/60">Run</dt>
            <dd className="font-mono text-soft/90">{report.run_id}</dd>
            <dt className="text-soft/60">Generated</dt>
            <dd className="text-soft/90">
              <Stamp iso={report.generated_at} seconds />
              {report.generated_by && <span className="text-soft/60"> · by {report.generated_by} (self-declared)</span>}
            </dd>
            <dt className="text-soft/60">SHA-256</dt>
            <dd className="flex min-w-0 items-start gap-1">
              <span className="font-mono text-[11.5px] break-all text-soft/90">{report.sha256}</span>
              <CopyHash value={report.sha256} label={`SHA-256 of ${report.report_id}`} />
            </dd>
            <dt className="text-soft/60">Size</dt>
            <dd className="text-soft/90">{report.size_bytes.toLocaleString()} bytes</dd>
          </dl>
        </div>
        <button type="button" onClick={save} disabled={download.status === "busy"} className={secondaryButton}>
          {download.status === "busy" ? "Verifying…" : "Download PDF"}
        </button>
      </div>
      {download.status === "error" && (
        <div className="mt-3">
          <ErrorNote text={download.message} missingRoute={false} what="" />
        </div>
      )}
      <DecisionPanel report={report} history={history} onReload={() => loadHistory()} />
    </li>
  );
}

export default function RunReports({ caseId }: { caseId: string }) {
  const zone = useDisplayZone();
  const [runs, setRuns] = useState<Load<RunSummary[]>>({ status: "loading" });
  const [reports, setReports] = useState<Load<CaseReport[]>>({ status: "loading" });
  const [runId, setRunId] = useState("");
  const [generatedBy, setGeneratedBy] = useState("");
  const [generate, setGenerate] = useState<GenerateState>({ status: "idle" });

  const load = useCallback(
    (signal?: AbortSignal) => {
      setRuns({ status: "loading" });
      setReports({ status: "loading" });
      listRuns(caseId, signal)
        .then(data => setRuns({ status: "ready", data }))
        .catch(error => !isAbort(error) && setRuns({ status: "error", message: message(error), missingRoute: isMissingRoute(error) }));
      listCaseReports(caseId, signal)
        .then(data => setReports({ status: "ready", data }))
        .catch(error => !isAbort(error) && setReports({ status: "error", message: message(error), missingRoute: isMissingRoute(error) }));
    },
    [caseId]
  );

  useEffect(() => {
    setRunId("");
    setGenerate({ status: "idle" });
    const controller = new AbortController();
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const reportCount = useMemo(() => {
    const counts = new Map<string, number>();
    if (reports.status === "ready") for (const r of reports.data) counts.set(r.run_id, (counts.get(r.run_id) ?? 0) + 1);
    return counts;
  }, [reports]);

  const runList = runs.status === "ready" ? runs.data : [];
  const selectedRun = runList.find(r => r.run_id === runId) ?? null;
  const canGenerate = selectedRun !== null && generate.status !== "saving";

  const submit = async () => {
    if (!selectedRun) return;
    setGenerate({ status: "saving" });
    try {
      const report = await createRunReport(caseId, selectedRun.run_id, generatedBy.trim() ? { generated_by: generatedBy.trim() } : {});
      setGenerate({ status: "done", report });
      setReports(current =>
        current.status === "ready"
          ? { status: "ready", data: [report, ...current.data.filter(r => r.report_id !== report.report_id)] }
          : { status: "ready", data: [report] }
      );
    } catch (error) {
      setGenerate({ status: "error", message: message(error) });
    }
  };

  const runLabel = (run: RunSummary) => {
    const evidence = run.manifest?.evidence?.length ?? 0;
    const made = reportCount.get(run.run_id) ?? 0;
    const when = run.created_at ? formatTimestamp(run.created_at, zone) : "time not recorded";
    return `${run.run_id} · ${when} · ${evidence} evidence${made ? ` · ${made} report${made === 1 ? "" : "s"}` : ""}`;
  };

  return (
    <section aria-label="Run reports" className="rounded-xl border border-trace/25 bg-trace/[0.04] p-5">
      <div className="flex gap-4">
        <ReportIcon size={26} className="shrink-0 text-trace-soft" />
        <div className="min-w-0 text-[13.5px]">
          <h3 className="font-semibold text-white">Immutable report from an analysis run</h3>
          <p className="mt-1 text-soft/80">
            Built only from the selected completed run, its stored snapshot, claims and manifest evidence. Each report is saved once and
            never edited; it reads “Pending review” until a reviewer decision is recorded separately.
          </p>
        </div>
      </div>

      <div className="mt-5 grid gap-3 lg:grid-cols-[minmax(0,1fr)_220px]">
        <div>
          <label htmlFor="report-run" className="mb-1.5 block text-[12px] text-soft/75">
            Completed analysis run
          </label>
          <select
            id="report-run"
            className={field}
            value={runId}
            onChange={e => {
              setRunId(e.target.value);
              if (generate.status === "error") setGenerate({ status: "idle" });
            }}
            disabled={runs.status !== "ready" || runList.length === 0 || generate.status === "saving"}
          >
            <option value="">
              {runs.status === "loading" ? "Loading runs…" : runList.length === 0 ? "No completed runs" : "Choose a completed run"}
            </option>
            {runList.map(run => (
              <option key={run.run_id} value={run.run_id}>
                {runLabel(run)}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="report-by" className="mb-1.5 block text-[12px] text-soft/75">
            Generated by (optional)
          </label>
          <input
            id="report-by"
            className={field}
            value={generatedBy}
            maxLength={255}
            onChange={e => setGeneratedBy(e.target.value)}
            placeholder="Self-declared name"
            disabled={generate.status === "saving"}
          />
        </div>
      </div>

      {runs.status === "error" && (
        <div className="mt-3">
          <ErrorNote text={runs.message} missingRoute={runs.missingRoute} what="analysis runs" />
        </div>
      )}
      {runs.status === "ready" && runList.length === 0 && (
        <p className="mt-3 text-[12.5px] text-soft/70">
          This case has no completed analysis runs. Create one from the Run diff tab (“New run from current evidence”), then come back here.
        </p>
      )}

      <div className="mt-4 flex flex-wrap items-center gap-3">
        <button type="button" onClick={submit} disabled={!canGenerate} className={primaryButton}>
          {generate.status === "saving" ? "Generating report…" : "Generate report"}
        </button>
        {!selectedRun && runList.length > 0 && <span className="text-[12px] text-muted">Select a completed run first.</span>}
        {generate.status === "done" && (
          <span role="status" className="text-[12.5px] text-teal-200">
            Saved {generate.report.report_id} (v{generate.report.report_version}) for {generate.report.run_id}.
          </span>
        )}
      </div>
      {generate.status === "error" && (
        <div className="mt-3">
          <ErrorNote text={generate.message} missingRoute={false} what="" />
        </div>
      )}

      <div className="mt-6 border-t border-white/[0.07] pt-4">
        <div className="flex items-center gap-3">
          <h4 className="text-[14px] font-semibold text-white">
            Saved reports
            {reports.status === "ready" && <span className="ml-1.5 text-[12.5px] font-normal text-muted">{reports.data.length}</span>}
          </h4>
          <button type="button" className={`${secondaryButton} ml-auto`} onClick={() => load()} disabled={reports.status === "loading"}>
            <Refresh size={14} />
            Refresh
          </button>
        </div>
        <div className="mt-3">
          {reports.status === "loading" && (
            <ul className="flex flex-col gap-2.5" aria-busy="true" aria-label="Loading saved reports">
              {[0, 1].map(i => (
                <li key={i} className="h-24 animate-pulse rounded-xl bg-white/[0.04]" />
              ))}
            </ul>
          )}
          {reports.status === "error" && <ErrorNote text={reports.message} missingRoute={reports.missingRoute} what="saved reports" />}
          {reports.status === "ready" && reports.data.length === 0 && (
            <p className="text-[12.5px] text-soft/70">No reports have been saved for this case yet.</p>
          )}
          {reports.status === "ready" && reports.data.length > 0 && (
            <ul className="flex flex-col gap-2.5">
              {reports.data.map(report => (
                <ReportRow key={report.report_id} report={report} isNew={generate.status === "done" && generate.report.report_id === report.report_id} />
              ))}
            </ul>
          )}
        </div>
      </div>
    </section>
  );
}
