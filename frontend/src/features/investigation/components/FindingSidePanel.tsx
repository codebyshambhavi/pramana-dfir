// Role 4: right column: case context, the selected finding's summary, and review actions.
// Review actions call PATCH /findings/{id} in live mode. In demo mode there's no backend, so they're disabled and say why.
import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { Check, Close, Database, Folder, Shield } from "../../../components/console/icons";
import { useSourceLink } from "../../../components/console/useSourceLink";
import { API_URL, listFindingReviews, updateFindingStatus } from "../../../api/client";
import type { Finding, FindingReviewDecision } from "../../../api/types";
import { StatusChip, statusOf } from "../../dashboard/components/FindingsPanel";
import { GLASS } from "../../dashboard/components/ui";
import type { EvidenceSourceKind } from "../../vault/evidenceSource";
import { TYPE_LABEL, evidenceIdsFor, type CaseIndex } from "../findingModel";

export interface CaseCounts {
  evidence: number | null;
  events: number | null;
  findings: number | null;
  contradictions: number | null;
}

function Card({ title, icon, children }: { title: string; icon: ReactNode; children: ReactNode }) {
  return (
    <section aria-label={title} className={`relative ${GLASS} p-5`}>
      <span aria-hidden="true" className="pointer-events-none absolute inset-x-8 top-0 h-px bg-gradient-to-r from-transparent via-trace-soft/60 to-transparent" />
      <h2 className="flex items-center gap-2.5 text-[15px] font-semibold text-white">
        <span className="text-trace-soft">{icon}</span>
        {title}
      </h2>
      <div className="mt-3.5">{children}</div>
    </section>
  );
}

const count = (n: number | null) => (n === null ? "—" : n);

export function CaseContext({ caseId, sourceKind, counts }: { caseId: string; sourceKind: EvidenceSourceKind; counts: CaseCounts }) {
  return (
    <Card title="Case context" icon={<Folder size={18} />}>
      <p className="min-w-0 max-w-full break-all text-[18px] font-semibold tracking-[-0.01em]" title={caseId}>{caseId}</p>
      <p className={`mt-1 flex items-center gap-1.5 text-[12px] ${sourceKind !== "api" ? "text-amber-200" : "text-teal-200"}`}>
        <Database size={13} />
        {sourceKind === "demo" ? "Demo data · synthetic" : sourceKind === "recorded" ? "Recorded data · read-only" : `Live API · ${API_URL}`}
      </p>
      <dl className="mt-3 grid grid-cols-2 gap-x-3 gap-y-2 text-[13px]">
        {(
          [
            ["Evidence", counts.evidence, "text-trace-soft"],
            ["Events", counts.events, "text-trace-soft"],
            ["Findings", counts.findings, "text-trace-soft"],
            ["Contradictions", counts.contradictions, "text-alert-soft"]
          ] as const
        ).map(([label, value, tone]) => (
          <div key={label} className="flex items-baseline gap-1.5">
            <dd className={`font-semibold tabular-nums ${tone}`}>{count(value)}</dd>
            <dt className="text-soft/70">{label}</dt>
          </div>
        ))}
      </dl>
    </Card>
  );
}

type Save = { state: "idle" } | { state: "saving"; status: "approved" | "rejected" } | { state: "saved"; status: string } | { state: "error"; message: string };

export function FindingSummary({
  finding,
  index,
  sourceKind,
  onStatus
}: {
  finding: Finding;
  index: CaseIndex;
  sourceKind: EvidenceSourceKind;
  onStatus: (id: string, status: "pending" | "approved" | "rejected") => void;
}) {
  const toPath = useSourceLink();
  const [save, setSave] = useState<Save>({ state: "idle" });
  const [reviewerLabel, setReviewerLabel] = useState("");
  const [rationale, setRationale] = useState("");
  const [reviews, setReviews] = useState<FindingReviewDecision[]>([]);
  const [reviewsError, setReviewsError] = useState<string | null>(null);
  useEffect(() => {
    setSave({ state: "idle" });
    setRationale("");
    setReviews([]);
    setReviewsError(null);
    if (sourceKind !== "api") return undefined;
    const controller = new AbortController();
    listFindingReviews(finding.finding_id, controller.signal)
      .then(setReviews)
      .catch(error => {
        if (!controller.signal.aborted) setReviewsError(error instanceof Error ? error.message : "Review history unavailable");
      });
    return () => controller.abort();
  }, [finding.finding_id, sourceKind]);
  const evidence = evidenceIdsFor(finding, index);
  const readOnly = sourceKind !== "api";

  const decide = async (status: "approved" | "rejected") => {
    setSave({ state: "saving", status });
    try {
      const result = await updateFindingStatus(finding.finding_id, status, reviewerLabel.trim(), rationale.trim());
      // Show what the server says it stored; the mock may echo a different example ID, so key on ours.
      onStatus(finding.finding_id, result.status ?? status);
      setSave({ state: "saved", status: result.status ?? status });
      try {
        const history = await listFindingReviews(finding.finding_id);
        setReviews(history);
        setReviewsError(null);
      } catch (historyError) {
        setReviewsError(historyError instanceof Error ? historyError.message : "Review history refresh failed");
      }
    } catch (error) {
      setSave({ state: "error", message: error instanceof Error ? error.message : "The decision was not saved." });
    }
  };

  return (
    <>
      <Card title="Finding summary" icon={<Shield size={18} />}>
        <dl className="space-y-2.5 text-[13px]">
          <div className="flex justify-between gap-3">
            <dt className="text-soft/65">Type</dt>
            <dd className="text-white">{TYPE_LABEL[finding.type]}</dd>
          </div>
          <div className="flex items-center justify-between gap-3">
            <dt className="text-soft/65">Status</dt>
            <dd>
              <StatusChip finding={finding} />
            </dd>
          </div>
          <div className="flex justify-between gap-3">
            <dt className="text-soft/65">Cited events</dt>
            <dd className="text-white tabular-nums">{finding.evidence_event_ids.length}</dd>
          </div>
          <div>
            <dt className="text-soft/65">Related evidence</dt>
            <dd className="mt-1.5 flex flex-wrap gap-1.5">
              {evidence.length ? (
                evidence.map(id => (
                  <Link
                    key={id}
                    to={toPath("/app/evidence", { open: id })}
                    className="rounded-md border border-trace/40 bg-trace/10 px-2 py-0.5 text-[12px] text-trace-soft transition hover:border-trace hover:text-white"
                  >
                    {id}
                  </Link>
                ))
              ) : (
                <span className="text-soft/55">Not resolvable from loaded events</span>
              )}
            </dd>
          </div>
        </dl>
      </Card>

      <Card title="Review" icon={<Check size={18} />}>
        <label className="mb-2 block text-[12px] text-soft/75" htmlFor="reviewer-label">Reviewer name (self-declared)</label>
        <input id="reviewer-label" value={reviewerLabel} onChange={event => setReviewerLabel(event.target.value)} maxLength={120} placeholder="Name of reviewing investigator" disabled={readOnly || save.state === "saving"} className="mb-3 w-full rounded-lg border border-white/10 bg-black/20 px-3 py-2 text-[13px] text-white placeholder:text-soft/40" />
        <label className="mb-2 block text-[12px] text-soft/75" htmlFor="review-rationale">Review rationale</label>
        <textarea id="review-rationale" value={rationale} onChange={event => setRationale(event.target.value)} maxLength={4000} rows={3} placeholder="Explain the basis for this decision" disabled={readOnly || save.state === "saving"} className="mb-3 w-full resize-y rounded-lg border border-white/10 bg-black/20 px-3 py-2 text-[13px] text-white placeholder:text-soft/40" />
        <div className="grid grid-cols-2 gap-2.5">
          <button
            type="button"
            disabled={readOnly || save.state === "saving" || statusOf(finding) === "approved" || reviewerLabel.trim().length < 2 || rationale.trim().length < 5}
            onClick={() => decide("approved")}
            className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-teal-400/45 bg-teal-400/10 px-3 py-2.5 text-[13.5px] text-teal-100 transition hover:bg-teal-400/20 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <Check size={15} />
            {save.state === "saving" && save.status === "approved" ? "Saving…" : "Approve"}
          </button>
          <button
            type="button"
            disabled={readOnly || save.state === "saving" || statusOf(finding) === "rejected" || reviewerLabel.trim().length < 2 || rationale.trim().length < 5}
            onClick={() => decide("rejected")}
            className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-alert/45 bg-alert/10 px-3 py-2.5 text-[13.5px] text-alert-soft transition hover:bg-alert/20 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <Close size={15} />
            {save.state === "saving" && save.status === "rejected" ? "Saving…" : "Reject"}
          </button>
        </div>
        <p role="status" className="mt-3 text-[12px] leading-relaxed text-soft/70">
          {readOnly
            ? sourceKind === "recorded"
              ? "Recorded investigations are read-only, so review decisions cannot be saved."
              : "Demo data has no backend, so decisions can't be saved. In live mode these buttons call PATCH /findings/{id}."
            : save.state === "saved"
              ? `Saved: the server recorded "${save.status}".`
              : save.state === "error"
                ? <span className="text-alert-soft">{save.message}</span>
                : "Decisions are recorded in append-only review history. Reviewer names are self-declared; authentication is not yet implemented."}
        </p>
        <div className="mt-4 border-t border-white/10 pt-3">
          <h3 className="text-[12px] font-semibold uppercase tracking-wide text-soft/75">Decision history</h3>
          {reviewsError ? <p className="mt-2 text-[12px] text-alert-soft">{reviewsError}</p> : reviews.length === 0 ? (
            <p className="mt-2 text-[12px] text-soft/55">No review decisions recorded.</p>
          ) : (
            <ol className="mt-2 space-y-3">
              {reviews.map(review => (
                <li key={review.review_id} className="rounded-lg border border-white/10 bg-black/15 p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className={`text-[12px] font-semibold ${review.decision === "approved" ? "text-teal-200" : "text-alert-soft"}`}>{review.decision.toUpperCase()}</span>
                    <time className="text-[11px] text-soft/55" dateTime={review.decided_at}>{new Date(review.decided_at).toLocaleString()}</time>
                  </div>
                  <p className="mt-1 text-[12px] text-white">{review.reviewer_label} <span className="text-soft/55">· self-declared</span></p>
                  <p className="mt-1 whitespace-pre-wrap break-words text-[12px] leading-relaxed text-soft/75">{review.rationale}</p>
                </li>
              ))}
            </ol>
          )}
        </div>
      </Card>
    </>
  );
}
