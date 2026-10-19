// Role 4: the selected finding (centre column): claim, then Evidence, Analysis, Alternatives and Notes tabs.
// Evidence comes from GET /findings/{id}/lineage in live mode, or the same lineage built from loaded records in demo.
import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { Alert, ArrowRight, Info, MapPin, ScanSearch } from "../../../components/console/icons";
import { useSourceLink } from "../../../components/console/useSourceLink";
import { getFindingLineage } from "../../../api/client";
import type { Finding, FindingLineage } from "../../../api/types";
import { StatusChip, TYPE_CHIP } from "../../dashboard/components/FindingsPanel";
import { describe } from "../../dashboard/components/TimelinePanel";
import { formatStamp } from "../../dashboard/components/ui";
import { CopyButton, FileKindBadge } from "../../vault/components/ui";
import type { EvidenceSourceKind } from "../../vault/evidenceSource";
import { fileKind, truncateHash } from "../../vault/model";
import { TYPE_LABEL, lineageFromIndex, type CaseIndex } from "../findingModel";

type Tab = "evidence" | "analysis" | "alternatives" | "notes";

function Confidence({ value, tone }: { value: number; tone: "alert" | "trace" }) {
  return (
    <span className="flex items-center gap-2.5">
      <span className="h-1.5 w-24 overflow-hidden rounded-full bg-white/[0.08]">
        <span className={`block h-full rounded-full ${tone === "alert" ? "bg-alert shadow-[0_0_8px_#ef2b3c]" : "bg-trace shadow-[0_0_8px_#3b8cff]"}`} style={{ width: `${Math.round(value * 100)}%` }} />
      </span>
      <span className="text-[13px] text-white tabular-nums">{Math.round(value * 100)}%</span>
    </span>
  );
}

function Empty({ children }: { children: ReactNode }) {
  return <p className="rounded-lg border border-dashed border-white/10 px-4 py-6 text-center text-[13px] text-soft/70">{children}</p>;
}

function useLineage(finding: Finding, index: CaseIndex, sourceKind: EvidenceSourceKind) {
  const [state, setState] = useState<{ status: "loading" } | { status: "error"; message: string } | { status: "ready"; data: FindingLineage }>({
    status: "loading"
  });
  useEffect(() => {
    if (sourceKind === "demo") {
      setState({ status: "ready", data: lineageFromIndex(finding, index) });
      return undefined;
    }
    const controller = new AbortController();
    setState({ status: "loading" });
    getFindingLineage(finding.finding_id, controller.signal)
      .then(data => setState({ status: "ready", data }))
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        setState({ status: "error", message: error instanceof Error ? error.message : "Lineage unavailable" });
      });
    return () => controller.abort();
  }, [finding.finding_id, index, sourceKind]); // eslint-disable-line react-hooks/exhaustive-deps
  return state;
}

function EvidenceTab({ finding, index, sourceKind }: { finding: Finding; index: CaseIndex; sourceKind: EvidenceSourceKind }) {
  const lineage = useLineage(finding, index, sourceKind);
  const toPath = useSourceLink();
  if (lineage.status === "loading") return <div className="h-40 animate-pulse rounded-xl bg-white/[0.04]" aria-label="Loading lineage" />;
  if (lineage.status === "error")
    return (
      <Empty>
        Lineage unavailable: {lineage.message}
      </Empty>
    );
  if (lineage.data.evidence.length === 0) return <Empty>The cited events don't resolve to any loaded evidence.</Empty>;

  return (
    <ul className="grid gap-3 sm:grid-cols-2">
      {lineage.data.evidence.map(ev => {
        const events = lineage.data.events.filter(e => e.evidence_id === ev.evidence_id);
        return (
          <li
            key={ev.evidence_id}
            className="group relative flex flex-col overflow-hidden rounded-xl border border-trace/30 bg-[linear-gradient(160deg,rgba(16,28,52,0.85),rgba(7,11,20,0.9))] p-4 shadow-[0_0_22px_-12px_rgba(59,140,255,0.7)] transition hover:border-trace/60"
          >
            <span aria-hidden="true" className="absolute inset-x-5 top-0 h-px bg-gradient-to-r from-transparent via-trace-soft/70 to-transparent" />
            <div className="flex items-center justify-between gap-2">
              <span className="text-[13px] font-semibold text-white">{ev.evidence_id}</span>
              <FileKindBadge kind={fileKind(ev.filename)} />
            </div>
            <p className="mt-1 truncate text-[13.5px] text-soft" title={ev.filename}>
              {ev.filename}
            </p>
            <span className="mt-2 flex items-center gap-1">
              <code className="rounded-md border border-white/[0.07] bg-black/30 px-2 py-0.5 font-mono text-[12px] text-[#cfe0ff]" title={ev.sha256}>
                {truncateHash(ev.sha256)}
              </code>
              <CopyButton text={ev.sha256} label={`Copy SHA-256 of ${ev.evidence_id}`} />
            </span>
            <ul className="mt-3 space-y-1.5 border-t border-white/[0.06] pt-3">
              {events.map(e => {
                const full = index.eventById.get(e.event_id);
                return (
                  <li key={e.event_id} className="text-[12.5px]">
                    <span className="text-soft/55 tabular-nums">{e.event_id}</span>
                    <span className="ml-2 font-mono text-[11.5px] text-soft/60">{e.artifact_ref}</span>
                    {full && (
                      <span className="mt-0.5 block text-soft/90">
                        {describe(full)}
                        {full.location && (
                          <span className="ml-1.5 inline-flex items-center gap-1 rounded border border-teal-400/30 px-1 text-[11px] text-teal-200">
                            <MapPin size={11} />
                            from metadata
                          </span>
                        )}
                        <span className="block text-[11.5px] text-soft/55">{formatStamp(full.timestamp)}</span>
                      </span>
                    )}
                  </li>
                );
              })}
            </ul>
            <Link
              to={toPath("/app/evidence", { open: ev.evidence_id })}
              className="mt-3 inline-flex items-center gap-1.5 self-start text-[12.5px] text-trace-soft hover:text-white"
            >
              Open in Evidence Vault <ArrowRight size={13} />
            </Link>
          </li>
        );
      })}
    </ul>
  );
}

function AnalysisTab({ finding, index }: { finding: Finding; index: CaseIndex }) {
  const cited = finding.evidence_event_ids.map(id => ({ id, event: index.eventById.get(id) }));
  return (
    <div className="space-y-5">
      <dl className="grid gap-x-6 gap-y-3 text-[13.5px] sm:grid-cols-[120px_minmax(0,1fr)]">
        <dt className="text-soft/60">Reasoning</dt>
        <dd className="text-white">{finding.reasoning ?? <span className="text-soft/55">No reasoning supplied by the analysis.</span>}</dd>
        <dt className="text-soft/60">Confidence</dt>
        <dd>
          <Confidence value={finding.confidence} tone={finding.type === "contradiction" ? "alert" : "trace"} />
        </dd>
        <dt className="text-soft/60">Human review</dt>
        <dd className="text-white">{finding.needs_human_review ? "Required" : "Not required"}</dd>
      </dl>
      <div>
        <p className="text-[13px] font-semibold text-white">Cited events ({cited.length})</p>
        <ol className="relative mt-3 space-y-3 pl-6">
          <span aria-hidden="true" className="absolute top-1.5 bottom-1.5 left-[5px] w-px bg-trace/40" />
          {cited.map(({ id, event }) => (
            <li key={id} className="relative text-[13px]">
              <span aria-hidden="true" className="absolute top-1.5 -left-6 size-[11px] rounded-full border-2 border-trace bg-ink shadow-[0_0_8px_rgba(59,140,255,0.8)]" />
              {event ? (
                <>
                  <span className="text-soft/60 tabular-nums">
                    {formatStamp(event.timestamp)} · {event.evidence_id}
                  </span>
                  <span className="block text-white">{describe(event)}</span>
                </>
              ) : (
                <span className="text-soft/60">{id} (not in the loaded events)</span>
              )}
            </li>
          ))}
        </ol>
      </div>
    </div>
  );
}

function AlternativesTab({ finding }: { finding: Finding }) {
  if (!finding.alternatives?.length) return <Empty>The analysis supplied no alternative explanations for this finding.</Empty>;
  return (
    <ul className="space-y-3">
      {finding.alternatives.map(alt => (
        <li key={alt.claim} className="rounded-xl border border-violet-400/25 bg-violet-500/[0.05] p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-[14px] text-white">{alt.claim}</p>
            <Confidence value={alt.confidence} tone="trace" />
          </div>
          {alt.needed_evidence && alt.needed_evidence.length > 0 && (
            <p className="mt-2.5 flex flex-wrap items-center gap-1.5 text-[12px] text-soft/70">
              Would be settled by:
              {alt.needed_evidence.map(n => (
                <span key={n} className="rounded-md border border-white/12 px-1.5 py-px text-soft">
                  {n}
                </span>
              ))}
            </p>
          )}
        </li>
      ))}
    </ul>
  );
}

export default function FindingDetail({ finding, index, sourceKind }: { finding: Finding; index: CaseIndex; sourceKind: EvidenceSourceKind }) {
  const [tab, setTab] = useState<Tab>("evidence");
  useEffect(() => setTab("evidence"), [finding.finding_id]);
  const tabs: [Tab, string][] = [
    ["evidence", "Evidence"],
    ["analysis", "Analysis"],
    ["alternatives", `Alternatives${finding.alternatives?.length ? ` (${finding.alternatives.length})` : ""}`],
    ["notes", "Notes"]
  ];
  const hot = finding.type === "contradiction";

  return (
    <article aria-label={`Finding ${finding.finding_id}`} className="flex min-h-0 flex-1 flex-col">
      <header className="flex items-start gap-3.5">
        <span
          className={`flex size-11 shrink-0 items-center justify-center rounded-xl border ${
            hot ? "border-alert/50 bg-alert/10 text-alert shadow-[0_0_18px_rgba(239,43,60,0.5)]" : "border-trace/45 bg-trace/10 text-trace-soft shadow-[0_0_16px_rgba(59,140,255,0.4)]"
          }`}
        >
          {hot ? <Alert size={21} /> : <ScanSearch size={21} />}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[13px] text-soft/65 tabular-nums">{finding.finding_id}</span>
            <span className={`rounded-md border px-1.5 py-px text-[11.5px] ${TYPE_CHIP[finding.type] ?? TYPE_CHIP.hypothesis}`}>{TYPE_LABEL[finding.type]}</span>
            <StatusChip finding={finding} />
          </div>
          <h2 className="mt-1.5 text-[20px] leading-snug font-semibold tracking-[-0.01em] text-white">{finding.claim}</h2>
        </div>
      </header>

      <div role="tablist" aria-label="Finding sections" className="mt-5 flex gap-5 overflow-x-auto border-b border-white/[0.07]">
        {tabs.map(([key, label]) => (
          <button
            key={key}
            type="button"
            role="tab"
            aria-selected={tab === key}
            onClick={() => setTab(key)}
            className={`relative shrink-0 pb-2.5 text-[13.5px] transition-colors ${
              tab === key
                ? "text-white after:absolute after:inset-x-0 after:bottom-[-1px] after:h-[2px] after:bg-alert after:shadow-[0_0_10px_rgba(239,43,60,0.8)]"
                : "text-soft/65 hover:text-white"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      <div role="tabpanel" className="mt-4 min-h-0 flex-1">
        {tab === "evidence" && <EvidenceTab finding={finding} index={index} sourceKind={sourceKind} />}
        {tab === "analysis" && <AnalysisTab finding={finding} index={index} />}
        {tab === "alternatives" && <AlternativesTab finding={finding} />}
        {tab === "notes" && (
          <div className="flex gap-3 rounded-xl border border-trace/20 bg-trace/[0.04] p-4 text-[13px] text-soft/80">
            <Info size={18} className="mt-px shrink-0 text-trace-soft" />
            <p>
              Analysis notes aren't part of the finding contract yet, and no endpoint stores them, so there's nowhere to save a note. Record
              notes in the report once that's built.
            </p>
          </div>
        )}
      </div>
    </article>
  );
}
