// Role 4: Investigation Workspace. Findings, Timeline, Graph and Report as tabs over the same case data
// (GET evidence/events/findings/graph, or the labelled demo set). URL state: ?tab=…&finding=…&type=…&source=demo.
import { Suspense, lazy, useCallback, useMemo, useState, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import ConsoleShell, { GUTTER } from "../components/console/ConsoleShell";
import { Alert, CircleCheck, GraphIcon, ReportIcon, ScanSearch, Timeline as TimelineIcon } from "../components/console/icons";
import { useSourceLink } from "../components/console/useSourceLink";
import type { Finding } from "../api/types";
import { statusOf } from "../features/dashboard/components/FindingsPanel";
import KpiCard, { type KpiValue } from "../features/dashboard/components/KpiCard";
import NetworkBackdrop from "../features/dashboard/components/NetworkBackdrop";
import SourceBanner from "../features/dashboard/components/SourceBanner";
import { GLASS, SectionGate } from "../features/dashboard/components/ui";
import { readyData, useDashboardData, type Section } from "../features/dashboard/dashboardData";
import { entityIdsOfEvent } from "../features/dashboard/graph";
import FindingDetail from "../features/investigation/components/FindingDetail";
import FindingsList, { matchesFinding, type TypeFilter } from "../features/investigation/components/FindingsList";
import { CaseContext, FindingSummary } from "../features/investigation/components/FindingSidePanel";
import { buildIndex } from "../features/investigation/findingModel";
import { DEFAULT_CASE_ID, resolveSourceKind } from "../features/vault/evidenceSource";
import Report from "./Report";
import Timeline from "./Timeline";

// React Flow is only needed on the Graph tab, so it loads on demand.
const GraphView = lazy(() => import("./GraphView"));

export type WorkspaceTab = "findings" | "timeline" | "graph" | "report";
const TABS: { key: WorkspaceTab; label: string; icon: typeof ScanSearch }[] = [
  { key: "findings", label: "Findings", icon: ScanSearch },
  { key: "timeline", label: "Timeline", icon: TimelineIcon },
  { key: "graph", label: "Graph", icon: GraphIcon },
  { key: "report", label: "Report", icon: ReportIcon }
];
const isTab = (v: string | null): v is WorkspaceTab => TABS.some(t => t.key === v);
const isType = (v: string | null): v is Finding["type"] => ["contradiction", "anomaly", "correlation", "hypothesis"].includes(v ?? "");

const kpi = <T,>(section: Section<T>, count: (data: T) => number): KpiValue =>
  section.status === "ready" ? count(section.data) : section.status === "error" ? "unavailable" : null;

function Pane({ title, note, children, className = "" }: { title?: string; note?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`relative flex min-w-0 flex-col ${GLASS} p-5 ${className}`} aria-label={title}>
      <span aria-hidden="true" className="pointer-events-none absolute inset-x-8 top-0 h-px bg-gradient-to-r from-transparent via-trace-soft/60 to-transparent" />
      {title && (
        <h2 className="mb-3.5 text-[16.5px] font-semibold tracking-[-0.01em] text-white">
          {title}
          {note && <span className="ml-1.5 text-[13px] font-normal text-muted">{note}</span>}
        </h2>
      )}
      {children}
    </section>
  );
}

export default function InvestigationWorkspace() {
  const [params, setParams] = useSearchParams();
  const sourceKind = resolveSourceKind(params.get("source"));
  const caseId = DEFAULT_CASE_ID;
  const toPath = useSourceLink();
  const { data, reload } = useDashboardData(sourceKind, caseId);
  const [overrides, setOverrides] = useState<Map<string, Finding["status"]>>(new Map());
  const [query, setQuery] = useState("");

  const tab: WorkspaceTab = isTab(params.get("tab")) ? (params.get("tab") as WorkspaceTab) : "findings";
  const type: TypeFilter = isType(params.get("type")) ? (params.get("type") as Finding["type"]) : "all";

  const evidence = readyData(data.evidence);
  const events = readyData(data.events);
  const rawFindings = readyData(data.findings);
  const index = useMemo(() => buildIndex(events, evidence), [events, evidence]);

  // Review decisions the server confirmed in this session, layered over the loaded findings.
  const findings = useMemo(
    () => rawFindings?.map(f => (overrides.has(f.finding_id) ? { ...f, status: overrides.get(f.finding_id) } : f)) ?? null,
    [rawFindings, overrides]
  );
  const ordered = useMemo(
    () =>
      [...(findings ?? [])].sort(
        (a, b) => Number(statusOf(b) === "pending") - Number(statusOf(a) === "pending") || Number(b.type === "contradiction") - Number(a.type === "contradiction") || a.finding_id.localeCompare(b.finding_id)
      ),
    [findings]
  );
  const visible = ordered.filter(f => (type === "all" || f.type === type) && matchesFinding(f, index, query));
  const selected = ordered.find(f => f.finding_id === params.get("finding")) ?? visible[0] ?? ordered[0] ?? null;

  const cited = useMemo(() => new Set(selected?.evidence_event_ids ?? []), [selected]);
  const hotEntities = useMemo(
    () => new Set((selected?.evidence_event_ids ?? []).flatMap(id => (index.eventById.get(id) ? entityIdsOfEvent(index.eventById.get(id)!) : []))),
    [selected, index]
  );

  const update = useCallback(
    (changes: Record<string, string | null>) =>
      setParams(
        prev => {
          const next = new URLSearchParams(prev);
          Object.entries(changes).forEach(([k, v]) => (v === null ? next.delete(k) : next.set(k, v)));
          return next;
        },
        { replace: true }
      ),
    [setParams]
  );

  const tabHref = (key: WorkspaceTab) => {
    const next = new URLSearchParams(params);
    next.set("tab", key);
    return `/app/investigation?${next}`;
  };
  const errors = Object.values(data).filter(s => s.status === "error").length;
  const contradictions = (d: Finding[]) => d.filter(f => f.type === "contradiction");

  return (
    <ConsoleShell>
      <div className={`mx-auto max-w-[1680px] pt-5 pb-14 ${GUTTER}`}>
        <SourceBanner
          sourceKind={sourceKind}
          errors={errors}
          total={4}
          onRetry={reload}
          liveHref={`/app/investigation?tab=${tab}`}
          demoHref={`/app/investigation?tab=${tab}&source=demo`}
        />

        {/* Hero */}
        <section className="relative px-1 pt-1">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-y-[-45%] right-[-4%] left-[38%] hidden lg:block [mask-image:radial-gradient(ellipse_70%_75%_at_55%_45%,#000_35%,transparent_80%)]"
          >
            <NetworkBackdrop />
          </div>
          <div className="relative max-w-[680px] [text-shadow:0_2px_18px_rgba(5,7,12,0.9)]">
            <p className="text-[11px] font-semibold tracking-[0.38em] text-soft/80">
              INVESTIGATION WORKSPACE <span className="ml-1.5 inline-block size-[5px] -translate-y-0.5 rounded-full bg-alert align-middle" />
            </p>
            <h1 className="mt-3 text-[clamp(2.2rem,3.8vw,3.4rem)] leading-[1.05] font-bold tracking-[-0.025em]">
              Connect the <span className="text-alert drop-shadow-[0_0_20px_rgba(239,43,60,0.45)]">Dots.</span>
            </h1>
            <p className="mt-3 max-w-[560px] text-[16px] leading-relaxed text-soft/85">
              Work through each finding, check it against the events and evidence it cites, follow the timeline and the entity graph, then build
              the report.
            </p>
          </div>
        </section>

        {/* Tabs */}
        <nav aria-label="Workspace sections" className={`mt-7 grid grid-cols-2 overflow-hidden sm:grid-cols-4 ${GLASS} p-1.5`}>
          {TABS.map(({ key, label, icon: Icon }) => {
            const active = tab === key;
            return (
              <Link
                key={key}
                to={tabHref(key)}
                replace
                aria-current={active ? "page" : undefined}
                className={`flex items-center justify-center gap-2.5 rounded-xl px-4 py-3 text-[14.5px] transition ${
                  active
                    ? "border border-alert/60 bg-[linear-gradient(180deg,rgba(239,43,60,0.18),rgba(239,43,60,0.05))] text-white shadow-[0_0_24px_-6px_rgba(239,43,60,0.7)]"
                    : "border border-transparent text-soft/75 hover:bg-white/[0.03] hover:text-white"
                }`}
              >
                <Icon size={18} className={active ? "text-alert" : ""} />
                {label}
              </Link>
            );
          })}
        </nav>

        {tab === "findings" && (
          <>
            <div className="mt-5 grid grid-cols-2 gap-3 sm:gap-4 2xl:grid-cols-4">
              <KpiCard
                tone="trace"
                icon={<ScanSearch size={20} />}
                value={kpi(data.findings, d => d.length)}
                label="Total findings"
                sub={findings && `${findings.filter(f => statusOf(f) === "pending").length} need review`}
                to={toPath("/app/investigation", { tab: "findings" })}
              />
              <KpiCard
                tone="alert"
                icon={<Alert size={20} />}
                value={kpi(data.findings, d => contradictions(d).length)}
                label="Contradictions"
                sub={findings && `${contradictions(findings).filter(f => statusOf(f) === "pending").length} unresolved`}
                to={toPath("/app/investigation", { tab: "findings", type: "contradiction" })}
              />
              <KpiCard
                tone="trace"
                icon={<Alert size={20} />}
                value={kpi(data.findings, d => d.filter(f => f.type === "anomaly").length)}
                label="Anomalies"
                sub={findings && `${findings.filter(f => f.type === "anomaly" && statusOf(f) === "pending").length} unresolved`}
                to={toPath("/app/investigation", { tab: "findings", type: "anomaly" })}
              />
              <KpiCard
                tone="trace"
                icon={<CircleCheck size={20} />}
                value={kpi(data.findings, d => d.filter(f => statusOf(f) === "approved").length)}
                label="Approved"
                sub="Reviewed by an investigator"
              />
            </div>

            <div className="mt-5 grid gap-5 lg:grid-cols-2 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.05fr)_300px]">
              <Pane title="Findings" note={findings ? `${visible.length} of ${findings.length}` : undefined}>
                <SectionGate section={data.findings} isEmpty={d => d.length === 0} empty="No findings yet. Run the analysis to generate them." rows={5}>
                  {() => (
                    <FindingsList
                      findings={visible}
                      index={index}
                      selectedId={selected?.finding_id ?? null}
                      onSelect={id => update({ finding: id })}
                      query={query}
                      onQuery={setQuery}
                      type={type}
                      onType={t => update({ type: t === "all" ? null : t })}
                    />
                  )}
                </SectionGate>
              </Pane>

              <Pane
                className={
                  selected?.type === "contradiction"
                    ? "border-alert/45 shadow-[0_0_40px_-14px_rgba(239,43,60,0.7),inset_0_1px_0_rgba(255,90,102,0.08)]"
                    : ""
                }
              >
                {data.findings.status !== "ready" ? (
                  <SectionGate section={data.findings} empty="" rows={6}>
                    {() => null}
                  </SectionGate>
                ) : selected ? (
                  <FindingDetail finding={selected} index={index} sourceKind={sourceKind} />
                ) : (
                  <p className="py-12 text-center text-[13.5px] text-soft/70">Select a finding to see its evidence.</p>
                )}
              </Pane>

              <div className="flex flex-col gap-5 lg:col-span-2 lg:grid lg:grid-cols-2 xl:col-span-1 xl:flex">
                <CaseContext
                  caseId={caseId}
                  sourceKind={sourceKind}
                  counts={{
                    evidence: evidence?.length ?? null,
                    events: events?.length ?? null,
                    findings: findings?.length ?? null,
                    contradictions: findings ? contradictions(findings).length : null
                  }}
                />
                {selected && (
                  <FindingSummary
                    finding={selected}
                    index={index}
                    sourceKind={sourceKind}
                    onStatus={(id, status) => setOverrides(prev => new Map(prev).set(id, status))}
                  />
                )}
              </div>
            </div>
          </>
        )}

        {tab === "timeline" && (
          <Pane title="Investigation timeline" note={events ? `${events.length} events` : undefined} className="mt-5">
            <SectionGate section={data.events} isEmpty={d => d.length === 0} empty="No events parsed yet." rows={6}>
              {list => <Timeline events={list} cited={cited} citedLabel={selected?.finding_id} />}
            </SectionGate>
          </Pane>
        )}

        {tab === "graph" && (
          <Pane title="Entity graph" className="mt-5">
            <SectionGate section={data.graph} isEmpty={g => g.nodes.length === 0} empty="No entities in the graph yet." rows={6}>
              {graph => (
                <Suspense fallback={<div className="h-[560px] animate-pulse rounded-xl bg-white/[0.04]" aria-label="Loading graph" />}>
                  <GraphView graph={graph} hot={hotEntities} hotLabel={selected?.finding_id} />
                </Suspense>
              )}
            </SectionGate>
          </Pane>
        )}

        {tab === "report" && (
          <Pane title="Report" className="mt-5">
            <Report caseId={caseId} sourceKind={sourceKind} evidence={evidence} findings={findings} />
          </Pane>
        )}
      </div>
    </ConsoleShell>
  );
}
