// Role 4: Investigation Dashboard. Every number, chart, event, finding and alert here is derived from the same
// four documented endpoints (evidence, events, findings, graph), or from the labelled demo set with ?source=demo.
import { useMemo, type ComponentType, type SVGProps } from "react";
import { Link, NavLink, useSearchParams } from "react-router-dom";
import ConsoleShell, { GUTTER } from "../components/console/ConsoleShell";
import {
  Activity,
  Alert,
  ArrowRight,
  FileIcon,
  Folder,
  GraphIcon,
  LayoutGrid,
  ScanSearch,
} from "../components/console/icons";
import { useSourceLink } from "../components/console/useSourceLink";
import { API_URL } from "../api/client";
import type { CaseEvent, EvidenceItem, Finding } from "../api/types";
import AlertsPanel, { type AlertItem } from "../features/dashboard/components/AlertsPanel";
import EntitiesPanel from "../features/dashboard/components/EntitiesPanel";
import EvidenceOverview from "../features/dashboard/components/EvidenceOverview";
import FindingsPanel, { statusOf } from "../features/dashboard/components/FindingsPanel";
import KpiCard, { type KpiValue } from "../features/dashboard/components/KpiCard";
import NetworkBackdrop from "../features/dashboard/components/NetworkBackdrop";
import TimelinePanel from "../features/dashboard/components/TimelinePanel";
import { GLASS, Panel, PanelLink, SectionGate, formatStamp } from "../features/dashboard/components/ui";
import SourceBanner from "../features/dashboard/components/SourceBanner";
import { readyData, useDashboardData, type Section } from "../features/dashboard/dashboardData";
import { DEFAULT_CASE_ID, resolveSourceKind } from "../features/vault/evidenceSource";
import { fileKind, isParsedKind } from "../features/vault/model";

type IconType = ComponentType<SVGProps<SVGSVGElement> & { size?: number }>;

const SECTIONS: { to: string; label: string; icon: IconType; end?: boolean }[] = [
  { to: "/app", label: "Dashboard", icon: LayoutGrid, end: true },
  { to: "/app/evidence", label: "Evidence Vault", icon: Folder },
  { to: "/app/investigation", label: "Investigation Workspace", icon: GraphIcon }
];

const span = (times: string[]) => {
  const sorted = times.map(t => Date.parse(t)).filter(t => !Number.isNaN(t)).sort((a, b) => a - b);
  return sorted.length ? { first: new Date(sorted[0]).toISOString(), last: new Date(sorted[sorted.length - 1]).toISOString() } : null;
};

/** Loading → null, failed source → "unavailable", otherwise the computed number. */
const kpi = <T,>(section: Section<T>, count: (data: T) => number): KpiValue =>
  section.status === "ready" ? count(section.data) : section.status === "error" ? "unavailable" : null;

function buildAlerts(
  evidence: EvidenceItem[] | null,
  events: CaseEvent[] | null,
  findings: Finding[] | null,
  evidenceFor: (f: Finding) => string[],
  linkTo: (id: string) => string,
  linkToFinding: (f: Finding) => string
): AlertItem[] {
  const alerts: AlertItem[] = [];
  const eventTime = new Map(events?.map(e => [e.event_id, e.timestamp]));
  for (const f of findings ?? []) {
    if (statusOf(f) !== "pending" || (f.type !== "contradiction" && f.type !== "anomaly")) continue;
    const cited = span(f.evidence_event_ids.map(id => eventTime.get(id)).filter((t): t is string => Boolean(t)));
    alerts.push({
      key: f.finding_id,
      kind: f.type,
      title: f.type === "contradiction" ? "Contradiction needs review" : "Anomaly needs review",
      detail: f.claim,
      time: cited ? { iso: cited.last, label: "Time of the latest cited event" } : undefined,
      to: linkToFinding(f)
    });
  }
  const noCustody = evidence?.filter(e => e.custody.length === 0) ?? [];
  if (noCustody.length)
    alerts.push({
      key: "custody",
      kind: "custody",
      title: noCustody.length === 1 ? `${noCustody[0].evidence_id} has no custody entries` : `${noCustody.length} items have no custody entries`,
      detail: noCustody.map(e => e.filename).join(", "),
      time: { iso: noCustody[noCustody.length - 1].intake_time, label: "Intake time" },
      to: linkTo(noCustody[0].evidence_id)
    });
  const unparsed = evidence?.filter(e => !isParsedKind(fileKind(e.filename))) ?? [];
  if (unparsed.length)
    alerts.push({
      key: "unparsed",
      kind: "unparsed",
      title: `${unparsed.length} ${unparsed.length === 1 ? "file has" : "files have"} no parser`,
      detail: `${unparsed.map(e => e.filename).join(", ")} produce no events`,
      to: linkTo(unparsed[0].evidence_id)
    });
  return alerts;
}

export default function Dashboard() {
  const [searchParams] = useSearchParams();
  const sourceKind = resolveSourceKind(searchParams.get("source"));
  const caseId = DEFAULT_CASE_ID;
  const toPath = useSourceLink();
  const { data, reload } = useDashboardData(sourceKind, caseId);

  const evidence = readyData(data.evidence);
  const events = readyData(data.events);
  const findings = readyData(data.findings);

  const derived = useMemo(() => {
    const eventById = new Map(events?.map(e => [e.event_id, e]));
    const evidenceFor = (f: Finding) => [
      ...new Set(f.evidence_event_ids.map(id => eventById.get(id)?.evidence_id).filter((id): id is string => Boolean(id)))
    ];
    const pendingContradictions = findings?.filter(f => f.type === "contradiction" && statusOf(f) === "pending") ?? [];
    const flagged = new Set(pendingContradictions.flatMap(f => f.evidence_event_ids));
    return { evidenceFor, flagged };
  }, [events, findings]);

  const linkToEvidence = (id: string) => toPath("/app/evidence", { open: id });
  const linkToFinding = (f: Finding) => toPath("/app/investigation", { tab: "findings", finding: f.finding_id });
  const alerts = buildAlerts(evidence, events, findings, derived.evidenceFor, linkToEvidence, linkToFinding);
  const intake = evidence ? span(evidence.map(e => e.intake_time)) : null;
  const activity = events ? span(events.map(e => e.timestamp)) : null;
  const errors = Object.values(data).filter(s => s.status === "error").length;
  const contradictions = findings?.filter(f => f.type === "contradiction") ?? null;
  const recover =
    sourceKind === "api" ? (
      <Link to="/app?source=demo" className="text-[12.5px] text-trace-soft underline-offset-4 hover:text-white hover:underline">
        Open demo data
      </Link>
    ) : undefined;

  return (
    <ConsoleShell>
      <div className={`mx-auto max-w-[1680px] pt-5 pb-14 ${GUTTER}`}>
        <SourceBanner sourceKind={sourceKind} errors={errors} total={4} onRetry={reload} liveHref="/app" demoHref="/app?source=demo" />

        <div className="grid gap-5 xl:grid-cols-[248px_minmax(0,1fr)]">
          {/* Case rail */}
          <aside className="order-2 flex flex-col gap-5 xl:order-none">
            <section aria-label="Case" className={`${GLASS} p-5`}>
              <div className="flex items-center gap-3">
                <Folder size={22} className="text-soft" />
                <h2 className="text-[18px] font-semibold tracking-[-0.01em]">{caseId}</h2>
              </div>
              <div
                className={`mt-3.5 rounded-lg border px-3 py-2.5 text-[12.5px] ${
                  sourceKind === "demo"
                    ? "border-amber-300/30 bg-amber-300/[0.06] text-amber-100/90"
                    : errors > 0
                      ? "border-alert/35 bg-alert/[0.07] text-soft"
                      : "border-teal-400/30 bg-teal-400/[0.06] text-teal-100/90"
                }`}
              >
                <p className="flex items-center gap-2 font-semibold tracking-[0.08em] uppercase">
                  <span
                    className={`size-1.5 rounded-full ${
                      sourceKind === "demo" ? "bg-amber-300" : errors > 0 ? "bg-alert" : "bg-teal-300 shadow-[0_0_6px_#5eead4]"
                    }`}
                  />
                  {sourceKind === "demo" ? "Demo data" : "Live API"}
                </p>
                <p className="mt-1 text-[12px] opacity-80">
                  {sourceKind === "demo" ? "Synthetic records, not from the backend" : errors > 0 ? `Unreachable · ${API_URL}` : API_URL}
                </p>
              </div>
              <dl className="mt-4 grid gap-3 text-[13px] sm:grid-cols-2 xl:grid-cols-1">
                <div>
                  <dt className="text-soft/60">Evidence intake</dt>
                  <dd className="mt-0.5 text-white">
                    {intake ? (
                      <>
                        {formatStamp(intake.first)}
                        {intake.last !== intake.first && <span className="block text-soft/70">to {formatStamp(intake.last)}</span>}
                      </>
                    ) : (
                      <span className="text-soft/50">{data.evidence.status === "loading" ? "Loading…" : "Not available"}</span>
                    )}
                  </dd>
                </div>
                <div>
                  <dt className="text-soft/60">Recorded activity</dt>
                  <dd className="mt-0.5 text-white">
                    {activity ? (
                      <>
                        {formatStamp(activity.first)}
                        <span className="block text-soft/70">to {formatStamp(activity.last)}</span>
                      </>
                    ) : (
                      <span className="text-soft/50">{data.events.status === "loading" ? "Loading…" : "Not available"}</span>
                    )}
                  </dd>
                </div>
              </dl>
              <p className="mt-4 border-t border-white/[0.06] pt-3 text-[11.5px] leading-relaxed text-muted">
                Case name, status and owner aren't in the API contract yet, so they aren't shown.
              </p>
            </section>

            <nav aria-label="Case sections" className={`${GLASS} hidden overflow-hidden py-2 xl:block`}>
              {SECTIONS.map(({ to, label, icon: Icon, end }) => (
                <NavLink
                  key={to}
                  to={toPath(to)}
                  end={end}
                  className={({ isActive }) =>
                    `flex items-center gap-3 px-5 py-2.5 text-[14px] transition ${
                      isActive
                        ? "bg-[linear-gradient(90deg,rgba(239,43,60,0.2),rgba(239,43,60,0.02))] text-white shadow-[inset_3px_0_0_#ef2b3c]"
                        : "text-soft/80 hover:bg-white/[0.03] hover:text-white"
                    }`
                  }
                >
                  {({ isActive }) => (
                    <>
                      <Icon size={18} className={isActive ? "text-alert" : "text-soft/70"} />
                      {label}
                    </>
                  )}
                </NavLink>
              ))}
            </nav>

            <p className="hidden px-1 text-[30px] leading-[1.15] font-light text-soft/80 xl:block">
              From
              <br />
              <span className="font-medium text-white">Evidence</span>
              <br />
              to <span className="font-semibold text-alert">Truth.</span>
            </p>
          </aside>

          <div className="relative order-1 min-w-0 space-y-5 xl:order-none">
            <div aria-hidden="true" className="pointer-events-none absolute inset-0 -z-0">
              <div className="absolute top-[22%] left-[2%] h-[340px] w-[46%] rounded-full bg-trace/[0.09] blur-[90px]" />
              <div className="absolute top-[18%] right-[0%] h-[320px] w-[40%] rounded-full bg-alert/[0.08] blur-[90px]" />
              <div className="absolute bottom-[4%] left-[30%] h-[260px] w-[40%] rounded-full bg-trace/[0.06] blur-[100px]" />
            </div>
            {/* Hero */}
            <section className="relative px-1 pt-2 pb-1">
              <div className="pointer-events-none absolute inset-y-[-35%] right-[-4%] left-[30%] hidden lg:block [mask-image:radial-gradient(ellipse_72%_78%_at_55%_45%,#000_40%,transparent_82%)]">
                <NetworkBackdrop />
              </div>
              <div className="relative max-w-[640px] [text-shadow:0_2px_18px_rgba(5,7,12,0.9)]">
                <p className="text-[11px] font-semibold tracking-[0.38em] text-soft/80">
                  INVESTIGATION DASHBOARD <span className="ml-1.5 inline-block size-[5px] -translate-y-0.5 rounded-full bg-alert align-middle" />
                </p>
                <h1 className="mt-3 text-[clamp(2rem,3.3vw,3rem)] leading-[1.08] font-bold tracking-[-0.02em]">
                  Unify Evidence.
                  <br />
                  Uncover the <span className="text-alert drop-shadow-[0_0_18px_rgba(239,43,60,0.45)]">Truth.</span>
                </h1>
                <p className="mt-3 max-w-[520px] text-[15px] leading-relaxed text-soft/85">
                  One view of the case: hashed evidence, the events parsed from it, the findings built on those events, and the contradictions
                  that need an investigator's eye.
                </p>
                <Link
                  to={toPath("/app/evidence")}
                  className="mt-5 inline-flex items-center gap-2.5 rounded-lg bg-alert px-5 py-3 text-[14.5px] font-medium text-white shadow-[0_0_26px_rgba(239,43,60,0.4)] transition hover:bg-[#ff3a4a] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-alert"
                >
                  Open Evidence Vault
                  <ArrowRight size={16} />
                </Link>
              </div>
            </section>

            {/* KPIs */}
            <div className="grid gap-4 sm:grid-cols-2 2xl:grid-cols-4">
              <KpiCard
                tone="trace"
                icon={<FileIcon size={21} />}
                value={kpi(data.evidence, d => d.length)}
                label="Total evidence"
                sub={evidence && `${evidence.reduce((n, e) => n + e.custody.length, 0)} custody entries`}
                to={toPath("/app/evidence")}
              />
              <KpiCard
                tone="alert"
                icon={<Activity size={21} />}
                value={kpi(data.events, d => d.length)}
                label="Events analyzed"
                sub={events && `from ${new Set(events.map(e => e.evidence_id)).size} evidence files`}
                to={toPath("/app/investigation", { tab: "timeline" })}
              />
              <KpiCard
                tone="trace"
                icon={<ScanSearch size={21} />}
                value={kpi(data.findings, d => d.length)}
                label="Findings"
                sub={findings && `${findings.filter(f => statusOf(f) === "pending").length} need review`}
                to={toPath("/app/investigation", { tab: "findings" })}
              />
              <KpiCard
                tone="alert"
                icon={<Alert size={21} />}
                value={kpi(data.findings, d => d.filter(f => f.type === "contradiction").length)}
                label="Contradictions"
                sub={contradictions && `${contradictions.filter(f => statusOf(f) === "pending").length} unresolved`}
                to={toPath("/app/investigation", { tab: "findings", type: "contradiction" })}
              />
            </div>

            {/* Intelligence row */}
            <div className="grid gap-5 lg:grid-cols-2 2xl:grid-cols-[minmax(0,1fr)_minmax(0,1.12fr)_minmax(0,1fr)]">
              <Panel title="Evidence overview" action={<PanelLink to={toPath("/app/evidence")}>Vault</PanelLink>}>
                <SectionGate recover={recover} section={data.evidence} isEmpty={d => d.length === 0} empty="No evidence uploaded yet.">
                  {items => <EvidenceOverview items={items} />}
                </SectionGate>
              </Panel>
              <Panel title="Investigation timeline" note="latest" action={<PanelLink to={toPath("/app/investigation", { tab: "timeline" })}>Timeline</PanelLink>}>
                <SectionGate recover={recover} section={data.events} isEmpty={d => d.length === 0} empty="No events parsed yet." rows={5}>
                  {list => <TimelinePanel events={list} flagged={derived.flagged} linkTo={linkToEvidence} />}
                </SectionGate>
              </Panel>
              <Panel
                title="Case entities"
                note="preview"
                className="lg:col-span-2 2xl:col-span-1"
                action={<PanelLink to={toPath("/app/investigation", { tab: "graph" })}>View graph</PanelLink>}
              >
                <SectionGate recover={recover} section={data.graph} isEmpty={g => g.nodes.length === 0} empty="No entities in the graph yet.">
                  {graph => <EntitiesPanel graph={graph} />}
                </SectionGate>
              </Panel>
            </div>

            {/* Findings and alerts */}
            <div className="grid gap-5 2xl:grid-cols-[minmax(0,1.55fr)_minmax(0,1fr)]">
              <Panel
                id="findings"
                title="Recent findings"
                note={findings ? `${findings.length} total` : undefined}
                action={<PanelLink to={toPath("/app/investigation", { tab: "findings" })}>Workspace</PanelLink>}
              >
                <SectionGate recover={recover} section={data.findings} isEmpty={d => d.length === 0} empty="No findings yet. Run the analysis to generate them.">
                  {list => <FindingsPanel findings={list} evidenceFor={derived.evidenceFor} linkFor={linkToFinding} />}
                </SectionGate>
              </Panel>
              <Panel id="alerts" title="Active alerts" note={alerts.length ? `${alerts.length}` : undefined}>
                {data.findings.status === "loading" || data.evidence.status === "loading" ? (
                  <SectionGate section={{ status: "loading" }} empty="" rows={3}>
                    {() => null}
                  </SectionGate>
                ) : data.findings.status === "error" && alerts.length === 0 ? (
                  <SectionGate recover={recover} section={data.findings} empty="">
                    {() => null}
                  </SectionGate>
                ) : (
                  <AlertsPanel alerts={alerts} />
                )}
              </Panel>
            </div>
          </div>
        </div>
      </div>
    </ConsoleShell>
  );
}
