// Role 4 / T11: Claim Inspector. Lists the run's claims; the selected one shows what it asserts (type, status, grade,
// rule and parameters), its SUPPORTS and CONTRADICTS relationships, the hypothesis items that use it, and its lineage
// from GET /runs/{run}/claims/{claim}/lineage down to each source file's intake SHA-256. Only fields the backend
// returned are shown; nothing is filled in. No weights or other decimals are displayed.
import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import type { ClaimGrade, ClaimLineage, ClaimStatus, EdgeRole, RunClaim } from "../../../api/pending/runs";
import { ArrowRight, Info } from "../../../components/console/icons";
import { useSourceLink } from "../../../components/console/useSourceLink";
import { describe } from "../../dashboard/components/TimelinePanel";
import { SectionGate, humanize } from "../../dashboard/components/ui";
import { Stamp } from "../../../lib/time";
import type { LoadedRun } from "../../hypotheses/runSource";
import { CopyButton } from "../../vault/components/ui";
import { truncateHash } from "../../vault/model";
import { useCaseRecords, useClaimLineage, type CaseRecords } from "../claimSource";

const CHIP = "inline-flex items-center rounded-md border px-2 py-0.5 text-[12px] whitespace-nowrap";

const CLAIM_STATUS: Record<ClaimStatus, string> = {
  ASSERTED: "border-trace/40 bg-trace/10 text-trace-soft",
  CORROBORATED: "border-teal-400/35 bg-teal-400/10 text-teal-200",
  CONTESTED: "border-amber-400/40 bg-amber-400/10 text-amber-200",
  REFUTED: "border-alert/45 bg-alert/[0.12] text-alert-soft",
  ASSUMED: "border-violet-400/35 bg-violet-400/10 text-violet-200"
};

/** SUPPORTS and CONTRADICTS must never look alike. */
export const ROLE: Record<EdgeRole, { label: string; chip: string; panel: string; mark: string }> = {
  SUPPORTS: { label: "Supports", chip: "border-teal-400/40 bg-teal-400/10 text-teal-200", panel: "border-teal-400/25 bg-teal-400/[0.04]", mark: "+" },
  CONTRADICTS: { label: "Contradicts", chip: "border-alert/50 bg-alert/[0.12] text-alert-soft", panel: "border-alert/30 bg-alert/[0.05]", mark: "−" }
};

const GRADE_NOTE = "Evidence grade, A strongest. A category, not a probability.";
const shortId = (id: string) => (id.length > 16 ? `${id.slice(0, 12)}…` : id);
/** Event IDs look like "<hash>:<hash>:EV-000024"; the last part is the readable one. */
const eventLabel = (id: string) => id.split(":").pop() ?? id;

const StatusChip = ({ status }: { status: ClaimStatus }) => <span className={`${CHIP} ${CLAIM_STATUS[status] ?? CLAIM_STATUS.ASSERTED}`}>{humanize(status.toLowerCase())}</span>;
const GradeChip = ({ grade }: { grade: ClaimGrade }) => (
  <span className={`${CHIP} border-white/15 bg-white/[0.04] text-white`} title={GRADE_NOTE}>
    Grade {grade}
  </span>
);
const RoleChip = ({ role }: { role: EdgeRole }) => (
  <span className={`${CHIP} ${ROLE[role].chip}`}>
    <span aria-hidden="true" className="mr-1 font-semibold">
      {ROLE[role].mark}
    </span>
    {ROLE[role].label}
  </span>
);

function Block({ title, note, children }: { title: string; note?: ReactNode; children: ReactNode }) {
  return (
    <section aria-label={title}>
      <h4 className="mb-2 text-[12px] font-semibold tracking-[0.16em] text-soft/70 uppercase">
        {title}
        {note && <span className="ml-1.5 font-normal tracking-normal text-soft/45 normal-case">{note}</span>}
      </h4>
      {children}
    </section>
  );
}

const ParamValue = ({ value }: { value: unknown }) =>
  typeof value === "string" ? (
    <span className="font-mono text-[12px] break-all text-[#cfe0ff]">{value}</span>
  ) : (
    <span className="font-mono text-[12px] break-all text-soft">{JSON.stringify(value)}</span>
  );

function ClaimsList({ claims, selectedId, onSelect }: { claims: RunClaim[]; selectedId: string; onSelect: (id: string) => void }) {
  return (
    <ul className="space-y-2" aria-label="Claims in this run">
      {claims.map(c => {
        const active = c.claim_id === selectedId;
        const supports = c.edges.filter(e => e.role === "SUPPORTS").length;
        const contradicts = c.edges.length - supports;
        return (
          <li key={c.claim_id}>
            <button
              type="button"
              onClick={() => onSelect(c.claim_id)}
              aria-pressed={active}
              className={`w-full rounded-xl border p-3 text-left transition outline-none focus-visible:border-trace ${
                active ? "border-trace/55 bg-trace/[0.08] shadow-[0_0_22px_-10px_rgba(59,140,255,0.8)]" : "border-white/[0.07] bg-white/[0.02] hover:border-trace/30"
              }`}
            >
              <span className="block font-mono text-[12.5px] text-white">{c.type}</span>
              <span className="mt-1.5 flex flex-wrap items-center gap-1.5">
                <StatusChip status={c.status} />
                <GradeChip grade={c.grade} />
              </span>
              <span className="mt-2 flex flex-wrap gap-x-3 text-[12px] tabular-nums">
                <span className="text-teal-200/90">+{supports} supports</span>
                <span className={contradicts ? "text-alert-soft" : "text-soft/50"}>−{contradicts} contradicts</span>
                <span className="text-soft/45" title={c.claim_id}>
                  {shortId(c.claim_id)}
                </span>
              </span>
            </button>
          </li>
        );
      })}
    </ul>
  );
}

/** The claim's edges as stored in the run: who supports it, who contradicts it, and why (reason codes). */
function Relationships({ claim, onSelect }: { claim: RunClaim; onSelect: (id: string) => void }) {
  return (
    <div className="grid gap-3 md:grid-cols-2">
      {(["SUPPORTS", "CONTRADICTS"] as EdgeRole[]).map(role => {
        const edges = claim.edges.filter(e => e.role === role);
        const events = edges.filter(e => e.ref_kind === "event");
        const claims = edges.filter(e => e.ref_kind === "claim");
        const count = (key: (e: (typeof edges)[number]) => string | null) =>
          [...edges.reduce((m, e) => m.set(key(e) ?? "—", (m.get(key(e) ?? "—") ?? 0) + 1), new Map<string, number>())];
        return (
          <div key={role} className={`rounded-xl border p-3.5 ${ROLE[role].panel}`}>
            <div className="flex items-center justify-between gap-2">
              <RoleChip role={role} />
              <span className="text-[12px] text-soft/60 tabular-nums">
                {events.length} event{events.length === 1 ? "" : "s"} · {claims.length} claim{claims.length === 1 ? "" : "s"}
              </span>
            </div>
            {edges.length === 0 ? (
              <p className="mt-2.5 text-[12.5px] text-soft/60">None recorded in this run.</p>
            ) : (
              <dl className="mt-2.5 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-[12.5px]">
                <dt className="text-soft/55">Reasons</dt>
                <dd className="flex flex-wrap gap-1">
                  {count(e => e.reason_code).map(([code, n]) => (
                    <span key={code} className="rounded border border-white/10 px-1.5 py-px font-mono text-[11px] text-soft">
                      {code} ×{n}
                    </span>
                  ))}
                </dd>
                <dt className="text-soft/55">Sources</dt>
                <dd className="text-soft/85">{count(e => e.family).map(([fam, n]) => `${fam} (${n})`).join(", ")}</dd>
                {claims.length > 0 && (
                  <>
                    <dt className="text-soft/55">Claims</dt>
                    <dd className="flex flex-wrap gap-1.5">
                      {claims.map(e => (
                        <button key={e.ref_id} type="button" onClick={() => onSelect(e.ref_id)} className="font-mono text-[11.5px] text-trace-soft hover:text-white" title={e.ref_id}>
                          {shortId(e.ref_id)}
                        </button>
                      ))}
                    </dd>
                  </>
                )}
              </dl>
            )}
          </div>
        );
      })}
    </div>
  );
}

const PREVIEW = 6;

function EvidenceGroup({
  evidenceId,
  sha256,
  events,
  records,
  liveVaultLink
}: {
  evidenceId: string | null;
  sha256: string | null;
  events: ClaimLineage["events"];
  records: CaseRecords | null;
  liveVaultLink: ((id: string) => string) | null;
}) {
  const [all, setAll] = useState(false);
  const file = evidenceId ? records?.evidenceById.get(evidenceId) : undefined;
  const shown = all ? events : events.slice(0, PREVIEW);
  return (
    <li className="relative overflow-hidden rounded-xl border border-trace/30 bg-[linear-gradient(160deg,rgba(16,28,52,0.85),rgba(7,11,20,0.9))] p-4">
      <span aria-hidden="true" className="absolute inset-x-5 top-0 h-px bg-gradient-to-r from-transparent via-trace-soft/70 to-transparent" />
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className="text-[13px] font-semibold text-white">{evidenceId ?? "Evidence not resolved"}</span>
        {file && <span className="truncate text-[13px] text-soft">{file.filename}</span>}
        <span className="ml-auto text-[12px] text-soft/60 tabular-nums">
          {events.length} event{events.length === 1 ? "" : "s"}
        </span>
      </div>
      <span className="mt-2 flex items-center gap-1 text-[12px] text-soft/60">
        Intake SHA-256
        {sha256 ? (
          <>
            <code className="rounded-md border border-white/[0.07] bg-black/30 px-2 py-0.5 font-mono text-[11.5px] text-[#cfe0ff]" title={sha256}>
              {truncateHash(sha256)}
            </code>
            <CopyButton text={sha256} label={`Copy SHA-256 of ${evidenceId}`} />
          </>
        ) : (
          <span className="text-alert-soft">not returned by the lineage</span>
        )}
      </span>
      <ul className="mt-3 space-y-2 border-t border-white/[0.06] pt-3">
        {shown.map(e => {
          const full = records?.eventById.get(e.event_id);
          return (
            <li key={`${e.role}:${e.event_id}`} className="flex flex-wrap items-start gap-x-2.5 gap-y-1 text-[12.5px]">
              <RoleChip role={e.role} />
              <span className="min-w-0 flex-1">
                <span className="text-soft/60 tabular-nums" title={e.event_id}>
                  {eventLabel(e.event_id)}
                </span>
                {full && <span className="ml-2 text-white">{describe(full)}</span>}
                <span className="block text-[11.5px] text-soft/55">
                  {full && <><Stamp iso={full.timestamp} /> · </>}
                  <span className="font-mono">{e.artifact_ref ?? "no artifact reference"}</span>
                </span>
              </span>
            </li>
          );
        })}
      </ul>
      {events.length > PREVIEW && (
        <button type="button" onClick={() => setAll(v => !v)} className="mt-2.5 text-[12.5px] text-trace-soft hover:text-white">
          {all ? "Show fewer" : `Show all ${events.length} events`}
        </button>
      )}
      {liveVaultLink && evidenceId && (
        <Link to={liveVaultLink(evidenceId)} className="mt-3 flex w-fit items-center gap-1.5 text-[12.5px] text-trace-soft hover:text-white">
          Open in Evidence Vault <ArrowRight size={13} />
        </Link>
      )}
    </li>
  );
}

function Lineage({ loaded, claimId, onSelect }: { loaded: LoadedRun; claimId: string; onSelect: (id: string) => void }) {
  const lineage = useClaimLineage(loaded, claimId);
  const records = useCaseRecords(loaded);
  const toPath = useSourceLink();
  const recordsData = records.status === "ready" ? records.data : null;
  // The vault's demo set is a different, synthetic case, so recorded lineage does not link into it.
  const vaultLink = loaded.origin === "api" ? (id: string) => toPath("/app/evidence", { open: id }) : null;

  return (
    <SectionGate section={lineage} empty="" rows={4}>
      {data => {
        const groups = [...data.events.reduce((m, e) => m.set(e.evidence_id ?? "", [...(m.get(e.evidence_id ?? "") ?? []), e]), new Map<string, ClaimLineage["events"]>())];
        return (
          <div className="space-y-3">
            {records.status === "error" && (
              <p className="text-[12px] text-soft/60">Event details unavailable ({records.message}); showing IDs and hashes only.</p>
            )}
            {loaded.origin === "recorded" && (
              <p className="flex items-start gap-2 text-[12px] text-soft/60">
                <Info size={14} className="mt-px shrink-0 text-trace-soft" />
                Recorded lineage. Files are shown here rather than linked: the Evidence Vault's demo set is a different, synthetic case.
              </p>
            )}
            {groups.length === 0 ? (
              <p className="text-[12.5px] text-soft/60">The lineage lists no events for this claim.</p>
            ) : (
              <ul className="grid gap-3 lg:grid-cols-2">
                {groups.map(([id, events]) => (
                  <EvidenceGroup key={id} evidenceId={id || null} sha256={events[0]?.evidence_sha256 ?? null} events={events} records={recordsData} liveVaultLink={vaultLink} />
                ))}
              </ul>
            )}
            {data.claims.length > 0 && (
              <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
                <span className="text-soft/60">Rests on claims:</span>
                {data.claims.map(c => (
                  <span key={c.claim_id} className="flex items-center gap-1.5">
                    <RoleChip role={c.role} />
                    <button type="button" onClick={() => onSelect(c.claim_id)} className="font-mono text-[11.5px] text-trace-soft hover:text-white" title={c.claim_id}>
                      {shortId(c.claim_id)}
                    </button>
                    {"cycle" in c && <span className="text-[11px] text-amber-200">(cycle)</span>}
                  </span>
                ))}
              </div>
            )}
          </div>
        );
      }}
    </SectionGate>
  );
}

function ClaimDetail({ loaded, claim, onSelect }: { loaded: LoadedRun; claim: RunClaim; onSelect: (id: string) => void }) {
  const toPath = useSourceLink();
  const usedBy = loaded.run.ranked_hypotheses.flatMap(h =>
    h.evaluations.filter(e => e.matched_claim_ids.includes(claim.claim_id)).map(e => ({ hypothesis: h, item: e }))
  );
  const params = Object.entries(claim.params ?? {});

  return (
    <article aria-label={`Claim ${claim.claim_id}`} className="min-w-0 space-y-5">
      <header>
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="font-mono text-[17px] font-semibold text-white">{claim.type}</h3>
          <StatusChip status={claim.status} />
          <GradeChip grade={claim.grade} />
        </div>
        <dl className="mt-2 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-[12px] text-soft/60">
          <dt>Claim ID</dt>
          <dd className="flex items-center gap-1 font-mono break-all text-soft/85">
            {claim.claim_id} <CopyButton text={claim.claim_id} label="Copy claim ID" />
          </dd>
          <dt>Claim key</dt>
          <dd className="font-mono break-all text-soft/70">{claim.claim_key}</dd>
        </dl>
      </header>

      <Block title="What it asserts" note="rule and parameters, as recorded">
        <dl className="grid grid-cols-[minmax(120px,auto)_minmax(0,1fr)] gap-x-4 gap-y-1.5 rounded-xl border border-white/[0.07] bg-black/20 p-3.5 text-[12.5px]">
          <dt className="text-soft/55">Rule</dt>
          <dd className="font-mono text-[12px] text-white">
            {claim.rule_id}@{claim.rule_version}
          </dd>
          {params.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-soft/55">{humanize(k)}</dt>
              <dd>
                <ParamValue value={v} />
              </dd>
            </div>
          ))}
        </dl>
      </Block>

      <Block title="Relationships">
        <Relationships claim={claim} onSelect={onSelect} />
      </Block>

      <Block title="Used by hypotheses" note={`${usedBy.length} item${usedBy.length === 1 ? "" : "s"}`}>
        {usedBy.length === 0 ? (
          <p className="text-[12.5px] text-soft/60">No hypothesis item matched this claim.</p>
        ) : (
          <ul className="flex flex-wrap gap-2">
            {usedBy.map(({ hypothesis, item }) => (
              <li key={`${hypothesis.id}:${item.item_id}`}>
                <Link
                  to={toPath("/app/investigation", { tab: "hypotheses", hyp: hypothesis.id, run: loaded.run.run_id })}
                  className="inline-flex items-center gap-1.5 rounded-md border border-white/10 px-2 py-1 text-[12px] text-soft hover:border-trace/40 hover:text-white"
                >
                  <span className="tabular-nums">{item.item_id}</span>
                  <span className="text-soft/50">{hypothesis.name}</span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Block>

      <Block title="Lineage" note="claim → events → source evidence intake SHA-256">
        <Lineage loaded={loaded} claimId={claim.claim_id} onSelect={onSelect} />
      </Block>
    </article>
  );
}

export default function ClaimInspector({
  loaded,
  selectedId,
  onSelect
}: {
  loaded: LoadedRun;
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  const claims = loaded.run.claims;
  if (!claims.length) return <p className="py-10 text-center text-[13.5px] text-soft/70">This run has no claims.</p>;
  const selected = claims.find(c => c.claim_id === selectedId) ?? claims[0];
  const missing = selectedId && selectedId !== selected.claim_id;
  const { run } = loaded;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-x-5 gap-y-2 rounded-xl border border-white/[0.07] bg-black/20 px-4 py-3 text-[12.5px] text-soft/75">
        {loaded.origin === "recorded" && (
          <span className="rounded-md border border-violet-400/35 bg-violet-400/10 px-2 py-0.5 text-[12px] text-violet-200">Recorded real run</span>
        )}
        <span>
          Case <span className="text-white">{run.case_id}</span>
        </span>
        <span>
          Run <span className="text-white tabular-nums">{run.run_id}</span>
        </span>
        {run.parent_run_id && <span>parent {run.parent_run_id}</span>}
        <span>
          Validity{" "}
          <span className={run.validity === "VALID" ? "text-teal-200" : "text-alert-soft"} title={run.invalidation_reasons.join("\n") || undefined}>
            {run.validity === "VALID" ? "Valid" : "Invalidated"}
          </span>
        </span>
      </div>
    <div className="grid gap-5 xl:grid-cols-[300px_minmax(0,1fr)]">
      <section aria-label="Claims">
        <h3 className="mb-3 text-[14px] font-semibold text-white">
          Claims <span className="text-[13px] font-normal text-muted">{claims.length} in this run</span>
        </h3>
        <ClaimsList claims={claims} selectedId={selected.claim_id} onSelect={onSelect} />
      </section>
      <div className="min-w-0 space-y-3">
        {missing && <p className="rounded-lg border border-amber-400/30 bg-amber-400/[0.06] px-3 py-2 text-[12.5px] text-amber-200">Claim {shortId(selectedId)} is not in this run; showing the first claim.</p>}
        <ClaimDetail key={selected.claim_id} loaded={loaded} claim={selected} onSelect={onSelect} />
      </div>
    </div>
    </div>
  );
}
