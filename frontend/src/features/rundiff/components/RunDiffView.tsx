// Role 4 / T11: Run diff. Presents GET /runs/{a}/diff/{b} as returned: input evidence added or removed, claims matched
// by claim_key (removed, added, modified), hypothesis rank and status changes with the matrix items that shifted, and
// reconstruction stage changes. Alongside it, facts read from the two run records (assumptions, engine, templates,
// outcome). Removed claims show the evidence their lineage rests on, so a removal can be traced to an input change.
// Scores and penalties are not shown; nothing is inferred beyond what the diff, the runs and the lineage contain.
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import type { ClaimStatus, HypothesisDiff, HypothesisStatus, RunClaim, RunDetails, RunDiff, StageStatus } from "../../../api/pending/runs";
import type { EvidenceItem } from "../../../api/types";
import { ArrowRight, Info } from "../../../components/console/icons";
import { useSourceLink } from "../../../components/console/useSourceLink";
import { SectionGate, humanize } from "../../dashboard/components/ui";
import { useClaimLineage } from "../../claims/claimSource";
import { HypothesisChip, StateChip } from "../../hypotheses/components/HypothesesView";
import { Stamp } from "../../../lib/time";
import type { LoadedRun } from "../../hypotheses/runSource";
import { truncateHash } from "../../vault/model";

const CHIP = "inline-flex items-center rounded-md border px-2 py-0.5 text-[12px] whitespace-nowrap";
const shortKey = (k: string) => `${k.slice(0, 10)}…`;
const Arrow = () => <ArrowRight size={13} className="shrink-0 text-soft/45" />;

function Block({ title, note, children }: { title: string; note?: ReactNode; children: ReactNode }) {
  return (
    <section aria-label={title} className="space-y-3">
      <h3 className="text-[14px] font-semibold text-white">
        {title}
        {note && <span className="ml-1.5 text-[13px] font-normal text-muted">{note}</span>}
      </h3>
      {children}
    </section>
  );
}

const Same = () => <span className="text-[12px] text-soft/55">unchanged</span>;
const Changed = () => <span className="text-[12px] text-amber-200">changed</span>;

function RunCard({ label, loaded }: { label: string; loaded: LoadedRun }) {
  const { run } = loaded;
  return (
    <div className="flex-1 rounded-xl border border-white/[0.07] bg-black/20 px-4 py-3 text-[12.5px] text-soft/75">
      <p className="text-[11px] font-semibold tracking-[0.18em] text-soft/60 uppercase">{label}</p>
      <p className="mt-1 text-[14px] text-white tabular-nums">{run.run_id}</p>
      <p className="mt-0.5">
        {run.created_at ? <Stamp iso={run.created_at} /> : "no creation time"}
        {run.parent_run_id && <span className="text-soft/55"> · parent {run.parent_run_id}</span>}
      </p>
      <p className="mt-1">
        Validity{" "}
        <span className={run.validity === "VALID" ? "text-teal-200" : "text-alert-soft"} title={run.invalidation_reasons.join("\n") || undefined}>
          {run.validity === "VALID" ? "Valid" : "Invalidated"}
        </span>
        {run.validity !== "VALID" && run.invalidation_reasons.length > 0 && (
          <span className="block text-[12px] text-alert-soft/80">{run.invalidation_reasons.join("; ")}</span>
        )}
      </p>
    </div>
  );
}

/** Facts from the two run records. The diff endpoint compares evidence only; the rest is read from each run. */
function Inputs({ a, b, diff, evidence }: { a: RunDetails; b: RunDetails; diff: { added: { evidence_id: string; sha256: string }[]; removed: { evidence_id: string; sha256: string }[] }; evidence: EvidenceItem[] | null }) {
  const byId = new Map(evidence?.map(e => [e.evidence_id, e]));
  const row = (label: string, changed: boolean, detail: ReactNode) => (
    <tr className="border-t border-white/[0.05] align-top">
      <th scope="row" className="py-2.5 pr-4 pl-1 text-left font-normal whitespace-nowrap text-soft/65">
        {label}
      </th>
      <td className="w-[90px] py-2.5 pr-4">{changed ? <Changed /> : <Same />}</td>
      <td className="py-2.5 pr-1 text-soft/85">{detail}</td>
    </tr>
  );
  const evChanged = diff.added.length + diff.removed.length > 0;
  const fileLine = (e: { evidence_id: string; sha256: string }, sign: "+" | "−") => {
    const now = byId.get(e.evidence_id);
    return (
      <li key={e.evidence_id} className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
        <span className={sign === "−" ? "text-alert-soft" : "text-teal-200"}>{sign}</span>
        <span className="text-white">{e.evidence_id}</span>
        {now && <span>{now.filename}</span>}
        <code className="font-mono text-[11.5px] text-soft/60" title={e.sha256}>
          {truncateHash(e.sha256)}
        </code>
        {now?.status && (
          <span className={`${CHIP} ${now.status === "QUARANTINED" ? "border-alert/45 bg-alert/[0.12] text-alert-soft" : "border-white/12 text-soft/75"}`}>
            now {humanize(now.status.toLowerCase())}
            {now.verify_state ? ` · ${now.verify_state}` : ""}
          </span>
        )}
      </li>
    );
  };
  return (
    <div className="-mx-1 overflow-x-auto">
      <table className="w-full min-w-[620px] border-collapse text-[13px]">
        <tbody>
          {row(
            "Input evidence",
            evChanged,
            <>
              <span className="tabular-nums">
                {a.manifest.evidence.length} → {b.manifest.evidence.length} files
              </span>
              {evChanged && (
                <ul className="mt-1.5 space-y-1 text-[12.5px]">
                  {diff.removed.map(e => fileLine(e, "−"))}
                  {diff.added.map(e => fileLine(e, "+"))}
                </ul>
              )}
            </>
          )}
          {row(
            "Assumptions",
            a.assumptions_hash !== b.assumptions_hash,
            <span className="font-mono text-[12px]">
              {JSON.stringify(a.manifest.assumptions)}
              {a.assumptions_hash !== b.assumptions_hash && <> → {JSON.stringify(b.manifest.assumptions)}</>}
            </span>
          )}
          {row("Engine", a.engine_version !== b.engine_version, a.engine_version === b.engine_version ? a.engine_version : `${a.engine_version} → ${b.engine_version}`)}
          {row(
            "Hypothesis templates",
            a.template_hash !== b.template_hash,
            <code className="font-mono text-[12px]">{a.template_hash === b.template_hash ? truncateHash(a.template_hash) : `${truncateHash(a.template_hash)} → ${truncateHash(b.template_hash)}`}</code>
          )}
          {row(
            "Outcome",
            a.outcome !== b.outcome,
            <span>
              {a.outcome ? humanize(a.outcome.toLowerCase()) : "none"} → {b.outcome ? humanize(b.outcome.toLowerCase()) : "none"}
            </span>
          )}
          {row(
            "Ranking hash",
            a.ranking_hash !== b.ranking_hash,
            <code className="font-mono text-[12px]">
              {truncateHash(a.ranking_hash)} → {truncateHash(b.ranking_hash)}
            </code>
          )}
        </tbody>
      </table>
    </div>
  );
}

function Hypotheses({ diffs, a, b }: { diffs: HypothesisDiff[]; a: string; b: string }) {
  const toPath = useSourceLink();
  const link = (id: string, run: string, children: ReactNode) => (
    <Link to={toPath("/app/investigation", { tab: "hypotheses", hyp: id, run })} className="text-trace-soft hover:text-white">
      {children}
    </Link>
  );
  return (
    <ul className="space-y-3">
      {diffs.map(h =>
        "transition" in h ? (
          <li key={h.hypothesis_id} className="rounded-xl border border-white/[0.07] bg-white/[0.02] p-3.5 text-[13px] text-white">
            {h.hypothesis_id} <span className="text-amber-200">{h.transition === "DROPPED" ? "only in run A (dropped)" : "only in run B (introduced)"}</span>
          </li>
        ) : (
          <li key={h.hypothesis_id} className={`rounded-xl border p-3.5 ${h.changed ? "border-trace/30 bg-trace/[0.04]" : "border-white/[0.07] bg-white/[0.02]"}`}>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
              <span className="text-[14px] font-semibold text-white">{h.name}</span>
              <span className="text-[12px] text-soft/55">{h.hypothesis_id}</span>
              <span className="flex items-center gap-1.5">
                <HypothesisChip status={h.old_status as HypothesisStatus} />
                <Arrow />
                <HypothesisChip status={h.new_status as HypothesisStatus} />
              </span>
              <span className={`text-[12.5px] tabular-nums ${h.old_rank !== h.new_rank ? "text-amber-200" : "text-soft/60"}`}>
                Rank {h.old_rank} → {h.new_rank}
                {h.old_rank === h.new_rank && " (same)"}
              </span>
              <span className="ml-auto flex gap-3 text-[12px]">
                {link(h.hypothesis_id, a, "Run A matrix")}
                {link(h.hypothesis_id, b, "Run B matrix")}
              </span>
            </div>
            {h.item_state_shifts.length > 0 ? (
              <ul className="mt-2.5 space-y-1.5 border-t border-white/[0.06] pt-2.5">
                {h.item_state_shifts.map(s => (
                  <li key={s.item_id} className="flex flex-wrap items-center gap-2 text-[12.5px]">
                    <span className="w-[104px] text-soft/65 tabular-nums">{s.item_id}</span>
                    <StateChip state={s.old_state} />
                    <Arrow />
                    <StateChip state={s.new_state} />
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mt-2 text-[12px] text-soft/55">No matrix item changed state.</p>
            )}
          </li>
        )
      )}
    </ul>
  );
}

/** Which evidence a run-A claim rests on, from its recorded or fetched lineage. */
function DependsOn({ a, claimId, removedIds, evidence }: { a: LoadedRun; claimId: string; removedIds: Set<string>; evidence: EvidenceItem[] | null }) {
  const lineage = useClaimLineage(a, claimId);
  const byId = new Map(evidence?.map(e => [e.evidence_id, e]));
  return (
    <SectionGate section={lineage} empty="" rows={1}>
      {data => {
        const ids = [...new Set(data.events.map(e => e.evidence_id).filter((x): x is string => Boolean(x)))].sort();
        const hit = ids.filter(id => removedIds.has(id));
        return (
          <p className="mt-2 text-[12.5px] text-soft/75">
            Lineage rests on{" "}
            {ids.map((id, i) => (
              <span key={id}>
                {i > 0 && ", "}
                <span className={removedIds.has(id) ? "font-semibold text-alert-soft" : "text-soft"}>
                  {id}
                  {byId.get(id) && ` (${byId.get(id)!.filename})`}
                </span>
              </span>
            ))}
            .{" "}
            {hit.length > 0 ? (
              <span className="text-alert-soft">{hit.join(", ")} is not among run B's input evidence.</span>
            ) : (
              <span className="text-soft/55">None of these was removed from run B's inputs.</span>
            )}
          </p>
        );
      }}
    </SectionGate>
  );
}

function ClaimRow({ claim, sign, runId, children }: { claim: RunClaim; sign: "+" | "−"; runId: string; children?: ReactNode }) {
  const toPath = useSourceLink();
  const params = Object.entries(claim.params ?? {}).filter(([, v]) => typeof v !== "object");
  return (
    <li className={`rounded-xl border p-3.5 ${sign === "−" ? "border-alert/30 bg-alert/[0.04]" : "border-teal-400/25 bg-teal-400/[0.04]"}`}>
      <div className="flex flex-wrap items-center gap-2">
        <span className={`text-[15px] font-semibold ${sign === "−" ? "text-alert-soft" : "text-teal-200"}`}>{sign}</span>
        <span className="font-mono text-[13px] text-white">{claim.type}</span>
        <span className={`${CHIP} border-white/12 text-soft/80`}>{humanize((claim.status as ClaimStatus).toLowerCase())}</span>
        <span className={`${CHIP} border-white/12 text-soft/80`}>Grade {claim.grade}</span>
        <span className="text-[12px] text-soft/55" title={claim.claim_key}>
          key {shortKey(claim.claim_key)}
        </span>
        <Link
          to={toPath("/app/investigation", { tab: "claims", claim: claim.claim_id, run: runId })}
          className="ml-auto inline-flex items-center gap-1 text-[12.5px] text-trace-soft hover:text-white"
        >
          Inspect in {sign === "−" ? "run A" : "run B"} <ArrowRight size={13} />
        </Link>
      </div>
      {params.length > 0 && (
        <p className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5 text-[12px] text-soft/60">
          {params
            .filter(([k]) => !k.endsWith("event_id"))
            .map(([k, v]) => (
              <span key={k}>
                {humanize(k)}: <span className="font-mono text-soft/85">{String(v)}</span>
              </span>
            ))}
        </p>
      )}
      {children}
    </li>
  );
}

function StageChip({ status }: { status: StageStatus }) {
  return status === "GAP" ? (
    <span className={`${CHIP} border-dashed border-amber-400/45 text-amber-200`}>Gap</span>
  ) : (
    <span className={`${CHIP} border-teal-400/35 bg-teal-400/10 text-teal-200`}>Supported</span>
  );
}

export default function RunDiffView({
  a,
  b,
  diff,
  evidence
}: {
  a: LoadedRun;
  b: LoadedRun;
  diff: RunDiff;
  evidence: EvidenceItem[] | null;
}) {
  const toPath = useSourceLink();
  const removedIds = new Set(diff.evidence_diff.removed.map(e => e.evidence_id));
  const c = diff.claims_diff;
  const mismatch = diff.run_a_id !== a.run.run_id || diff.run_b_id !== b.run.run_id;

  return (
    <div className="space-y-6">
      {mismatch && <p className="text-[12.5px] text-alert-soft">The diff and the loaded runs do not match ({diff.run_a_id} → {diff.run_b_id}).</p>}
      <div className="flex flex-col items-stretch gap-3 md:flex-row md:items-center">
        <RunCard label="Run A" loaded={a} />
        <ArrowRight size={18} className="hidden shrink-0 text-soft/50 md:block" />
        <RunCard label="Run B" loaded={b} />
      </div>
      {a.origin === "recorded" && (
        <p className="flex items-start gap-2 text-[12px] text-soft/60">
          <Info size={14} className="mt-px shrink-0 text-trace-soft" />
          Recorded: run B was created after EVID-002 (browser_history.csv) was tampered with and quarantined. Run A is shown as read back after that
          quarantine. These are the only two runs in the recording.
        </p>
      )}

      <Block title="Inputs" note="evidence from the diff; the other rows from the two run records">
        <Inputs a={a.run} b={b.run} diff={diff.evidence_diff} evidence={evidence} />
      </Block>

      <Block title="Hypotheses" note="rank and status, and the matrix items that changed state">
        <Hypotheses diffs={diff.hypothesis_diffs} a={a.run.run_id} b={b.run.run_id} />
      </Block>

      <Block title="Claims" note={`matched by claim_key · ${c.unchanged_count} unchanged`}>
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="space-y-2">
            <p className="text-[12.5px] text-alert-soft">Removed in run B ({c.removed_count})</p>
            {c.removed_claims.length === 0 ? (
              <p className="text-[12.5px] text-soft/55">None.</p>
            ) : (
              <ul className="space-y-2">
                {c.removed_claims.map(cl => (
                  <ClaimRow key={cl.claim_key} claim={cl} sign="−" runId={a.run.run_id}>
                    <DependsOn a={a} claimId={cl.claim_id} removedIds={removedIds} evidence={evidence} />
                  </ClaimRow>
                ))}
              </ul>
            )}
          </div>
          <div className="space-y-2">
            <p className="text-[12.5px] text-teal-200">Added in run B ({c.added_count})</p>
            {c.added_claims.length === 0 ? (
              <p className="text-[12.5px] text-soft/55">None.</p>
            ) : (
              <ul className="space-y-2">
                {c.added_claims.map(cl => (
                  <ClaimRow key={cl.claim_key} claim={cl} sign="+" runId={b.run.run_id} />
                ))}
              </ul>
            )}
            <p className="pt-2 text-[12.5px] text-amber-200">Modified ({c.modified_count})</p>
            {c.modified_claims.length === 0 ? (
              <p className="text-[12.5px] text-soft/55">None: no claim_key kept in both runs changed status or grade.</p>
            ) : (
              <ul className="space-y-1.5 text-[12.5px]">
                {c.modified_claims.map(m => (
                  <li key={m.claim_key} className="flex flex-wrap items-center gap-2 rounded-lg border border-amber-400/25 px-3 py-2">
                    <span className="font-mono text-white">{m.type}</span>
                    <span className="text-soft/55" title={m.claim_key}>
                      key {shortKey(m.claim_key)}
                    </span>
                    <span>
                      {humanize(m.old_status.toLowerCase())} → {humanize(m.new_status.toLowerCase())}
                    </span>
                    <span>
                      Grade {m.old_grade} → {m.new_grade}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </Block>

      <Block title="Reconstruction stages" note={`${diff.stage_changes.length} changed`}>
        {diff.stage_changes.length === 0 ? (
          <p className="text-[12.5px] text-soft/55">No stage changed status.</p>
        ) : (
          <ul className="space-y-2">
            {diff.stage_changes.map(s => (
              <li key={s.stage_name} className="flex flex-wrap items-center gap-2 rounded-xl border border-white/[0.07] bg-white/[0.02] px-3.5 py-2.5 text-[13px]">
                <span className="text-white">{humanize(s.stage_name)}</span>
                <StageChip status={s.old_status} />
                <Arrow />
                <StageChip status={s.new_status} />
                <span className="ml-auto flex gap-3 text-[12px]">
                  <Link to={toPath("/app/investigation", { tab: "reconstruction", run: a.run.run_id })} className="text-trace-soft hover:text-white">
                    Run A stages
                  </Link>
                  <Link to={toPath("/app/investigation", { tab: "reconstruction", run: b.run.run_id })} className="text-trace-soft hover:text-white">
                    Run B stages
                  </Link>
                </span>
              </li>
            ))}
          </ul>
        )}
      </Block>
    </div>
  );
}
