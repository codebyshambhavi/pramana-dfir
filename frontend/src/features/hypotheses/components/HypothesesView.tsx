// Role 4 / T11: ranked hypotheses with status chips, and the required / expected / forbidden matrix of the selected
// one. Everything shown comes from the run as returned by the backend. Rank and status are the engine's; no score,
// penalty or other decimal is displayed.
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { useSourceLink } from "../../../components/console/useSourceLink";
import type { HypothesisStatus, ItemCategory, ItemEvaluation, ItemState, RankedHypothesis, RunDetails } from "../../../api/pending/runs";
import { Info } from "../../../components/console/icons";
import { CopyButton } from "../../vault/components/ui";
import { truncateHash } from "../../vault/model";
import type { LoadedRun } from "../runSource";

const CHIP = "inline-flex items-center rounded-md border px-2 py-0.5 text-[12px] whitespace-nowrap";

export const HYPOTHESIS_STATUS: Record<HypothesisStatus, { label: string; style: string; note: string }> = {
  LEADING: { label: "Leading", style: "border-trace/55 bg-trace/15 text-trace-soft shadow-[0_0_12px_-4px_rgba(59,140,255,0.8)]", note: "Least disconfirmed, by the required margin" },
  VIABLE: { label: "Viable", style: "border-teal-400/35 bg-teal-400/10 text-teal-200", note: "Not ruled out" },
  WEAKENED: { label: "Weakened", style: "border-amber-400/35 bg-amber-400/10 text-amber-200", note: "Expected evidence missing" },
  REFUTED: { label: "Refuted", style: "border-alert/45 bg-alert/[0.12] text-alert-soft", note: "A required or forbidden item failed" },
  UNDETERMINED: { label: "Undetermined", style: "border-white/12 bg-white/[0.04] text-soft/75", note: "No hypothesis separates from the others" }
};

/** MISSING and UNOBSERVABLE look deliberately different: one counts against the hypothesis, the other never does. */
export const ITEM_STATE: Record<ItemState, { label: string; style: string; meaning: string }> = {
  SATISFIED: { label: "Satisfied", style: "border-teal-400/35 bg-teal-400/10 text-teal-200", meaning: "The item holds: required or expected evidence is present, or forbidden evidence is absent." },
  VIOLATED: { label: "Violated", style: "border-alert/45 bg-alert/[0.12] text-alert-soft", meaning: "Forbidden evidence is present, or a constraint fails." },
  MISSING: {
    label: "Missing",
    style: "border-amber-400/45 bg-amber-400/[0.12] text-amber-200",
    meaning: "The source was collected and covers the window, but the record is not there. Counts against the hypothesis."
  },
  UNOBSERVABLE: {
    label: "Unobservable",
    style: "border-dashed border-white/25 bg-transparent text-soft/80",
    meaning: "The source was not collected or does not cover the window, so absence says nothing. Never counts against the hypothesis."
  },
  NEUTRAL: { label: "Neutral", style: "border-white/12 bg-white/[0.04] text-soft/65", meaning: "Cannot be checked either way; does not count." }
};

const CATEGORIES: { key: ItemCategory; label: string; hint: string }[] = [
  { key: "requires", label: "Required", hint: "must be present" },
  { key: "expects", label: "Expected", hint: "should be present" },
  { key: "forbids", label: "Forbidden", hint: "must be absent" },
  { key: "constraint", label: "Constraints", hint: "ordering and identity rules" }
];

const Chip = ({ className, title, children }: { className: string; title?: string; children: ReactNode }) => (
  <span className={`${CHIP} ${className}`} title={title}>
    {children}
  </span>
);

export const HypothesisChip = ({ status }: { status: HypothesisStatus }) => {
  const s = HYPOTHESIS_STATUS[status] ?? HYPOTHESIS_STATUS.UNDETERMINED;
  return (
    <Chip className={s.style} title={s.note}>
      {s.label}
    </Chip>
  );
};

export const StateChip = ({ state }: { state: ItemState }) => {
  const s = ITEM_STATE[state] ?? ITEM_STATE.NEUTRAL;
  return (
    <Chip className={s.style} title={s.meaning}>
      {s.label}
    </Chip>
  );
};

/** Run times come back as naive UTC ("2026-11-08T04:39:12"); read them as UTC and say so, instead of as local time. */
export const formatUtc = (iso: string) => {
  const d = new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(iso) ? iso : `${iso}Z`);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.toLocaleString(undefined, { timeZone: "UTC", day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" })} UTC`;
};

/** The engine appends "[NON-DIAGNOSTIC: …]" to the rationale of items that every hypothesis shares. */
const splitRationale = (text: string) => {
  const m = text.match(/^(.*?)\s*\[NON-DIAGNOSTIC:\s*(.*)\]\s*$/s);
  return m ? { text: m[1], nonDiagnostic: m[2] } : { text, nonDiagnostic: null };
};

function RunHeader({ loaded }: { loaded: LoadedRun }) {
  const { run, origin } = loaded;
  return (
    <div className="flex flex-wrap items-center gap-x-5 gap-y-2 rounded-xl border border-white/[0.07] bg-black/20 px-4 py-3 text-[12.5px] text-soft/75">
      {origin === "recorded" && (
        <span className="rounded-md border border-violet-400/35 bg-violet-400/10 px-2 py-0.5 text-[12px] text-violet-200">Recorded real run</span>
      )}
      <span>
        Case <span className="text-white">{run.case_id}</span>
      </span>
      <span>
        Run <span className="text-white tabular-nums">{run.run_id}</span>
      </span>
      {run.created_at && <span title={run.created_at}>{formatUtc(run.created_at)}</span>}
      <span>
        Validity{" "}
        <span className={run.validity === "VALID" ? "text-teal-200" : "text-alert-soft"} title={run.invalidation_reasons.join("\n") || undefined}>
          {run.validity === "VALID" ? "Valid" : "Invalidated"}
        </span>
      </span>
      <span className="flex items-center gap-1">
        Ranking hash
        <code className="rounded-md border border-white/[0.07] bg-black/30 px-1.5 py-px font-mono text-[11.5px] text-[#cfe0ff]" title={run.ranking_hash}>
          {truncateHash(run.ranking_hash)}
        </code>
        <CopyButton text={run.ranking_hash} label="Copy ranking hash" />
      </span>
    </div>
  );
}

function RankedList({ hypotheses, selectedId, onSelect }: { hypotheses: RankedHypothesis[]; selectedId: string; onSelect: (id: string) => void }) {
  return (
    <ol className="space-y-2.5" aria-label="Ranked hypotheses">
      {hypotheses.map(h => {
        const active = h.id === selectedId;
        return (
          <li key={h.id}>
            <button
              type="button"
              onClick={() => onSelect(h.id)}
              aria-pressed={active}
              className={`flex w-full items-start gap-3.5 rounded-xl border p-3.5 text-left transition outline-none focus-visible:border-trace ${
                active ? "border-trace/55 bg-trace/[0.08] shadow-[0_0_22px_-10px_rgba(59,140,255,0.8)]" : "border-white/[0.07] bg-white/[0.02] hover:border-trace/30"
              }`}
            >
              <span
                aria-label={`Rank ${h.rank}`}
                className={`flex size-8 shrink-0 items-center justify-center rounded-lg border text-[14px] font-semibold tabular-nums ${
                  h.rank === 1 ? "border-trace/50 text-trace-soft" : "border-white/12 text-soft/70"
                }`}
              >
                {h.rank}
              </span>
              <span className="min-w-0 flex-1">
                <span className="flex flex-wrap items-center gap-2">
                  <span className="text-[14.5px] font-semibold text-white">{h.name}</span>
                  <span className="text-[12px] text-soft/55 tabular-nums">{h.id}</span>
                  <HypothesisChip status={h.status} />
                </span>
                <span className="mt-1 block text-[12.5px] leading-snug text-soft/75">{h.description}</span>
                <span className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[12px] tabular-nums">
                  <span className={h.hard_violations_count ? "text-alert-soft" : "text-soft/55"}>{h.hard_violations_count} violated</span>
                  <span className={h.missing_expected_count ? "text-amber-200" : "text-soft/55"}>{h.missing_expected_count} missing</span>
                  <span className="text-soft/55">{h.unobservable_count} unobservable</span>
                  <span className="text-soft/55">{h.supporting_claim_ids.length} supporting claims</span>
                </span>
              </span>
            </button>
          </li>
        );
      })}
    </ol>
  );
}

function Legend() {
  return (
    <details className="group rounded-xl border border-trace/20 bg-trace/[0.04] px-4 py-3 text-[12.5px]">
      <summary className="flex cursor-pointer list-none items-center gap-2 text-soft/85 select-none">
        <Info size={15} className="text-trace-soft" />
        <span>
          <span className="text-amber-200">Missing</span> counts against a hypothesis; <span className="text-soft">Unobservable</span> never does.
        </span>
        <span className="ml-auto text-soft/55 group-open:hidden">What each state means</span>
      </summary>
      <dl className="mt-3 grid gap-x-4 gap-y-2.5 sm:grid-cols-[auto_minmax(0,1fr)]">
        {(Object.keys(ITEM_STATE) as ItemState[]).map(state => (
          <div key={state} className="contents">
            <dt>
              <StateChip state={state} />
            </dt>
            <dd className="text-soft/80">{ITEM_STATE[state].meaning}</dd>
          </div>
        ))}
      </dl>
    </details>
  );
}

function MatrixRow({ item, runId }: { item: ItemEvaluation; runId: string }) {
  const rationale = splitRationale(item.rationale);
  const toPath = useSourceLink();
  return (
    <tr className="border-t border-white/[0.05] align-top">
      <td className="py-2.5 pr-3 pl-1 whitespace-nowrap text-soft/60 tabular-nums">{item.item_id}</td>
      <td className="py-2.5 pr-3">
        <span className="block text-white">{item.description}</span>
        <span className="mt-0.5 block font-mono text-[11.5px] text-soft/55">{item.claim_type}</span>
      </td>
      <td className="py-2.5 pr-3 whitespace-nowrap text-soft/80">{item.stage.replace(/_/g, " ")}</td>
      <td className="py-2.5 pr-3">
        <StateChip state={item.state} />
      </td>
      <td className="py-2.5 pr-3 font-mono text-[11.5px] break-all text-soft/65">{item.witness_family ?? "—"}</td>
      <td className="py-2.5 pr-1 text-soft/80">
        {rationale.text}
        <span className="mt-1 flex flex-wrap gap-1.5">
          {rationale.nonDiagnostic !== null && (
            <span className="rounded border border-white/12 px-1.5 py-px text-[11px] text-soft/60" title={rationale.nonDiagnostic}>
              Non-diagnostic
            </span>
          )}
          {item.matched_claim_ids.map(id => (
            <Link
              key={id}
              to={toPath("/app/investigation", { tab: "claims", claim: id, run: runId })}
              title={`Inspect claim ${id}`}
              className="rounded border border-trace/25 px-1.5 py-px font-mono text-[11px] text-trace-soft hover:border-trace/50 hover:text-white"
            >
              claim {id.slice(0, 8)}…
            </Link>
          ))}
          {item.assumed_claim_ids.length > 0 && (
            <span className="rounded border border-violet-400/30 px-1.5 py-px text-[11px] text-violet-200">
              {item.assumed_claim_ids.length} assumed
            </span>
          )}
        </span>
      </td>
    </tr>
  );
}

function Matrix({ hypothesis, runId }: { hypothesis: RankedHypothesis; runId: string }) {
  const groups = CATEGORIES.map(c => ({ ...c, items: hypothesis.evaluations.filter(e => e.category === c.key) })).filter(g => g.items.length);
  return (
    <div className="-mx-1 overflow-x-auto">
      <table className="w-full min-w-[760px] border-collapse text-[13px]">
        <thead>
          <tr className="text-left text-[12px] text-soft/65">
            <th scope="col" className="w-[104px] py-2 pr-3 pl-1 font-medium">Item</th>
            <th scope="col" className="py-2 pr-3 font-medium">Evidence item</th>
            <th scope="col" className="w-[120px] py-2 pr-3 font-medium">Stage</th>
            <th scope="col" className="w-[118px] py-2 pr-3 font-medium">State</th>
            <th scope="col" className="w-[170px] py-2 pr-3 font-medium">Source</th>
            <th scope="col" className="py-2 pr-1 font-medium">Why</th>
          </tr>
        </thead>
        {groups.map(g => (
          <tbody key={g.key}>
            <tr>
              <th scope="rowgroup" colSpan={6} className="pt-4 pb-1.5 pl-1 text-left text-[11px] font-semibold tracking-[0.18em] text-soft/70 uppercase">
                {g.label} <span className="font-normal tracking-normal text-soft/45 normal-case">· {g.hint}</span>
              </th>
            </tr>
            {g.items.map(item => (
              <MatrixRow key={item.item_id} item={item} runId={runId} />
            ))}
          </tbody>
        ))}
      </table>
    </div>
  );
}

export default function HypothesesView({
  loaded,
  selectedId,
  onSelect
}: {
  loaded: LoadedRun;
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  const run: RunDetails = loaded.run;
  const ranked = [...run.ranked_hypotheses].sort((a, b) => a.rank - b.rank);
  if (!ranked.length)
    return (
      <div className="space-y-4">
        <RunHeader loaded={loaded} />
        <p className="py-10 text-center text-[13.5px] text-soft/70">
          This run has no ranked hypotheses{run.snapshot_status === "UNAVAILABLE" ? " (its analysis snapshot is unavailable)" : ""}.
        </p>
      </div>
    );
  const selected = ranked.find(h => h.id === selectedId) ?? ranked[0];

  return (
    <div className="space-y-4">
      <RunHeader loaded={loaded} />
      <div className="grid gap-5 xl:grid-cols-[minmax(320px,0.8fr)_minmax(0,2fr)]">
        <section aria-label="Ranking">
          <h3 className="mb-1 text-[14px] font-semibold text-white">Ranking</h3>
          <p className="mb-3 text-[12px] text-soft/60">Ordered by how little the evidence contradicts each hypothesis, not by how much supports it.</p>
          <RankedList hypotheses={ranked} selectedId={selected.id} onSelect={onSelect} />
        </section>
        <section aria-label={`Evidence matrix for ${selected.name}`} className="min-w-0 space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-[14px] font-semibold text-white">Evidence matrix · {selected.name}</h3>
            <HypothesisChip status={selected.status} />
          </div>
          <Legend />
          <Matrix hypothesis={selected} runId={run.run_id} />
        </section>
      </div>
    </div>
  );
}
