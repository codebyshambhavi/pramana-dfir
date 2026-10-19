// Role 4: searchable list of findings (left column). Selecting a row drives the detail and summary panels.
import { ChevronDown, ScanSearch, Search } from "../../../components/console/icons";
import type { Finding } from "../../../api/types";
import { StatusChip, TYPE_CHIP } from "../../dashboard/components/FindingsPanel";
import { TYPE_LABEL, evidenceIdsFor, type CaseIndex } from "../findingModel";

export type TypeFilter = Finding["type"] | "all";

interface Props {
  findings: Finding[];
  index: CaseIndex;
  selectedId: string | null;
  onSelect: (id: string) => void;
  query: string;
  onQuery: (q: string) => void;
  type: TypeFilter;
  onType: (t: TypeFilter) => void;
}

export const matchesFinding = (f: Finding, index: CaseIndex, query: string) => {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return [f.finding_id, f.claim, f.reasoning ?? "", ...f.evidence_event_ids, ...evidenceIdsFor(f, index)].some(v => v.toLowerCase().includes(q));
};

export default function FindingsList({ findings, index, selectedId, onSelect, query, onQuery, type, onType }: Props) {
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex flex-col gap-2.5 sm:flex-row">
        <label className="relative block min-w-0 flex-1">
          <span className="sr-only">Search findings</span>
          <Search size={17} className="pointer-events-none absolute top-1/2 left-3.5 -translate-y-1/2 text-soft/70" />
          <input
            type="search"
            value={query}
            onChange={e => onQuery(e.target.value)}
            placeholder="Search findings, evidence or event IDs…"
            className="h-10 w-full rounded-lg border border-white/10 bg-panel/80 pr-3 pl-10 text-[13.5px] text-white placeholder:text-muted transition hover:border-trace/40 focus:border-trace/60 focus:outline-none"
          />
        </label>
        <label className="relative block sm:w-[150px]">
          <span className="sr-only">Finding type</span>
          <select
            value={type}
            onChange={e => onType(e.target.value as TypeFilter)}
            className="h-10 w-full cursor-pointer appearance-none rounded-lg border border-white/10 bg-panel/80 pr-8 pl-3 text-[13.5px] text-white transition hover:border-trace/40 focus:border-trace/60 focus:outline-none"
          >
            <option value="all" className="bg-panel">
              All types
            </option>
            {(Object.keys(TYPE_LABEL) as Finding["type"][]).map(t => (
              <option key={t} value={t} className="bg-panel">
                {TYPE_LABEL[t]}
              </option>
            ))}
          </select>
          <ChevronDown size={15} className="pointer-events-none absolute top-1/2 right-3 -translate-y-1/2 text-soft/70" />
        </label>
      </div>

      {findings.length === 0 ? (
        <div className="flex flex-1 flex-col items-center justify-center gap-2 py-12 text-center">
          <ScanSearch size={24} className="text-soft/50" />
          <p className="text-[13.5px] text-soft/75">No findings match.</p>
        </div>
      ) : (
        <ul className="mt-3 -mx-2 space-y-1" aria-label="Findings">
          {findings.map(f => {
            const active = f.finding_id === selectedId;
            const evidence = evidenceIdsFor(f, index);
            return (
              <li key={f.finding_id}>
                <button
                  type="button"
                  onClick={() => onSelect(f.finding_id)}
                  aria-current={active ? "true" : undefined}
                  className={`grid w-full grid-cols-[minmax(0,1fr)_auto] gap-x-3 gap-y-2 rounded-xl border px-3 py-3 text-left transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-trace ${
                    active
                      ? "border-alert/60 bg-[linear-gradient(90deg,rgba(239,43,60,0.14),rgba(239,43,60,0.03))] shadow-[inset_3px_0_0_#ef2b3c,0_0_26px_-8px_rgba(239,43,60,0.65)]"
                      : "border-transparent hover:border-trace/25 hover:bg-trace/[0.04]"
                  }`}
                >
                  <span className="min-w-0">
                    <span className="flex items-center gap-2 text-[12px] text-soft/60 tabular-nums">
                      {f.finding_id}
                      <span className={`rounded-md border px-1.5 py-px text-[11px] ${TYPE_CHIP[f.type] ?? TYPE_CHIP.hypothesis}`}>{TYPE_LABEL[f.type]}</span>
                    </span>
                    <span className="mt-1 line-clamp-2 block text-[14px] leading-snug text-white">{f.claim}</span>
                    {evidence.length > 0 && (
                      <span className="mt-1.5 block truncate text-[12px] text-trace-soft/80 tabular-nums">{evidence.join(" · ")}</span>
                    )}
                  </span>
                  <span className="self-start">
                    <StatusChip finding={f} />
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
