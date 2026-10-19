// Role 4: evidence table (cards below md) with selection, sorting and row actions.
import type { KeyboardEvent, ReactNode } from "react";
import { FileIcon, SortArrows } from "../../../components/console/icons";
import type { EvidenceItem } from "../../../api/types";
import { fileKind, formatIntake, isParsedKind, truncateHash } from "../model";
import RowMenu from "./RowMenu";
import { CopyButton, FileKindBadge } from "./ui";

export type SortKey = "evidence_id" | "intake_time";
export interface SortState {
  key: SortKey;
  dir: "asc" | "desc";
}

interface Props {
  rows: EvidenceItem[];
  loading: boolean;
  selected: ReadonlySet<string>;
  activeId: string | null;
  sort: SortState;
  onSort: (key: SortKey) => void;
  onToggle: (id: string) => void;
  onToggleAll: (ids: string[], checked: boolean) => void;
  onOpen: (id: string) => void;
}

const Checkbox = ({ checked, indeterminate = false, label, onChange }: { checked: boolean; indeterminate?: boolean; label: string; onChange: (v: boolean) => void }) => (
  <input
    type="checkbox"
    aria-label={label}
    checked={checked}
    ref={el => {
      if (el) el.indeterminate = indeterminate;
    }}
    onClick={e => e.stopPropagation()}
    onChange={e => onChange(e.target.checked)}
    className="size-[18px] cursor-pointer appearance-none rounded border border-white/25 bg-transparent transition checked:border-trace checked:bg-trace checked:bg-[url('data:image/svg+xml,%3Csvg%20xmlns=%22http://www.w3.org/2000/svg%22%20viewBox=%220%200%2024%2024%22%20fill=%22none%22%20stroke=%22white%22%20stroke-width=%223%22%3E%3Cpath%20d=%22m5%2012.5%204.5%204.5L19%207.5%22/%3E%3C/svg%3E')] indeterminate:border-trace indeterminate:bg-trace/60 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-trace"
  />
);

function SortHeader({ label, sortKey, sort, onSort }: { label: string; sortKey: SortKey; sort: SortState; onSort: (k: SortKey) => void }) {
  const active = sort.key === sortKey;
  return (
    <button
      type="button"
      onClick={() => onSort(sortKey)}
      className="inline-flex items-center gap-1.5 hover:text-white"
      aria-label={`Sort by ${label}${active ? (sort.dir === "asc" ? ", ascending" : ", descending") : ""}`}
    >
      {label}
      <SortArrows size={14} className={active ? "text-trace-soft" : "text-soft/50"} />
    </button>
  );
}

const Intake = ({ iso }: { iso: string }) => {
  const t = formatIntake(iso);
  return (
    <time dateTime={t.iso} title={t.valid ? t.iso : "Unparseable timestamp"} className="whitespace-nowrap tabular-nums">
      {t.date}
      {t.valid && <span className="text-soft/60"> · {t.time}</span>}
    </time>
  );
};

const custodyLabel = (n: number) => (n === 0 ? "None" : `${n} ${n === 1 ? "entry" : "entries"}`);

function SkeletonRows() {
  return (
    <>
      {Array.from({ length: 6 }, (_, i) => (
        <tr key={i} className="border-t border-white/[0.05]">
          {Array.from({ length: 8 }, (_, j) => (
            <td key={j} className="px-4 py-4">
              <span className="block h-3.5 animate-pulse rounded bg-white/[0.07]" style={{ width: `${[18, 60, 70, 50, 75, 70, 40, 16][j]}%` }} />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}

export default function EvidenceTable({ rows, loading, selected, activeId, sort, onSort, onToggle, onToggleAll, onOpen }: Props) {
  const ids = rows.map(r => r.evidence_id);
  const selectedOnPage = ids.filter(id => selected.has(id)).length;
  const onRowKey = (e: KeyboardEvent, id: string) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onOpen(id);
    }
  };

  const th = (children: ReactNode, className = "") => (
    <th scope="col" className={`bg-white/[0.025] px-4 py-3.5 text-left text-[12.5px] font-semibold tracking-[0.02em] whitespace-nowrap text-soft/85 ${className}`}>
      {children}
    </th>
  );

  return (
    <>
      {/* Table from md up. */}
      <div className="hidden overflow-x-auto md:block">
        <table className="w-full min-w-[820px] border-collapse">
          <caption className="sr-only">Evidence items in this case</caption>
          <thead>
            <tr>
              {th(
                <Checkbox
                  label="Select all on this page"
                  checked={rows.length > 0 && selectedOnPage === rows.length}
                  indeterminate={selectedOnPage > 0 && selectedOnPage < rows.length}
                  onChange={checked => onToggleAll(ids, checked)}
                />,
                "w-12"
              )}
              {th(<SortHeader label="Evidence ID" sortKey="evidence_id" sort={sort} onSort={onSort} />)}
              {th("File name")}
              {th("File type")}
              {th(<SortHeader label="Intake time" sortKey="intake_time" sort={sort} onSort={onSort} />)}
              {th("SHA-256 (truncated)")}
              {th("Custody", "hidden xl:table-cell")}
              {th(<span className="sr-only">Actions</span>, "w-14 text-right")}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <SkeletonRows />
            ) : (
              rows.map(item => {
                const kind = fileKind(item.filename);
                const active = item.evidence_id === activeId;
                return (
                  <tr
                    key={item.evidence_id}
                    tabIndex={0}
                    aria-current={active ? "true" : undefined}
                    onClick={() => onOpen(item.evidence_id)}
                    onKeyDown={e => onRowKey(e, item.evidence_id)}
                    className={`cursor-pointer border-t border-white/[0.05] text-[14px] transition-colors outline-none hover:bg-trace/[0.045] focus-visible:bg-trace/[0.07] ${
                      active
                        ? "bg-[linear-gradient(90deg,rgba(239,43,60,0.12),rgba(239,43,60,0.03))] shadow-[inset_0_0_0_1px_rgba(239,43,60,0.7),inset_3px_0_0_#ef2b3c,0_0_24px_-8px_rgba(239,43,60,0.6)]"
                        : ""
                    }`}
                  >
                    <td className="px-4 py-3.5">
                      <Checkbox
                        label={`Select ${item.evidence_id}`}
                        checked={selected.has(item.evidence_id)}
                        onChange={() => onToggle(item.evidence_id)}
                      />
                    </td>
                    <td className="px-4 py-3.5 whitespace-nowrap">
                      <span className="inline-flex items-center gap-2.5 font-semibold tracking-[0.01em]">
                        <FileIcon
                          size={19}
                          className={isParsedKind(kind) ? "text-trace-soft drop-shadow-[0_0_6px_rgba(59,140,255,0.6)]" : "text-alert-soft drop-shadow-[0_0_6px_rgba(239,43,60,0.5)]"}
                        />
                        {item.evidence_id}
                      </span>
                    </td>
                    <td className="max-w-[240px] truncate px-4 py-3.5" title={item.filename}>
                      {item.filename}
                    </td>
                    <td className="px-4 py-3.5">
                      <FileKindBadge kind={kind} />
                    </td>
                    <td className="px-4 py-3.5 text-soft/90">
                      <Intake iso={item.intake_time} />
                    </td>
                    <td className="px-4 py-3.5">
                      <span className="inline-flex items-center gap-1.5">
                        <code
                          className="rounded-md border border-white/[0.07] bg-black/30 px-2 py-0.5 font-mono text-[12.5px] tracking-[0.02em] text-[#cfe0ff]"
                          title={item.sha256}
                        >
                          {truncateHash(item.sha256)}
                        </code>
                        <CopyButton text={item.sha256} label={`Copy SHA-256 of ${item.evidence_id}`} />
                      </span>
                    </td>
                    <td className="hidden px-4 py-3.5 text-[13px] whitespace-nowrap text-soft/75 xl:table-cell">
                      {custodyLabel(item.custody.length)}
                    </td>
                    <td className="px-4 py-3.5 text-right">
                      <RowMenu item={item} onOpen={() => onOpen(item.evidence_id)} />
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Cards below md. */}
      <ul className="divide-y divide-white/[0.06] md:hidden">
        {loading
          ? Array.from({ length: 4 }, (_, i) => (
              <li key={i} className="space-y-2.5 p-4">
                <span className="block h-4 w-1/3 animate-pulse rounded bg-white/[0.07]" />
                <span className="block h-3.5 w-2/3 animate-pulse rounded bg-white/[0.07]" />
              </li>
            ))
          : rows.map(item => {
              const kind = fileKind(item.filename);
              const active = item.evidence_id === activeId;
              return (
                <li
                  key={item.evidence_id}
                  tabIndex={0}
                  onClick={() => onOpen(item.evidence_id)}
                  onKeyDown={e => onRowKey(e, item.evidence_id)}
                  className={`flex cursor-pointer gap-3 p-4 outline-none focus-visible:bg-trace/[0.06] ${active ? "bg-alert/[0.05]" : ""}`}
                >
                  <div className="pt-0.5">
                    <Checkbox
                      label={`Select ${item.evidence_id}`}
                      checked={selected.has(item.evidence_id)}
                      onChange={() => onToggle(item.evidence_id)}
                    />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{item.evidence_id}</span>
                      <FileKindBadge kind={kind} />
                    </div>
                    <p className="mt-1 truncate text-[14px] text-soft" title={item.filename}>
                      {item.filename}
                    </p>
                    <p className="mt-1 text-[12.5px] text-soft/70">
                      <Intake iso={item.intake_time} />
                    </p>
                    <span className="mt-1 flex items-center gap-1">
                      <code className="font-mono text-[12.5px] text-soft/80">{truncateHash(item.sha256)}</code>
                      <CopyButton text={item.sha256} label={`Copy SHA-256 of ${item.evidence_id}`} />
                    </span>
                  </div>
                  <RowMenu item={item} onOpen={() => onOpen(item.evidence_id)} />
                </li>
              );
            })}
      </ul>
    </>
  );
}
