// Role 4: search and filters for the evidence table.
import type { ChangeEvent } from "react";
import { ChevronDown, Search } from "../../../components/console/icons";
import { KIND_LABEL, type FileKind } from "../model";

export type SupportFilter = "all" | "parsed" | "unparsed";

export interface VaultFilters {
  query: string;
  kind: FileKind | "all";
  support: SupportFilter;
}

function Select<T extends string>({
  label,
  value,
  options,
  onChange
}: {
  label: string;
  value: T;
  options: { value: T; label: string }[];
  onChange: (value: T) => void;
}) {
  return (
    <label className="relative block min-w-0">
      <span className="sr-only">{label}</span>
      <select
        value={value}
        onChange={(e: ChangeEvent<HTMLSelectElement>) => onChange(e.target.value as T)}
        className="h-11 w-full cursor-pointer appearance-none rounded-lg border border-white/10 bg-panel/80 pr-9 pl-3.5 text-[14px] text-white transition hover:border-trace/40 focus:border-trace/60 focus:outline-none"
      >
        {options.map(option => (
          <option key={option.value} value={option.value} className="bg-panel">
            {option.label}
          </option>
        ))}
      </select>
      <ChevronDown size={16} className="pointer-events-none absolute top-1/2 right-3 -translate-y-1/2 text-soft/70" />
    </label>
  );
}

export default function VaultToolbar({
  filters,
  kinds,
  onChange
}: {
  filters: VaultFilters;
  kinds: FileKind[];
  onChange: (next: VaultFilters) => void;
}) {
  return (
    <div className="flex flex-col gap-2.5 lg:flex-row lg:items-center">
      <label className="relative block min-w-0 flex-1 lg:max-w-[560px]">
        <span className="sr-only">Search evidence</span>
        <Search size={18} className="pointer-events-none absolute top-1/2 left-4 -translate-y-1/2 text-soft/70" />
        <input
          type="search"
          value={filters.query}
          onChange={e => onChange({ ...filters, query: e.target.value })}
          placeholder="Search by file name, evidence ID or SHA-256…"
          className="h-11 w-full rounded-lg border border-white/10 bg-panel/80 pr-4 pl-11 text-[14px] text-white placeholder:text-muted transition hover:border-trace/40 focus:border-trace/60 focus:outline-none"
        />
      </label>
      <div className="grid grid-cols-2 gap-2.5 lg:ml-auto lg:flex">
        <Select
          label="File type"
          value={filters.kind}
          onChange={kind => onChange({ ...filters, kind })}
          options={[{ value: "all" as const, label: "All types" }, ...kinds.map(k => ({ value: k, label: KIND_LABEL[k] }))]}
        />
        <Select
          label="Parser support"
          value={filters.support}
          onChange={support => onChange({ ...filters, support })}
          options={[
            { value: "all", label: "All parser support" },
            { value: "parsed", label: "Parsed types" },
            { value: "unparsed", label: "Unparsed types" }
          ]}
        />
      </div>
    </div>
  );
}
