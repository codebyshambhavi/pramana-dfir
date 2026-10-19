// Role 4: evidence by file type as an SVG doughnut. Types are derived from file extensions (labelled as such).
import type { EvidenceItem } from "../../../api/types";
import { KIND_LABEL, fileKind, type FileKind } from "../../vault/model";

const KIND_COLOR: Record<FileKind, string> = {
  image: "#3b8cff",
  csv: "#2dd4bf",
  json: "#a78bfa",
  pcap: "#38bdf8",
  video: "#ef2b3c",
  pdf: "#fb7185",
  audio: "#f59e0b",
  other: "#64748b"
};

export default function EvidenceOverview({ items }: { items: EvidenceItem[] }) {
  const counts = new Map<FileKind, number>();
  items.forEach(item => counts.set(fileKind(item.filename), (counts.get(fileKind(item.filename)) ?? 0) + 1));
  const rows = [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const total = items.length;

  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const gap = rows.length > 1 ? 3 : 0;
  let offset = 0;

  return (
    <div className="flex flex-1 flex-col items-center gap-5 sm:flex-row sm:items-center">
      <div className="relative size-[150px] shrink-0">
        <svg viewBox="0 0 140 140" className="size-full -rotate-90" role="img" aria-label={`${total} evidence items by file type`}>
          <circle cx="70" cy="70" r={radius} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="16" />
          {rows.map(([kind, count]) => {
            const length = (count / total) * circumference;
            const dash = Math.max(length - gap, 0.5);
            const segment = (
              <circle
                key={kind}
                cx="70"
                cy="70"
                r={radius}
                fill="none"
                stroke={KIND_COLOR[kind]}
                strokeWidth="16"
                strokeDasharray={`${dash} ${circumference - dash}`}
                strokeDashoffset={-offset}
                style={{ filter: `drop-shadow(0 0 5px ${KIND_COLOR[kind]}66)` }}
              />
            );
            offset += length;
            return segment;
          })}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-[28px] leading-none font-semibold tabular-nums">{total}</span>
          <span className="mt-1 text-[12.5px] text-soft/75">Evidence</span>
        </div>
      </div>

      <ul className="w-full min-w-0 flex-1 space-y-2">
        {rows.map(([kind, count]) => (
          <li key={kind} className="flex items-center gap-2.5 text-[13.5px]">
            <span className="size-2.5 shrink-0 rounded-full" style={{ background: KIND_COLOR[kind], boxShadow: `0 0 8px ${KIND_COLOR[kind]}` }} />
            <span className="flex-1 truncate text-soft/90">{KIND_LABEL[kind]}</span>
            <span className="text-white tabular-nums">{count}</span>
            <span className="w-11 text-right text-soft/60 tabular-nums">{Math.round((count / total) * 100)}%</span>
          </li>
        ))}
        <li className="pt-1 text-[11.5px] text-muted">Type judged from the file extension</li>
      </ul>
    </div>
  );
}
