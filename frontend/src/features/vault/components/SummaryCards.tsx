// Role 4: counts the evidence list actually supports. No "verified" count: the API reports no verification status.
import type { ReactNode } from "react";
import { Alert, Custody, FileIcon } from "../../../components/console/icons";

export interface VaultCounts {
  total: number;
  custodyEntries: number;
  notParsed: number;
}

const TONE = {
  trace: {
    card: "border-trace/40 shadow-[0_0_28px_-10px_rgba(59,140,255,0.6),inset_0_1px_0_rgba(122,180,255,0.1)] hover:border-trace/70",
    edge: "via-trace-soft",
    bloom: "bg-trace/30",
    icon: "text-trace-soft drop-shadow-[0_0_8px_rgba(59,140,255,0.8)]"
  },
  cyan: {
    card: "border-cyan-400/35 shadow-[0_0_28px_-10px_rgba(34,211,238,0.5),inset_0_1px_0_rgba(103,232,249,0.1)] hover:border-cyan-300/60",
    edge: "via-cyan-300",
    bloom: "bg-cyan-400/25",
    icon: "text-cyan-300 drop-shadow-[0_0_8px_rgba(34,211,238,0.7)]"
  },
  alert: {
    card: "border-alert/45 shadow-[0_0_28px_-10px_rgba(239,43,60,0.65),inset_0_1px_0_rgba(255,90,102,0.1)] hover:border-alert/75",
    edge: "via-alert-soft",
    bloom: "bg-alert/30",
    icon: "text-alert drop-shadow-[0_0_8px_rgba(239,43,60,0.8)]"
  }
};

function Card({ icon, value, label, hint, tone }: { icon: ReactNode; value: ReactNode; label: string; hint: string; tone: keyof typeof TONE }) {
  const t = TONE[tone];
  return (
    <div
      className={`group relative min-w-0 overflow-hidden rounded-xl border bg-[linear-gradient(160deg,rgba(18,30,56,0.85),rgba(6,9,17,0.92)_65%)] px-4 py-3.5 transition-[border-color] duration-300 sm:px-5 sm:py-4 ${t.card}`}
      title={hint}
    >
      <span aria-hidden="true" className={`absolute inset-x-4 top-0 h-px bg-gradient-to-r from-transparent ${t.edge} to-transparent`} />
      <span aria-hidden="true" className={`pointer-events-none absolute -right-10 -bottom-12 size-28 rounded-full blur-3xl ${t.bloom} opacity-50 transition-opacity group-hover:opacity-90`} />
      <span className={`relative block ${t.icon}`}>{icon}</span>
      <p className="relative mt-2.5 text-[30px] leading-none font-semibold tracking-[-0.02em] tabular-nums">{value}</p>
      <p className="relative mt-1.5 truncate text-[13px] text-soft/85">{label}</p>
    </div>
  );
}

export default function SummaryCards({ counts }: { counts: VaultCounts | null }) {
  const show = (n: number) => (counts ? n : <span className="inline-block h-7 w-9 animate-pulse rounded bg-white/10 align-middle" />);
  return (
    <div className="grid grid-cols-3 gap-2.5 sm:gap-3">
      <Card
        tone="trace"
        icon={<FileIcon size={26} />}
        value={show(counts?.total ?? 0)}
        label="Total evidence"
        hint="Items returned by GET /cases/{id}/evidence"
      />
      <Card
        tone="cyan"
        icon={<Custody size={26} />}
        value={show(counts?.custodyEntries ?? 0)}
        label="Custody entries"
        hint="Sum of custody entries across all items"
      />
      <Card
        tone="alert"
        icon={<Alert size={26} />}
        value={show(counts?.notParsed ?? 0)}
        label="Unparsed types"
        hint="File types the evidence engine has no parser for (judged from the file extension)"
      />
    </div>
  );
}
