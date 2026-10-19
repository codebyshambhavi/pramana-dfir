// Role 4: one KPI card: label, prominent value, one grounded sub-line. No trend lines: the API returns no history.
import type { ReactNode } from "react";
import { Link } from "react-router-dom";

export type Tone = "trace" | "alert";

const TONE = {
  trace: {
    card: "border-trace/35 hover:border-trace/70 shadow-[0_0_30px_-12px_rgba(59,140,255,0.55),inset_0_1px_0_rgba(122,180,255,0.08)] hover:shadow-[0_0_40px_-8px_rgba(59,140,255,0.6),inset_0_1px_0_rgba(122,180,255,0.12)]",
    edge: "via-trace-soft",
    bloom: "bg-trace/25",
    icon: "border-trace/45 bg-trace/[0.12] text-trace-soft shadow-[0_0_16px_rgba(59,140,255,0.45)]",
    sub: "text-trace-soft"
  },
  alert: {
    card: "border-alert/40 hover:border-alert/75 shadow-[0_0_30px_-12px_rgba(239,43,60,0.6),inset_0_1px_0_rgba(255,90,102,0.08)] hover:shadow-[0_0_40px_-8px_rgba(239,43,60,0.65),inset_0_1px_0_rgba(255,90,102,0.12)]",
    edge: "via-alert-soft",
    bloom: "bg-alert/25",
    icon: "border-alert/50 bg-alert/[0.12] text-alert shadow-[0_0_16px_rgba(239,43,60,0.5)]",
    sub: "text-alert-soft"
  }
};

/** `null` while loading; `"unavailable"` when its data source failed. */
export type KpiValue = number | null | "unavailable";

export default function KpiCard({
  icon,
  value,
  label,
  sub,
  tone,
  to
}: {
  icon: ReactNode;
  value: KpiValue;
  label: string;
  sub?: ReactNode;
  tone: Tone;
  to?: string;
}) {
  const t = TONE[tone];
  const body = (
    <>
      <span aria-hidden="true" className={`absolute inset-x-6 top-0 h-px bg-gradient-to-r from-transparent ${t.edge} to-transparent opacity-80`} />
      <span aria-hidden="true" className={`pointer-events-none absolute -top-14 -right-12 size-36 rounded-full blur-3xl ${t.bloom} opacity-60 transition-opacity duration-300 group-hover:opacity-100`} />
      <div className="relative flex items-center gap-3">
        <span className={`flex size-10 shrink-0 items-center justify-center rounded-xl border ${t.icon}`}>{icon}</span>
        <p className="text-[12px] font-semibold tracking-[0.14em] text-soft/85 uppercase">{label}</p>
      </div>
      <p className="relative mt-4 text-[42px] leading-none font-semibold tracking-[-0.03em] tabular-nums">
        {value === null ? (
          <span className="inline-block h-9 w-14 animate-pulse rounded-md bg-white/10 align-middle" aria-label="Loading" />
        ) : value === "unavailable" ? (
          <span className="text-soft/35" aria-label="Unavailable">
            —
          </span>
        ) : (
          value
        )}
      </p>
      <p className={`relative mt-2.5 min-h-[18px] truncate text-[12.5px] ${value === "unavailable" ? "text-muted" : t.sub}`}>
        {value === "unavailable" ? "Source unavailable" : sub}
      </p>
    </>
  );
  const className = `group relative block overflow-hidden rounded-2xl border bg-[linear-gradient(155deg,rgba(18,30,56,0.85),rgba(7,11,21,0.92)_60%)] px-5 pt-4.5 pb-4 transition-[border-color,box-shadow] duration-300 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-trace ${t.card}`;
  if (!to) return <div className={className}>{body}</div>;
  return to.startsWith("#") ? (
    <a href={to} className={className}>
      {body}
    </a>
  ) : (
    <Link to={to} className={className}>
      {body}
    </Link>
  );
}
