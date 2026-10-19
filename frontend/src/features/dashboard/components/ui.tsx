// Role 4: shared dashboard pieces: glass panel, section states and small formatters.
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { Alert, ArrowRight } from "../../../components/console/icons";
import type { Section } from "../dashboardData";

export const GLASS =
  "rounded-2xl border border-trace/[0.2] bg-[linear-gradient(180deg,rgba(14,23,42,0.72),rgba(6,10,19,0.8))] shadow-[inset_0_1px_0_rgba(255,255,255,0.045),0_24px_48px_-28px_rgba(0,0,0,0.9),0_0_28px_-18px_rgba(59,140,255,0.45)] backdrop-blur-[4px]";

export function Panel({
  title,
  note,
  action,
  children,
  className = "",
  id
}: {
  title: string;
  note?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  id?: string;
}) {
  return (
    <section
      id={id}
      aria-label={title}
      className={`relative flex min-w-0 scroll-mt-6 flex-col ${GLASS} transition-[border-color,box-shadow] duration-300 hover:border-trace/40 hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.06),0_24px_48px_-28px_rgba(0,0,0,0.9),0_0_36px_-14px_rgba(59,140,255,0.55)] ${className}`}
    >
      <span aria-hidden="true" className="pointer-events-none absolute inset-x-8 top-0 h-px bg-gradient-to-r from-transparent via-trace-soft/60 to-transparent" />
      <header className="flex items-center gap-3 border-b border-white/[0.05] px-5 pt-4 pb-3.5">
        <h2 className="text-[16.5px] font-semibold tracking-[-0.01em] text-white">
          {title}
          {note && <span className="ml-1.5 text-[13px] font-normal text-muted">{note}</span>}
        </h2>
        {action && <div className="ml-auto">{action}</div>}
      </header>
      <div className="flex min-h-0 flex-1 flex-col px-5 pt-4 pb-5">{children}</div>
    </section>
  );
}

export function PanelLink({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Link
      to={to}
      className="inline-flex items-center gap-1.5 rounded-md border border-white/10 px-2.5 py-1.5 text-[12.5px] text-soft transition hover:border-trace/40 hover:text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-trace"
    >
      {children}
      <ArrowRight size={13} />
    </Link>
  );
}

/** Loading skeleton, error or empty state for a panel whose data isn't ready. */
export function SectionGate<T>({
  section,
  isEmpty,
  empty,
  rows = 4,
  recover,
  children
}: {
  section: Section<T>;
  isEmpty?: (data: T) => boolean;
  empty: string;
  rows?: number;
  /** Offered under the error message, e.g. a link to the demo data. */
  recover?: ReactNode;
  children: (data: T) => ReactNode;
}) {
  if (section.status === "loading")
    return (
      <div className="space-y-3 pt-1" aria-busy="true" aria-label="Loading">
        {Array.from({ length: rows }, (_, i) => (
          <span key={i} className="block h-9 animate-pulse rounded-lg bg-white/[0.05]" style={{ width: `${92 - i * 9}%` }} />
        ))}
      </div>
    );
  if (section.status === "error")
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-2 py-8 text-center">
        <Alert size={20} className="text-soft/60" />
        <p className="text-[13.5px] text-soft/80">Unavailable</p>
        <p className="max-w-[260px] text-[12.5px] text-muted">{section.message}</p>
        {recover && <div className="mt-2">{recover}</div>}
      </div>
    );
  if (isEmpty?.(section.data))
    return <p className="flex flex-1 items-center justify-center py-8 text-center text-[13.5px] text-soft/70">{empty}</p>;
  return <>{children(section.data)}</>;
}

export const humanize = (action: string) => {
  const text = action.replace(/_/g, " ");
  return text.charAt(0).toUpperCase() + text.slice(1);
};

export function formatStamp(iso: string) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" })}, ${d.toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit"
  })}`;
}
