// Role 4: Timeline tab of the Investigation Workspace. Every event in time order, filterable by source.
// Events cited by the selected finding are highlighted; clicking an event opens its evidence in the vault.
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useSourceLink } from "../components/console/useSourceLink";
import type { CaseEvent } from "../api/types";
import { SOURCE_ICON, describe } from "../features/dashboard/components/TimelinePanel";
import { formatClock, formatDay, storedTime, useDisplayZone } from "../lib/time";

const SOURCES: CaseEvent["source"][] = ["browser", "chat", "log", "pcap", "image"];


export default function Timeline({
  events,
  cited,
  citedLabel
}: {
  events: CaseEvent[];
  /** Event IDs cited by the selected finding. */
  cited: ReadonlySet<string>;
  citedLabel?: string;
}) {
  const toPath = useSourceLink();
  const [source, setSource] = useState<CaseEvent["source"] | "all">("all");
  const present = useMemo(() => SOURCES.filter(s => events.some(e => e.source === s)), [events]);
  const zone = useDisplayZone();
  const groups = useMemo(() => {
    const sorted = [...events].filter(e => source === "all" || e.source === source).sort((a, b) => storedTime(a.timestamp) - storedTime(b.timestamp));
    const map = new Map<string, CaseEvent[]>();
    // Days are grouped in the display zone, so an event can move to another day when the zone changes.
    sorted.forEach(e => {
      const day = formatDay(e.timestamp, zone);
      map.set(day, [...(map.get(day) ?? []), e]);
    });
    return [...map];
  }, [events, source, zone]);

  const chip = (value: CaseEvent["source"] | "all", label: string) => (
    <button
      key={value}
      type="button"
      onClick={() => setSource(value)}
      aria-pressed={source === value}
      className={`rounded-full border px-3 py-1 text-[12.5px] capitalize transition ${
        source === value ? "border-trace/70 bg-trace/15 text-white shadow-[0_0_14px_-4px_rgba(59,140,255,0.8)]" : "border-white/12 text-soft/75 hover:text-white"
      }`}
    >
      {label}
    </button>
  );

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2">
        {chip("all", `All (${events.length})`)}
        {present.map(s => chip(s, s))}
        {cited.size > 0 && (
          <span className="ml-auto flex items-center gap-2 text-[12.5px] text-soft/70">
            <span className="size-2.5 rounded-full bg-alert shadow-[0_0_8px_#ef2b3c]" /> Cited by {citedLabel}
          </span>
        )}
      </div>

      {groups.length === 0 ? (
        <p className="py-12 text-center text-[13.5px] text-soft/70">No events for this source.</p>
      ) : (
        groups.map(([day, list]) => (
          <section key={day} className="mt-6">
            <h3 className="text-[12px] font-semibold tracking-[0.2em] text-soft/60 uppercase">{day}</h3>
            <ol className="relative mt-3 space-y-1 pl-9">
              <span aria-hidden="true" className="absolute top-3 bottom-3 left-[15px] w-[2px] rounded-full bg-gradient-to-b from-trace/60 to-trace/10 shadow-[0_0_8px_rgba(59,140,255,0.5)]" />
              {list.map(event => {
                const Icon = SOURCE_ICON[event.source];
                const hot = cited.has(event.event_id);
                return (
                  <li key={event.event_id} className="relative">
                    <span
                      className={`absolute top-3 -left-9 z-10 flex size-8 items-center justify-center rounded-full border ${
                        hot ? "border-alert/70 bg-alert/15 text-alert shadow-[0_0_14px_rgba(239,43,60,0.7)]" : "border-trace/50 bg-ink text-trace-soft shadow-[0_0_10px_rgba(59,140,255,0.45)]"
                      }`}
                    >
                      <Icon size={15} />
                    </span>
                    <Link
                      to={toPath("/app/evidence", { open: event.evidence_id })}
                      className={`grid min-w-0 gap-x-4 gap-y-1 rounded-xl border px-4 py-3 transition sm:grid-cols-[96px_minmax(0,1fr)_minmax(0,160px)] ${
                        hot ? "border-alert/40 bg-alert/[0.06]" : "border-transparent hover:border-trace/25 hover:bg-trace/[0.04]"
                      }`}
                    >
                      <time dateTime={event.timestamp} title={`Stored: ${event.timestamp}`} className="text-[13px] text-soft/75 tabular-nums">
                        {formatClock(event.timestamp, zone)}
                      </time>
                      <span className="min-w-0">
                        <span className="block truncate text-[14px] text-white">{describe(event)}</span>
                        <span className="mt-0.5 block truncate text-[12px] text-soft/60">
                          {[event.actor, event.device].filter(Boolean).join(" on ") || event.source}
                          <span className="ml-2 break-all font-mono text-[11.5px] text-soft/45" title={event.artifact_ref}>{event.artifact_ref}</span>
                        </span>
                      </span>
                      <span className="min-w-0 break-all text-[12.5px] text-trace-soft/85 tabular-nums sm:text-right">
                        <span className="block" title={event.evidence_id}>{event.evidence_id}</span>
                        <span className="block text-[11.5px] text-soft/45" title={event.event_id}>{event.event_id}</span>
                      </span>
                    </Link>
                  </li>
                );
              })}
            </ol>
          </section>
        ))
      )}
    </div>
  );
}
