// Role 4 / T12: one place that turns backend timestamps into display text, in UTC or IST (Asia/Kolkata).
// Display only: stored values are never rewritten. The backend returns UTC either with an offset/"Z" or naive
// ("2026-10-17T10:41:00", naive UTC); a naive value is read as UTC, never as the browser's local time.
// The chosen zone is shared by every view (a tiny external store) and remembered per browser when storage allows.
import { useSyncExternalStore } from "react";

export type DisplayZone = "UTC" | "IST";

const IANA: Record<DisplayZone, string> = { UTC: "UTC", IST: "Asia/Kolkata" };
const STORAGE_KEY = "pramana.displayZone";
const HAS_ZONE = /(?:[zZ]|[+-]\d\d:?\d\d)$/;

/** Parse a backend timestamp; naive values are UTC. Invalid input gives an Invalid Date. */
export function parseStored(iso: string): Date {
  return new Date(HAS_ZONE.test(iso) || !iso.includes("T") ? iso : `${iso}Z`);
}

/** Milliseconds since the epoch, for sorting; NaN when unparseable. */
export const storedTime = (iso: string) => parseStored(iso).getTime();

function fmt(d: Date, zone: DisplayZone, options: Intl.DateTimeFormatOptions) {
  return d.toLocaleString("en-GB", { timeZone: IANA[zone], ...options });
}

/** "17 Oct 2026, 16:11 IST" (seconds optional). Unparseable input is returned as is. */
export function formatTimestamp(iso: string, zone: DisplayZone, opts: { seconds?: boolean } = {}) {
  const d = parseStored(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const date = fmt(d, zone, { day: "numeric", month: "short", year: "numeric" });
  const time = fmt(d, zone, { hour: "2-digit", minute: "2-digit", second: opts.seconds ? "2-digit" : undefined, hour12: false });
  return `${date}, ${time} ${zone}`;
}

/** Date and time separately, for table cells; `iso` is the UTC instant ("…Z"). */
export function timestampParts(iso: string, zone: DisplayZone) {
  const d = parseStored(iso);
  if (Number.isNaN(d.getTime())) return { valid: false as const, date: iso, time: "", iso };
  return {
    valid: true as const,
    date: fmt(d, zone, { day: "numeric", month: "short", year: "numeric" }),
    time: `${fmt(d, zone, { hour: "2-digit", minute: "2-digit", hour12: false })} ${zone}`,
    iso: d.toISOString()
  };
}

/** Day heading in the display zone, e.g. "Sat 17 Oct 2026". */
export function formatDay(iso: string, zone: DisplayZone) {
  const d = parseStored(iso);
  return Number.isNaN(d.getTime()) ? "Unknown date" : fmt(d, zone, { weekday: "short", day: "numeric", month: "short", year: "numeric" });
}

/** Time of day in the display zone, e.g. "16:11:00 IST". */
export function formatClock(iso: string, zone: DisplayZone) {
  const d = parseStored(iso);
  return Number.isNaN(d.getTime()) ? iso : `${fmt(d, zone, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false })} ${zone}`;
}

// ----- shared zone choice -----

function readStored(): DisplayZone {
  try {
    return window.localStorage.getItem(STORAGE_KEY) === "IST" ? "IST" : "UTC";
  } catch {
    return "UTC";
  }
}

let current: DisplayZone = typeof window === "undefined" ? "UTC" : readStored();
const listeners = new Set<() => void>();

export function setDisplayZone(zone: DisplayZone) {
  if (zone === current) return;
  current = zone;
  try {
    window.localStorage.setItem(STORAGE_KEY, zone);
  } catch {
    // Storage blocked: the choice still applies for this page.
  }
  listeners.forEach(fn => fn());
}

const subscribe = (fn: () => void) => {
  listeners.add(fn);
  return () => listeners.delete(fn);
};

/** The zone every timestamp is shown in; components re-render when it changes. */
export const useDisplayZone = () => useSyncExternalStore(subscribe, () => current, () => "UTC" as DisplayZone);

/** A timestamp in the current display zone. The hover title keeps the value exactly as stored. */
export function Stamp({ iso, seconds, className }: { iso: string; seconds?: boolean; className?: string }) {
  const zone = useDisplayZone();
  const d = parseStored(iso);
  return (
    <time dateTime={Number.isNaN(d.getTime()) ? undefined : d.toISOString()} title={`Stored: ${iso}`} className={className}>
      {formatTimestamp(iso, zone, { seconds })}
    </time>
  );
}

/** UTC / IST switch for the console header. */
export function ZoneToggle() {
  const zone = useDisplayZone();
  return (
    <div role="group" aria-label="Show times in" className="flex items-center rounded-md border border-white/10 bg-black/30 p-0.5 text-[12.5px]">
      {(["UTC", "IST"] as const).map(z => (
        <button
          key={z}
          type="button"
          aria-pressed={zone === z}
          onClick={() => setDisplayZone(z)}
          title={z === "IST" ? "Show times in India Standard Time (UTC+05:30)" : "Show times in UTC"}
          className={`rounded px-2.5 py-1 transition-colors ${zone === z ? "bg-white/10 text-white" : "text-soft/70 hover:text-white"}`}
        >
          {z}
        </button>
      ))}
    </div>
  );
}
