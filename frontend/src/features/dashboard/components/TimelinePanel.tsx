// Role 4: the latest events, oldest first, as a vertical timeline. Events cited by an unresolved contradiction
// are marked red. Clicking an event opens its evidence in the Evidence Vault.
import type { ComponentType, SVGProps } from "react";
import { Link } from "react-router-dom";
import { Globe, ImageIcon, Message, Network, Terminal } from "../../../components/console/icons";
import type { CaseEvent } from "../../../api/types";
import { formatStamp, humanize } from "./ui";

export const SOURCE_ICON: Record<CaseEvent["source"], ComponentType<SVGProps<SVGSVGElement> & { size?: number }>> = {
  browser: Globe,
  chat: Message,
  log: Terminal,
  pcap: Network,
  image: ImageIcon
};

export const describe = (e: CaseEvent) => {
  const target = e.object ?? e.ip ?? (e.location ? `${e.location.lat.toFixed(2)}, ${e.location.lon.toFixed(2)}` : null);
  return target ? `${humanize(e.action)} — ${target}` : humanize(e.action);
};

export default function TimelinePanel({
  events,
  flagged,
  linkTo
}: {
  events: CaseEvent[];
  flagged: ReadonlySet<string>;
  linkTo: (evidenceId: string) => string;
}) {
  const latest = [...events]
    .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))
    .slice(0, 5)
    .reverse();

  return (
    <ol className="relative space-y-1">
      {latest.map((event, i) => {
        const Icon = SOURCE_ICON[event.source] ?? Terminal;
        const hot = flagged.has(event.event_id);
        return (
          <li key={event.event_id} className="relative">
            {i < latest.length - 1 && (
              <span
                aria-hidden="true"
                className={`absolute top-10 bottom-[-6px] left-[19px] w-px ${hot ? "bg-alert/40" : "bg-trace/35"} shadow-[0_0_6px_rgba(59,140,255,0.5)]`}
              />
            )}
            <Link
              to={linkTo(event.evidence_id)}
              className="group flex items-start gap-3.5 rounded-lg p-1.5 -mx-1.5 transition hover:bg-white/[0.03] focus-visible:outline focus-visible:outline-2 focus-visible:outline-trace"
            >
              <span
                className={`relative z-10 flex size-[30px] shrink-0 items-center justify-center rounded-full border ${
                  hot
                    ? "border-alert/60 bg-alert/15 text-alert shadow-[0_0_14px_rgba(239,43,60,0.55)]"
                    : "border-trace/50 bg-trace/10 text-trace-soft shadow-[0_0_12px_rgba(59,140,255,0.4)]"
                }`}
              >
                <Icon size={15} />
              </span>
              <span className="min-w-0 flex-1">
                <span className="block text-[12.5px] text-soft/70 tabular-nums">
                  <time dateTime={event.timestamp}>{formatStamp(event.timestamp)}</time>
                  <span className="ml-2 text-soft/45">{event.evidence_id}</span>
                </span>
                <span className="mt-0.5 block truncate text-[13.5px] text-white group-hover:text-trace-soft" title={describe(event)}>
                  {describe(event)}
                </span>
              </span>
            </Link>
          </li>
        );
      })}
    </ol>
  );
}
