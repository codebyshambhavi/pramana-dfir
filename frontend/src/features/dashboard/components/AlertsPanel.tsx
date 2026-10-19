// Role 4: alerts built only from the data: unresolved contradiction/anomaly findings, evidence with no custody
// entries, and evidence types the engine can't parse. No severity is shown because the contract has none.
import type { ComponentType, SVGProps } from "react";
import { Link } from "react-router-dom";
import { Alert, Custody, FileIcon } from "../../../components/console/icons";
import { formatStamp } from "./ui";

export interface AlertItem {
  key: string;
  kind: "contradiction" | "anomaly" | "custody" | "unparsed";
  title: string;
  detail: string;
  /** ISO time the alert is anchored to, with what it means. */
  time?: { iso: string; label: string };
  to?: string;
}

const KIND: Record<AlertItem["kind"], { icon: ComponentType<SVGProps<SVGSVGElement> & { size?: number }>; ring: string }> = {
  contradiction: { icon: Alert, ring: "border-alert/50 bg-alert/10 text-alert shadow-[0_0_14px_rgba(239,43,60,0.4)]" },
  anomaly: { icon: Alert, ring: "border-amber-400/45 bg-amber-400/10 text-amber-300" },
  custody: { icon: Custody, ring: "border-trace/45 bg-trace/10 text-trace-soft" },
  unparsed: { icon: FileIcon, ring: "border-trace/45 bg-trace/10 text-trace-soft" }
};

export default function AlertsPanel({ alerts }: { alerts: AlertItem[] }) {
  if (alerts.length === 0)
    return <p className="flex flex-1 items-center justify-center py-8 text-[13.5px] text-soft/70">No open alerts. Everything flagged has been reviewed.</p>;

  return (
    <ul className="-mx-2 space-y-0.5">
      {alerts.slice(0, 4).map(alert => {
        const { icon: Icon, ring } = KIND[alert.kind];
        const body = (
          <>
            <span className={`flex size-9 shrink-0 items-center justify-center rounded-lg border ${ring}`}>
              <Icon size={17} />
            </span>
            <span className="min-w-0 flex-1">
              <span className="block text-[13.5px] font-medium text-white">{alert.title}</span>
              <span className="mt-0.5 block truncate text-[12.5px] text-soft/75" title={alert.detail}>
                {alert.detail}
              </span>
            </span>
            {alert.time && (
              <span className="hidden shrink-0 text-right text-[12px] text-soft/65 sm:block" title={alert.time.label}>
                {formatStamp(alert.time.iso)}
              </span>
            )}
          </>
        );
        const className = "flex items-center gap-3 rounded-lg px-2 py-2";
        return (
          <li key={alert.key}>
            {alert.to ? (
              <Link
                to={alert.to}
                className={`${className} transition hover:bg-white/[0.03] focus-visible:outline focus-visible:outline-2 focus-visible:outline-trace`}
              >
                {body}
              </Link>
            ) : (
              <div className={className}>{body}</div>
            )}
          </li>
        );
      })}
      {alerts.length > 4 && <li className="px-2 pt-1 text-[12px] text-muted">+{alerts.length - 4} more</li>}
    </ul>
  );
}
