// Role 4: says which data a console page is showing. Demo mode gets a permanent label; a live API failure gets a
// clear notice with Retry and an explicit switch to the demo data (never an automatic fallback).
import { Link } from "react-router-dom";
import { Alert, Database, Refresh } from "../../../components/console/icons";
import { API_URL } from "../../../api/client";
import type { EvidenceSourceKind } from "../../vault/evidenceSource";

export default function SourceBanner({
  sourceKind,
  errors,
  total,
  onRetry,
  liveHref,
  demoHref
}: {
  sourceKind: EvidenceSourceKind;
  errors: number;
  total: number;
  onRetry: () => void;
  liveHref: string;
  demoHref: string;
}) {
  if (sourceKind === "demo")
    return (
      <div className="mb-5 flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border border-amber-300/25 bg-amber-300/[0.06] px-4 py-2.5 text-[13px] text-amber-100/90">
        <Database size={16} className="text-amber-300" />
        <span>
          <strong className="font-semibold">Demo data.</strong> Synthetic evidence, events and findings for UI development; none of it came from the backend.
        </span>
        <Link to={liveHref} className="ml-auto text-amber-200 underline-offset-4 hover:underline">
          Use live API
        </Link>
      </div>
    );
  if (errors === 0) return null;
  return (
    <div
      role="status"
      className="relative mb-5 flex flex-wrap items-center gap-x-4 gap-y-3 overflow-hidden rounded-xl border border-alert/35 bg-[linear-gradient(90deg,rgba(239,43,60,0.12),rgba(239,43,60,0.03))] px-5 py-3.5 shadow-[0_0_30px_-14px_rgba(239,43,60,0.6)]"
    >
      <span className="flex size-9 items-center justify-center rounded-lg border border-alert/45 bg-alert/10 text-alert">
        <Alert size={18} />
      </span>
      <div className="min-w-0 flex-1 text-[13.5px]">
        <p className="font-semibold text-white">{errors === total ? "Live API unavailable" : `${errors} of ${total} live data sources unavailable`}</p>
        <p className="text-soft/75">
          {errors === total ? `Nothing could be read from ${API_URL}.` : `Some data couldn't be read from ${API_URL}.`} Start the backend or the Prism
          mock, or explore the labelled demo data.
        </p>
      </div>
      <div className="flex gap-2.5">
        <button
          type="button"
          onClick={onRetry}
          className="inline-flex items-center gap-1.5 rounded-lg border border-white/15 px-3.5 py-2 text-[13.5px] text-soft hover:border-white/30 hover:text-white"
        >
          <Refresh size={14} /> Retry
        </button>
        <Link
          to={demoHref}
          className="inline-flex items-center gap-1.5 rounded-lg bg-alert px-3.5 py-2 text-[13.5px] font-medium text-white shadow-[0_0_18px_rgba(239,43,60,0.35)] hover:bg-[#ff3a4a]"
        >
          <Database size={14} /> Open demo data
        </Link>
      </div>
    </div>
  );
}
