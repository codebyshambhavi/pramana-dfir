// Role 4: recent findings; a row opens the finding in the Investigation Workspace. Claim, type, confidence and status come from the Finding contract; the
// related evidence is resolved through the cited events. The contract has no timestamp, so none is shown.
import { useNavigate } from "react-router-dom";
import type { Finding } from "../../../api/types";

export const TYPE_CHIP: Record<Finding["type"], string> = {
  contradiction: "border-alert/40 bg-alert/10 text-alert-soft",
  anomaly: "border-amber-400/35 bg-amber-400/10 text-amber-200",
  correlation: "border-trace/35 bg-trace/10 text-trace-soft",
  hypothesis: "border-violet-400/35 bg-violet-400/10 text-violet-200"
};

export const statusOf = (f: Finding) => f.status ?? (f.needs_human_review ? "pending" : undefined);

export function StatusChip({ finding }: { finding: Finding }) {
  const status = statusOf(finding);
  if (!status) return <span className="text-soft/50">—</span>;
  const style =
    status === "approved"
      ? "border-teal-400/35 bg-teal-400/10 text-teal-200"
      : status === "rejected"
        ? "border-white/12 bg-white/[0.04] text-soft/70"
        : finding.type === "contradiction"
          ? "border-alert/45 bg-alert/[0.12] text-alert-soft"
          : "border-amber-400/35 bg-amber-400/10 text-amber-200";
  const label = status === "pending" ? "Needs review" : status === "approved" ? "Approved" : "Rejected";
  return <span className={`inline-flex rounded-md border px-2 py-0.5 text-[12px] whitespace-nowrap ${style}`}>{label}</span>;
}

export default function FindingsPanel({
  findings,
  evidenceFor,
  linkFor
}: {
  findings: Finding[];
  evidenceFor: (finding: Finding) => string[];
  /** Where clicking a finding goes: its view in the Investigation Workspace. */
  linkFor: (finding: Finding) => string;
}) {
  const navigate = useNavigate();
  // Unresolved first, then by confidence.
  const rows = [...findings]
    .sort((a, b) => Number(statusOf(b) === "pending") - Number(statusOf(a) === "pending") || b.confidence - a.confidence)
    .slice(0, 6);

  return (
    <div className="-mx-5 overflow-x-auto">
      <table className="w-full min-w-[640px] table-fixed border-collapse text-[13.5px]">
        <thead>
          <tr className="text-left text-[12.5px] text-soft/70">
            <th scope="col" className="w-[78px] py-2 pr-3 pl-5 font-medium">ID</th>
            <th scope="col" className="py-2 pr-3 font-medium">Finding</th>
            <th scope="col" className="w-[118px] py-2 pr-3 font-medium">Type</th>
            <th scope="col" className="w-[104px] py-2 pr-3 font-medium">Confidence</th>
            <th scope="col" className="w-[118px] py-2 pr-3 font-medium">Status</th>
            <th scope="col" className="w-[112px] py-2 pr-5 font-medium">Evidence</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(f => {
            const evidence = evidenceFor(f);
            const open = () => navigate(linkFor(f));
            return (
              <tr
                key={f.finding_id}
                tabIndex={0}
                onClick={open}
                onKeyDown={e => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), open())}
                className="cursor-pointer border-t border-white/[0.05] transition-colors outline-none hover:bg-white/[0.025] focus-visible:bg-trace/[0.06]"
                title={f.reasoning}
              >
                <td className="py-2.5 pr-3 pl-5 whitespace-nowrap text-soft/60 tabular-nums">{f.finding_id}</td>
                <td className="truncate py-2.5 pr-3 text-white" title={f.claim}>{f.claim}</td>
                <td className="py-2.5 pr-3">
                  <span className={`inline-flex rounded-md border px-2 py-0.5 text-[12px] capitalize ${TYPE_CHIP[f.type] ?? TYPE_CHIP.hypothesis}`}>{f.type}</span>
                </td>
                <td className="py-2.5 pr-3">
                  <span className="flex items-center gap-2">
                    <span className="h-1 w-12 overflow-hidden rounded-full bg-white/[0.08]">
                      <span
                        className={`block h-full rounded-full ${f.type === "contradiction" ? "bg-alert" : "bg-trace"}`}
                        style={{ width: `${Math.round(f.confidence * 100)}%` }}
                      />
                    </span>
                    <span className="tabular-nums">{Math.round(f.confidence * 100)}%</span>
                  </span>
                </td>
                <td className="py-2.5 pr-3">
                  <StatusChip finding={f} />
                </td>
                <td className="py-2.5 pr-5 whitespace-nowrap text-soft/85 tabular-nums">
                  {evidence.length ? (
                    <>
                      {evidence[0]}
                      {evidence.length > 1 && <span className="text-soft/50"> +{evidence.length - 1}</span>}
                    </>
                  ) : (
                    <span className="text-soft/50">—</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
