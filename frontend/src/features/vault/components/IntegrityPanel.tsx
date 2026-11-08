// Role 4 / T12: live integrity controls for one evidence item, wired to the real T4 endpoints.
//   Verify:          POST /evidence/{id}/verify re-hashes the stored file. MISMATCH, MISSING or CUSTODY_BROKEN
//                    quarantines it (the backend decides; nothing is computed here).
//   Simulate tamper: POST /evidence/{id}/simulate-tamper (only when the backend runs with DEMO_MODE=1; 404 otherwise)
//                    appends bytes to the stored copy, then the same verify call runs so the quarantine is real.
// After either action the vault reloads the evidence list, so status and custody come from the backend.
import { useState } from "react";
import { ApiError, simulateTamper, verifyEvidence } from "../../../api/client";
import type { EvidenceItem, TamperSimulation, VerificationResult } from "../../../api/types";
import { Alert, Shield } from "../../../components/console/icons";
import { Stamp } from "../../../lib/time";
import { truncateHash } from "../model";

type Busy = null | "verify" | "tamper";
type Outcome = { verify: VerificationResult; tamper?: TamperSimulation };

const STATUS_STYLE: Record<string, string> = {
  ACTIVE: "border-verified/35 bg-verified/[0.08] text-verified",
  QUARANTINED: "border-alert/45 bg-alert/[0.1] text-alert-soft",
  REMOVED: "border-white/15 bg-white/[0.04] text-soft/80"
};

function errorText(error: unknown, action: Busy) {
  if (error instanceof ApiError && error.status === 404 && action === "tamper")
    return "Simulated tamper is off. Start the backend with DEMO_MODE=1 (scripts/demo/serve.sh does this).";
  return error instanceof Error ? error.message : "The request failed.";
}

export default function IntegrityPanel({ item, onChanged }: { item: EvidenceItem; onChanged: () => void }) {
  const [busy, setBusy] = useState<Busy>(null);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [error, setError] = useState<string | null>(null);
  const status = item.status ?? "ACTIVE";
  const shown = outcome?.verify.evidence_id === item.evidence_id ? outcome : null;

  const run = async (action: Exclude<Busy, null>) => {
    setBusy(action);
    setError(null);
    try {
      const tamper = action === "tamper" ? await simulateTamper(item.evidence_id) : undefined;
      const verify = await verifyEvidence(item.evidence_id, "Investigator (PRAMANA UI)");
      setOutcome({ verify, tamper });
      onChanged();
    } catch (e) {
      setError(errorText(e, action));
      // A tamper may have landed even if verify failed; reload so the custody log shows it.
      if (action === "tamper") onChanged();
    } finally {
      setBusy(null);
    }
  };

  const button = "rounded-lg border px-3 py-2 text-[13px] transition disabled:cursor-not-allowed disabled:opacity-50";

  return (
    <div className="mt-3 space-y-3 rounded-lg border border-trace/20 bg-trace/[0.05] p-3.5 text-[13px]">
      <div className="flex flex-wrap items-center gap-2">
        <Shield size={20} className="text-trace-soft" />
        <span className="font-semibold text-white">Integrity</span>
        <span className={`rounded-md border px-2 py-0.5 text-[12px] font-medium ${STATUS_STYLE[status] ?? STATUS_STYLE.REMOVED}`} data-testid="evidence-status">
          {status}
        </span>
        <span className="text-soft/70">
          {item.verify_state ? `last check: ${item.verify_state}` : "never verified"}
          {item.verified_at && (
            <>
              {" · "}
              <Stamp iso={item.verified_at} />
            </>
          )}
        </span>
      </div>

      <div className="flex flex-wrap gap-2">
        <button type="button" disabled={busy !== null} onClick={() => run("verify")} className={`${button} border-trace/40 text-trace-soft hover:bg-trace/10`}>
          {busy === "verify" ? "Verifying…" : "Verify integrity"}
        </button>
        <button
          type="button"
          disabled={busy !== null}
          onClick={() => run("tamper")}
          title="Demo only: modifies the stored copy on the backend, then verifies it"
          className={`${button} border-alert/45 text-alert-soft hover:bg-alert/10`}
        >
          {busy === "tamper" ? "Tampering…" : "Simulate tamper & verify"}
        </button>
      </div>

      {error && (
        <p role="alert" className="flex gap-2 text-alert-soft">
          <Alert size={16} className="mt-0.5 shrink-0" />
          {error}
        </p>
      )}

      {shown && (
        <dl role="status" className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 border-t border-white/[0.07] pt-3 text-[12.5px]">
          {shown.tamper && (
            <>
              <dt className="text-soft/60">Tamper</dt>
              <dd className="text-white">stored copy changed to {truncateHash(shown.tamper.tampered_sha256)}</dd>
            </>
          )}
          <dt className="text-soft/60">Result</dt>
          <dd className={shown.verify.match ? "text-verified" : "text-alert-soft"}>
            {shown.verify.outcome}: {shown.verify.previous_status} → {shown.verify.status}
          </dd>
          <dt className="text-soft/60">Intake</dt>
          <dd className="font-mono text-soft/85">{truncateHash(shown.verify.intake_sha256)}</dd>
          <dt className="text-soft/60">Observed</dt>
          <dd className="font-mono text-soft/85">{shown.verify.observed_sha256 ? truncateHash(shown.verify.observed_sha256) : "file missing"}</dd>
          <dt className="text-soft/60">Custody</dt>
          <dd className="text-soft/85">{shown.verify.custody_message}</dd>
          {!shown.verify.match && (
            <dd className="col-span-2 mt-1 text-soft/75">
              Runs that used this file are now invalidated. Create a new run in the Investigation Workspace (Run diff tab) to see what changes.
            </dd>
          )}
        </dl>
      )}
    </div>
  );
}
