// Role 4 / T11: Reconstruction stages. Shows the backend's narrative reconstruction of the leading hypothesis:
// stages in the order the backend returns them, each with its status (SUPPORTED or GAP), the relationship to the
// previous stage that the backend computed, its time window, its claims (linked to the Claim Inspector) and the
// events behind it. Order and relationships are the backend's; nothing here infers chronology or fills a gap.
import { useState } from "react";
import { Link } from "react-router-dom";
import type { HypothesisStatus, NarrativeReconstruction, StageReconstruction, StageRelationship } from "../../../api/pending/runs";
import { Info } from "../../../components/console/icons";
import { useSourceLink } from "../../../components/console/useSourceLink";
import { humanize } from "../../dashboard/components/ui";
import { HypothesisChip, formatUtc } from "../../hypotheses/components/HypothesesView";
import type { LoadedRun } from "../../hypotheses/runSource";

const CHIP = "inline-flex items-center rounded-md border px-2 py-0.5 text-[12px] whitespace-nowrap";

const RELATIONSHIP: Record<StageRelationship, { label: string; meaning: string; tone: string }> = {
  FIRST_STAGE: { label: "First stage", meaning: "Nothing to compare against.", tone: "text-soft/60" },
  PRECEDES: { label: "Follows the previous stage", meaning: "The previous stage's window is definitely before this one, allowing for source clock uncertainty.", tone: "text-teal-200" },
  CONCURRENT_OR_OVERLAPPING: { label: "Overlaps the previous stage", meaning: "The two windows overlap, so neither can be said to come first.", tone: "text-trace-soft" },
  OUT_OF_ORDER: { label: "Out of order", meaning: "The previous stage's window is definitely after this one, against the hypothesis' expected order.", tone: "text-alert-soft" },
  UNPROVEN: { label: "Order unproven", meaning: "The windows neither overlap nor fall clearly in order once clock uncertainty is allowed for.", tone: "text-amber-200" },
  GAP_DETECTED: { label: "Order not checkable (gap)", meaning: "This stage or the previous one is a gap, so the two cannot be compared.", tone: "text-amber-200" }
};

const eventLabel = (id: string) => id.split(":").pop() ?? id;
const str = (v: unknown) => (typeof v === "string" && v ? v : null);

/** A stage's raw event, read defensively: it is untyped in the pending contract. */
function EventRow({ event }: { event: Record<string, unknown> }) {
  const id = str(event.event_id) ?? "event";
  const action = str(event.action);
  const target = str(event.object) ?? str(event.ip);
  const ts = str(event.timestamp);
  return (
    <li className="relative text-[12.5px]">
      <span aria-hidden="true" className="absolute top-1.5 -left-[19px] size-[7px] rounded-full bg-trace/70" />
      <span className="text-soft/60 tabular-nums">{ts ? formatUtc(ts) : "no timestamp"}</span>
      <span className="ml-2 text-white">
        {action ? humanize(action) : "Unknown action"}
        {target && <span className="text-soft/80"> — {target}</span>}
      </span>
      <span className="block text-[11.5px] text-soft/50">
        <span title={id}>{eventLabel(id)}</span>
        {str(event.actor) && ` · ${str(event.actor)}`}
        {str(event.source) && ` · ${str(event.source)}`}
        {str(event.artifact_ref) && <span className="font-mono"> · {str(event.artifact_ref)}</span>}
      </span>
    </li>
  );
}

const PREVIEW = 5;

function Stage({ stage, index, runId }: { stage: StageReconstruction; index: number; runId: string }) {
  const toPath = useSourceLink();
  const [all, setAll] = useState(false);
  const gap = stage.status === "GAP";
  const rel = RELATIONSHIP[stage.relationship_to_previous] ?? { label: humanize(stage.relationship_to_previous.toLowerCase()), meaning: "", tone: "text-soft/60" };
  // Recorded timestamps only; events without one keep their backend order at the end.
  const events = [...stage.raw_events].sort((a, b) => (str(a.timestamp) ?? "~").localeCompare(str(b.timestamp) ?? "~"));
  const shown = all ? events : events.slice(0, PREVIEW);

  return (
    <li className="relative pl-12">
      <span
        aria-hidden="true"
        className={`absolute top-3 left-0 flex size-8 items-center justify-center rounded-full border text-[13px] font-semibold tabular-nums ${
          gap ? "border-dashed border-amber-400/50 bg-ink text-amber-200" : "border-trace/60 bg-ink text-trace-soft shadow-[0_0_14px_rgba(59,140,255,0.55)]"
        }`}
      >
        {index + 1}
      </span>
      <p className={`mb-1.5 text-[12px] ${rel.tone}`} title={rel.meaning}>
        {rel.label}
      </p>
      <article
        aria-label={`Stage ${stage.stage_name}`}
        className={`rounded-xl border p-4 ${gap ? "border-dashed border-amber-400/35 bg-amber-400/[0.03]" : "border-trace/30 bg-[linear-gradient(160deg,rgba(16,28,52,0.85),rgba(7,11,20,0.9))]"}`}
      >
        <header className="flex flex-wrap items-center gap-2">
          <h3 className="text-[15px] font-semibold text-white">{humanize(stage.stage_name)}</h3>
          <span className={`${CHIP} ${gap ? "border-dashed border-amber-400/45 text-amber-200" : "border-teal-400/35 bg-teal-400/10 text-teal-200"}`}>
            {gap ? "Gap" : "Supported"}
          </span>
          <span className="ml-auto text-[12px] text-soft/65 tabular-nums">
            {stage.time_window ? (
              <>
                {stage.time_window.lo ? formatUtc(stage.time_window.lo) : "?"} → {stage.time_window.hi ? formatUtc(stage.time_window.hi) : "?"}
              </>
            ) : (
              "No time window"
            )}
          </span>
        </header>

        {gap ? (
          <p className="mt-2.5 text-[12.5px] text-amber-100/80">No claims or events support this stage in this run. The backend records it as a gap; nothing is inferred to fill it.</p>
        ) : (
          <>
            <div className="mt-3 flex flex-wrap items-center gap-1.5 text-[12.5px]">
              <span className="text-soft/55">Claims</span>
              {stage.claims.length === 0 && <span className="text-soft/50">none recorded</span>}
              {stage.claims.map((c, i) =>
                c.claim_id ? (
                  <Link
                    key={c.claim_id}
                    to={toPath("/app/investigation", { tab: "claims", claim: c.claim_id, run: runId })}
                    title={`Inspect claim ${c.claim_id}`}
                    className="inline-flex items-center gap-1.5 rounded-md border border-trace/30 px-2 py-0.5 hover:border-trace/60"
                  >
                    <span className="font-mono text-[11.5px] text-white">{c.type ?? "claim"}</span>
                    {c.grade && <span className="text-[11px] text-soft/60">grade {c.grade}</span>}
                    <span className="font-mono text-[11px] text-trace-soft">{c.claim_id.slice(0, 8)}…</span>
                  </Link>
                ) : (
                  <span key={i} className="text-soft/50">
                    claim without ID
                  </span>
                )
              )}
            </div>
            <div className="mt-3 border-t border-white/[0.06] pt-3">
              <p className="mb-2 text-[12px] text-soft/55">
                {events.length} event{events.length === 1 ? "" : "s"}
              </p>
              {events.length > 0 && (
                <ol className="relative space-y-2 pl-5">
                  <span aria-hidden="true" className="absolute top-1 bottom-1 left-[2px] w-px bg-trace/30" />
                  {shown.map((e, i) => (
                    <EventRow key={str(e.event_id) ?? i} event={e} />
                  ))}
                </ol>
              )}
              {events.length > PREVIEW && (
                <button type="button" onClick={() => setAll(v => !v)} className="mt-2.5 text-[12.5px] text-trace-soft hover:text-white">
                  {all ? "Show fewer" : `Show all ${events.length} events`}
                </button>
              )}
            </div>
          </>
        )}
      </article>
    </li>
  );
}

function Outside({ label, ids, note }: { label: string; ids: string[]; note: string }) {
  return (
    <div className="rounded-xl border border-white/[0.07] bg-black/20 p-3.5 text-[12.5px]">
      <p className="text-white">
        {label} <span className="text-soft/60 tabular-nums">({ids.length})</span>
      </p>
      <p className="mt-0.5 text-[12px] text-soft/55">{note}</p>
      {ids.length > 0 && (
        <p className="mt-2 flex flex-wrap gap-1.5">
          {ids.map(id => (
            <span key={id} className="rounded border border-white/10 px-1.5 py-px text-[11.5px] text-soft tabular-nums" title={id}>
              {eventLabel(id)}
            </span>
          ))}
        </p>
      )}
    </div>
  );
}

export default function ReconstructionView({ loaded, reconstruction }: { loaded: LoadedRun; reconstruction: NarrativeReconstruction }) {
  const toPath = useSourceLink();
  const { run } = loaded;
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-xl border border-white/[0.07] bg-black/20 px-4 py-3 text-[12.5px] text-soft/75">
        {loaded.origin === "recorded" && (
          <span className="rounded-md border border-violet-400/35 bg-violet-400/10 px-2 py-0.5 text-[12px] text-violet-200">Recorded real run</span>
        )}
        <span>
          Run <span className="text-white tabular-nums">{run.run_id}</span>
        </span>
        <span className="flex items-center gap-2">
          Reconstructs
          <Link to={toPath("/app/investigation", { tab: "hypotheses", hyp: reconstruction.hypothesis_id, run: run.run_id })} className="text-white hover:text-trace-soft">
            {reconstruction.hypothesis_name} ({reconstruction.hypothesis_id})
          </Link>
          <HypothesisChip status={reconstruction.status as HypothesisStatus} />
        </span>
        <span>
          Validity <span className={run.validity === "VALID" ? "text-teal-200" : "text-alert-soft"}>{run.validity === "VALID" ? "Valid" : "Invalidated"}</span>
        </span>
      </div>

      <p className="flex items-start gap-2 rounded-xl border border-trace/20 bg-trace/[0.04] px-4 py-3 text-[12.5px] text-soft/85">
        <Info size={15} className="mt-px shrink-0 text-trace-soft" />
        <span>
          <span className="text-white">Backend summary: </span>
          {reconstruction.narrative_summary}
          <span className="mt-1 block text-[12px] text-soft/55">
            Stages follow the hypothesis template's order. Each label above a stage is the backend's comparison of its time window with the previous stage's. Times are UTC.
          </span>
        </span>
      </p>

      <ol className="relative space-y-5" aria-label="Reconstruction stages">
        <span aria-hidden="true" className="absolute top-4 bottom-4 left-4 w-px bg-gradient-to-b from-trace/50 via-trace/25 to-transparent" />
        {reconstruction.stages.map((s, i) => (
          <Stage key={`${s.stage_name}:${i}`} stage={s} index={i} runId={run.run_id} />
        ))}
      </ol>

      <div className="grid gap-3 md:grid-cols-2">
        <Outside label="Background activity" ids={reconstruction.background_activity_event_ids} note="Events in the case that are not part of this hypothesis' stages." />
        <Outside label="Residual events (H0)" ids={reconstruction.residual_h0_event_ids} note="Events no evaluated hypothesis accounts for. Never ranked." />
      </div>
    </div>
  );
}
