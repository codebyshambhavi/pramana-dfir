import { useEffect, useState } from "react";
import { getGraph, listEvents, listFindings } from "../../api/client";
import type { CaseEvent, CaseGraph, EvidenceItem, Finding } from "../../api/types";
import { loadRecording } from "../../api/recorded/loadRecording";
import { getEvidenceSource, type EvidenceSourceKind } from "../vault/evidenceSource";
import { DEMO_EVENTS, DEMO_FINDINGS } from "./demoAnalysis";
import { graphFromEvents } from "./graph";

export type Section<T> =
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "ready"; data: T };

export interface DashboardData {
  evidence: Section<EvidenceItem[]>;
  events: Section<CaseEvent[]>;
  findings: Section<Finding[]>;
  graph: Section<CaseGraph>;
}

const LOADING: DashboardData = {
  evidence: { status: "loading" },
  events: { status: "loading" },
  findings: { status: "loading" },
  graph: { status: "loading" }
};

const delay = <T,>(value: T, ms = 380) =>
  new Promise<T>(resolve => setTimeout(() => resolve(value), ms));

function loaders(kind: EvidenceSourceKind, caseId: string, signal: AbortSignal) {
  if (kind === "recorded") {
    return {
      evidence: getEvidenceSource("recorded").list(caseId, signal),
      events: loadRecording().then(recording => delay(recording.events)),
      findings: loadRecording().then(recording =>
        delay(
          recording.runA.claims.map(claim => ({
            finding_id: claim.claim_id,
            case_id: recording.caseId,
            type: "hypothesis" as const,
            claim: `${claim.type} (${claim.status})`,
            confidence: claim.grade === "A" ? 1 : claim.grade === "B" ? 0.75 : 0.5,
            evidence_event_ids: (recording.runALineage[claim.claim_id]?.events ?? []).map(event => event.event_id),
            reasoning: `Recorded claim from ${recording.runA.run_id}; grade ${claim.grade}.`,
            needs_human_review: false,
            status: "pending" as const
          }))
        )
      ),
      graph: loadRecording().then(recording => delay(graphFromEvents(recording.events)))
    };
  }

  if (kind === "demo") {
    return {
      evidence: getEvidenceSource("demo").list(caseId, signal),
      events: delay(DEMO_EVENTS),
      findings: delay(DEMO_FINDINGS),
      graph: delay(graphFromEvents(DEMO_EVENTS))
    };
  }

  return {
    evidence: getEvidenceSource("api").list(caseId, signal),
    events: listEvents(caseId, {}, signal),
    findings: listFindings(caseId, signal),
    graph: getGraph(caseId, signal)
  };
}

export function useDashboardData(kind: EvidenceSourceKind, caseId: string) {
  const [data, setData] = useState<DashboardData>(LOADING);
  const [version, setVersion] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setData(LOADING);

    const settle = <K extends keyof DashboardData>(
      key: K,
      promise: Promise<unknown>
    ) =>
      promise
        .then(value =>
          !controller.signal.aborted &&
          setData(prev => ({
            ...prev,
            [key]: { status: "ready", data: value }
          }))
        )
        .catch((error: unknown) => {
          if (controller.signal.aborted) return;
          setData(prev => ({
            ...prev,
            [key]: {
              status: "error",
              message: error instanceof Error ? error.message : "Unavailable"
            }
          }));
        });

    const load = loaders(kind, caseId, controller.signal);
    (Object.keys(load) as (keyof DashboardData)[]).forEach(key =>
      settle(key, load[key])
    );

    return () => controller.abort();
  }, [kind, caseId, version]);

  return { data, reload: () => setVersion(v => v + 1) };
}

export const readyData = <T,>(section: Section<T>) =>
  section.status === "ready" ? section.data : null;
