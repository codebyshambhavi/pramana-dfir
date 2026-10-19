// Role 4: data for the Investigation Dashboard. Each section loads on its own, so one missing endpoint shows as
// "unavailable" in its panel without blanking the rest. Live mode uses the four documented GET endpoints; demo mode
// uses the same in-memory demo evidence as the Evidence Vault plus the synthetic events and findings.
import { useEffect, useState } from "react";
import { getGraph, listEvents, listFindings } from "../../api/client";
import type { CaseEvent, CaseGraph, EvidenceItem, Finding } from "../../api/types";
import { getEvidenceSource, type EvidenceSourceKind } from "../vault/evidenceSource";
import { DEMO_EVENTS, DEMO_FINDINGS } from "./demoAnalysis";
import { graphFromEvents } from "./graph";

export type Section<T> = { status: "loading" } | { status: "error"; message: string } | { status: "ready"; data: T };

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

const delay = <T,>(value: T, ms = 380) => new Promise<T>(resolve => setTimeout(() => resolve(value), ms));

function loaders(kind: EvidenceSourceKind, caseId: string, signal: AbortSignal) {
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
    const settle = <K extends keyof DashboardData>(key: K, promise: Promise<unknown>) =>
      promise
        .then(value => !controller.signal.aborted && setData(prev => ({ ...prev, [key]: { status: "ready", data: value } })))
        .catch((error: unknown) => {
          if (controller.signal.aborted) return;
          setData(prev => ({ ...prev, [key]: { status: "error", message: error instanceof Error ? error.message : "Unavailable" } }));
        });
    const load = loaders(kind, caseId, controller.signal);
    (Object.keys(load) as (keyof DashboardData)[]).forEach(key => settle(key, load[key]));
    return () => controller.abort();
  }, [kind, caseId, version]);

  return { data, reload: () => setVersion(v => v + 1) };
}

export const readyData = <T,>(section: Section<T>) => (section.status === "ready" ? section.data : null);
