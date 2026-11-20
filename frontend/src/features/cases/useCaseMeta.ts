// Role 3: title, status and owner of the active case (GET /cases/{id}). Only the live API has case metadata;
// demo and recorded modes return null and the pages fall back to showing the case ID.
import { useEffect, useState } from "react";
import { getCase } from "../../api/client";
import type { CaseSummary } from "../../api/types";
import type { EvidenceSourceKind } from "../vault/evidenceSource";

export type CaseMeta = { status: "loading" } | { status: "ready"; data: CaseSummary } | { status: "unavailable"; message?: string };

export function useCaseMeta(caseId: string, sourceKind: EvidenceSourceKind): CaseMeta {
  const [meta, setMeta] = useState<CaseMeta>({ status: sourceKind === "api" ? "loading" : "unavailable" });

  useEffect(() => {
    if (sourceKind !== "api") {
      setMeta({ status: "unavailable" });
      return;
    }
    const controller = new AbortController();
    setMeta({ status: "loading" });
    getCase(caseId, controller.signal)
      .then(data => setMeta({ status: "ready", data }))
      .catch(error => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setMeta({ status: "unavailable", message: error instanceof Error ? error.message : undefined });
      });
    return () => controller.abort();
  }, [caseId, sourceKind]);

  return meta;
}
