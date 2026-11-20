// Role 4: keeps demo mode sticky across console pages. If the current URL has ?source=demo, links built with
// this hook carry it too, so the dashboard and Evidence Vault always show the same data set.
// Role 3: the selected case travels the same way (?case=), so every console page shows one case.
import { useCallback } from "react";
import { useSearchParams } from "react-router-dom";

export function useSourceLink() {
  const [params] = useSearchParams();
  const source = params.get("source");
  const caseId = params.get("case");
  return useCallback(
    (path: string, extra: Record<string, string> = {}) => {
      const query = new URLSearchParams(extra);
      if (source === "demo" || source === "recorded") {
        query.set("source", source);
      }
      if (caseId && !query.has("case") && source !== "recorded") {
        query.set("case", caseId);
      }
      const qs = query.toString();
      return qs ? `${path}?${qs}` : path;
    },
    [source, caseId]
  );
}
