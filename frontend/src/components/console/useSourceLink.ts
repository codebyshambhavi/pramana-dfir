// Role 4: keeps demo mode sticky across console pages. If the current URL has ?source=demo, links built with
// this hook carry it too, so the dashboard and Evidence Vault always show the same data set.
import { useCallback } from "react";
import { useSearchParams } from "react-router-dom";

export function useSourceLink() {
  const [params] = useSearchParams();
  const demo = params.get("source") === "demo";
  return useCallback(
    (path: string, extra: Record<string, string> = {}) => {
      const query = new URLSearchParams(extra);
      if (demo) query.set("source", "demo");
      const qs = query.toString();
      return qs ? `${path}?${qs}` : path;
    },
    [demo]
  );
}
