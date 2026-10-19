// Role 4: data and clipboard hooks for the Evidence Vault.
import { useCallback, useEffect, useRef, useState } from "react";
import type { EvidenceItem } from "../../api/types";
import type { EvidenceSource } from "./evidenceSource";

export type LoadState =
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "ready"; items: EvidenceItem[] };

export function useEvidenceList(source: EvidenceSource, caseId: string) {
  const [state, setState] = useState<LoadState>({ status: "loading" });
  const [version, setVersion] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setState({ status: "loading" });
    source
      .list(caseId, controller.signal)
      .then(items => setState({ status: "ready", items }))
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setState({ status: "error", message: error instanceof Error ? error.message : "Could not load evidence." });
      });
    return () => controller.abort();
  }, [source, caseId, version]);

  const reload = useCallback(() => setVersion(v => v + 1), []);
  return { state, reload };
}

export function useCopy(resetMs = 1600) {
  const [copied, setCopied] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout>>();

  useEffect(() => () => clearTimeout(timer.current), []);

  const copy = useCallback(
    async (text: string, key = text) => {
      try {
        await navigator.clipboard.writeText(text);
      } catch {
        const area = document.createElement("textarea");
        area.value = text;
        area.style.position = "fixed";
        area.style.opacity = "0";
        document.body.appendChild(area);
        area.select();
        document.execCommand("copy");
        area.remove();
      }
      setCopied(key);
      clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(null), resetMs);
    },
    [resetMs]
  );

  return { copied, copy };
}
