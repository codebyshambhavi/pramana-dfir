// Role 3: which case the console is showing.
//
// Order: ?case= in the URL, then the case last opened in this browser, then VITE_CASE_ID / CASE-001. The URL wins
// so a shared link always opens the same case; the remembered choice only fills in when a link carries no case.
// Recorded mode (?source=recorded) always shows its bundled CASE-DEMO-IST snapshot.
import { useEffect } from "react";
import { useSearchParams } from "react-router-dom";
import { DEFAULT_CASE_ID, RECORDED_CASE_ID, resolveSourceKind } from "../vault/evidenceSource";

const STORAGE_KEY = "pramana.activeCase";

export function rememberCase(caseId: string): void {
  try {
    localStorage.setItem(STORAGE_KEY, caseId);
  } catch {
    // Storage blocked (private window, policy): the URL still carries the case.
  }
}

export function rememberedCase(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

/** The case id the current console page should load. */
export function useActiveCaseId(): string {
  const [params] = useSearchParams();
  const sourceKind = resolveSourceKind(params.get("source"));
  const fromUrl = params.get("case")?.trim() || null;
  const caseId = sourceKind === "recorded" ? RECORDED_CASE_ID : fromUrl ?? rememberedCase() ?? DEFAULT_CASE_ID;

  useEffect(() => {
    if (sourceKind === "api" && fromUrl) rememberCase(fromUrl);
  }, [sourceKind, fromUrl]);

  return caseId;
}
