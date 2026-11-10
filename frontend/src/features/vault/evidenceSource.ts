import { listEvidence, uploadEvidence } from "../../api/client";
import type { EvidenceItem, EvidenceUploadResult } from "../../api/types";
import { RECORDED_CASE_DEMO_IST } from "../../api/recorded/case-demo-ist";
import { DEMO_EVIDENCE } from "./demoEvidence";
import { sha256OfFile } from "./model";

export type EvidenceSourceKind = "api" | "demo" | "recorded";

export const RECORDED_CASE_ID = "CASE-DEMO-IST";
export const DEFAULT_CASE_ID: string = import.meta.env.VITE_CASE_ID ?? "CASE-001";

export interface EvidenceSource {
  kind: EvidenceSourceKind;
  list(caseId: string, signal?: AbortSignal): Promise<EvidenceItem[]>;
  upload(caseId: string, file: File, signal?: AbortSignal): Promise<EvidenceUploadResult>;
}

export const apiSource: EvidenceSource = {
  kind: "api",
  list: listEvidence,
  upload: uploadEvidence
};

const wait = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => {
      clearTimeout(timer);
      reject(new DOMException("Aborted", "AbortError"));
    });
  });

function createDemoSource(): EvidenceSource {
  const store = DEMO_EVIDENCE.map(item => ({ ...item }));

  return {
    kind: "demo",
    async list(_caseId, signal) {
      await wait(450, signal);
      return store.map(item => ({ ...item }));
    },
    async upload(_caseId, file, signal) {
      const sha256 = await sha256OfFile(file);
      await wait(600, signal);
      const evidence_id = `EVID-${String(store.length + 1).padStart(3, "0")}`;
      store.push({
        evidence_id,
        filename: file.name,
        sha256,
        intake_time: new Date().toISOString(),
        custody: []
      });
      return { evidence_id, filename: file.name, sha256, events_created: 0 };
    }
  };
}

const recordedSource: EvidenceSource = {
  kind: "recorded",
  async list(_caseId, signal) {
    if (signal?.aborted) throw new DOMException("Aborted", "AbortError");
    return RECORDED_CASE_DEMO_IST.evidenceBefore.map(item => ({
      ...item,
      custody: [...item.custody]
    }));
  },
  async upload() {
    throw new Error("The recorded investigation is read-only.");
  }
};

let demoSource: EvidenceSource | null = null;

export function getEvidenceSource(kind: EvidenceSourceKind): EvidenceSource {
  if (kind === "api") return apiSource;
  if (kind === "recorded") return recordedSource;
  return (demoSource ??= createDemoSource());
}

export function resolveSourceKind(param: string | null): EvidenceSourceKind {
  const value = param ?? import.meta.env.VITE_EVIDENCE_SOURCE;
  if (value === "recorded") return "recorded";
  return value === "demo" ? "demo" : "api";
}
