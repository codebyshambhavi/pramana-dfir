// Role 4: typed client for contracts/openapi.yaml.
// Point VITE_API_URL at a Prism mock first, then at the real backend.
import type { CaseEvent, CaseGraph, EvidenceItem, EvidenceUploadResult, Finding, FindingLineage, FindingStatusUpdate } from "./types";

export const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:4010";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status?: number
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_URL}${path}`, init);
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiError(`Could not reach the API at ${API_URL}.`);
  }
  if (!response.ok) {
    let detail = "";
    try {
      const body = (await response.json()) as { detail?: unknown };
      if (typeof body.detail === "string") detail = `: ${body.detail}`;
    } catch {
      // No JSON body; the status code is enough.
    }
    throw new ApiError(`${init?.method ?? "GET"} ${path} failed with ${response.status}${detail}`, response.status);
  }
  return response.json() as Promise<T>;
}

export async function get<T>(path: string): Promise<T> {
  return request<T>(path);
}

const isString = (value: unknown): value is string => typeof value === "string";

/** Rejects responses that don't carry the documented fields instead of rendering half-empty rows. */
function assertEvidenceList(data: unknown): asserts data is EvidenceItem[] {
  const valid =
    Array.isArray(data) &&
    data.every(
      item =>
        item !== null &&
        typeof item === "object" &&
        isString((item as EvidenceItem).evidence_id) &&
        isString((item as EvidenceItem).filename) &&
        isString((item as EvidenceItem).sha256) &&
        isString((item as EvidenceItem).intake_time)
    );
  if (!valid) throw new ApiError("The evidence list did not match the documented response shape.");
}

/** GET /cases/{id}/evidence */
export async function listEvidence(caseId: string, signal?: AbortSignal): Promise<EvidenceItem[]> {
  const data = await request<unknown>(`/cases/${encodeURIComponent(caseId)}/evidence`, { signal });
  assertEvidenceList(data);
  return data.map(item => ({ ...item, custody: Array.isArray(item.custody) ? item.custody : [] }));
}

/** POST /cases/{id}/evidence, multipart with a single `file` field. */
export async function uploadEvidence(caseId: string, file: File, signal?: AbortSignal): Promise<EvidenceUploadResult> {
  const body = new FormData();
  body.append("file", file);
  return request<EvidenceUploadResult>(`/cases/${encodeURIComponent(caseId)}/evidence`, { method: "POST", body, signal });
}

const isObjectArray = (data: unknown): data is Record<string, unknown>[] =>
  Array.isArray(data) && data.every(item => item !== null && typeof item === "object");

/** GET /cases/{id}/events, optionally filtered by time range and source. */
export async function listEvents(
  caseId: string,
  filters: { from?: string; to?: string; source?: CaseEvent["source"] } = {},
  signal?: AbortSignal
): Promise<CaseEvent[]> {
  const query = new URLSearchParams(Object.entries(filters).filter((entry): entry is [string, string] => Boolean(entry[1])));
  const suffix = query.toString() ? `?${query}` : "";
  const data = await request<unknown>(`/cases/${encodeURIComponent(caseId)}/events${suffix}`, { signal });
  if (!isObjectArray(data) || !data.every(e => isString(e.event_id) && isString(e.evidence_id) && isString(e.timestamp) && isString(e.action)))
    throw new ApiError("The events list did not match the documented response shape.");
  return data as unknown as CaseEvent[];
}

/** GET /cases/{id}/findings */
export async function listFindings(caseId: string, signal?: AbortSignal): Promise<Finding[]> {
  const data = await request<unknown>(`/cases/${encodeURIComponent(caseId)}/findings`, { signal });
  if (
    !isObjectArray(data) ||
    !data.every(f => isString(f.finding_id) && isString(f.claim) && typeof f.confidence === "number" && Array.isArray(f.evidence_event_ids))
  )
    throw new ApiError("The findings list did not match the documented response shape.");
  return data as unknown as Finding[];
}

/** GET /cases/{id}/graph */
export async function getGraph(caseId: string, signal?: AbortSignal): Promise<CaseGraph> {
  const data = await request<unknown>(`/cases/${encodeURIComponent(caseId)}/graph`, { signal });
  const graph = data as Partial<CaseGraph> | null;
  if (!graph || !Array.isArray(graph.nodes) || !Array.isArray(graph.edges))
    throw new ApiError("The graph did not match the documented response shape.");
  return graph as CaseGraph;
}

/** GET /findings/{id}/lineage */
export async function getFindingLineage(findingId: string, signal?: AbortSignal): Promise<FindingLineage> {
  const data = await request<Partial<FindingLineage> | null>(`/findings/${encodeURIComponent(findingId)}/lineage`, { signal });
  if (!data || !Array.isArray(data.events) || !Array.isArray(data.evidence))
    throw new ApiError("The lineage did not match the documented response shape.");
  return data as FindingLineage;
}

/** PATCH /findings/{id}: the investigator approves or rejects a finding. */
export async function updateFindingStatus(findingId: string, status: "approved" | "rejected", signal?: AbortSignal): Promise<FindingStatusUpdate> {
  return request<FindingStatusUpdate>(`/findings/${encodeURIComponent(findingId)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status }),
    signal
  });
}

/** GET /cases/{id}/report?format=pdf, returned as a Blob so the page can preview and save exactly what the server sent. */
export async function fetchReportPdf(caseId: string, signal?: AbortSignal): Promise<Blob> {
  let response: Response;
  try {
    response = await fetch(`${API_URL}/cases/${encodeURIComponent(caseId)}/report?format=pdf`, { signal });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiError(`Could not reach the API at ${API_URL}.`);
  }
  if (!response.ok) throw new ApiError(`GET /cases/${caseId}/report failed with ${response.status}`, response.status);
  const blob = await response.blob();
  if (!blob.type.includes("pdf") || blob.size === 0) throw new ApiError("The server did not return a PDF.");
  return blob;
}
