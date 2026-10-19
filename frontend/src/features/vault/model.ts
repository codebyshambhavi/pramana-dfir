// Role 4: client-side helpers for the Evidence Vault. Anything here that isn't in the API response is
// derived on the client (file kind from the extension) and is labelled as such in the UI.
import type { EvidenceItem } from "../../api/types";

export type FileKind = "csv" | "json" | "pcap" | "image" | "video" | "audio" | "pdf" | "other";

const KIND_BY_EXTENSION: Record<string, FileKind> = {
  csv: "csv",
  json: "json",
  pcap: "pcap",
  pcapng: "pcap",
  jpg: "image",
  jpeg: "image",
  png: "image",
  mp4: "video",
  mov: "video",
  wav: "audio",
  mp3: "audio",
  pdf: "pdf"
};

export const KIND_LABEL: Record<FileKind, string> = {
  csv: "CSV",
  json: "JSON",
  pcap: "PCAP",
  image: "Image",
  video: "Video",
  audio: "Audio",
  pdf: "PDF",
  other: "Other"
};

/** Kinds the Role 1 parsers handle (browser/log CSV, chat JSON, PCAP, image EXIF). Others are rejected at parse time. */
export const PARSED_KINDS: ReadonlySet<FileKind> = new Set<FileKind>(["csv", "json", "pcap", "image"]);

export const ACCEPTED_EXTENSIONS = ".csv,.json,.pcap,.pcapng,.jpg,.jpeg,.png";

export const extensionOf = (filename: string) => {
  const dot = filename.lastIndexOf(".");
  return dot > 0 ? filename.slice(dot + 1).toLowerCase() : "";
};

export const fileKind = (filename: string): FileKind => KIND_BY_EXTENSION[extensionOf(filename)] ?? "other";

export const isParsedKind = (kind: FileKind) => PARSED_KINDS.has(kind);

export const truncateHash = (hash: string) => (hash.length > 16 ? `${hash.slice(0, 8)}…${hash.slice(-4)}` : hash);

export function formatIntake(iso: string) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return { valid: false as const, date: iso, time: "", iso };
  return {
    valid: true as const,
    date: date.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" }),
    time: date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", hour12: false }),
    iso: date.toISOString()
  };
}

export function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

/**
 * A custody entry as far as we can read it. The contract leaves the shape open, so we pick up the fields the
 * backend plan names (actor, action, time, sha256, prev_hash) when present and keep the raw entry otherwise.
 */
export interface CustodyView {
  actor?: string;
  action?: string;
  time?: string;
  sha256?: string;
  prevHash?: string;
  raw: unknown;
}

const pickString = (entry: Record<string, unknown>, ...keys: string[]) => {
  for (const key of keys) if (typeof entry[key] === "string") return entry[key] as string;
  return undefined;
};

export function readCustody(entries: unknown[]): { entries: CustodyView[]; recognised: boolean } {
  const views = entries.map<CustodyView>(raw => {
    if (!raw || typeof raw !== "object") return { raw };
    const entry = raw as Record<string, unknown>;
    return {
      actor: pickString(entry, "actor", "who"),
      action: pickString(entry, "action", "what"),
      time: pickString(entry, "time", "when", "timestamp"),
      sha256: pickString(entry, "sha256"),
      prevHash: pickString(entry, "prev_hash"),
      raw
    };
  });
  const recognised = views.every(v => v.action !== undefined || v.time !== undefined);
  const sorted = [...views].sort((a, b) => {
    const ta = a.time ? Date.parse(a.time) : NaN;
    const tb = b.time ? Date.parse(b.time) : NaN;
    if (Number.isNaN(ta) || Number.isNaN(tb)) return 0;
    return ta - tb;
  });
  return { entries: sorted, recognised };
}

/** Matches an evidence item against a free-text query on ID, filename or SHA-256. */
export const matchesQuery = (item: EvidenceItem, query: string) => {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return (
    item.evidence_id.toLowerCase().includes(q) || item.filename.toLowerCase().includes(q) || item.sha256.toLowerCase().includes(q)
  );
};

/** SHA-256 of a file computed in the browser, for comparing with the hash the backend records. */
export async function sha256OfFile(file: File): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
}
