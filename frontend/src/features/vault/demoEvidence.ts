// Role 4: SYNTHETIC evidence for UI development only. None of these records, hashes or custody entries come from
// the backend. Custody entries follow the field names in backend/app/db/models.py (actor, action, time, sha256,
// prev_hash), which is the backend's plan, not part of the API contract.
import type { EvidenceItem } from "../../api/types";

/** Deterministic 64-character hex string. It is NOT a real hash of any file. */
function fakeHash(seed: string) {
  let h = 2166136261;
  let out = "";
  for (let round = 0; out.length < 64; round++) {
    for (let i = 0; i < seed.length; i++) h = Math.imul(h ^ seed.charCodeAt(i), 16777619) ^ round;
    out += (h >>> 0).toString(16).padStart(8, "0");
  }
  return out.slice(0, 64);
}

const custody = (sha256: string, steps: [string, string, string][]) => {
  let prev = "0".repeat(64);
  return steps.map(([time, actor, action]) => {
    const entry = { time, actor, action, sha256, prev_hash: prev };
    prev = fakeHash(prev + time + action);
    return entry;
  });
};

const make = (id: number, filename: string, intake: string, steps: [string, string][] = []): EvidenceItem => {
  const evidence_id = `EVID-${String(id).padStart(3, "0")}`;
  const sha256 = fakeHash(evidence_id + filename);
  const entries: [string, string, string][] = [
    [intake, "investigator_a", "intake"],
    ...steps.map(([time, action]) => [time, action === "parsed" ? "system" : "analyst_01", action] as [string, string, string])
  ];
  return { evidence_id, filename, sha256, intake_time: intake, custody: custody(sha256, entries) };
};

export const DEMO_EVIDENCE: EvidenceItem[] = [
  make(1, "browser_history.csv", "2026-10-14T16:52:10Z", [["2026-10-14T16:52:14Z", "parsed"], ["2026-10-14T17:40:00Z", "accessed"]]),
  make(2, "chat_export.json", "2026-10-14T16:55:41Z", [["2026-10-14T16:55:45Z", "parsed"]]),
  make(3, "system_log.csv", "2026-10-14T16:58:03Z", [["2026-10-14T16:58:06Z", "parsed"]]),
  make(4, "capture_01.pcap", "2026-10-14T17:02:27Z", [["2026-10-14T17:02:40Z", "parsed"], ["2026-10-14T18:05:12Z", "accessed"]]),
  make(5, "photo_01.jpg", "2026-10-14T17:05:19Z", [["2026-10-14T17:05:21Z", "parsed"], ["2026-10-14T18:11:30Z", "accessed"]]),
  make(6, "photo_02.jpg", "2026-10-14T17:05:58Z", [["2026-10-14T17:06:00Z", "parsed"]]),
  make(7, "location_log.json", "2026-10-14T17:09:44Z", [["2026-10-14T17:09:47Z", "parsed"]]),
  make(8, "wifi_connections.csv", "2026-10-14T17:12:15Z", [["2026-10-14T17:12:18Z", "parsed"]]),
  make(9, "cctv_footage.mp4", "2026-10-14T17:16:02Z"),
  make(10, "incident_report.pdf", "2026-10-14T17:21:36Z"),
  make(11, "audio_record.wav", "2026-10-14T17:24:50Z"),
  make(12, "dns_capture.pcap", "2026-10-14T17:30:08Z", [["2026-10-14T17:30:20Z", "parsed"]])
];
