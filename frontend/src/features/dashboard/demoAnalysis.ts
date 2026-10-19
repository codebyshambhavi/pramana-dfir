// Role 4: SYNTHETIC events and findings for UI development only, built on the demo evidence set so every ID,
// hash and reference lines up. Shapes follow contracts/event.schema.json and contracts/finding.schema.json.
// The story mirrors datasets/sample_case_001: an odd-hour login, an archive created then uploaded, and a photo
// whose EXIF location disagrees with the phone's GPS and IP. Nothing here came from the backend or Role 2.
import type { CaseEvent, Finding } from "../../api/types";
import { DEMO_EVIDENCE } from "../vault/demoEvidence";

const CASE_ID = "CASE-001";
const hashOf = (evidenceId: string) => DEMO_EVIDENCE.find(e => e.evidence_id === evidenceId)?.sha256 ?? "";
const fileOf = (evidenceId: string) => DEMO_EVIDENCE.find(e => e.evidence_id === evidenceId)?.filename ?? "";

type EventSeed = Omit<CaseEvent, "case_id" | "sha256" | "artifact_ref"> & { ref: string };

const SEEDS: EventSeed[] = [
  { event_id: "EV-000101", evidence_id: "EVID-003", ref: "row=88", timestamp: "2026-10-13T21:47:10Z", source: "log", action: "login", actor: "user_01", device: "laptop_A", ip: "203.0.113.7" },
  { event_id: "EV-000102", evidence_id: "EVID-003", ref: "row=94", timestamp: "2026-10-13T21:52:33Z", source: "log", action: "file_access", actor: "user_01", device: "laptop_A", object: "finance_q3.xlsx" },
  { event_id: "EV-000103", evidence_id: "EVID-003", ref: "row=101", timestamp: "2026-10-13T21:58:05Z", source: "log", action: "file_create", actor: "user_01", device: "laptop_A", object: "secret.zip" },
  { event_id: "EV-000104", evidence_id: "EVID-012", ref: "packet=1204", timestamp: "2026-10-13T22:01:38Z", source: "pcap", action: "dns_lookup", device: "laptop_A", ip: "203.0.113.7", object: "fileshare.example" },
  { event_id: "EV-000105", evidence_id: "EVID-001", ref: "row=412", timestamp: "2026-10-13T22:03:12Z", source: "browser", action: "file_upload", actor: "user_01", device: "laptop_A", object: "secret.zip", ip: "203.0.113.7" },
  { event_id: "EV-000106", evidence_id: "EVID-004", ref: "packet=3381", timestamp: "2026-10-13T22:03:15Z", source: "pcap", action: "connection", device: "laptop_A", ip: "198.51.100.24" },
  { event_id: "EV-000107", evidence_id: "EVID-003", ref: "row=133", timestamp: "2026-10-13T22:20:44Z", source: "log", action: "logout", actor: "user_01", device: "laptop_A" },
  { event_id: "EV-000108", evidence_id: "EVID-002", ref: "message=57", timestamp: "2026-10-14T04:10:02Z", source: "chat", action: "message_sent", actor: "user_01", device: "phone_B", object: "says they are at home" },
  { event_id: "EV-000109", evidence_id: "EVID-002", ref: "message=58", timestamp: "2026-10-14T04:12:19Z", source: "chat", action: "message_received", actor: "user_02", device: "phone_B" },
  { event_id: "EV-000110", evidence_id: "EVID-008", ref: "row=19", timestamp: "2026-10-14T04:20:10Z", source: "log", action: "wifi_connect", actor: "user_01", device: "phone_B", object: "office_wifi", ip: "203.0.113.9" },
  { event_id: "EV-000111", evidence_id: "EVID-007", ref: "row=7", timestamp: "2026-10-14T04:21:30Z", source: "log", action: "gps_fix", device: "phone_B", location: { lat: 28.61, lon: 77.2 } },
  { event_id: "EV-000112", evidence_id: "EVID-005", ref: "exif", timestamp: "2026-10-14T04:22:05Z", source: "image", action: "photo_taken", device: "phone_B", object: "photo_01.jpg", location: { lat: 26.91, lon: 75.79 } },
  { event_id: "EV-000113", evidence_id: "EVID-006", ref: "exif", timestamp: "2026-10-14T04:40:51Z", source: "image", action: "photo_taken", device: "phone_B", object: "photo_02.jpg", location: { lat: 28.61, lon: 77.21 } }
];

export const DEMO_EVENTS: CaseEvent[] = SEEDS.map(({ ref, ...seed }) => ({
  ...seed,
  case_id: CASE_ID,
  sha256: hashOf(seed.evidence_id),
  artifact_ref: `${fileOf(seed.evidence_id)}#${ref}`
}));

export const DEMO_FINDINGS: Finding[] = [
  {
    finding_id: "F-0001",
    case_id: CASE_ID,
    type: "anomaly",
    claim: "Login at an unusual hour for user_01",
    confidence: 0.71,
    evidence_event_ids: ["EV-000101"],
    reasoning: "Login falls outside the account's usual activity window",
    alternatives: [
      { claim: "Scheduled overnight work", confidence: 0.4, needed_evidence: ["work rota"] },
      { claim: "Credentials used by someone else", confidence: 0.6, needed_evidence: ["badge access log"] }
    ],
    needs_human_review: true,
    status: "pending"
  },
  {
    finding_id: "F-0002",
    case_id: CASE_ID,
    type: "correlation",
    claim: "secret.zip was created and uploaded within five minutes",
    confidence: 0.84,
    evidence_event_ids: ["EV-000103", "EV-000105", "EV-000106"],
    reasoning: "Same device and file name within the 120 s correlation window chain",
    needs_human_review: true,
    status: "approved"
  },
  {
    finding_id: "F-0003",
    case_id: CASE_ID,
    type: "contradiction",
    claim: "Photo EXIF location differs from device GPS and IP location",
    confidence: 0.62,
    evidence_event_ids: ["EV-000112", "EV-000111", "EV-000110"],
    reasoning: "EXIF places the photo in Jaipur while GPS and IP place the phone in Delhi",
    alternatives: [
      { claim: "Metadata edited", confidence: 0.62, needed_evidence: ["original file hash"] },
      { claim: "Photo copied from another device", confidence: 0.38, needed_evidence: ["perceptual hash match"] }
    ],
    needs_human_review: true,
    status: "pending"
  },
  {
    finding_id: "F-0004",
    case_id: CASE_ID,
    type: "contradiction",
    claim: "Chat says user was at home while the phone joined office Wi-Fi",
    confidence: 0.58,
    evidence_event_ids: ["EV-000108", "EV-000110"],
    reasoning: "Message and Wi-Fi connection are ten minutes apart from different places",
    needs_human_review: true,
    status: "pending"
  },
  {
    finding_id: "F-0005",
    case_id: CASE_ID,
    type: "hypothesis",
    claim: "Upload may have been made by a second person on laptop_A",
    confidence: 0.35,
    evidence_event_ids: ["EV-000101", "EV-000105"],
    needs_human_review: true,
    status: "rejected"
  }
];
