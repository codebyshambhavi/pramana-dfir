// Role 4: upload one evidence file (POST /cases/{id}/evidence takes a single `file` field).
// The browser also hashes the file so the user can compare it with the SHA-256 the backend records.
import { useEffect, useRef, useState, type DragEvent } from "react";
import { Alert, Check, Close, CloudUpload, Upload } from "../../../components/console/icons";
import type { EvidenceUploadResult } from "../../../api/types";
import type { EvidenceSource } from "../evidenceSource";
import { ACCEPTED_EXTENSIONS, fileKind, formatBytes, isParsedKind, sha256OfFile, truncateHash } from "../model";
import { FileKindBadge } from "./ui";

type Phase =
  | { name: "idle" }
  | { name: "ready"; file: File }
  | { name: "uploading"; file: File }
  | { name: "done"; file: File; result: EvidenceUploadResult; localHash: string | null }
  | { name: "error"; file: File; message: string };

interface Props {
  source: EvidenceSource;
  caseId: string;
  onClose: () => void;
  onUploaded: (result: EvidenceUploadResult, localHash: string | null) => void;
  onOpenItem: (evidenceId: string) => void;
}

export default function UploadEvidenceModal({ source, caseId, onClose, onUploaded, onOpenItem }: Props) {
  const [phase, setPhase] = useState<Phase>({ name: "idle" });
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef<AbortController | null>(null);
  const busy = phase.name === "uploading";

  useEffect(() => {
    dialogRef.current?.focus();
    return () => abortRef.current?.abort();
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !busy) onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [busy, onClose]);

  const choose = (files: FileList | null) => {
    const file = files?.[0];
    if (file) setPhase({ name: "ready", file });
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    if (!busy) choose(e.dataTransfer.files);
  };

  const upload = async (file: File) => {
    const controller = new AbortController();
    abortRef.current = controller;
    setPhase({ name: "uploading", file });
    try {
      const [result, localHash] = await Promise.all([
        source.upload(caseId, file, controller.signal),
        sha256OfFile(file).catch(() => null)
      ]);
      setPhase({ name: "done", file, result, localHash });
      onUploaded(result, localHash);
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        setPhase({ name: "ready", file });
        return;
      }
      setPhase({ name: "error", file, message: error instanceof Error ? error.message : "Upload failed." });
    }
  };

  const file = phase.name === "idle" ? null : phase.file;
  const kind = file ? fileKind(file.name) : null;

  return (
    <div className="fixed inset-0 z-50 flex items-end justify-center p-0 sm:items-center sm:p-6">
      <div className="absolute inset-0 bg-black/65 backdrop-blur-[2px]" onClick={() => !busy && onClose()} aria-hidden="true" />
      <div
        ref={dialogRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby="upload-title"
        className="relative w-full max-w-[520px] overflow-hidden rounded-t-2xl border border-trace/40 bg-[linear-gradient(180deg,#0e1628,#070a12)] shadow-[0_20px_60px_rgba(0,0,0,0.65),0_0_44px_-6px_rgba(59,140,255,0.4)] outline-none sm:rounded-2xl"
      >
        <span aria-hidden="true" className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-trace-soft to-transparent" />
        <header className="flex items-center gap-3 border-b border-white/[0.07] px-5 py-4">
          <CloudUpload size={24} className="text-trace-soft drop-shadow-[0_0_8px_rgba(59,140,255,0.8)]" />
          <div className="min-w-0 flex-1">
            <h2 id="upload-title" className="text-[16px] font-semibold">
              Upload evidence
            </h2>
            <p className="text-[12px] text-soft/65">
              {source.kind === "demo" ? "Demo mode · the file stays in this browser" : `Live API · POST /cases/${caseId}/evidence`}
            </p>
          </div>
          <span
            className={`hidden rounded-md border px-2 py-0.5 text-[11px] font-semibold tracking-[0.08em] uppercase sm:inline ${
              source.kind === "demo" ? "border-amber-300/35 text-amber-200" : "border-teal-400/35 text-teal-200"
            }`}
          >
            {source.kind === "demo" ? "Demo" : "Live"}
          </span>
          <button
            type="button"
            onClick={onClose}
            disabled={busy}
            aria-label="Close"
            className="rounded-md p-1.5 text-soft/80 hover:bg-white/[0.06] hover:text-white disabled:opacity-40"
          >
            <Close size={18} />
          </button>
        </header>

        <div className="space-y-4 px-5 py-5">
          {phase.name === "done" ? (
            <div className="rounded-xl border border-verified/25 bg-verified/[0.05] p-4">
              <p className="flex items-center gap-2 font-semibold text-verified">
                <Check size={18} />
                {source.kind === "demo" ? "Added to the demo vault" : "Stored by the backend"}
              </p>
              <dl className="mt-3 grid grid-cols-[110px_minmax(0,1fr)] gap-y-1.5 text-[13.5px]">
                <dt className="text-soft/65">Evidence ID</dt>
                <dd>{phase.result.evidence_id}</dd>
                <dt className="text-soft/65">SHA-256</dt>
                <dd className="font-mono text-[12.5px]" title={phase.result.sha256}>
                  {truncateHash(phase.result.sha256)}
                </dd>
                {source.kind === "api" && (
                  <>
                    <dt className="text-soft/65">Events created</dt>
                    <dd>{phase.result.events_created}</dd>
                  </>
                )}
                <dt className="text-soft/65">Local hash</dt>
                <dd>
                  {phase.localHash === null ? (
                    <span className="text-soft/70">Couldn't compute in this browser</span>
                  ) : phase.localHash === phase.result.sha256 ? (
                    <span className="text-verified">Matches the recorded SHA-256</span>
                  ) : (
                    <span className="text-alert-soft">Differs from the recorded SHA-256</span>
                  )}
                </dd>
              </dl>
              {source.kind === "demo" && (
                <p className="mt-3 text-[12px] text-amber-100/80">Demo mode: the file stayed in this browser. Nothing was sent to the backend.</p>
              )}
            </div>
          ) : (
            <div
              onDragOver={e => {
                e.preventDefault();
                if (!busy) setDragging(true);
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={onDrop}
              className={`flex flex-col items-center rounded-xl border border-dashed px-5 py-8 text-center transition ${
                dragging
                  ? "border-trace bg-trace/[0.12] shadow-[0_0_30px_-6px_rgba(59,140,255,0.6),inset_0_0_24px_rgba(59,140,255,0.15)]"
                  : "border-trace/45 bg-trace/[0.04] shadow-[inset_0_0_24px_rgba(59,140,255,0.06)] hover:border-trace/70"
              }`}
            >
              <CloudUpload size={44} strokeWidth={1.4} className="text-trace-soft drop-shadow-[0_0_12px_rgba(59,140,255,0.8)]" />
              <p className="mt-3 text-[15px] text-white">Drag and drop a file here</p>
              <button
                type="button"
                disabled={busy}
                onClick={() => inputRef.current?.click()}
                className="mt-1 text-[14px] text-trace-soft underline-offset-4 hover:underline disabled:opacity-50"
              >
                or choose a file
              </button>
              <input
                ref={inputRef}
                type="file"
                accept={ACCEPTED_EXTENSIONS}
                className="sr-only"
                onChange={e => {
                  choose(e.target.files);
                  e.target.value = "";
                }}
              />
              <p className="mt-3 text-[12px] text-muted">
                Parsed types: CSV, JSON, PCAP, JPG, PNG. One file per upload.
              </p>
            </div>
          )}

          {file && phase.name !== "done" && kind && (
            <div className="flex items-center gap-3 rounded-lg border border-trace/30 bg-trace/[0.06] px-3.5 py-3">
              <Check size={18} className="shrink-0 text-trace-soft" />
              <div className="min-w-0 flex-1">
                <p className="truncate text-[14px]" title={file.name}>
                  {file.name}
                </p>
                <p className="mt-0.5 text-[12.5px] text-soft/65">{formatBytes(file.size)}</p>
              </div>
              <FileKindBadge kind={kind} />
            </div>
          )}

          {file && kind && !isParsedKind(kind) && phase.name !== "done" && (
            <p className="flex gap-2 text-[12.5px] text-amber-100/85">
              <Alert size={16} className="mt-px shrink-0 text-amber-300" />
              The evidence engine has no parser for this file type, so the backend may reject it.
            </p>
          )}

          {phase.name === "error" && (
            <p role="alert" className="flex gap-2 rounded-lg border border-alert/35 bg-alert/[0.07] px-3.5 py-3 text-[13px] text-alert-soft">
              <Alert size={17} className="mt-px shrink-0" />
              {phase.message}
            </p>
          )}

          {phase.name === "uploading" && (
            <div aria-live="polite">
              <p className="text-[13px] text-soft/80">Uploading and hashing…</p>
              <div className="mt-2 h-1 overflow-hidden rounded-full bg-white/[0.08]">
                <div className="h-full w-1/3 animate-[upload_1.1s_ease-in-out_infinite] rounded-full bg-trace" />
              </div>
            </div>
          )}
        </div>

        <footer className="flex flex-wrap justify-end gap-2.5 border-t border-white/[0.07] px-5 py-4">
          {phase.name === "done" ? (
            <>
              <button
                type="button"
                onClick={() => setPhase({ name: "idle" })}
                className="rounded-lg border border-white/12 px-4 py-2.5 text-[14px] text-soft hover:text-white"
              >
                Upload another
              </button>
              <button
                type="button"
                onClick={() => onOpenItem(phase.result.evidence_id)}
                className="rounded-lg bg-alert px-4 py-2.5 text-[14px] font-medium text-white hover:bg-[#ff3a4a]"
              >
                View details
              </button>
            </>
          ) : (
            <>
              <button
                type="button"
                onClick={() => (busy ? abortRef.current?.abort() : onClose())}
                className="rounded-lg border border-white/12 px-4 py-2.5 text-[14px] text-soft hover:text-white"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={!file || busy}
                onClick={() => file && upload(file)}
                className="inline-flex items-center gap-2 rounded-lg bg-alert px-4 py-2.5 text-[14px] font-medium text-white shadow-[0_0_20px_rgba(239,43,60,0.3)] transition hover:bg-[#ff3a4a] disabled:cursor-not-allowed disabled:opacity-45 disabled:shadow-none"
              >
                <Upload size={16} />
                {phase.name === "error" ? "Retry upload" : "Upload file"}
              </button>
            </>
          )}
        </footer>
      </div>
    </div>
  );
}
