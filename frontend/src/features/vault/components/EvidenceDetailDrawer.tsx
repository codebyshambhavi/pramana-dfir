// Role 4: right-side detail panel for one evidence item: metadata, full SHA-256 and the custody chain.
// It shows only what the API returned. It never marks a hash "verified": the contract has no such field.
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Close, Custody, FileIcon, Hash, Info, Shield } from "../../../components/console/icons";
import type { EvidenceItem } from "../../../api/types";
import { fileKind, formatIntake, readCustody, type CustodyView } from "../model";
import { CopyButton, Derived, FileKindBadge } from "./ui";

export interface LocalHashCheck {
  localHash: string;
  matches: boolean;
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[104px_minmax(0,1fr)] gap-3 py-1.5 text-[13.5px]">
      <dt className="text-soft/65">{label}</dt>
      <dd className="min-w-0 text-white">{children}</dd>
    </div>
  );
}

function SectionTitle({ icon, children }: { icon: ReactNode; children: ReactNode }) {
  return (
    <h3 className="flex items-center gap-2.5 text-[14.5px] font-semibold text-white">
      <span className="text-trace-soft">{icon}</span>
      {children}
    </h3>
  );
}

const ACTION_CHIP: Record<string, string> = {
  intake: "border-trace/45 bg-trace/10 text-trace-soft",
  parsed: "border-cyan-400/40 bg-cyan-400/10 text-cyan-200",
  accessed: "border-alert/45 bg-alert/10 text-alert-soft"
};

function CustodyTimeline({ entries }: { entries: CustodyView[] }) {
  return (
    <ol className="relative mt-4 space-y-5 pl-7">
      <span
        className="absolute top-2 bottom-2 left-[7px] w-[2px] rounded-full bg-gradient-to-b from-trace/70 via-trace/40 to-trace/10 shadow-[0_0_8px_rgba(59,140,255,0.6)]"
        aria-hidden="true"
      />
      {entries.map((entry, i) => {
        const time = entry.time ? formatIntake(entry.time) : null;
        return (
          <li key={i} className="relative">
            <span
              className="absolute top-1 -left-7 flex size-4 items-center justify-center rounded-full border-2 border-trace bg-ink shadow-[0_0_10px_rgba(59,140,255,0.85)]"
              aria-hidden="true"
            >
              <span className="size-1.5 rounded-full bg-trace-soft" />
            </span>
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <p className="text-[13.5px] text-white tabular-nums">
                  {time ? (
                    <time dateTime={time.iso} title={time.iso}>
                      {time.date}
                      {time.valid && ` · ${time.time}`}
                    </time>
                  ) : (
                    <span className="text-soft/60">No time recorded</span>
                  )}
                </p>
                <p className="mt-0.5 text-[13px] text-soft/80">
                  {entry.action ?? "Unspecified action"}
                  {entry.actor && (
                    <>
                      {" by "}
                      <span className="text-white">{entry.actor}</span>
                    </>
                  )}
                </p>
                {entry.prevHash && (
                  <p className="mt-1 truncate font-mono text-[11.5px] text-soft/50" title={`Previous entry hash: ${entry.prevHash}`}>
                    prev {entry.prevHash.slice(0, 12)}…
                  </p>
                )}
              </div>
              {entry.action && (
                <span
                  className={`shrink-0 rounded-md border px-2 py-0.5 text-[11.5px] capitalize ${
                    ACTION_CHIP[entry.action.toLowerCase()] ?? "border-white/15 bg-white/[0.04] text-soft/80"
                  }`}
                >
                  {entry.action}
                </span>
              )}
            </div>
          </li>
        );
      })}
    </ol>
  );
}

export default function EvidenceDetailDrawer({
  item,
  isDemo,
  localCheck,
  onClose
}: {
  item: EvidenceItem;
  isDemo: boolean;
  localCheck?: LocalHashCheck;
  onClose: () => void;
}) {
  const closeRef = useRef<HTMLButtonElement>(null);
  const kind = fileKind(item.filename);
  const intake = formatIntake(item.intake_time);
  const custody = readCustody(item.custody);

  const [tab, setTab] = useState<"details" | "custody">("details");

  useEffect(() => {
    closeRef.current?.focus();
    setTab("details");
  }, [item.evidence_id]);

  return (
    <aside
      aria-label={`Details for ${item.evidence_id}`}
      className="relative flex h-full flex-col overflow-hidden rounded-none border-l border-trace/50 bg-[linear-gradient(180deg,rgba(13,22,42,0.98),rgba(6,9,17,0.99))] shadow-[0_0_44px_-6px_rgba(59,140,255,0.5),inset_0_0_0_1px_rgba(122,180,255,0.06)] xl:rounded-2xl xl:border"
    >
      <span aria-hidden="true" className="pointer-events-none absolute inset-x-8 top-0 h-px bg-gradient-to-r from-transparent via-trace-soft to-transparent" />
      <span aria-hidden="true" className="pointer-events-none absolute -top-16 -right-16 size-44 rounded-full bg-trace/20 blur-3xl" />
      <header className="relative flex items-start gap-3.5 px-5 pt-5 pb-3">
        <span className="flex size-11 shrink-0 items-center justify-center rounded-xl border border-trace/45 bg-trace/10 text-trace-soft shadow-[0_0_18px_rgba(59,140,255,0.45)]">
          <FileIcon size={22} />
        </span>
        <div className="min-w-0 flex-1">
          <h2 className="text-[20px] leading-tight font-semibold tracking-[-0.01em]">{item.evidence_id}</h2>
          <p className="truncate text-[13.5px] text-soft/80" title={item.filename}>
            {item.filename}
          </p>
        </div>
        <button
          ref={closeRef}
          type="button"
          onClick={onClose}
          aria-label="Close details"
          className="rounded-md p-1.5 text-soft/80 hover:bg-white/[0.06] hover:text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-trace"
        >
          <Close size={20} />
        </button>
      </header>

      <div role="tablist" aria-label="Evidence detail sections" className="relative flex gap-6 border-b border-white/[0.07] px-5">
        {(
          [
            ["details", "Details"],
            ["custody", `Chain of custody (${custody.entries.length})`]
          ] as const
        ).map(([key, label]) => (
          <button
            key={key}
            type="button"
            role="tab"
            id={`tab-${key}`}
            aria-selected={tab === key}
            aria-controls={`panel-${key}`}
            onClick={() => setTab(key)}
            className={`relative py-3 text-[14px] transition-colors ${
              tab === key
                ? "text-white after:absolute after:inset-x-0 after:bottom-[-1px] after:h-[2px] after:bg-alert after:shadow-[0_0_10px_rgba(239,43,60,0.8)]"
                : "text-soft/70 hover:text-white"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      <div
        role="tabpanel"
        id={`panel-${tab}`}
        aria-labelledby={`tab-${tab}`}
        className="relative flex-1 space-y-6 overflow-y-auto px-5 py-5"
      >
        {isDemo && (
          <p className="rounded-lg border border-amber-300/25 bg-amber-300/[0.06] px-3 py-2 text-[12.5px] text-amber-100/90">
            {localCheck
              ? "Demo record kept in this browser. Its SHA-256 was computed from your file; nothing was sent to the backend."
              : "Synthetic demo record. Its hash and custody entries are made up for UI development."}
          </p>
        )}

        {tab === "details" && (
          <>
        <section>
          <SectionTitle icon={<Info size={18} />}>Evidence information</SectionTitle>
          <dl className="mt-2.5">
            <Row label="Evidence ID">{item.evidence_id}</Row>
            <Row label="File name">
              <span className="break-all">{item.filename}</span>
            </Row>
            <Row label="File type">
              <FileKindBadge kind={kind} />
              <Derived>from extension</Derived>
            </Row>
            <Row label="Intake time">
              {intake.valid ? (
                <>
                  <span className="tabular-nums">
                    {intake.date} · {intake.time}
                  </span>
                  <span className="block font-mono text-[11.5px] text-soft/55">{intake.iso}</span>
                </>
              ) : (
                <span className="text-soft/70">{item.intake_time || "Not recorded"}</span>
              )}
            </Row>
          </dl>
        </section>

        <section>
          <SectionTitle icon={<Hash size={18} />}>SHA-256</SectionTitle>
          <div className="mt-2.5 flex items-start gap-2 rounded-lg border border-trace/25 bg-black/40 p-3 shadow-[inset_0_0_18px_rgba(59,140,255,0.06)]">
            <code className="min-w-0 flex-1 font-mono text-[13px] leading-[1.7] tracking-[0.04em] break-all text-[#d6e4ff]">
              {(item.sha256.match(/.{1,8}/g) ?? [item.sha256]).map((group, i) => (
                <span key={i} className="mr-[0.6ch] inline-block last:mr-0">
                  {group}
                </span>
              ))}
            </code>
            <CopyButton text={item.sha256} label="Copy full SHA-256" />
          </div>

          {localCheck ? (
            <div
              className={`mt-3 flex gap-3 rounded-lg border p-3.5 ${
                localCheck.matches ? "border-verified/30 bg-verified/[0.06]" : "border-alert/40 bg-alert/[0.07]"
              }`}
            >
              <Shield size={22} className={localCheck.matches ? "text-verified" : "text-alert"} />
              <div className="text-[13px]">
                <p className={`font-semibold ${localCheck.matches ? "text-verified" : "text-alert-soft"}`}>
                  {localCheck.matches ? "Matches your uploaded copy" : "Does not match your uploaded copy"}
                </p>
                <p className="mt-0.5 text-soft/75">
                  Compared with the SHA-256 this browser computed for the file you uploaded in this session.
                </p>
              </div>
            </div>
          ) : (
            <div className="mt-3 flex gap-3 rounded-lg border border-trace/20 bg-trace/[0.05] p-3.5">
              <Shield size={22} className="text-trace-soft" />
              <div className="text-[13px]">
                <p className="font-semibold text-white">Recorded at intake</p>
                <p className="mt-0.5 text-soft/75">
                  The API does not report a verification status yet. Re-hash the original file to compare.
                </p>
              </div>
            </div>
          )}
        </section>

          </>
        )}

        {tab === "custody" && (
        <section>
          <SectionTitle icon={<Custody size={18} />}>Chain of custody</SectionTitle>
          {custody.entries.length === 0 ? (
            <p className="mt-2.5 rounded-lg border border-dashed border-white/10 px-3.5 py-3 text-[13px] text-soft/70">
              No custody entries were returned for this item.
            </p>
          ) : custody.recognised ? (
            <CustodyTimeline entries={custody.entries} />
          ) : (
            <>
              <p className="mt-2.5 text-[12.5px] text-soft/70">
                These entries use a shape the contract doesn't define yet, so they're shown as returned.
              </p>
              <pre className="mt-2 max-h-64 overflow-auto rounded-lg border border-white/[0.08] bg-black/30 p-3 font-mono text-[12px] text-soft/85">
                {JSON.stringify(item.custody, null, 2)}
              </pre>
            </>
          )}
        </section>
        )}
      </div>
    </aside>
  );
}
