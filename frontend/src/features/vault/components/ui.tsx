// Role 4: small shared pieces for the Evidence Vault.
import type { ComponentType, ReactNode, SVGProps } from "react";
import { AudioWave, Braces, Check, Copy, FileIcon, ImageIcon, Network, TableIcon, VideoIcon } from "../../../components/console/icons";
import { useCopy } from "../hooks";
import { KIND_LABEL, type FileKind } from "../model";

export const PANEL =
  "rounded-xl border border-trace/[0.22] bg-[linear-gradient(180deg,rgba(14,23,42,0.78),rgba(6,10,19,0.84))] shadow-[inset_0_1px_0_rgba(255,255,255,0.045),0_24px_48px_-28px_rgba(0,0,0,0.9),0_0_30px_-18px_rgba(59,140,255,0.5)] backdrop-blur-[4px]";

const KIND_STYLE: Record<FileKind, string> = {
  csv: "border-teal-400/40 bg-teal-400/[0.12] text-teal-200",
  json: "border-trace/45 bg-trace/[0.14] text-trace-soft",
  pcap: "border-sky-400/40 bg-sky-400/[0.12] text-sky-200",
  image: "border-trace/45 bg-trace/[0.14] text-trace-soft",
  video: "border-violet-400/45 bg-violet-500/[0.16] text-violet-200",
  audio: "border-cyan-400/40 bg-cyan-400/[0.12] text-cyan-200",
  pdf: "border-alert/45 bg-alert/[0.13] text-alert-soft",
  other: "border-white/15 bg-white/[0.05] text-soft"
};

const KIND_ICON: Record<FileKind, ComponentType<SVGProps<SVGSVGElement> & { size?: number }>> = {
  csv: TableIcon,
  json: Braces,
  pcap: Network,
  image: ImageIcon,
  video: VideoIcon,
  audio: AudioWave,
  pdf: FileIcon,
  other: FileIcon
};

export function FileKindBadge({ kind }: { kind: FileKind }) {
  const Icon = KIND_ICON[kind];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-[3px] text-[12px] font-medium ${KIND_STYLE[kind]}`}>
      <Icon size={13} strokeWidth={1.9} />
      {KIND_LABEL[kind]}
    </span>
  );
}

export function CopyButton({ text, label, className = "" }: { text: string; label: string; className?: string }) {
  const { copied, copy } = useCopy();
  return (
    <button
      type="button"
      onClick={event => {
        event.stopPropagation();
        void copy(text);
      }}
      className={`inline-flex size-7 shrink-0 items-center justify-center rounded-md text-soft/70 transition hover:bg-white/[0.06] hover:text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-trace ${className}`}
      aria-label={copied ? `${label} copied` : label}
      title={copied ? "Copied" : label}
    >
      {copied ? <Check size={15} className="text-verified" /> : <Copy size={15} />}
    </button>
  );
}

export function Eyebrow({ children }: { children: ReactNode }) {
  return <p className="text-[11px] font-semibold tracking-[0.38em] text-soft/80">{children}</p>;
}

/** Marks a value the client derived rather than read from the API. */
export function Derived({ children = "derived" }: { children?: ReactNode }) {
  return (
    <span className="ml-1.5 rounded border border-white/10 px-1 py-px text-[10px] tracking-wide text-muted uppercase">{children}</span>
  );
}
