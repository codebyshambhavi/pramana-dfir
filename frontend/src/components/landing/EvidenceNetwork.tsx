// Hero visual: the dithered live evidence scene with crisp hubs and evidence cards layered on top.
// All sizes inside use container-relative units (cqw) so the cards keep the reference's proportions.
// Below MIN_WIDTH the whole visual is laid out at MIN_WIDTH and scaled down, so text never collapses.
import { useEffect, useMemo, useRef, useState, type CSSProperties, type ReactNode } from "react";
import { Link } from "react-router-dom";
import DitherVeil from "../effects/DitherVeil";
import { createEvidenceScene } from "./evidenceScene";
import { CORE, HUBS, VISUAL_ASPECT, type Point, type Tone } from "./evidenceLayout";
import {
  AlertTriangle,
  ArrowRight,
  ChatBubble,
  CheckCircle,
  EventBox,
  FileText,
  Laptop,
  LaptopWireframe,
  Monitor
} from "./icons";

const MIN_WIDTH = 720;

const at = ({ x, y }: Point): CSSProperties => ({ left: `${x * 100}%`, top: `${y * 100}%` });

const toneRing: Record<Tone, string> = {
  trace: "border-trace/80 text-trace-soft shadow-[0_0_2.4cqw_rgba(59,140,255,0.55),inset_0_0_1.2cqw_rgba(59,140,255,0.35)]",
  alert: "border-alert text-alert-soft shadow-[0_0_2.8cqw_rgba(239,43,60,0.7),inset_0_0_1.2cqw_rgba(239,43,60,0.4)]"
};

function Hub({ point, tone, children }: { point: Point; tone: Tone; children: ReactNode }) {
  return (
    <div
      className={`absolute flex size-[5.4cqw] -translate-x-1/2 -translate-y-1/2 items-center justify-center rounded-full border-[0.2cqw] bg-[#060a14]/90 ${toneRing[tone]}`}
      style={at(point)}
    >
      {children}
    </div>
  );
}

const cardTone: Record<Tone, string> = {
  trace:
    "border-trace/45 shadow-[0_0_3cqw_rgba(59,140,255,0.22),inset_0_0_2cqw_rgba(59,140,255,0.07)] bg-[linear-gradient(160deg,rgba(14,24,44,0.78),rgba(5,9,18,0.82))]",
  alert:
    "border-alert/55 shadow-[0_0_3.4cqw_rgba(239,43,60,0.3),inset_0_0_2cqw_rgba(239,43,60,0.08)] bg-[linear-gradient(160deg,rgba(36,10,16,0.72),rgba(8,6,12,0.85))]"
};

function Card({
  tone = "trace",
  style,
  className = "",
  children
}: {
  tone?: Tone;
  style: CSSProperties;
  className?: string;
  children: ReactNode;
}) {
  return (
    <div
      className={`absolute rounded-[0.7cqw] border p-[2.2cqw] backdrop-blur-[2px] [transform-style:preserve-3d] ${cardTone[tone]} ${className}`}
      style={style}
    >
      {children}
    </div>
  );
}

const Label = ({ children, className = "" }: { children: ReactNode; className?: string }) => (
  <span className={`text-[1.15cqw] font-semibold tracking-[0.22em] text-soft/90 ${className}`}>{children}</span>
);

const Meta = ({ children }: { children: ReactNode }) => (
  <p className="text-[1.38cqw] leading-[1.75] text-soft/85 tabular-nums">{children}</p>
);

function Crosshair() {
  return (
    <svg viewBox="0 0 24 24" className="size-[2.6cqw]" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
      <circle cx="12" cy="12" r="8" />
      <path d="M12 2v6M12 16v6M2 12h6M16 12h6" />
    </svg>
  );
}

export default function EvidenceNetwork({ className = "" }: { className?: string }) {
  const scene = useMemo(() => createEvidenceScene(), []);
  const outerRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);

  useEffect(() => {
    const outer = outerRef.current;
    if (!outer) return undefined;
    const observer = new ResizeObserver(([entry]) => setWidth(entry.contentRect.width));
    observer.observe(outer);
    return () => observer.disconnect();
  }, []);

  const innerWidth = Math.max(width, MIN_WIDTH);
  const scale = width ? width / innerWidth : 1;

  return (
    <div
      ref={outerRef}
      className={`relative w-full ${className}`}
      style={{ height: width ? (innerWidth / VISUAL_ASPECT) * scale : undefined, aspectRatio: width ? undefined : VISUAL_ASPECT }}
      role="img"
      aria-label="Illustration of an evidence network with synthetic data: a verified file, a laptop, a chat message and a contradiction finding linked to one piece of evidence"
    >
      <div
        className="@container absolute top-0 left-0 origin-top-left"
        style={{ width: innerWidth, aspectRatio: VISUAL_ASPECT, transform: scale < 1 ? `scale(${scale})` : undefined }}
      >
        <DitherVeil
          scene={scene}
          pattern="noise"
          palette="rgb"
          levels={3}
          pixelSize={2}
          inkColor="#05070c"
          paperColor="#ffffff"
          contrast={1.15}
          brightness={0.08}
          revealRadius={140}
          softness={0.55}
          linger={1.1}
          style={{ position: "absolute", inset: 0 }}
        />

        {/* Fade the canvas into the page so it bleeds like the reference instead of ending on a hard edge. */}
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_75%_70%_at_50%_50%,transparent_62%,#05070c_100%)]" />

        <div aria-hidden="true" className="pointer-events-none absolute inset-0 [perspective:140cqw]">
          {/* Core: the piece of evidence every thread resolves to. */}
          <div
            className="absolute flex size-[8cqw] -translate-x-1/2 -translate-y-1/2 items-center justify-center rounded-[1.4cqw] border-[0.22cqw] border-transparent text-white shadow-[0_0_3cqw_rgba(59,140,255,0.55),0_0_5cqw_rgba(239,43,60,0.35)] [background:linear-gradient(#08101e,#0d0a16)_padding-box,linear-gradient(135deg,#4b9bff_0%,#7a5cff_50%,#ef2b3c_100%)_border-box]"
            style={at(CORE)}
          >
            <FileText size="4.4cqw" strokeWidth={1.4} className="text-trace-soft drop-shadow-[0_0_0.8cqw_rgba(120,180,255,0.9)]" />
          </div>

          {/* File */}
          <Card style={{ left: "4.3%", top: "7.2%", width: "21.8%", transform: "rotateY(9deg) rotateZ(-0.6deg)" }}>
            <div className="flex items-center gap-[1.6cqw]">
              <FileText size="4.2cqw" strokeWidth={1.3} className="text-trace-soft" />
              <Label>FILE</Label>
            </div>
            <p className="mt-[1.6cqw] text-[1.75cqw] font-medium text-white">evidence_01.pdf</p>
            <p className="mt-[1cqw] text-[1.38cqw] text-soft/85">SHA-256</p>
            <p className="text-[1.38cqw] tracking-wide text-soft/85 tabular-nums">3f2a6e...9c4d1e7b</p>
            <p className="mt-[1.1cqw] flex items-center gap-[0.8cqw] text-[1.15cqw] font-semibold tracking-[0.1em] text-verified">
              <CheckCircle size="2cqw" strokeWidth={1.8} />
              VERIFIED
            </p>
            <div className="mt-[1.3cqw]">
              <Meta>Source:&nbsp; Laptop-001</Meta>
              <Meta>Captured:&nbsp; Oct 14, 2024 22:31</Meta>
            </div>
          </Card>

          {/* Device */}
          <Card
            style={{ left: "59.6%", top: "6.4%", width: "30.4%", transform: "rotateY(-16deg) rotateX(4deg) rotateZ(-3.2deg)" }}
            className="overflow-hidden"
          >
            <div className="flex items-start gap-[1.8cqw]">
              <Laptop size="3.8cqw" strokeWidth={1.4} className="mt-[0.4cqw] text-trace-soft" />
              <div>
                <Label>DEVICE</Label>
                <p className="mt-[1cqw] text-[1.75cqw] font-medium text-white">Laptop-001</p>
                <p className="mt-[0.8cqw] text-[1.32cqw] text-soft/85">Windows 11</p>
                <p className="mt-[0.7cqw] text-[1.2cqw] text-soft/75">5 related events</p>
              </div>
            </div>
            <LaptopWireframe className="absolute right-[1.2cqw] bottom-[1.2cqw] w-[14cqw] text-trace-soft/80" />
          </Card>

          {/* Event */}
          <Card style={{ left: "0.8%", top: "60.4%", width: "25.2%", transform: "rotateY(10deg) rotateZ(0.6deg)" }}>
            <div className="flex items-center gap-[1.8cqw]">
              <EventBox size="3cqw" className="text-trace-soft" />
              <Label>EVENT</Label>
            </div>
            <p className="mt-[1.6cqw] text-[1.75cqw] font-medium text-white">Message sent</p>
            <div className="mt-[0.6cqw]">
              <Meta>Oct 14, 2024 22:15</Meta>
              <Meta>Source:&nbsp; WhatsApp</Meta>
              <Meta>From:&nbsp; +91 98765 43210</Meta>
              <Meta>To:&nbsp; +91 91234 56789</Meta>
            </div>
          </Card>

          {/* Finding */}
          <Card
            tone="alert"
            style={{ left: "63.4%", top: "59.4%", width: "29.4%", transform: "rotateY(-9deg) rotateZ(-0.4deg)" }}
          >
            <div className="flex items-start gap-[1.6cqw]">
              <AlertTriangle size="4cqw" strokeWidth={1.7} className="text-alert drop-shadow-[0_0_0.8cqw_rgba(239,43,60,0.8)]" />
              <div className="pt-[0.3cqw]">
                <Label>FINDING</Label>
                <p className="mt-[1cqw] text-[1.22cqw] font-semibold tracking-[0.04em] text-alert-soft">
                  CONTRADICTION <span className="text-alert-soft/70">·</span> REVIEW
                </p>
              </div>
            </div>
            <p className="mt-[1.6cqw] text-[1.42cqw] leading-[1.6] text-soft/90">
              Message claims user was at home, but device shows office Wi-Fi connection at the same time.
            </p>
            <Link
              to="/app"
              tabIndex={-1}
              className="pointer-events-auto mt-[1.4cqw] inline-flex items-center gap-[0.8cqw] text-[1.38cqw] text-trace-soft hover:text-white"
            >
              View related evidence
              <ArrowRight size="1.6cqw" />
            </Link>
          </Card>

          {/* Hubs sit on the card edges, above the cards. */}
          <Hub point={HUBS.file} tone="trace">
            <Crosshair />
          </Hub>
          <Hub point={HUBS.device} tone="trace">
            <Monitor size="2.6cqw" />
          </Hub>
          <Hub point={HUBS.event} tone="trace">
            <ChatBubble size="2.7cqw" />
          </Hub>
          <Hub point={HUBS.finding} tone="alert">
            <AlertTriangle size="2.8cqw" strokeWidth={1.8} />
          </Hub>
        </div>
      </div>
    </div>
  );
}
