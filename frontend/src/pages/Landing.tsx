// Role 4: public landing page. Static marketing content with synthetic sample data; it calls no API.
import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import EvidenceNetwork from "../components/landing/EvidenceNetwork";
import {
  ArrowRight,
  FileText,
  Flag,
  Folder,
  Layers,
  LinkChain,
  LogoMark,
  Menu,
  NetworkNodes,
  PlayCircle,
  ShieldCheck
} from "../components/landing/icons";

const NAV = [
  { label: "Home", href: "#top" },
  { label: "How It Works", href: "#how-it-works" },
  { label: "Features", href: "#features" },
  { label: "Use Cases", href: "#timeline" },
  { label: "About", href: "#pipeline" }
];

const FEATURES = [
  { icon: Layers, label: ["Multi-source", "Evidence Analysis"] },
  { icon: NetworkNodes, label: ["Contradiction", "Detection"] },
  { icon: LinkChain, label: ["Claim-level", "Source Tracing"] },
  { icon: FileText, label: ["Report Aligned", "with Section 63 BSA"] }
];

const TIMELINE = [
  { time: "10:12 PM", label: "Message Sent" },
  { time: "10:15 PM", label: "Location Match" },
  { time: "10:18 PM", label: "File Accessed" },
  { time: "10:21 PM", label: "Contradiction Detected", alert: true }
];

const PIPELINE = ["EVIDENCE", "EVENTS", "FINDINGS", "TRUTH"];

const STEPS = [
  { icon: Folder, title: "Ingest Evidence", body: "Upload extracted data with cryptographic hashing." },
  { icon: NetworkNodes, title: "Analyze & Correlate", body: "Build connections, detect contradictions, surface findings." },
  { icon: FileText, title: "Trace to Source", body: "Explore the full lineage from finding to original file." },
  { icon: ShieldCheck, title: "Generate Report", body: "Create an investigation report aligned with Section 63 BSA." }
];

const GUTTER = "px-4 sm:px-8 lg:px-[clamp(2rem,5.4vw,5.5rem)]";

function Nav() {
  const [open, setOpen] = useState(false);
  return (
    <header className="relative z-20 border-b border-white/[0.07]">
      <nav className={`mx-auto flex h-[76px] max-w-[1600px] items-center justify-between lg:h-[90px] ${GUTTER}`}>
        <a href="#top" className="flex items-center gap-3 text-white sm:gap-5" aria-label="PRAMANA home">
          <LogoMark className="size-8 sm:size-10" />
          <span className="text-[15px] font-medium tracking-[0.32em] sm:text-[22px] sm:tracking-[0.5em]">PRAMANA</span>
        </a>

        <ul className="mr-auto ml-[clamp(2rem,9.6vw,9.8rem)] hidden items-stretch gap-[clamp(1.5rem,3.2vw,3.2rem)] self-stretch lg:flex">
          {NAV.map((item, i) => (
            <li key={item.label} className="flex">
              <a
                href={item.href}
                aria-current={i === 0 ? "page" : undefined}
                className={`relative flex items-center text-[15px] transition-colors ${
                  i === 0
                    ? "text-alert-soft after:absolute after:inset-x-0 after:bottom-[-1px] after:h-[2px] after:bg-alert after:shadow-[0_0_10px_rgba(239,43,60,0.9)]"
                    : "text-soft hover:text-white"
                }`}
              >
                {item.label}
              </a>
            </li>
          ))}
        </ul>

        <div className="flex items-center gap-1 sm:gap-3">
          <Link
            to="/app"
            className="group inline-flex items-center gap-3 rounded-md border border-alert/80 bg-alert/[0.04] px-3 py-2 text-[13px] text-white shadow-[0_0_24px_rgba(239,43,60,0.18)] transition hover:bg-alert/15 sm:px-6 sm:py-3 sm:text-[17px]"
          >
            <span className="hidden sm:inline">Launch Investigation</span>
            <span className="sm:hidden">Launch</span>
            <ArrowRight size={18} className="transition-transform group-hover:translate-x-0.5" />
          </Link>
          <button
            type="button"
            className="rounded-md p-2 text-soft hover:text-white lg:hidden"
            aria-label="Menu"
            aria-expanded={open}
            onClick={() => setOpen(v => !v)}
          >
            <Menu size={24} />
          </button>
        </div>
      </nav>
      {open && (
        <ul className={`border-t border-white/[0.07] bg-ink/95 py-3 lg:hidden ${GUTTER}`}>
          {NAV.map(item => (
            <li key={item.label}>
              <a href={item.href} onClick={() => setOpen(false)} className="block py-2.5 text-soft hover:text-white">
                {item.label}
              </a>
            </li>
          ))}
        </ul>
      )}
    </header>
  );
}

function Eyebrow({ children }: { children: ReactNode }) {
  return <p className="text-[11px] font-medium tracking-[0.42em] text-soft/80 sm:text-xs">{children}</p>;
}

function Hero() {
  return (
    <section className="relative grid grid-cols-[minmax(0,1fr)] items-start gap-y-10 lg:grid-cols-[minmax(0,43%)_minmax(0,1fr)]">
      <div className="relative z-10 pt-12 lg:pt-[5.4rem]">
        <Eyebrow>
          DIGITAL FORENSICS <span className="mx-2 inline-block size-[5px] -translate-y-0.5 rounded-full bg-alert align-middle" />{" "}
          EVIDENCE TRACEABILITY
        </Eyebrow>
        <h1 className="mt-6 text-[2.4rem] leading-[1.09] font-bold tracking-[-0.025em] sm:text-[3.25rem] lg:mt-7 lg:text-[clamp(2.5rem,4.05vw,4.1rem)] lg:whitespace-nowrap">
          Every finding.
          <br />
          <span className="text-alert">Proven</span> to its source.
        </h1>
        <p className="mt-7 max-w-[33rem] text-[clamp(1.05rem,1.26vw,1.26rem)] leading-[1.45] text-soft/90">
          Verify digital evidence integrity, uncover connections and contradictions, and trace every investigative
          finding back to its original source.
        </p>

        <div className="mt-8 flex flex-wrap items-center gap-x-9 gap-y-5">
          <Link
            to="/app"
            className="group inline-flex items-center gap-3 rounded-md bg-alert px-8 py-4 text-[17px] font-medium text-white shadow-[0_0_34px_rgba(239,43,60,0.45)] transition hover:bg-[#ff3a4a] sm:text-lg"
          >
            Explore Investigation
            <ArrowRight size={18} className="transition-transform group-hover:translate-x-0.5" />
          </Link>
          <a href="#how-it-works" className="group inline-flex items-center gap-4 text-[17px] text-soft hover:text-white">
            <PlayCircle size={30} strokeWidth={1.3} />
            <span className="border-b border-soft/60 pb-0.5 group-hover:border-white">How it works</span>
          </a>
        </div>

        <ul id="features" className="mt-12 grid grid-cols-2 gap-y-6 sm:flex sm:flex-wrap sm:gap-y-4 xl:flex-nowrap lg:mt-[3.2rem]">
          {FEATURES.map(({ icon: Icon, label }, i) => (
            <li
              key={label[0]}
              className={`flex shrink-0 items-center gap-2.5 pr-3.5 text-[11.5px] leading-[1.45] text-soft/90 ${
                i > 0 ? "sm:border-l sm:border-white/10 sm:pl-3.5" : ""
              }`}
            >
              <Icon size={28} strokeWidth={1.3} className="shrink-0 text-alert" />
              <span>
                {label[0]}
                <br />
                {label[1]}
              </span>
            </li>
          ))}
        </ul>
      </div>

      {/* The visual bleeds past the right gutter, like the reference. */}
      <div className="relative -mx-4 sm:-mx-8 lg:mx-0 lg:mt-3 lg:-mr-[clamp(2rem,5.4vw,5.5rem)]">
        <EvidenceNetwork />
      </div>
    </section>
  );
}

function InvestigationTimeline() {
  return (
    <section
      id="timeline"
      className="relative mt-10 flex flex-col gap-10 border-t border-white/[0.06] pt-6 lg:mt-1 lg:flex-row lg:items-center lg:justify-between lg:gap-12"
    >
      <div className="min-w-0 lg:w-[57%]">
        <p className="flex items-center gap-3 text-[11px] font-semibold tracking-[0.36em] text-soft/80">
          <Flag size={14} className="text-alert" />
          INVESTIGATION TIMELINE
        </p>
        <div className="-mx-4 overflow-x-auto px-4 sm:mx-0 sm:px-0">
          <ol className="relative mt-6 flex min-w-[560px] pl-6">
            {/* Track: evidence-blue up to the contradiction, then fading out. */}
            <span className="absolute top-0 left-0 h-8 w-[2px] -translate-y-[45%] bg-alert/90" aria-hidden="true" />
            <span
              className="absolute top-0 right-0 left-0 h-px bg-[linear-gradient(90deg,rgba(59,140,255,0.7)_0%,rgba(59,140,255,0.55)_45%,rgba(239,43,60,0.6)_60%,rgba(255,255,255,0.12)_68%,rgba(255,255,255,0.04)_100%)]"
              aria-hidden="true"
            />
            {TIMELINE.map(item => (
              <li key={item.label} className="relative w-[155px] shrink-0 pt-5 pl-6">
                <span
                  className={`absolute top-0 left-0 size-2.5 -translate-x-1/2 -translate-y-1/2 rounded-full ${
                    item.alert
                      ? "bg-alert shadow-[0_0_0_4px_rgba(239,43,60,0.2),0_0_16px_rgba(239,43,60,0.95)]"
                      : "bg-trace shadow-[0_0_10px_rgba(59,140,255,0.9)]"
                  }`}
                  aria-hidden="true"
                />
                <span
                  className={`absolute top-0 left-0 h-6 w-px ${item.alert ? "bg-alert/50" : "bg-trace/40"}`}
                  aria-hidden="true"
                />
                <p className="text-[13.5px] whitespace-nowrap text-white/90 tabular-nums">{item.time}</p>
                <p className="mt-1 text-[13.5px] whitespace-nowrap text-soft/80">{item.label}</p>
              </li>
            ))}
          </ol>
        </div>
      </div>

      <div id="pipeline" className="relative self-start px-7 py-6 lg:mr-[2%] lg:self-center">
        <span className="absolute inset-y-0 left-0 w-2.5 border-y border-l border-alert/80" aria-hidden="true" />
        <span className="absolute inset-y-0 right-0 w-2.5 border-y border-r border-alert/80" aria-hidden="true" />
        <ol className="flex flex-wrap items-center gap-x-4 gap-y-2 text-[10.5px] font-medium tracking-[0.3em] text-soft/75 sm:gap-x-5">
          {PIPELINE.map((step, i) => (
            <li key={step} className="flex items-center gap-4 sm:gap-5">
              <span className={i === PIPELINE.length - 1 ? "text-white" : ""}>{step}</span>
              {i < PIPELINE.length - 1 && <ArrowRight size={12} className="text-soft/60" />}
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}

function Workflow() {
  return (
    <section id="how-it-works" className="mt-12 border-t border-white/[0.06] lg:mt-11">
      <h2 className="sr-only">How it works</h2>
      <ol className="grid sm:grid-cols-2 xl:grid-cols-4">
        {STEPS.map(({ icon: Icon, title, body }, i) => (
          <li
            key={title}
            className={`flex items-start gap-6 py-7 sm:px-6 xl:px-0 ${
              i > 0 ? "border-t border-white/[0.06] sm:border-t-0" : ""
            } ${i % 2 === 1 ? "sm:border-l sm:border-white/[0.06]" : ""} ${
              i > 0 ? "xl:border-l xl:border-white/[0.06] xl:pl-[clamp(1.5rem,2.6vw,2.6rem)]" : "xl:pl-0"
            }`}
          >
            <span className="flex size-[66px] shrink-0 items-center justify-center rounded-lg border border-white/[0.07] bg-white/[0.02] text-alert shadow-[inset_0_0_18px_rgba(239,43,60,0.06)]">
              <Icon size={34} strokeWidth={1.3} />
            </span>
            <div className="pt-1">
              <h3 className="text-[15px] font-semibold text-white">{title}</h3>
              <p className="mt-2 max-w-[17rem] text-[14px] leading-[1.5] text-soft/75">{body}</p>
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}

export default function Landing() {
  return (
    <div id="top" className="relative min-h-screen overflow-x-clip bg-ink text-white">
      {/* Backdrop: faint dot grid, vignette and edge ticks from the reference. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 bg-[radial-gradient(rgba(255,255,255,0.05)_1px,transparent_1px)] [background-size:26px_26px] [mask-image:radial-gradient(ellipse_80%_70%_at_50%_40%,#000_30%,transparent_85%)]"
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute top-24 left-3 hidden h-[60%] w-px bg-[repeating-linear-gradient(180deg,rgba(239,43,60,0.55)_0_6px,transparent_6px_64px)] lg:block"
      />

      <Nav />
      <main className={`relative mx-auto max-w-[1600px] pb-4 ${GUTTER}`}>
        <Hero />
        <InvestigationTimeline />
        <Workflow />
      </main>
    </div>
  );
}
