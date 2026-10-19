// Role 4: short explanation of what the vault records. It describes the mechanism and claims nothing it can't back:
// no "tamper-proof", no verification status (the API has none yet).
import { Custody, Hash } from "../../../components/console/icons";

export default function IntegrityStrip() {
  return (
    <section
      aria-label="How evidence is recorded"
      className="relative mt-6 grid overflow-hidden rounded-xl border border-trace/25 bg-[linear-gradient(90deg,rgba(14,24,46,0.8),rgba(8,12,22,0.75)_55%,rgba(30,10,18,0.55))] shadow-[0_0_30px_-16px_rgba(59,140,255,0.6)] md:grid-cols-2"
    >
      <span aria-hidden="true" className="absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-trace-soft/70 to-transparent" />
      <div className="flex items-start gap-4 px-5 py-4">
        <span className="flex size-11 shrink-0 items-center justify-center rounded-xl border border-trace/40 bg-trace/10 text-trace-soft shadow-[0_0_16px_rgba(59,140,255,0.35)]">
          <Hash size={20} />
        </span>
        <div>
          <p className="text-[14.5px] font-semibold text-white">Hashed at intake</p>
          <p className="mt-0.5 text-[13px] leading-relaxed text-soft/75">
            Each file gets a SHA-256 when it is uploaded. Re-hash the original and compare to spot any change.
          </p>
        </div>
      </div>
      <div className="flex items-start gap-4 border-t border-white/[0.06] px-5 py-4 md:border-t-0 md:border-l">
        <span className="flex size-11 shrink-0 items-center justify-center rounded-xl border border-alert/40 bg-alert/10 text-alert shadow-[0_0_16px_rgba(239,43,60,0.3)]">
          <Custody size={20} />
        </span>
        <div>
          <p className="text-[14.5px] font-semibold text-white">Chain of custody</p>
          <p className="mt-0.5 text-[13px] leading-relaxed text-soft/75">
            Who handled each item and when, as recorded by the backend. Open an item to see its entries in order.
          </p>
        </div>
      </div>
    </section>
  );
}
