// Role 4: per-row actions menu. Only actions the client can honour without new endpoints.
import { useEffect, useRef, useState } from "react";
import { MoreVertical } from "../../../components/console/icons";
import { useCopy } from "../hooks";
import type { EvidenceItem } from "../../../api/types";

export default function RowMenu({ item, onOpen }: { item: EvidenceItem; onOpen: () => void }) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const { copied, copy } = useCopy(1200);

  useEffect(() => {
    if (!open) return undefined;
    const onPointer = (e: PointerEvent) => {
      if (!root.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("pointerdown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const items = [
    { key: "open", label: "View details", run: () => onOpen() },
    { key: "hash", label: copied === "hash" ? "SHA-256 copied" : "Copy SHA-256", run: () => copy(item.sha256, "hash") },
    { key: "id", label: copied === "id" ? "Evidence ID copied" : "Copy evidence ID", run: () => copy(item.evidence_id, "id") }
  ];

  return (
    <div ref={root} className="relative inline-block" onClick={e => e.stopPropagation()} onKeyDown={e => e.stopPropagation()}>
      <button
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`Actions for ${item.evidence_id}`}
        onClick={() => setOpen(v => !v)}
        className="inline-flex size-8 items-center justify-center rounded-md text-soft/80 transition hover:bg-white/[0.06] hover:text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-trace"
      >
        <MoreVertical size={18} />
      </button>
      {open && (
        <ul
          role="menu"
          className="absolute top-full right-0 z-20 mt-1 w-48 overflow-hidden rounded-lg border border-white/10 bg-[#0b1020] py-1 text-left shadow-[0_12px_32px_rgba(0,0,0,0.5)]"
        >
          {items.map(entry => (
            <li key={entry.key} role="none">
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  void entry.run();
                  if (entry.key === "open") setOpen(false);
                }}
                className="block w-full px-3.5 py-2 text-left text-[13.5px] text-soft hover:bg-white/[0.06] hover:text-white focus-visible:bg-white/[0.06] focus-visible:outline-none"
              >
                {entry.label}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
