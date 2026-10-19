// Role 4: Evidence Vault. Lists a case's evidence with hashes and custody, uploads new files, and opens a
// detail panel per item. Data comes from an EvidenceSource: the live API by default, or labelled demo data.
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import ConsoleShell, { GUTTER } from "../components/console/ConsoleShell";
import { Alert, Database, Filter, Home, Refresh, Upload } from "../components/console/icons";
import { useSourceLink } from "../components/console/useSourceLink";
import type { EvidenceUploadResult } from "../api/types";
import { API_URL } from "../api/client";
import EvidenceDetailDrawer, { type LocalHashCheck } from "../features/vault/components/EvidenceDetailDrawer";
import EvidenceTable, { type SortKey, type SortState } from "../features/vault/components/EvidenceTable";
import Pagination from "../features/vault/components/Pagination";
import SummaryCards, { type VaultCounts } from "../features/vault/components/SummaryCards";
import UploadEvidenceModal from "../features/vault/components/UploadEvidenceModal";
import VaultToolbar, { type VaultFilters } from "../features/vault/components/VaultToolbar";
import IntegrityStrip from "../features/vault/components/IntegrityStrip";
import NetworkBackdrop from "../features/dashboard/components/NetworkBackdrop";
import { Eyebrow, PANEL } from "../features/vault/components/ui";
import { DEFAULT_CASE_ID, getEvidenceSource, resolveSourceKind } from "../features/vault/evidenceSource";
import { useCopy, useEvidenceList } from "../features/vault/hooks";
import { fileKind, isParsedKind, matchesQuery, type FileKind } from "../features/vault/model";

const PAGE_SIZE = 8;
const EMPTY_FILTERS: VaultFilters = { query: "", kind: "all", support: "all" };

function StateMessage({ icon, title, body, children }: { icon: ReactNode; title: string; body: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center px-6 py-16 text-center">
      <span className="flex size-14 items-center justify-center rounded-xl border border-white/10 bg-white/[0.03] text-soft/80">{icon}</span>
      <p className="mt-4 text-[16px] font-semibold">{title}</p>
      <p className="mt-1.5 max-w-md text-[14px] text-soft/75">{body}</p>
      {children && <div className="mt-5 flex flex-wrap justify-center gap-2.5">{children}</div>}
    </div>
  );
}

const secondaryButton =
  "inline-flex items-center gap-2 rounded-lg border border-white/12 px-4 py-2.5 text-[14px] text-soft transition hover:border-white/25 hover:text-white";
const primaryButton =
  "inline-flex items-center gap-2 rounded-lg bg-alert px-4 py-2.5 text-[14px] font-medium text-white shadow-[0_0_22px_rgba(239,43,60,0.3)] transition hover:bg-[#ff3a4a]";

export default function EvidenceVault() {
  const { caseId = DEFAULT_CASE_ID } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const sourceKind = resolveSourceKind(searchParams.get("source"));
  const toPath = useSourceLink();
  const source = useMemo(() => getEvidenceSource(sourceKind), [sourceKind]);
  const { state, reload } = useEvidenceList(source, caseId);

  const [filters, setFilters] = useState<VaultFilters>(EMPTY_FILTERS);
  const [sort, setSort] = useState<SortState>({ key: "intake_time", dir: "desc" });
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  // The open drawer lives in ?open= so refresh, back/forward and deep links all agree with what's on screen.
  const activeId = searchParams.get("open");
  const setActiveId = (id: string | null) =>
    setSearchParams(
      prev => {
        const next = new URLSearchParams(prev);
        if (id) next.set("open", id);
        else next.delete("open");
        return next;
      },
      { replace: true }
    );
  const [uploadOpen, setUploadOpen] = useState(false);
  const [localChecks, setLocalChecks] = useState<Map<string, LocalHashCheck>>(new Map());
  const { copied, copy } = useCopy();

  const items = useMemo(() => (state.status === "ready" ? state.items : []), [state]);

  const counts: VaultCounts | null =
    state.status === "ready"
      ? {
          total: items.length,
          custodyEntries: items.reduce((sum, item) => sum + item.custody.length, 0),
          notParsed: items.filter(item => !isParsedKind(fileKind(item.filename))).length
        }
      : null;

  const kinds = useMemo(() => [...new Set(items.map(item => fileKind(item.filename)))].sort() as FileKind[], [items]);

  const visible = useMemo(() => {
    const filtered = items.filter(item => {
      const kind = fileKind(item.filename);
      if (filters.kind !== "all" && kind !== filters.kind) return false;
      if (filters.support === "parsed" && !isParsedKind(kind)) return false;
      if (filters.support === "unparsed" && isParsedKind(kind)) return false;
      return matchesQuery(item, filters.query);
    });
    const dir = sort.dir === "asc" ? 1 : -1;
    return filtered.sort((a, b) => {
      if (sort.key === "intake_time") return (Date.parse(a.intake_time) - Date.parse(b.intake_time)) * dir || a.evidence_id.localeCompare(b.evidence_id);
      return a.evidence_id.localeCompare(b.evidence_id, undefined, { numeric: true }) * dir;
    });
  }, [items, filters, sort]);

  const pages = Math.max(1, Math.ceil(visible.length / PAGE_SIZE));
  const current = Math.min(page, pages);
  const pageRows = visible.slice((current - 1) * PAGE_SIZE, current * PAGE_SIZE);
  const active = activeId ? items.find(item => item.evidence_id === activeId) ?? null : null;

  useEffect(() => setPage(1), [filters]);

  useEffect(() => {
    if (!active) return undefined;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && !uploadOpen && setActiveId(null);
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [active, uploadOpen]);

  const onSort = (key: SortKey) =>
    setSort(prev => (prev.key === key ? { key, dir: prev.dir === "asc" ? "desc" : "asc" } : { key, dir: key === "intake_time" ? "desc" : "asc" }));

  const toggle = (id: string) =>
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const toggleAll = (ids: string[], checked: boolean) =>
    setSelected(prev => {
      const next = new Set(prev);
      ids.forEach(id => (checked ? next.add(id) : next.delete(id)));
      return next;
    });

  const onUploaded = useCallback(
    (result: EvidenceUploadResult, localHash: string | null) => {
      if (localHash) {
        setLocalChecks(prev => new Map(prev).set(result.evidence_id, { localHash, matches: localHash === result.sha256 }));
      }
      reload();
    },
    [reload]
  );

  const selectedItems = items.filter(item => selected.has(item.evidence_id));
  const filtersActive = filters.query !== "" || filters.kind !== "all" || filters.support !== "all";

  const switchSource = (kind: "api" | "demo") => {
    const next = new URLSearchParams(searchParams);
    if (kind === "demo") next.set("source", "demo");
    else next.delete("source");
    next.delete("open");
    setSearchParams(next);
    setSelected(new Set());
  };

  return (
    <ConsoleShell>
      <div className={`mx-auto max-w-[1680px] pt-5 pb-14 ${GUTTER}`}>
        <nav aria-label="Breadcrumb" className="text-[13.5px] text-soft/80">
          <ol className="flex flex-wrap items-center gap-2">
            <li>
              <Link to="/" className="inline-flex hover:text-white" aria-label="Home">
                <Home size={16} />
              </Link>
            </li>
            <li aria-hidden="true">/</li>
            <li>
              <Link to={toPath("/app")} className="hover:text-white">
                Investigation <span className="text-white">{caseId}</span>
              </Link>
            </li>
            <li aria-hidden="true">/</li>
            <li aria-current="page" className="text-white">
              Evidence Vault
            </li>
          </ol>
        </nav>

        {sourceKind === "demo" && (
          <div className="mt-4 flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border border-amber-300/25 bg-amber-300/[0.06] px-4 py-2.5 text-[13px] text-amber-100/90">
            <Database size={16} className="text-amber-300" />
            <span>
              <strong className="font-semibold">Demo data.</strong> Synthetic records for UI development; none of it came from the backend.
            </span>
            <button type="button" onClick={() => switchSource("api")} className="ml-auto text-amber-200 underline-offset-4 hover:underline">
              Use live API
            </button>
          </div>
        )}

        <div className={`mt-6 grid gap-6 ${active ? "xl:grid-cols-[minmax(0,1fr)_400px]" : ""}`}>
          <div className="relative min-w-0">
            <div aria-hidden="true" className="pointer-events-none absolute inset-0">
              <div className="absolute top-[30%] left-[-4%] h-[360px] w-[45%] rounded-full bg-trace/[0.08] blur-[100px]" />
              <div className="absolute top-[45%] right-[-2%] h-[320px] w-[35%] rounded-full bg-alert/[0.06] blur-[100px]" />
            </div>
            <header className="relative flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
              {/* Red/blue particle network behind the hero, kept clear of the heading. */}
              <div
                aria-hidden="true"
                className="pointer-events-none absolute inset-y-[-60%] right-[-8%] left-[35%] hidden lg:block [mask-image:radial-gradient(ellipse_70%_70%_at_55%_45%,#000_30%,transparent_80%)]"
              >
                <NetworkBackdrop className="opacity-70" />
              </div>
              <div className="relative [text-shadow:0_2px_18px_rgba(5,7,12,0.9)]">
                <Eyebrow>
                  EVIDENCE VAULT <span className="ml-1.5 inline-block size-[5px] -translate-y-0.5 rounded-full bg-alert align-middle" />
                </Eyebrow>
                <h1 className="mt-3 text-[clamp(2.3rem,4vw,3.75rem)] leading-[1.04] font-bold tracking-[-0.025em]">
                  Secure. <span className="text-alert drop-shadow-[0_0_20px_rgba(239,43,60,0.45)]">Verify.</span> Trace.
                </h1>
                <p className="mt-3.5 max-w-[560px] text-[16.5px] leading-relaxed text-soft/85">
                  Every file is hashed at intake and carries its chain of custody, so each finding can be traced back to the original bytes.
                </p>
              </div>
              <div className="relative w-full lg:w-[460px] xl:w-[500px]">
                <SummaryCards counts={state.status === "error" ? null : counts} />
              </div>
            </header>

            <div className="mt-7 flex flex-col gap-2.5 sm:flex-row sm:items-start">
              <div className="min-w-0 flex-1">
                <VaultToolbar filters={filters} kinds={kinds} onChange={setFilters} />
              </div>
              <button type="button" onClick={() => setUploadOpen(true)} className={`${primaryButton} h-11 justify-center`}>
                <Upload size={17} />
                Upload evidence
              </button>
            </div>

            <section aria-label="Evidence list" className={`relative mt-4 overflow-hidden ${PANEL}`}>
              <span aria-hidden="true" className="pointer-events-none absolute inset-x-10 top-0 z-10 h-px bg-gradient-to-r from-transparent via-trace-soft/60 to-transparent" />
              {selected.size > 0 && (
                <div className="flex flex-wrap items-center gap-3 border-b border-white/[0.07] bg-trace/[0.06] px-4 py-2.5 text-[13.5px] sm:px-5">
                  <span>
                    {selected.size} selected
                  </span>
                  <button
                    type="button"
                    onClick={() => copy(selectedItems.map(i => `${i.evidence_id}  ${i.filename}  ${i.sha256}`).join("\n"), "selection")}
                    className="text-trace-soft hover:text-white"
                  >
                    {copied === "selection" ? "Copied" : "Copy IDs and hashes"}
                  </button>
                  <button type="button" onClick={() => setSelected(new Set())} className="ml-auto text-soft/75 hover:text-white">
                    Clear selection
                  </button>
                </div>
              )}

              {state.status === "error" ? (
                <StateMessage icon={<Alert size={26} className="text-alert" />} title="Couldn't load evidence" body={state.message}>
                  <button type="button" onClick={reload} className={secondaryButton}>
                    <Refresh size={16} />
                    Retry
                  </button>
                  {sourceKind === "api" && (
                    <button type="button" onClick={() => switchSource("demo")} className={secondaryButton}>
                      <Database size={16} />
                      Open demo data
                    </button>
                  )}
                </StateMessage>
              ) : state.status === "ready" && items.length === 0 ? (
                <StateMessage
                  icon={<Upload size={26} />}
                  title="No evidence in this case yet"
                  body={`Upload the first file to ${caseId}. It is hashed on intake and gets an evidence ID.`}
                >
                  <button type="button" onClick={() => setUploadOpen(true)} className={primaryButton}>
                    <Upload size={16} />
                    Upload evidence
                  </button>
                </StateMessage>
              ) : state.status === "ready" && visible.length === 0 ? (
                <StateMessage icon={<Filter size={26} />} title="No evidence matches" body="Try a different search or clear the filters.">
                  <button type="button" onClick={() => setFilters(EMPTY_FILTERS)} className={secondaryButton}>
                    Clear filters
                  </button>
                </StateMessage>
              ) : (
                <>
                  <EvidenceTable
                    rows={pageRows}
                    loading={state.status === "loading"}
                    selected={selected}
                    activeId={activeId}
                    sort={sort}
                    onSort={onSort}
                    onToggle={toggle}
                    onToggleAll={toggleAll}
                    onOpen={setActiveId}
                  />
                  {state.status === "ready" && (
                    <div className="border-t border-white/[0.06]">
                      <Pagination
                        page={current}
                        pages={pages}
                        from={(current - 1) * PAGE_SIZE + 1}
                        to={Math.min(current * PAGE_SIZE, visible.length)}
                        total={visible.length}
                        onPage={setPage}
                      />
                    </div>
                  )}
                </>
              )}
            </section>

            <p className="mt-4 flex flex-wrap items-center gap-x-2 text-[12.5px] text-muted">
              <span>
                {sourceKind === "api" ? `Live API · ${API_URL} · case ${caseId}` : `Demo data · case ${caseId}`}
              </span>
              {filtersActive && state.status === "ready" && <span>· {visible.length} of {items.length} shown</span>}
              {sourceKind === "api" && state.status !== "error" && (
                <button type="button" onClick={() => switchSource("demo")} className="text-soft/70 underline-offset-4 hover:text-white hover:underline">
                  · Open demo data
                </button>
              )}
            </p>

            <IntegrityStrip />
          </div>

          {active && (
            <>
              <div className="fixed inset-0 z-40 bg-black/60 xl:hidden" onClick={() => setActiveId(null)} aria-hidden="true" />
              <div className="fixed inset-y-0 right-0 z-40 w-full max-w-[440px] xl:sticky xl:top-5 xl:z-auto xl:h-[calc(100vh-108px)] xl:max-w-none">
                <EvidenceDetailDrawer
                  item={active}
                  isDemo={sourceKind === "demo"}
                  localCheck={localChecks.get(active.evidence_id)}
                  onClose={() => setActiveId(null)}
                />
              </div>
            </>
          )}
        </div>
      </div>

      {uploadOpen && (
        <UploadEvidenceModal
          source={source}
          caseId={caseId}
          onClose={() => setUploadOpen(false)}
          onUploaded={onUploaded}
          onOpenItem={id => {
            setUploadOpen(false);
            setActiveId(id);
          }}
        />
      )}
    </ConsoleShell>
  );
}
