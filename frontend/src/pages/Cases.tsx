// Role 3: case dashboard. Lists every case from GET /cases, creates new ones (POST /cases) and opens a case,
// which makes it the active case for the Dashboard, Evidence Vault and Investigation Workspace.
import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import ConsoleShell, { GUTTER } from "../components/console/ConsoleShell";
import { Alert, ArrowRight, Close, Folder, Refresh, Search } from "../components/console/icons";
import { ApiError, API_URL, closeCase, createCase, listCases, reopenCase } from "../api/client";
import type { CaseStatus, CaseSummary } from "../api/types";
import { rememberCase, rememberedCase } from "../features/cases/activeCase";
import { Eyebrow, PANEL } from "../features/vault/components/ui";
import { Stamp } from "../lib/time";

const primaryButton =
  "inline-flex items-center gap-2 rounded-lg bg-alert px-4 py-2.5 text-[14px] font-medium text-white shadow-[0_0_22px_rgba(239,43,60,0.3)] transition hover:bg-[#ff3a4a] disabled:cursor-not-allowed disabled:opacity-50";
const secondaryButton =
  "inline-flex items-center gap-2 rounded-lg border border-white/12 px-3 py-2 text-[13px] text-soft transition hover:border-white/25 hover:text-white disabled:cursor-not-allowed disabled:opacity-50";
const input =
  "w-full rounded-lg border border-white/10 bg-black/20 px-3 py-2 text-[14px] text-white placeholder:text-soft/40 focus:border-trace/50 focus:outline-none";
const label = "mb-1.5 block text-[12.5px] text-soft/75";

const STATUS_STYLE: Partial<Record<CaseStatus, string>> = {
  OPEN: "border-teal-400/40 bg-teal-400/[0.1] text-teal-200",
  REOPENED: "border-amber-300/40 bg-amber-300/[0.08] text-amber-100",
  CLOSED: "border-white/15 bg-white/[0.04] text-soft/70"
};

function StatusBadge({ status }: { status: CaseStatus }) {
  return (
    <span className={`inline-flex rounded-full border px-2.5 py-0.5 text-[11px] font-semibold tracking-[0.08em] ${STATUS_STYLE[status] ?? "border-trace/40 bg-trace/[0.1] text-trace-soft"}`}>
      {status.replace(/_/g, " ")}
    </span>
  );
}

type ListState = { status: "loading" } | { status: "error"; message: string } | { status: "ready"; cases: CaseSummary[] };

const errorText = (error: unknown) => (error instanceof ApiError || error instanceof Error ? error.message : "Something went wrong.");

function CreateCaseForm({ onCreated, onCancel }: { onCreated: (created: CaseSummary) => void; onCancel: () => void }) {
  const [form, setForm] = useState({ name: "", case_id: "", owner: "", scope: "", description: "", tags: "" });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const set = (key: keyof typeof form) => (event: { target: { value: string } }) => setForm(f => ({ ...f, [key]: event.target.value }));

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!form.name.trim()) {
      setError("A case title is required.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const created = await createCase({
        name: form.name.trim(),
        case_id: form.case_id.trim() || undefined,
        owner: form.owner.trim() || undefined,
        scope: form.scope.trim() || undefined,
        description: form.description.trim() || undefined,
        tags: form.tags.split(",").map(t => t.trim()).filter(Boolean)
      });
      onCreated(created);
    } catch (err) {
      setError(errorText(err));
      setSaving(false);
    }
  }

  return (
    <form onSubmit={submit} aria-label="Create case" className={`${PANEL} relative p-5 sm:p-6`}>
      <div className="flex items-center gap-3">
        <h2 className="text-[17px] font-semibold">New case</h2>
        <button type="button" onClick={onCancel} className="ml-auto rounded-md p-1.5 text-soft hover:text-white" aria-label="Cancel new case">
          <Close size={18} />
        </button>
      </div>
      <p className="mt-1 text-[13px] text-muted">The case gets its ID before any evidence is uploaded, and every upload is scoped to it.</p>

      <div className="mt-5 grid gap-4 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <label className={label} htmlFor="case-name">Title *</label>
          <input id="case-name" className={input} value={form.name} onChange={set("name")} maxLength={255} placeholder="e.g. Laptop data exfiltration" required autoFocus />
        </div>
        <div>
          <label className={label} htmlFor="case-owner">Investigator (self-declared)</label>
          <input id="case-owner" className={input} value={form.owner} onChange={set("owner")} maxLength={255} placeholder="Name of lead investigator" />
        </div>
        <div>
          <label className={label} htmlFor="case-id">Case ID (optional)</label>
          <input id="case-id" className={`${input} font-mono`} value={form.case_id} onChange={set("case_id")} maxLength={64} pattern="[A-Za-z0-9][A-Za-z0-9_.\-]*" title="Letters, digits, dot, dash or underscore" placeholder="Generated if left blank" />
        </div>
        <div className="sm:col-span-2">
          <label className={label} htmlFor="case-scope">Scope</label>
          <input id="case-scope" className={input} value={form.scope} onChange={set("scope")} maxLength={4000} placeholder="Devices, accounts and time window covered" />
        </div>
        <div className="sm:col-span-2">
          <label className={label} htmlFor="case-description">Description</label>
          <textarea id="case-description" className={`${input} min-h-20 resize-y`} value={form.description} onChange={set("description")} maxLength={4000} />
        </div>
        <div className="sm:col-span-2">
          <label className={label} htmlFor="case-tags">Tags</label>
          <input id="case-tags" className={input} value={form.tags} onChange={set("tags")} placeholder="Comma separated, e.g. insider, exfiltration" />
        </div>
      </div>

      {error && (
        <p role="alert" className="mt-4 flex items-start gap-2 rounded-lg border border-alert/35 bg-alert/[0.07] px-3 py-2.5 text-[13px] text-soft">
          <Alert size={16} className="mt-0.5 shrink-0 text-alert" />
          {error}
        </p>
      )}

      <div className="mt-5 flex flex-wrap gap-3">
        <button type="submit" className={primaryButton} disabled={saving}>
          {saving ? "Creating…" : "Create case"}
        </button>
        <button type="button" className={secondaryButton} onClick={onCancel} disabled={saving}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function CaseRow({ item, active, onOpen, onToggleClosed, busy }: { item: CaseSummary; active: boolean; onOpen: () => void; onToggleClosed: () => void; busy: boolean }) {
  const closed = item.status === "CLOSED";
  return (
    <li className={`${PANEL} flex flex-col gap-4 p-5 lg:flex-row lg:items-center ${active ? "border-alert/45" : ""}`}>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
          <Folder size={18} className="text-soft" />
          <h3 className="min-w-0 truncate text-[16.5px] font-semibold">{item.name}</h3>
          <StatusBadge status={item.status} />
          {active && <span className="text-[11.5px] font-semibold tracking-[0.08em] text-alert uppercase">Active</span>}
        </div>
        <p className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[12.5px] text-muted">
          <span className="font-mono text-soft/80">{item.case_id}</span>
          <span>Owner: {item.owner ?? <span className="text-soft/50">not set</span>}</span>
          <span>
            Created <Stamp iso={item.created_at} />
          </span>
        </p>
        {item.scope && <p className="mt-2 line-clamp-2 text-[13px] text-soft/80">{item.scope}</p>}
        {item.tags.length > 0 && (
          <ul className="mt-2.5 flex flex-wrap gap-1.5" aria-label="Tags">
            {item.tags.map(tag => (
              <li key={tag} className="rounded-md border border-trace/30 bg-trace/[0.08] px-2 py-0.5 text-[11.5px] text-trace-soft">
                {tag}
              </li>
            ))}
          </ul>
        )}
      </div>

      <dl className="grid grid-cols-3 gap-5 text-center lg:w-72">
        {[
          ["Evidence", item.evidence_count],
          ["Findings", item.finding_count],
          ["Runs", item.run_count]
        ].map(([name, value]) => (
          <div key={name}>
            <dd className="text-[22px] font-semibold tabular-nums">{value}</dd>
            <dt className="text-[11.5px] text-muted">{name}</dt>
          </div>
        ))}
      </dl>

      <div className="flex gap-2.5 lg:flex-col lg:items-stretch">
        <button type="button" onClick={onOpen} className={`${primaryButton} justify-center`}>
          Open case
          <ArrowRight size={15} />
        </button>
        <button type="button" onClick={onToggleClosed} className={`${secondaryButton} justify-center`} disabled={busy}>
          {busy ? "Saving…" : closed ? "Reopen" : "Close case"}
        </button>
      </div>
    </li>
  );
}

export default function Cases() {
  const navigate = useNavigate();
  const [state, setState] = useState<ListState>({ status: "loading" });
  const [creating, setCreating] = useState(false);
  const [query, setQuery] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const activeId = rememberedCase();

  const load = useCallback((signal?: AbortSignal) => {
    setState({ status: "loading" });
    listCases(signal)
      .then(cases => setState({ status: "ready", cases }))
      .catch(error => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setState({ status: "error", message: errorText(error) });
      });
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const visible = useMemo(() => {
    if (state.status !== "ready") return [];
    const q = query.trim().toLowerCase();
    if (!q) return state.cases;
    return state.cases.filter(c =>
      [c.case_id, c.name, c.owner ?? "", c.scope ?? "", ...c.tags].some(field => field.toLowerCase().includes(q))
    );
  }, [state, query]);

  const open = (caseId: string) => {
    rememberCase(caseId);
    navigate(`/app?case=${encodeURIComponent(caseId)}`);
  };

  const toggleClosed = async (item: CaseSummary) => {
    setBusyId(item.case_id);
    setActionError(null);
    try {
      const updated = item.status === "CLOSED" ? await reopenCase(item.case_id) : await closeCase(item.case_id);
      setState(s => (s.status === "ready" ? { status: "ready", cases: s.cases.map(c => (c.case_id === updated.case_id ? updated : c)) } : s));
    } catch (error) {
      setActionError(errorText(error));
    } finally {
      setBusyId(null);
    }
  };

  return (
    <ConsoleShell>
      <div className={`mx-auto max-w-[1280px] pt-8 pb-16 ${GUTTER}`}>
        <header className="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <Eyebrow>
              CASES <span className="ml-1.5 inline-block size-1.25 -translate-y-0.5 rounded-full bg-alert align-middle" />
            </Eyebrow>
            <h1 className="mt-3 text-[clamp(2.1rem,3.6vw,3.25rem)] leading-[1.05] font-bold tracking-tight">
              One case. <span className="text-alert drop-shadow-[0_0_20px_rgba(239,43,60,0.45)]">One</span> chain of proof.
            </h1>
            <p className="mt-3 max-w-150 text-[16px] leading-relaxed text-soft/85">
              Create a case before adding evidence. Evidence, findings and analysis runs stay inside the case they were added to.
            </p>
          </div>
          {!creating && (
            <button type="button" className={`${primaryButton} self-start lg:self-auto`} onClick={() => setCreating(true)}>
              + New case
            </button>
          )}
        </header>

        {creating && (
          <div className="mt-7">
            <CreateCaseForm
              onCancel={() => setCreating(false)}
              onCreated={created => {
                setCreating(false);
                setState(s => (s.status === "ready" ? { status: "ready", cases: [created, ...s.cases] } : { status: "ready", cases: [created] }));
                open(created.case_id);
              }}
            />
          </div>
        )}

        <div className="mt-8 flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="relative min-w-0 flex-1">
            <Search size={16} className="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-soft/50" />
            <input
              aria-label="Search cases"
              className={`${input} pl-9`}
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Search by title, ID, owner, scope or tag"
            />
          </div>
          <button type="button" className={secondaryButton} onClick={() => load()}>
            <Refresh size={15} />
            Refresh
          </button>
        </div>

        {actionError && (
          <p role="alert" className="mt-4 flex items-start gap-2 rounded-lg border border-alert/35 bg-alert/[0.07] px-3 py-2.5 text-[13px] text-soft">
            <Alert size={16} className="mt-0.5 shrink-0 text-alert" />
            {actionError}
          </p>
        )}

        <section aria-label="Case list" className="mt-5">
          {state.status === "loading" && (
            <ul className="flex flex-col gap-3" aria-busy="true">
              {[0, 1, 2].map(i => (
                <li key={i} className={`${PANEL} h-28 animate-pulse`} />
              ))}
            </ul>
          )}

          {state.status === "error" && (
            <div className={`${PANEL} p-6`}>
              <p className="flex items-center gap-2 font-semibold">
                <Alert size={18} className="text-alert" />
                Cases could not be loaded
              </p>
              <p className="mt-1.5 text-[13.5px] text-soft/80">{state.message}</p>
              <p className="mt-1 text-[12.5px] text-muted">Backend: {API_URL}</p>
              <button type="button" className={`${secondaryButton} mt-4`} onClick={() => load()}>
                <Refresh size={15} />
                Retry
              </button>
            </div>
          )}

          {state.status === "ready" && state.cases.length === 0 && (
            <div className={`${PANEL} p-8 text-center`}>
              <p className="text-[16px] font-semibold">No cases yet</p>
              <p className="mt-1.5 text-[13.5px] text-soft/80">Create the first case, then upload evidence into it.</p>
              {!creating && (
                <button type="button" className={`${primaryButton} mt-5`} onClick={() => setCreating(true)}>
                  + New case
                </button>
              )}
            </div>
          )}

          {state.status === "ready" && state.cases.length > 0 && (
            <>
              <p className="mb-3 text-[12.5px] text-muted">
                {visible.length} of {state.cases.length} {state.cases.length === 1 ? "case" : "cases"}
              </p>
              {visible.length === 0 ? (
                <p className={`${PANEL} p-6 text-[13.5px] text-soft/80`}>No case matches “{query}”.</p>
              ) : (
                <ul className="flex flex-col gap-3">
                  {visible.map(item => (
                    <CaseRow
                      key={item.case_id}
                      item={item}
                      active={item.case_id === activeId}
                      busy={busyId === item.case_id}
                      onOpen={() => open(item.case_id)}
                      onToggleClosed={() => toggleClosed(item)}
                    />
                  ))}
                </ul>
              )}
            </>
          )}
        </section>

        <p className="mt-8 text-[12px] text-muted">
          Owner names are self-declared; authentication is not implemented yet. Looking for the bundled walkthrough?{" "}
          <Link to="/app?source=recorded" className="text-trace-soft hover:text-white">
            Open the recorded CASE-DEMO-IST
          </Link>
          .
        </p>
      </div>
    </ConsoleShell>
  );
}
