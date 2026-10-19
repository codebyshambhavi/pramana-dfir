// Role 4: client-side pagination for the evidence table (the API returns the whole list).
import { ChevronLeft, ChevronRight } from "../../../components/console/icons";

const pageWindow = (page: number, pages: number) => {
  const start = Math.max(1, Math.min(page - 2, pages - 4));
  return Array.from({ length: Math.min(5, pages) }, (_, i) => start + i);
};

export default function Pagination({
  page,
  pages,
  from,
  to,
  total,
  onPage
}: {
  page: number;
  pages: number;
  from: number;
  to: number;
  total: number;
  onPage: (page: number) => void;
}) {
  const button =
    "inline-flex size-9 items-center justify-center rounded-md border text-[13.5px] transition disabled:cursor-not-allowed disabled:opacity-35 focus-visible:outline focus-visible:outline-2 focus-visible:outline-trace";
  return (
    <nav aria-label="Evidence pages" className="flex flex-col items-center justify-between gap-3 px-4 py-3.5 sm:flex-row sm:px-5">
      <p className="text-[13.5px] text-soft/80" aria-live="polite">
        Showing {from}–{to} of {total} evidence {total === 1 ? "item" : "items"}
      </p>
      {pages > 1 && (
        <ul className="flex items-center gap-1.5">
          <li>
            <button type="button" className={`${button} border-white/10 text-soft`} disabled={page === 1} onClick={() => onPage(page - 1)} aria-label="Previous page">
              <ChevronLeft size={16} />
            </button>
          </li>
          {pageWindow(page, pages).map(n => (
            <li key={n}>
              <button
                type="button"
                onClick={() => onPage(n)}
                aria-current={n === page ? "page" : undefined}
                className={`${button} ${n === page ? "border-alert/70 bg-alert/10 text-white" : "border-white/10 text-soft hover:text-white"}`}
              >
                {n}
              </button>
            </li>
          ))}
          <li>
            <button type="button" className={`${button} border-white/10 text-soft`} disabled={page === pages} onClick={() => onPage(page + 1)} aria-label="Next page">
              <ChevronRight size={16} />
            </button>
          </li>
        </ul>
      )}
    </nav>
  );
}
