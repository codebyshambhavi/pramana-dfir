// Role 4: frame for the investigator console pages: the same nav language as the landing page, scoped to the
// console routes, over a still dot-dither backdrop (no WebGL, so data pages stay light).
import { useState, type ReactNode } from "react";
import { Link, NavLink } from "react-router-dom";
import { LogoMark, Menu } from "../landing/icons";
import { useSourceLink } from "./useSourceLink";

const LINKS = [
  { to: "/app", label: "Dashboard", end: true },
  { to: "/app/evidence", label: "Evidence Vault" },
  { to: "/app/investigation", label: "Investigation Workspace" }
];

export const GUTTER = "px-4 sm:px-6 lg:px-8 2xl:px-10";

const linkClass = ({ isActive }: { isActive: boolean }) =>
  `relative flex items-center text-[14.5px] transition-colors ${
    isActive
      ? "text-white after:absolute after:inset-x-0 after:bottom-[-1px] after:h-[2px] after:bg-alert after:shadow-[0_0_10px_rgba(239,43,60,0.8)]"
      : "text-soft/80 hover:text-white"
  }`;

export default function ConsoleShell({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const toPath = useSourceLink();
  return (
    <div className="relative min-h-screen overflow-x-clip bg-ink text-white">
      <div aria-hidden="true" className="pointer-events-none fixed inset-0 overflow-hidden">
        {/* Dither particles: tiny dot grids masked to soft clouds in the corners. */}
        <div className="absolute -top-24 right-[-10%] h-[520px] w-[620px] bg-[radial-gradient(rgba(239,43,60,0.55)_1px,transparent_1.4px)] [background-size:7px_7px] opacity-40 [mask-image:radial-gradient(closest-side,#000_0%,rgba(0,0,0,0.35)_45%,transparent_100%)]" />
        <div className="absolute bottom-[-18%] left-[-12%] h-[560px] w-[680px] bg-[radial-gradient(rgba(59,140,255,0.55)_1px,transparent_1.4px)] [background-size:7px_7px] opacity-35 [mask-image:radial-gradient(closest-side,#000_0%,rgba(0,0,0,0.3)_45%,transparent_100%)]" />
        <div className="absolute inset-0 bg-[radial-gradient(rgba(255,255,255,0.045)_1px,transparent_1px)] [background-size:26px_26px] [mask-image:radial-gradient(ellipse_80%_70%_at_50%_30%,#000_30%,transparent_85%)]" />
      </div>

      <header className="relative z-30 border-b border-white/[0.07] bg-ink/70 backdrop-blur-sm">
        <nav className={`mx-auto flex h-[68px] max-w-[1680px] items-center gap-8 ${GUTTER}`}>
          <Link to="/" className="flex shrink-0 items-center gap-3 text-white" aria-label="PRAMANA home">
            <LogoMark className="size-8" />
            <span className="text-[17px] font-medium tracking-[0.42em]">PRAMANA</span>
          </Link>
          <ul className="ml-6 hidden items-stretch gap-8 self-stretch md:flex">
            {LINKS.map(link => (
              <li key={link.to} className="flex">
                <NavLink to={toPath(link.to)} end={link.end} className={linkClass}>
                  {link.label}
                </NavLink>
              </li>
            ))}
          </ul>
          <button
            type="button"
            className="ml-auto rounded-md p-2 text-soft hover:text-white md:hidden"
            aria-label="Menu"
            aria-expanded={open}
            onClick={() => setOpen(v => !v)}
          >
            <Menu size={22} />
          </button>
        </nav>
        {open && (
          <ul className={`border-t border-white/[0.07] py-2 md:hidden ${GUTTER}`}>
            {LINKS.map(link => (
              <li key={link.to}>
                <NavLink
                  to={toPath(link.to)}
                  end={link.end}
                  onClick={() => setOpen(false)}
                  className={({ isActive }) => `block py-2.5 ${isActive ? "text-white" : "text-soft/80"}`}
                >
                  {link.label}
                </NavLink>
              </li>
            ))}
          </ul>
        )}
      </header>

      <main className="relative">{children}</main>
    </div>
  );
}
