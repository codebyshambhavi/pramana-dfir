// Role 4: small radial preview of the case graph: the best-connected entity and its neighbours, drawn in SVG.
// Every node and edge comes from the graph data (GET /cases/{id}/graph, or derived from demo events).
import type { ComponentType, SVGProps } from "react";
import { FileIcon, Globe, LaptopIcon, MapPin, User } from "../../../components/console/icons";
import type { CaseGraph } from "../../../api/types";
import { previewGraph } from "../graph";

type IconType = ComponentType<SVGProps<SVGSVGElement> & { size?: number }>;

const TYPE_STYLE: Record<string, { icon: IconType; color: string }> = {
  person: { icon: User, color: "#3b8cff" },
  device: { icon: LaptopIcon, color: "#7ab4ff" },
  file: { icon: FileIcon, color: "#ef2b3c" },
  ip: { icon: Globe, color: "#a78bfa" },
  location: { icon: MapPin, color: "#2dd4bf" }
};

const styleFor = (type: string) => TYPE_STYLE[type] ?? { icon: FileIcon, color: "#94a3b8" };

export default function EntitiesPanel({ graph }: { graph: CaseGraph }) {
  const preview = previewGraph(graph);
  if (!preview) return <p className="flex flex-1 items-center justify-center text-[13.5px] text-soft/70">No entities in the graph yet.</p>;
  const at = (id: string) => preview.nodes.find(n => n.id === id)!;

  return (
    <div className="flex flex-1 flex-col">
      <div className="relative mx-auto aspect-[1.45] w-full max-w-[380px]">
        <svg viewBox="0 0 145 100" preserveAspectRatio="none" className="absolute inset-0 size-full" aria-hidden="true">
          {preview.edges.map(edge => {
            const a = at(edge.source);
            const b = at(edge.target);
            return (
              <line
                key={`${edge.source}-${edge.target}-${edge.action}`}
                x1={a.x * 145}
                y1={a.y * 100}
                x2={b.x * 145}
                y2={b.y * 100}
                stroke="rgba(122,180,255,0.55)"
                strokeWidth="0.6"
                style={{ filter: "drop-shadow(0 0 1.5px rgba(59,140,255,0.9))" }}
              />
            );
          })}
        </svg>
        {preview.nodes.map(node => {
          const { icon: Icon, color } = styleFor(node.type);
          return (
            <div
              key={node.id}
              className="absolute flex -translate-x-1/2 -translate-y-1/2 flex-col items-center gap-1"
              style={{ left: `${node.x * 100}%`, top: `${node.y * 100}%` }}
            >
              <span
                className={`flex items-center justify-center rounded-full border bg-[#08101e] ${node.hub ? "size-12" : "size-9"}`}
                style={{ borderColor: color, color, boxShadow: `0 0 ${node.hub ? 22 : 12}px ${color}88` }}
              >
                <Icon size={node.hub ? 20 : 16} />
              </span>
              <span className="max-w-[92px] truncate text-[11.5px] text-soft/90" title={`${node.id} (${node.type})`}>
                {node.id}
              </span>
            </div>
          );
        })}
      </div>
      <p className="mt-2 text-center text-[12px] text-muted">
        Showing {preview.nodes.length} of {preview.total.nodes} entities around the best-connected one
      </p>
    </div>
  );
}
