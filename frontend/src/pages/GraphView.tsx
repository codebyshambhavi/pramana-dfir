// Role 4: Graph tab of the Investigation Workspace. Draws GET /cases/{id}/graph with React Flow in type columns
// (person → device → file → IP → location). Entities touched by the selected finding's events glow red.
import { memo, useMemo } from "react";
import ReactFlow, { Background, Controls, Handle, Position, type Edge, type Node, type NodeProps } from "reactflow";
import "reactflow/dist/style.css";
import { FileIcon, Globe, LaptopIcon, MapPin, User } from "../components/console/icons";
import type { CaseGraph } from "../api/types";

const COLUMNS = ["person", "device", "file", "ip", "location"];
const ICON = { person: User, device: LaptopIcon, file: FileIcon, ip: Globe, location: MapPin } as const;

type EntityData = { label: string; type: string; hot: boolean };

const EntityNode = memo(({ data }: NodeProps<EntityData>) => {
  const Icon = ICON[data.type as keyof typeof ICON] ?? FileIcon;
  const color = data.hot ? "#ef2b3c" : "#4b9bff";
  return (
    <div className="flex w-[140px] flex-col items-center gap-1.5">
      <Handle type="target" position={Position.Left} className="!size-1 !border-0 !bg-transparent" />
      <span
        className="flex size-11 items-center justify-center rounded-full border-2 bg-[#08101e]"
        style={{ borderColor: color, color, boxShadow: `0 0 ${data.hot ? 22 : 14}px ${color}aa` }}
      >
        <Icon size={19} />
      </span>
      <span className={`max-w-full truncate rounded-md px-1.5 text-center text-[12px] ${data.hot ? "text-alert-soft" : "text-soft"}`} title={data.label}>
        {data.label}
      </span>
      <span className="text-[10px] tracking-[0.12em] text-muted uppercase">{data.type}</span>
      <Handle type="source" position={Position.Right} className="!size-1 !border-0 !bg-transparent" />
    </div>
  );
});
EntityNode.displayName = "EntityNode";

const nodeTypes = { entity: EntityNode };

export default function GraphView({ graph, hot, hotLabel }: { graph: CaseGraph; hot: ReadonlySet<string>; hotLabel?: string }) {
  const { nodes, edges } = useMemo(() => {
    const columns = new Map<number, string[]>();
    for (const n of graph.nodes) {
      const col = COLUMNS.indexOf(n.type);
      const key = col === -1 ? COLUMNS.length : col;
      columns.set(key, [...(columns.get(key) ?? []), n.id]);
    }
    const tallest = Math.max(...[...columns.values()].map(c => c.length), 1);
    const typeOf = new Map(graph.nodes.map(n => [n.id, n.type]));
    const nodes: Node<EntityData>[] = [];
    for (const [col, ids] of columns) {
      const offset = ((tallest - ids.length) * 110) / 2;
      ids.forEach((id, row) =>
        nodes.push({
          id,
          type: "entity",
          position: { x: col * 230, y: offset + row * 110 },
          data: { label: id, type: typeOf.get(id) ?? "entity", hot: hot.has(id) },
          draggable: true
        })
      );
    }
    const edges: Edge[] = graph.edges.map((e, i) => {
      const lit = hot.has(e.source) && hot.has(e.target);
      return {
        id: `${e.source}-${e.target}-${e.action}-${i}`,
        source: e.source,
        target: e.target,
        label: e.action.replace(/_/g, " "),
        style: { stroke: lit ? "#ef2b3c" : "rgba(122,180,255,0.55)", strokeWidth: lit ? 2 : 1.2 },
        labelStyle: { fill: lit ? "#ff8a94" : "#a9b8d3", fontSize: 10.5 },
        labelBgStyle: { fill: "#070b14", fillOpacity: 0.9 },
        labelBgPadding: [4, 2] as [number, number],
        labelBgBorderRadius: 4,
        animated: lit
      };
    });
    return { nodes, edges };
  }, [graph, hot]);

  return (
    <div>
      <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-[12.5px] text-soft/75">
        <span>
          {graph.nodes.length} entities · {graph.edges.length} relationships
        </span>
        <span className="flex items-center gap-1.5">
          <span className="size-2.5 rounded-full bg-trace shadow-[0_0_6px_#3b8cff]" /> Entity
        </span>
        {hot.size > 0 && (
          <span className="flex items-center gap-1.5">
            <span className="size-2.5 rounded-full bg-alert shadow-[0_0_6px_#ef2b3c]" /> In events cited by {hotLabel}
          </span>
        )}
        <span className="ml-auto text-muted">Drag to pan · scroll to zoom</span>
      </div>
      <div className="pramana-flow mt-3 h-[560px] overflow-hidden rounded-xl border border-trace/20 bg-[radial-gradient(ellipse_at_center,rgba(20,34,64,0.55),rgba(5,7,12,0.9))]">
        <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.15 }} minZoom={0.3} maxZoom={1.8} nodesConnectable={false}>
          <Background color="rgba(122,180,255,0.12)" gap={26} size={1} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
    </div>
  );
}
