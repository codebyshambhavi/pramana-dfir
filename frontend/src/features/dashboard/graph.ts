// Role 4: graph helpers. In demo mode the graph is derived from the demo events the same way the backend
// builder is meant to (person, device, file, IP and location nodes linked by event actions), so the preview
// never shows a relationship that isn't in an event.
import type { CaseEvent, CaseGraph } from "../../api/types";

export function graphFromEvents(events: CaseEvent[]): CaseGraph {
  const nodes = new Map<string, string>();
  const edges = new Map<string, CaseGraph["edges"][number]>();
  const node = (id: string | null | undefined, type: string) => {
    if (id) nodes.set(id, nodes.get(id) ?? type);
    return id ?? null;
  };
  const edge = (source: string | null, target: string | null, action: string) => {
    if (source && target && source !== target) edges.set(`${source}|${target}|${action}`, { source, target, action });
  };
  for (const e of events) {
    const actor = node(e.actor, "person");
    const device = node(e.device, "device");
    const object = e.source === "chat" ? null : node(e.object, "file");
    const ip = node(e.ip, "ip");
    const place = e.location ? node(`${e.location.lat.toFixed(2)}, ${e.location.lon.toFixed(2)}`, "location") : null;
    edge(actor, device, "used");
    edge(device ?? actor, object, e.action);
    edge(device ?? actor, ip, "connected");
    edge(device ?? object, place, "located");
  }
  return { nodes: [...nodes].map(([id, type]) => ({ id, type })), edges: [...edges.values()] };
}

export interface PreviewNode {
  id: string;
  type: string;
  x: number;
  y: number;
  hub: boolean;
}

/** The best-connected node and up to `limit` neighbours, laid out radially in a 0..1 box. */
export function previewGraph(graph: CaseGraph, limit = 6) {
  const degree = new Map<string, number>();
  for (const e of graph.edges) {
    degree.set(e.source, (degree.get(e.source) ?? 0) + 1);
    degree.set(e.target, (degree.get(e.target) ?? 0) + 1);
  }
  const hub = [...degree].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0]?.[0];
  if (!hub) return null;
  const typeOf = new Map(graph.nodes.map(n => [n.id, n.type]));
  const neighbours = [
    ...new Set(graph.edges.flatMap(e => (e.source === hub ? [e.target] : e.target === hub ? [e.source] : [])))
  ]
    .sort((a, b) => (degree.get(b) ?? 0) - (degree.get(a) ?? 0))
    .slice(0, limit);
  const nodes: PreviewNode[] = [
    { id: hub, type: typeOf.get(hub) ?? "entity", x: 0.5, y: 0.5, hub: true },
    ...neighbours.map((id, i) => {
      const angle = -Math.PI / 2 + (i / neighbours.length) * Math.PI * 2;
      return { id, type: typeOf.get(id) ?? "entity", x: 0.5 + Math.cos(angle) * 0.36, y: 0.5 + Math.sin(angle) * 0.36, hub: false };
    })
  ];
  const edges = graph.edges.filter(e => (e.source === hub && neighbours.includes(e.target)) || (e.target === hub && neighbours.includes(e.source)));
  return { nodes, edges, total: { nodes: graph.nodes.length, edges: graph.edges.length } };
}

/** Graph node IDs an event touches, using the same naming as graphFromEvents. */
export function entityIdsOfEvent(e: CaseEvent): string[] {
  return [
    e.actor,
    e.device,
    e.source === "chat" ? null : e.object,
    e.ip,
    e.location ? `${e.location.lat.toFixed(2)}, ${e.location.lon.toFixed(2)}` : null
  ].filter((id): id is string => Boolean(id));
}
