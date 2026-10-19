"""Role 3: NetworkX evidence graph builder.

Extracts nodes (person, device, file, ip, location) and edges (actions)
from forensic events.
"""
from __future__ import annotations

from typing import Any
import networkx as nx


def build_graph(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Construct a directed multigraph from forensic events and return nodes and edges.
    
    Nodes:
    - person: from event.actor
    - device: from event.device
    - file: from event.object
    - ip: from event.ip
    - location: from event.location (lat, lon)
    
    Edges:
    - Connect entities involved in the event, labeled with event.action.
    """
    g = nx.MultiDiGraph()

    for event in events:
        action = event.get("action") or "related"
        actor = event.get("actor")
        device = event.get("device")
        obj = event.get("object")
        ip = event.get("ip")
        loc = event.get("location")

        # Collect entities present in this event
        entities: list[tuple[str, str]] = []  # (node_id, node_type)

        if actor:
            entities.append((str(actor), "person"))
        if device:
            entities.append((str(device), "device"))
        if obj:
            entities.append((str(obj), "file"))
        if ip:
            entities.append((str(ip), "ip"))
        if loc and isinstance(loc, dict) and "lat" in loc and "lon" in loc:
            loc_id = f"loc:{loc['lat']},{loc['lon']}"
            entities.append((loc_id, "location"))

        # Register nodes in graph
        for node_id, node_type in entities:
            if node_id not in g:
                g.add_node(node_id, type=node_type)

        # Build meaningful edges based on entity precedence:
        # actor -> device -> object / ip / location
        if actor and device:
            g.add_edge(str(actor), str(device), action=action)
            if obj:
                g.add_edge(str(device), str(obj), action=action)
            if ip:
                g.add_edge(str(device), str(ip), action=action)
            if loc and isinstance(loc, dict):
                loc_id = f"loc:{loc['lat']},{loc['lon']}"
                g.add_edge(str(device), loc_id, action=action)
        elif actor and obj:
            g.add_edge(str(actor), str(obj), action=action)
            if ip:
                g.add_edge(str(actor), str(ip), action=action)
        elif device and obj:
            g.add_edge(str(device), str(obj), action=action)
            if ip:
                g.add_edge(str(device), str(ip), action=action)
        elif len(entities) >= 2:
            # Pairwise link for arbitrary pairs if neither actor nor device is present
            for i in range(len(entities) - 1):
                g.add_edge(entities[i][0], entities[i + 1][0], action=action)

    nodes = [{"id": n, "type": g.nodes[n].get("type", "unknown")} for n in g.nodes()]
    edges = [
        {"source": u, "target": v, "action": data.get("action", "related")}
        for u, v, data in g.edges(data=True)
    ]

    return {"nodes": nodes, "edges": edges}
