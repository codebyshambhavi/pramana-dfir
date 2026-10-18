# Architecture

```
files -> [R1] intake + hash -> parsers -> Event JSON
      -> [R3] Postgres + NetworkX graph
      -> [R2] correlate -> detect -> hypotheses -> Finding JSON
      -> [R3] lineage + PDF report
      -> [R4] console (timeline, graph, "view evidence")
```

Contracts: `contracts/event.schema.json` (Role 1), `contracts/finding.schema.json` (Role 2), `contracts/openapi.yaml` (Role 3). Frozen on 22 Oct.
