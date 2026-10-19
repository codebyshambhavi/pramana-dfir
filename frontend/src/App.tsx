// Role 4: routes. The public landing page lives at "/", the investigator console under "/app" with three
// destinations: Dashboard, Evidence Vault and Investigation Workspace (Findings, Timeline, Graph, Report tabs).
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import Landing from "./pages/Landing";
import Dashboard from "./pages/Dashboard";
import EvidenceVault from "./pages/EvidenceVault";
import InvestigationWorkspace from "./pages/InvestigationWorkspace";

/** Old /app/timeline, /app/graph and /app/report links land on the matching workspace tab, keeping ?source etc. */
function ToWorkspaceTab({ tab }: { tab: string }) {
  const { search } = useLocation();
  const params = new URLSearchParams(search);
  params.set("tab", tab);
  return <Navigate to={`/app/investigation?${params}`} replace />;
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/app" element={<Dashboard />} />
      <Route path="/app/evidence" element={<EvidenceVault />} />
      <Route path="/app/cases/:caseId/evidence" element={<EvidenceVault />} />
      <Route path="/app/investigation" element={<InvestigationWorkspace />} />
      <Route path="/app/timeline" element={<ToWorkspaceTab tab="timeline" />} />
      <Route path="/app/graph" element={<ToWorkspaceTab tab="graph" />} />
      <Route path="/app/report" element={<ToWorkspaceTab tab="report" />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
