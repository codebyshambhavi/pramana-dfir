// Role 4: routes. The public landing page lives at "/", the investigator console under "/app".
import { Navigate, Route, Routes } from "react-router-dom";
import Landing from "./pages/Landing";
import Dashboard from "./pages/Dashboard";
import EvidenceVault from "./pages/EvidenceVault";
import Timeline from "./pages/Timeline";
import GraphView from "./pages/GraphView";
import Report from "./pages/Report";

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/app" element={<Dashboard />} />
      <Route path="/app/evidence" element={<EvidenceVault />} />
      <Route path="/app/timeline" element={<Timeline />} />
      <Route path="/app/graph" element={<GraphView />} />
      <Route path="/app/report" element={<Report />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
