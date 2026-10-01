import { BrowserRouter, Routes, Route } from "react-router-dom";
import Login from "./pages/Login";
import Layout from "./components/Layout";
import ProtectedRoute from "./components/ProtectedRoute";
import Dashboard from "./pages/Dashboard";
import Assets from "./pages/Assets";
import Scans from "./pages/Scans";
import Vulnerabilities from "./pages/Vulnerabilities";
import Siem from "./pages/Siem";
import Surface from "./pages/Surface";
import Cloud from "./pages/Cloud";
import CodeRepos from "./pages/CodeRepos";
import Soar from "./pages/Soar";
import Cases from "./pages/Cases";
import PurpleTeam from "./pages/PurpleTeam";
import Reports from "./pages/Reports";
import Notifications from "./pages/Notifications";
import Integrations from "./pages/Integrations";
import Help from "./pages/Help";
import Organizations from "./pages/Organizations";
import Billing from "./pages/Billing";
import SsoCallback from "./pages/SsoCallback";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        {/* Fuera de ProtectedRoute a proposito: llega directo desde el
            proveedor de identidad externo (redirect de auth-service), sin
            tokens todavia -- los guarda ella misma antes de redirigir
            adentro de la app. Ver app/main.py::oidc_callback. */}
        <Route path="/sso/callback" element={<SsoCallback />} />
        <Route element={<ProtectedRoute />}>
          <Route element={<Layout />}>
            <Route path="/" element={<Dashboard />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/scans" element={<Scans />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/siem" element={<Siem />} />
            <Route path="/surface" element={<Surface />} />
            <Route path="/cloud" element={<Cloud />} />
            <Route path="/code-repos" element={<CodeRepos />} />
            <Route path="/soar" element={<Soar />} />
            <Route path="/cases" element={<Cases />} />
            <Route path="/purple-team" element={<PurpleTeam />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/notifications" element={<Notifications />} />
            <Route path="/integrations" element={<Integrations />} />
            <Route path="/help" element={<Help />} />
            <Route path="/organizations" element={<Organizations />} />
            <Route path="/billing" element={<Billing />} />
          </Route>
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
