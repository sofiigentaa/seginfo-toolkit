import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useAuthStore } from "../store/auth";

const NAV_ITEMS = [
  { to: "/", label: "Dashboard" },
  { to: "/assets", label: "Activos" },
  { to: "/scans", label: "Escaneos" },
  { to: "/surface", label: "Superficie Externa" },
  { to: "/cloud", label: "Integraciones Cloud" },
  { to: "/code-repos", label: "Código y Repositorios" },
  { to: "/vulnerabilities", label: "Vulnerabilidades" },
  { to: "/siem", label: "SIEM" },
  { to: "/soar", label: "SOAR" },
  { to: "/cases", label: "Casos" },
  { to: "/purple-team", label: "Purple Team" },
  { to: "/reports", label: "Reportes" },
  { to: "/notifications", label: "Notificaciones" },
  { to: "/integrations", label: "Integraciones" },
  { to: "/help", label: "Ayuda" },
];

// Solo un admin de organizacion (administra su propia empresa: usuarios,
// SSO, facturacion) o un platform_admin (administra la plataforma entera:
// crea organizaciones nuevas, ve/administra la facturacion de cualquiera)
// necesita estas dos paginas -- ver Organizations.tsx, Billing.tsx y
// dependencies.py::require_platform_admin/require_org_admin_or_platform_admin.
const ORG_NAV_ITEM = { to: "/organizations", label: "Organizaciones" };
const BILLING_NAV_ITEM = { to: "/billing", label: "Pagos y licencia" };

export default function Layout() {
  const claims = useAuthStore((s) => s.claims);
  const logout = useAuthStore((s) => s.logout);
  const navigate = useNavigate();

  const canManageOrganizations = claims?.role === "admin" || claims?.platform_admin === true;
  const navItems = canManageOrganizations ? [...NAV_ITEMS, ORG_NAV_ITEM, BILLING_NAV_ITEM] : NAV_ITEMS;

  function handleLogout() {
    logout();
    navigate("/login");
  }

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="sidebar-brand">SentinelOps</div>
        <nav>
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) => "nav-link" + (isActive ? " nav-link-active" : "")}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <div className="layout-main">
        <header className="topbar">
          <span className="topbar-user">{claims?.sub ?? "usuario"} &middot; {claims?.role ?? "sin rol"}</span>
          <button className="btn-secondary" onClick={handleLogout}>Salir</button>
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
