import { useQuery } from "@tanstack/react-query";
import { vulnApi, siemApi, caseApi, purpleApi, assetApi, scanApi, soarApi, notificationApi } from "../services/api";
import type {
  VulnerabilityStatsOut,
  AlertOut,
  CaseOut,
  CoverageResult,
  AssetOut,
  ScanJobOut,
  PlaybookRunOut,
  NotifyLogOut,
} from "../types";
import PageHeader from "../components/PageHeader";
import { StatusBadge } from "../components/Badge";
import { connectionErrorDetail } from "../utils/errors";

export default function Dashboard() {
  const vulnStats = useQuery({
    queryKey: ["vuln-stats"],
    queryFn: async () => (await vulnApi.get<VulnerabilityStatsOut>("/vulnerabilities/stats")).data,
  });
  const alerts = useQuery({
    queryKey: ["alerts", "dashboard"],
    queryFn: async () => (await siemApi.get<AlertOut[]>("/alerts")).data,
  });
  const cases = useQuery({
    queryKey: ["cases", "dashboard"],
    queryFn: async () => (await caseApi.get<CaseOut[]>("/cases")).data,
  });
  const coverage = useQuery({
    queryKey: ["coverage-overall"],
    queryFn: async () => (await purpleApi.get<CoverageResult>("/coverage/overall")).data,
  });
  const assets = useQuery({
    queryKey: ["assets", "dashboard"],
    queryFn: async () => (await assetApi.get<AssetOut[]>("/assets")).data,
  });
  const scans = useQuery({
    queryKey: ["scans", "dashboard"],
    queryFn: async () => (await scanApi.get<ScanJobOut[]>("/scans")).data,
  });
  const playbookRuns = useQuery({
    queryKey: ["playbook-runs", "dashboard"],
    queryFn: async () => (await soarApi.get<PlaybookRunOut[]>("/runs")).data,
  });
  const notifyLogs = useQuery({
    queryKey: ["notify-logs", "dashboard"],
    queryFn: async () => (await notificationApi.get<NotifyLogOut[]>("/logs")).data,
  });

  const openAlerts = alerts.data?.filter((a) => a.status === "new" || a.status === "acknowledged").length ?? 0;
  const openCases = cases.data?.filter((c) => c.status === "open" || c.status === "in_progress").length ?? 0;
  const now = new Date().toISOString();
  const breachedCases = cases.data?.filter((c) => c.sla_due_at && c.sla_due_at < now && c.status !== "resolved" && c.status !== "closed").length ?? 0;
  const criticalAssets = assets.data?.filter((a) => a.criticality === "critical").length ?? 0;
  const scansRunning = scans.data?.filter((s) => s.status === "running" || s.status === "pending").length ?? 0;

  // Servicios que fallaron al cargar -- se muestran como banner arriba y
  // cada stat-card que dependa de ese servicio cae a "-" en vez de a 0/0
  // (ver failedServiceLabels mas abajo: mostrar "0 alertas activas" cuando
  // en realidad siem-service no respondio es peor que mostrar nada, porque
  // da una falsa sensacion de que todo esta tranquilo).
  const serviceStatuses: { label: string; query: { isError: boolean; error: unknown } }[] = [
    { label: "vuln-service", query: vulnStats },
    { label: "siem-service", query: alerts },
    { label: "case-service", query: cases },
    { label: "purple-team-service", query: coverage },
    { label: "asset-service", query: assets },
    { label: "scan-service", query: scans },
    { label: "soar-service", query: playbookRuns },
    { label: "notification-service", query: notifyLogs },
  ];
  const failedServices = serviceStatuses.filter((s) => s.query.isError);

  const recentScans = [...(scans.data ?? [])]
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
    .slice(0, 5);
  const recentRuns = [...(playbookRuns.data ?? [])]
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
    .slice(0, 5);
  const recentNotifications = [...(notifyLogs.data ?? [])]
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
    .slice(0, 5);

  return (
    <div>
      <PageHeader title="Dashboard" subtitle="Vista general del estado de seguridad defensiva" />
      {failedServices.length > 0 && (
        <div className="panel">
          <p className="error-text">
            No se pudo conectar con {failedServices.length === 1 ? "este servicio" : "estos servicios"}: {failedServices.map((s) => s.label).join(", ")}.
            Las metricas que dependen de {failedServices.length === 1 ? "el" : "ellos"} muestran "-" en vez de 0 para
            no confundir "sin datos" con "no responde".
          </p>
          {failedServices.map((s) => (
            <p key={s.label} className="error-text" style={{ marginTop: 4 }}>
              {s.label}: <span className="error-detail">{connectionErrorDetail(s.query.error)}</span>
            </p>
          ))}
        </div>
      )}
      <div className="cards-grid">
        <div className="stat-card">
          <span className="stat-label">Vulnerabilidades abiertas</span>
          <span className="stat-value">{vulnStats.data?.total ?? "-"}</span>
          <span className="stat-hint">{vulnStats.data?.kev_count ?? 0} en catalogo CISA KEV</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Alertas SIEM activas</span>
          <span className="stat-value">{alerts.isLoading || alerts.isError ? "-" : openAlerts}</span>
          <span className="stat-hint">de {alerts.isError ? "-" : alerts.data?.length ?? 0} totales</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Casos abiertos</span>
          <span className="stat-value">{cases.isLoading || cases.isError ? "-" : openCases}</span>
          <span className="stat-hint">{cases.isError ? "-" : breachedCases} con SLA vencido</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Cobertura ATT&amp;CK</span>
          <span className="stat-value">{coverage.data ? `${coverage.data.coverage_pct}%` : "-"}</span>
          <span className="stat-hint">{coverage.data?.gaps.length ?? 0} tecnicas sin deteccion</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Activos inventariados</span>
          <span className="stat-value">{assets.isLoading || assets.isError ? "-" : assets.data?.length ?? 0}</span>
          <span className="stat-hint">{assets.isError ? "-" : criticalAssets} criticos</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Escaneos en curso</span>
          <span className="stat-value">{scans.isLoading || scans.isError ? "-" : scansRunning}</span>
          <span className="stat-hint">de {scans.isError ? "-" : scans.data?.length ?? 0} totales</span>
        </div>
      </div>

      <div className="panel">
        <h2>Vulnerabilidades por severidad</h2>
        <ul className="kv-list">
          {vulnStats.data && Object.entries(vulnStats.data.by_severity).map(([sev, count]) => (
            <li key={sev}><span>{sev}</span><span>{count}</span></li>
          ))}
        </ul>
      </div>

      <div className="panel">
        <h2>Brechas de deteccion MITRE ATT&amp;CK</h2>
        {coverage.data?.gaps.length ? (
          <ul className="kv-list">
            {coverage.data.gaps.map((g) => (
              <li key={g.technique_id}><span>{g.technique_id} - {g.name}</span><span>{g.tactic}</span></li>
            ))}
          </ul>
        ) : (
          <p className="empty-hint">Sin datos de cobertura todavia (o sin brechas detectadas).</p>
        )}
      </div>

      <div className="panel">
        <h2>Escaneos recientes</h2>
        {recentScans.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Tipo</th>
                <th>Estado</th>
                <th>Fecha</th>
              </tr>
            </thead>
            <tbody>
              {recentScans.map((s) => (
                <tr key={s.id}>
                  <td>{s.name || s.target}</td>
                  <td>{s.scanner_type}</td>
                  <td><StatusBadge value={s.status} /></td>
                  <td>{new Date(s.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="empty-hint">Sin escaneos todavia.</p>
        )}
      </div>

      <div className="panel">
        <h2>Playbooks SOAR ejecutados recientemente</h2>
        {recentRuns.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Playbook</th>
                <th>Estado</th>
                <th>Disparado por</th>
                <th>Fecha</th>
              </tr>
            </thead>
            <tbody>
              {recentRuns.map((r) => (
                <tr key={r.id}>
                  <td>{r.playbook_name}</td>
                  <td><StatusBadge value={r.status} /></td>
                  <td>{r.triggered_by || "-"}</td>
                  <td>{new Date(r.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="empty-hint">Sin playbooks ejecutados todavia.</p>
        )}
      </div>

      <div className="panel">
        <h2>Notificaciones recientes</h2>
        {recentNotifications.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Asunto</th>
                <th>Canal</th>
                <th>Estado</th>
                <th>Fecha</th>
              </tr>
            </thead>
            <tbody>
              {recentNotifications.map((n) => (
                <tr key={n.id}>
                  <td>{n.subject}</td>
                  <td>{n.channel_type}</td>
                  <td><StatusBadge value={n.status} /></td>
                  <td>{new Date(n.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="empty-hint">Sin notificaciones todavia.</p>
        )}
      </div>
    </div>
  );
}
