import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { asmApi } from "../services/api";
import type { MonitoredDomainOut, DiscoveredAssetOut, SurfaceAlertOut } from "../types";
import PageHeader from "../components/PageHeader";
import { SeverityBadge } from "../components/Badge";
import { connectionErrorDetail } from "../utils/errors";

const ALERT_TYPE_LABELS: Record<string, string> = {
  new_subdomain: "Subdominio nuevo",
  cert_expiring: "Certificado por vencer",
  cert_expired: "Certificado vencido",
  cert_check_failed: "Fallo al chequear certificado",
};

function alertTypeLabel(value: string): string {
  return ALERT_TYPE_LABELS[value] ?? value;
}

export default function Surface() {
  const queryClient = useQueryClient();

  const [newDomain, setNewDomain] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [selectedDomainId, setSelectedDomainId] = useState<string | null>(null);
  const [checkFeedback, setCheckFeedback] = useState<{ domainId: string; message: string } | null>(null);
  const [alertsFilter, setAlertsFilter] = useState<"all" | "pending">("pending");

  const domains = useQuery({
    queryKey: ["asm-domains"],
    queryFn: async () => (await asmApi.get<MonitoredDomainOut[]>("/domains")).data,
  });

  const assets = useQuery({
    queryKey: ["asm-domain-assets", selectedDomainId],
    queryFn: async () =>
      (await asmApi.get<DiscoveredAssetOut[]>(`/domains/${selectedDomainId}/assets`)).data,
    enabled: !!selectedDomainId,
  });

  const alerts = useQuery({
    queryKey: ["asm-alerts", alertsFilter],
    queryFn: async () =>
      (
        await asmApi.get<SurfaceAlertOut[]>("/alerts", {
          params: alertsFilter === "pending" ? { acknowledged: false } : {},
        })
      ).data,
  });

  const createDomain = useMutation({
    mutationFn: async () => (await asmApi.post<MonitoredDomainOut>("/domains", { domain: newDomain })).data,
    onSuccess: () => {
      setNewDomain("");
      setFormError(null);
      queryClient.invalidateQueries({ queryKey: ["asm-domains"] });
    },
    onError: (err: unknown) => {
      setFormError(err instanceof Error ? err.message : "No se pudo agregar el dominio.");
    },
  });

  const deleteDomain = useMutation({
    mutationFn: async (domainId: string) => {
      await asmApi.delete(`/domains/${domainId}`);
    },
    onSuccess: (_data, domainId) => {
      if (selectedDomainId === domainId) {
        setSelectedDomainId(null);
      }
      queryClient.invalidateQueries({ queryKey: ["asm-domains"] });
    },
  });

  const checkNow = useMutation({
    mutationFn: async (domainId: string) => {
      await asmApi.post(`/domains/${domainId}/check-now`);
      return domainId;
    },
    onSuccess: (domainId) => {
      setCheckFeedback({ domainId, message: "Chequeo disparado -- los resultados pueden tardar unos segundos en aparecer." });
      queryClient.invalidateQueries({ queryKey: ["asm-domain-assets", domainId] });
      queryClient.invalidateQueries({ queryKey: ["asm-alerts"] });
    },
    onError: (err: unknown, domainId) => {
      setCheckFeedback({
        domainId,
        message: err instanceof Error ? err.message : "No se pudo disparar el chequeo.",
      });
    },
  });

  const acknowledgeAlert = useMutation({
    mutationFn: async (alertId: string) => (await asmApi.patch<SurfaceAlertOut>(`/alerts/${alertId}`)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["asm-alerts"] });
    },
  });

  function onAddDomain() {
    setFormError(null);
    if (!newDomain.trim()) {
      setFormError("Ingresa un dominio (ej. empresa.com).");
      return;
    }
    createDomain.mutate();
  }

  return (
    <div>
      <PageHeader
        title="Superficie externa"
        subtitle="Monitoreo pasivo de dominios, subdominios (via Certificate Transparency) y certificados SSL"
      />

      <div className="panel">
        <h2>Agregar dominio a monitorear</h2>
        <p className="empty-hint">
          Registra un dominio propio (ej. "empresa.com"). SentinelOps descubre subdominios expuestos publicamente
          via logs de Certificate Transparency (crt.sh) y chequea periodicamente el certificado SSL que cada uno
          esta sirviendo -- nunca hace un escaneo activo de puertos ni toca infraestructura de terceros.
        </p>
        <div className="inline-form">
          <input
            placeholder="Dominio (ej. empresa.com)"
            value={newDomain}
            onChange={(e) => setNewDomain(e.target.value)}
          />
          <button className="btn-primary" onClick={onAddDomain} disabled={createDomain.isPending}>
            {createDomain.isPending ? "Agregando..." : "Agregar dominio"}
          </button>
        </div>
        {formError && <p className="error-text">{formError}</p>}
        {createDomain.isError && !formError && (
          <p className="error-text">
            No se pudo agregar el dominio.{" "}
            <span className="error-detail">{connectionErrorDetail(createDomain.error)}</span>
          </p>
        )}
      </div>

      <div className="panel">
        <h2>Dominios monitoreados</h2>
        {domains.isLoading && <p className="empty-hint">Cargando...</p>}
        {domains.isError && (
          <p className="error-text">
            No se pudo conectar con asm-service.{" "}
            <span className="error-detail">{connectionErrorDetail(domains.error)}</span>
          </p>
        )}
        {domains.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Dominio</th>
                <th>Habilitado</th>
                <th>Agregado por</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {domains.data.map((d) => (
                <tr key={d.id} className={d.id === selectedDomainId ? "row-selected" : undefined}>
                  <td>
                    <button className="btn-link" onClick={() => setSelectedDomainId(d.id)}>
                      {d.domain}
                    </button>
                  </td>
                  <td>{d.is_enabled ? "si" : "no"}</td>
                  <td>{d.created_by}</td>
                  <td>
                    <button
                      className="btn-link"
                      onClick={() => checkNow.mutate(d.id)}
                      disabled={checkNow.isPending && checkNow.variables === d.id}
                    >
                      {checkNow.isPending && checkNow.variables === d.id ? "Chequeando..." : "Chequear ahora"}
                    </button>{" "}
                    <button
                      className="btn-link"
                      onClick={() => {
                        if (confirm(`Dejar de monitorear ${d.domain}?`)) {
                          deleteDomain.mutate(d.id);
                        }
                      }}
                    >
                      Borrar
                    </button>
                    {checkFeedback && checkFeedback.domainId === d.id && (
                      <p className="empty-hint" style={{ margin: "4px 0 0" }}>
                        {checkFeedback.message}
                      </p>
                    )}
                  </td>
                </tr>
              ))}
              {domains.data.length === 0 && (
                <tr>
                  <td colSpan={4} className="empty-hint">
                    Sin dominios monitoreados todavia. Agrega uno arriba.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <h2>Subdominios descubiertos {selectedDomainId ? "" : "(elegi un dominio de la tabla de arriba)"}</h2>
        {selectedDomainId && assets.isLoading && <p className="empty-hint">Cargando...</p>}
        {selectedDomainId && assets.isError && (
          <p className="error-text">
            No se pudo cargar los subdominios.{" "}
            <span className="error-detail">{connectionErrorDetail(assets.error)}</span>
          </p>
        )}
        {selectedDomainId && assets.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Hostname</th>
                <th>Primera vez visto</th>
                <th>Ultima vez visto</th>
                <th>Activo</th>
              </tr>
            </thead>
            <tbody>
              {assets.data.map((a) => (
                <tr key={a.id}>
                  <td className="mono">{a.hostname}</td>
                  <td>{new Date(a.first_seen_at).toLocaleString()}</td>
                  <td>{new Date(a.last_seen_at).toLocaleString()}</td>
                  <td>{a.is_active ? "si" : "no"}</td>
                </tr>
              ))}
              {assets.data.length === 0 && (
                <tr>
                  <td colSpan={4} className="empty-hint">
                    Todavia no se descubrio ningun subdominio para este dominio -- probá "Chequear ahora".
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <div className="inline-form" style={{ justifyContent: "space-between" }}>
          <h2 style={{ margin: 0 }}>Alertas</h2>
          <select value={alertsFilter} onChange={(e) => setAlertsFilter(e.target.value as "all" | "pending")}>
            <option value="pending">Sin reconocer</option>
            <option value="all">Todas</option>
          </select>
        </div>
        {alerts.isLoading && <p className="empty-hint">Cargando...</p>}
        {alerts.isError && (
          <p className="error-text">
            No se pudo cargar las alertas.{" "}
            <span className="error-detail">{connectionErrorDetail(alerts.error)}</span>
          </p>
        )}
        {alerts.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Tipo</th>
                <th>Hostname</th>
                <th>Severidad</th>
                <th>Detalle</th>
                <th>Creada</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {alerts.data.map((a) => (
                <tr key={a.id}>
                  <td>{alertTypeLabel(a.alert_type)}</td>
                  <td className="mono">{a.hostname}</td>
                  <td><SeverityBadge value={a.severity} /></td>
                  <td>{a.detail}</td>
                  <td>{new Date(a.created_at).toLocaleString()}</td>
                  <td>
                    {a.is_acknowledged ? (
                      <span className="empty-hint">Reconocida por {a.acknowledged_by}</span>
                    ) : (
                      <button
                        className="btn-link"
                        onClick={() => acknowledgeAlert.mutate(a.id)}
                        disabled={acknowledgeAlert.isPending && acknowledgeAlert.variables === a.id}
                      >
                        {acknowledgeAlert.isPending && acknowledgeAlert.variables === a.id ? "Reconociendo..." : "Reconocer"}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {alerts.data.length === 0 && (
                <tr>
                  <td colSpan={6} className="empty-hint">
                    Sin alertas{alertsFilter === "pending" ? " sin reconocer" : ""} por el momento.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
