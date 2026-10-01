import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { siemApi, threatIntelApi } from "../services/api";
import type { AlertOut, SigmaRuleOut, ThreatIntelHit, IpReputationOut } from "../types";
import PageHeader from "../components/PageHeader";
import { SeverityBadge, StatusBadge } from "../components/Badge";
import { connectionErrorDetail } from "../utils/errors";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

const FIELD_OPTIONS = [
  { value: "host.name", label: "Host" },
  { value: "source.ip", label: "IP origen" },
  { value: "destination.ip", label: "IP destino" },
  { value: "user.name", label: "Usuario" },
  { value: "event.action", label: "Accion del evento" },
  { value: "event.category", label: "Categoria del evento" },
  { value: "event.outcome", label: "Resultado del evento" },
  { value: "message", label: "Mensaje" },
  { value: "sentinelops.source_type", label: "Origen (scanner/tipo de log)" },
  { value: "sentinelops.severity", label: "Severidad reportada" },
];

// --- Threat Intel (AbuseIPDB/MISP, via threatintel-service) -----------

function ThreatIntelResult({ result }: { result: IpReputationOut }) {
  if (result.is_malicious === null) {
    return (
      <p className="empty-hint">
        No se pudo chequear {result.ip} contra ninguna fuente (revisa ABUSEIPDB_API_KEY / MISP_URL en el servidor).
      </p>
    );
  }
  if (!result.is_malicious) {
    return (
      <p className="empty-hint">
        {result.ip}: sin reportes de reputacion negativa ({result.source}
        {result.cached ? ", cache" : ""}).
      </p>
    );
  }
  return (
    <p className="error-text">
      IP maliciosa conocida: {result.ip} ({result.source}, score {result.score ?? "?"})
      {result.categories.length > 0 && <> -- {result.categories.join(", ")}</>}
    </p>
  );
}

function ThreatIntelBadge({ threatIntel }: { threatIntel?: Record<string, ThreatIntelHit> }) {
  const entries = Object.entries(threatIntel ?? {});
  if (entries.length === 0) {
    return <span className="empty-hint">--</span>;
  }
  return (
    <span className="badge badge-critical">
      IP maliciosa conocida: {entries.map(([ip, hit]) => `${ip} (${hit.source}, score ${hit.score ?? "?"})`).join("; ")}
    </span>
  );
}

type ConditionRow = { field: string; value: string };

function buildDetection(conditions: ConditionRow[]): Record<string, unknown> {
  // Varias condiciones sobre el MISMO campo (ej. dos filas de "IP origen"
  // con valores distintos) no se pueden cumplir a la vez con AND -- lo que
  // el usuario quiere decir es "cualquiera de estos valores", que es
  // exactamente el OR que sigma.py::_field_matches ya soporta para un campo
  // con lista de valores. Por eso se acumulan en una lista en vez de que la
  // ultima condicion pise a las anteriores en el dict `selection`.
  const selection: Record<string, string[]> = {};
  for (const c of conditions) {
    if (!c.field || !c.value.trim()) continue;
    const values = c.value.split(",").map((v) => v.trim()).filter(Boolean);
    if (values.length === 0) continue;
    selection[c.field] = [...(selection[c.field] ?? []), ...values];
  }
  const normalized: Record<string, unknown> = {};
  for (const [field, values] of Object.entries(selection)) {
    normalized[field] = values.length > 1 ? values : values[0];
  }
  return { selection_1: normalized, condition: "selection_1" };
}

export default function Siem() {
  const queryClient = useQueryClient();

  const [ruleName, setRuleName] = useState("");
  const [ruleDescription, setRuleDescription] = useState("");
  const [ruleSeverity, setRuleSeverity] = useState("medium");
  const [ruleTags, setRuleTags] = useState("");
  const [conditions, setConditions] = useState<ConditionRow[]>([{ field: "event.category", value: "" }]);
  const [ruleFormError, setRuleFormError] = useState<string | null>(null);
  const [ruleActionError, setRuleActionError] = useState<unknown>(null);
  const [alertActionError, setAlertActionError] = useState<unknown>(null);
  const [seedDefaultsError, setSeedDefaultsError] = useState<unknown>(null);
  const [lookupIp, setLookupIp] = useState("");
  const [lookupFormError, setLookupFormError] = useState<string | null>(null);

  const alerts = useQuery({
    queryKey: ["alerts"],
    queryFn: async () => (await siemApi.get<AlertOut[]>("/alerts")).data,
  });
  const rules = useQuery({
    queryKey: ["rules"],
    queryFn: async () => (await siemApi.get<SigmaRuleOut[]>("/rules")).data,
  });

  const seedDefaults = useMutation({
    mutationFn: async () => (await siemApi.post<SigmaRuleOut[]>("/rules/seed-defaults")).data,
    onSuccess: () => {
      setSeedDefaultsError(null);
      queryClient.invalidateQueries({ queryKey: ["rules"] });
    },
    onError: (err: unknown) => setSeedDefaultsError(err),
  });

  const createRule = useMutation({
    mutationFn: async () =>
      (
        await siemApi.post<SigmaRuleOut>("/rules", {
          name: ruleName,
          description: ruleDescription,
          severity: ruleSeverity,
          tags: ruleTags.split(",").map((t) => t.trim()).filter(Boolean),
          detection: buildDetection(conditions),
          is_enabled: true,
        })
      ).data,
    onSuccess: () => {
      setRuleName("");
      setRuleDescription("");
      setRuleTags("");
      setConditions([{ field: "event.category", value: "" }]);
      setRuleFormError(null);
      queryClient.invalidateQueries({ queryKey: ["rules"] });
    },
  });

  const toggleRule = useMutation({
    mutationFn: async ({ id, is_enabled }: { id: string; is_enabled: boolean }) =>
      (await siemApi.patch<SigmaRuleOut>(`/rules/${id}`, { is_enabled })).data,
    onSuccess: () => {
      setRuleActionError(null);
      queryClient.invalidateQueries({ queryKey: ["rules"] });
    },
    onError: (err: unknown) => setRuleActionError(err),
  });

  const deleteRule = useMutation({
    mutationFn: async (id: string) => siemApi.delete(`/rules/${id}`),
    onSuccess: () => {
      setRuleActionError(null);
      queryClient.invalidateQueries({ queryKey: ["rules"] });
    },
    onError: (err: unknown) => setRuleActionError(err),
  });

  const updateAlert = useMutation({
    mutationFn: async ({ id, status: newStatus }: { id: string; status: string }) =>
      (await siemApi.patch<AlertOut>(`/alerts/${id}`, { status: newStatus })).data,
    onSuccess: () => {
      setAlertActionError(null);
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
    },
    onError: (err: unknown) => setAlertActionError(err),
  });

  const ipLookup = useMutation({
    mutationFn: async (ip: string) => (await threatIntelApi.get<IpReputationOut>(`/lookup/${encodeURIComponent(ip)}`)).data,
    onSuccess: () => setLookupFormError(null),
  });

  function onCreateRule() {
    setRuleFormError(null);
    if (!ruleName.trim()) {
      setRuleFormError("Ingresa un nombre para la regla.");
      return;
    }
    const detection = buildDetection(conditions);
    if (Object.keys(detection.selection_1 as object).length === 0) {
      setRuleFormError("Agrega al menos una condicion con campo y valor.");
      return;
    }
    createRule.mutate();
  }

  function onLookupIp() {
    setLookupFormError(null);
    if (!lookupIp.trim()) {
      setLookupFormError("Ingresa una IP para consultar.");
      return;
    }
    ipLookup.mutate(lookupIp.trim());
  }

  function updateCondition(idx: number, patch: Partial<ConditionRow>) {
    setConditions((prev) => prev.map((c, i) => (i === idx ? { ...c, ...patch } : c)));
  }

  const openAlertsCount = (alerts.data ?? []).filter((a) => a.status === "new").length;
  const criticalAlertsCount = (alerts.data ?? []).filter((a) => a.severity === "critical").length;
  const activeRulesCount = (rules.data ?? []).filter((r) => r.is_enabled).length;

  return (
    <div>
      <PageHeader title="SIEM" subtitle="Alertas generadas por el motor de reglas Sigma sobre logs normalizados (ECS-lite)" />

      <div className="cards-grid">
        <div className="stat-card">
          <span className="stat-label">Alertas totales</span>
          <span className="stat-value">{alerts.data?.length ?? "-"}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Alertas abiertas</span>
          <span className="stat-value">{openAlertsCount}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Alertas criticas</span>
          <span className="stat-value">{criticalAlertsCount}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Reglas activas</span>
          <span className="stat-value">{activeRulesCount} / {rules.data?.length ?? 0}</span>
        </div>
      </div>

      <div className="panel">
        <h2>Threat Intel</h2>
        <p className="empty-hint">
          Consulta si una IP es maliciosa conocida (AbuseIPDB / MISP, via threatintel-service). Las alertas nuevas ya
          se enriquecen automaticamente con esto -- ver columna "Threat Intel" en la tabla de abajo.
        </p>
        <div className="inline-form">
          <input
            placeholder="IP a consultar (ej. 8.8.8.8)"
            value={lookupIp}
            onChange={(e) => setLookupIp(e.target.value)}
          />
          <button className="btn-secondary" onClick={onLookupIp} disabled={ipLookup.isPending}>
            {ipLookup.isPending ? "Consultando..." : "Consultar IP"}
          </button>
        </div>
        {lookupFormError && <p className="error-text">{lookupFormError}</p>}
        {ipLookup.data && !lookupFormError && <ThreatIntelResult result={ipLookup.data} />}
        {ipLookup.isError && (
          <p className="error-text">
            No se pudo consultar threatintel-service.{" "}
            <span className="error-detail">{connectionErrorDetail(ipLookup.error)}</span>
          </p>
        )}
      </div>

      <div className="panel">
        <h2>Alertas</h2>
        {alerts.isLoading && <p className="empty-hint">Cargando...</p>}
        {alerts.isError && (
          <p className="error-text">
            No se pudo conectar con siem-service.{" "}
            <span className="error-detail">{connectionErrorDetail(alerts.error)}</span>
          </p>
        )}
        {alerts.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Regla</th>
                <th>Severidad</th>
                <th>Estado</th>
                <th>SOAR disparado</th>
                <th>Threat Intel</th>
                <th>Creada</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {alerts.data.map((a) => (
                <tr key={a.id}>
                  <td>{a.rule_name}</td>
                  <td><SeverityBadge value={a.severity} /></td>
                  <td><StatusBadge value={a.status} /></td>
                  <td>{a.soar_triggered ? "si" : "no"}</td>
                  <td><ThreatIntelBadge threatIntel={a.threat_intel} /></td>
                  <td>{new Date(a.created_at).toLocaleString()}</td>
                  <td>
                    {a.status === "new" && (
                      <button className="btn-link" onClick={() => updateAlert.mutate({ id: a.id, status: "acknowledged" })}>
                        Reconocer
                      </button>
                    )}
                    {a.status !== "closed" && (
                      <button className="btn-link" onClick={() => updateAlert.mutate({ id: a.id, status: "closed" })}>
                        Cerrar
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {alerts.data.length === 0 && (
                <tr><td colSpan={7} className="empty-hint">Sin alertas todavia.</td></tr>
              )}
            </tbody>
          </table>
        )}
        {alertActionError != null && (
          <p className="error-text">
            No se pudo actualizar la alerta.{" "}
            <span className="error-detail">{connectionErrorDetail(alertActionError)}</span>
          </p>
        )}
      </div>

      <div className="panel">
        <h2>Reglas de deteccion (Sigma)</h2>
        <p className="empty-hint">
          Una regla se dispara cuando TODAS las condiciones de abajo coinciden con un evento ingresado. Para
          comparar contra varios valores (ej. "admin" o "root"), separalos por coma.
        </p>

        <div className="inline-form">
          <button className="btn-secondary" onClick={() => seedDefaults.mutate()} disabled={seedDefaults.isPending}>
            {seedDefaults.isPending ? "Cargando..." : "Cargar reglas recomendadas"}
          </button>
          {seedDefaults.data && (
            <span className="empty-hint">{seedDefaults.data.length} regla(s) nueva(s) agregada(s).</span>
          )}
        </div>
        {seedDefaultsError != null && (
          <p className="error-text">
            No se pudieron cargar las reglas recomendadas.{" "}
            <span className="error-detail">{connectionErrorDetail(seedDefaultsError)}</span>
          </p>
        )}

        <h3 style={{ marginTop: 16 }}>Nueva regla</h3>
        <div className="inline-form">
          <input placeholder="Nombre" value={ruleName} onChange={(e) => setRuleName(e.target.value)} />
          <select value={ruleSeverity} onChange={(e) => setRuleSeverity(e.target.value)}>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <input placeholder="Tags (separados por coma)" value={ruleTags} onChange={(e) => setRuleTags(e.target.value)} />
        </div>
        <input
          placeholder="Descripcion (opcional)"
          style={{ width: "100%", marginTop: 8 }}
          value={ruleDescription}
          onChange={(e) => setRuleDescription(e.target.value)}
        />

        <div style={{ marginTop: 10 }}>
          <strong>Condiciones (todas deben cumplirse):</strong>
          {conditions.map((c, idx) => (
            <div className="inline-form" key={idx} style={{ marginTop: 6 }}>
              <select value={c.field} onChange={(e) => updateCondition(idx, { field: e.target.value })}>
                {FIELD_OPTIONS.map((f) => (
                  <option key={f.value} value={f.value}>{f.label}</option>
                ))}
              </select>
              <input
                placeholder="Valor (o valores separados por coma)"
                value={c.value}
                onChange={(e) => updateCondition(idx, { value: e.target.value })}
              />
              {conditions.length > 1 && (
                <button className="btn-link" onClick={() => setConditions((prev) => prev.filter((_, i) => i !== idx))}>
                  Quitar
                </button>
              )}
            </div>
          ))}
          <button
            type="button"
            className="btn-secondary"
            style={{ marginTop: 8 }}
            onClick={() => setConditions((prev) => [...prev, { field: "event.action", value: "" }])}
          >
            + Agregar condicion
          </button>
        </div>

        <div style={{ marginTop: 10 }}>
          <button className="btn-primary" onClick={onCreateRule} disabled={createRule.isPending}>
            {createRule.isPending ? "Creando..." : "Crear regla"}
          </button>
        </div>
        {ruleFormError && <p className="error-text">{ruleFormError}</p>}
        {createRule.isError && !ruleFormError && (
          <p className="error-text">
            No se pudo crear la regla.{" "}
            <span className="error-detail">{connectionErrorDetail(createRule.error)}</span>
          </p>
        )}

        {rules.data && (
          <table className="data-table" style={{ marginTop: 16 }}>
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Severidad</th>
                <th>Tags</th>
                <th>Habilitada</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {rules.data.map((r) => (
                <tr key={r.id}>
                  <td>{r.name}</td>
                  <td><SeverityBadge value={r.severity} /></td>
                  <td className="mono">{r.tags.join(", ")}</td>
                  <td>
                    <input
                      type="checkbox"
                      checked={r.is_enabled}
                      onChange={(e) => toggleRule.mutate({ id: r.id, is_enabled: e.target.checked })}
                    />
                  </td>
                  <td>
                    <button className="btn-link" onClick={() => deleteRule.mutate(r.id)}>Eliminar</button>
                  </td>
                </tr>
              ))}
              {rules.data.length === 0 && (
                <tr><td colSpan={5} className="empty-hint">Sin reglas cargadas todavia -- usa "Cargar reglas recomendadas" o crea una arriba.</td></tr>
              )}
            </tbody>
          </table>
        )}
        {ruleActionError != null && (
          <p className="error-text">
            No se pudo actualizar la regla.{" "}
            <span className="error-detail">{connectionErrorDetail(ruleActionError)}</span>
          </p>
        )}
      </div>
    </div>
  );
}
