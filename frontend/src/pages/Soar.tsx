import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { soarApi } from "../services/api";
import type { PlaybookOut, PlaybookRunOut } from "../types";
import PageHeader from "../components/PageHeader";
import { StatusBadge } from "../components/Badge";
import { connectionErrorDetail } from "../utils/errors";
import { useAuthStore } from "../store/auth";

const SEVERITIES = ["info", "low", "medium", "high", "critical"];

type ActionField = { key: string; label: string };
type ActionDef = { value: string; label: string; fields: ActionField[] };

const ACTIONS: ActionDef[] = [
  { value: "block_ip", label: "Bloquear IP (contencion de firewall)", fields: [
    { key: "ip", label: "IP a bloquear (vacio = toma la IP de origen de la alerta)" },
  ] },
  { value: "isolate_host", label: "Aislar host (contencion EDR/NAC)", fields: [
    { key: "host", label: "Host a aislar (vacio = toma el host de la alerta)" },
  ] },
  { value: "create_case", label: "Crear caso en Casos", fields: [
    { key: "title", label: "Titulo (opcional, se autogenera con la alerta)" },
    { key: "priority", label: "Prioridad (opcional: critical/high/medium/low)" },
  ] },
  { value: "create_ticket", label: "Crear ticket externo (Jira, via Integraciones)", fields: [
    { key: "title", label: "Titulo (opcional, se autogenera con la alerta)" },
  ] },
  { value: "notify", label: "Enviar notificacion", fields: [
    { key: "subject", label: "Asunto (opcional)" },
    { key: "body", label: "Mensaje (opcional)" },
  ] },
];

type StepDraft = { action: string; params: Record<string, string> };

function actionLabel(action: string): string {
  return ACTIONS.find((a) => a.value === action)?.label ?? action;
}

// PlaybookOut no expone organization_id (ver soar-service/app/schemas.py),
// asi que no podemos leerlo directo para saber si un playbook es global.
// source_file si viene en la respuesta y es un proxy exacto: solo lo llena
// playbook_loader.py al sincronizar los YAML de playbooks/ (que son
// justamente los playbooks con organization_id=NULL/global); un playbook
// creado a mano via POST /playbooks nunca tiene source_file. Ver
// main.py::update_playbook / delete_playbook -- ahi es donde el backend
// exige platform_admin para tocar uno de estos.
function isGlobalPlaybook(playbook: PlaybookOut): boolean {
  return Boolean(playbook.source_file);
}

export default function Soar() {
  const queryClient = useQueryClient();
  const claims = useAuthStore((s) => s.claims);
  const isPlatformAdmin = claims?.platform_admin === true;
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [minSeverity, setMinSeverity] = useState("high");
  const [ruleTags, setRuleTags] = useState("");
  const [steps, setSteps] = useState<StepDraft[]>([]);
  const [draftAction, setDraftAction] = useState(ACTIONS[0].value);
  const [draftParams, setDraftParams] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [runFeedback, setRunFeedback] = useState<{ playbookId: string; message: string } | null>(null);
  const [playbookActionError, setPlaybookActionError] = useState<unknown>(null);

  const playbooks = useQuery({
    queryKey: ["playbooks"],
    queryFn: async () => (await soarApi.get<PlaybookOut[]>("/playbooks")).data,
  });
  const runs = useQuery({
    queryKey: ["runs"],
    queryFn: async () => (await soarApi.get<PlaybookRunOut[]>("/runs")).data,
  });

  const createPlaybook = useMutation({
    mutationFn: async () =>
      (
        await soarApi.post<PlaybookOut>("/playbooks", {
          name,
          description,
          min_severity: minSeverity,
          rule_tags: ruleTags.split(",").map((t) => t.trim()).filter(Boolean),
          steps: steps.map((s) => ({
            action: s.action,
            params: Object.fromEntries(Object.entries(s.params).filter(([, v]) => v.trim() !== "")),
          })),
          is_enabled: true,
        })
      ).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["playbooks"] });
      setName("");
      setDescription("");
      setRuleTags("");
      setSteps([]);
      setFormError(null);
    },
  });

  const togglePlaybook = useMutation({
    mutationFn: async ({ id, is_enabled }: { id: string; is_enabled: boolean }) =>
      (await soarApi.patch<PlaybookOut>(`/playbooks/${id}`, { is_enabled })).data,
    onSuccess: () => {
      setPlaybookActionError(null);
      queryClient.invalidateQueries({ queryKey: ["playbooks"] });
    },
    onError: (err: unknown) => setPlaybookActionError(err),
  });

  const deletePlaybook = useMutation({
    mutationFn: async (id: string) => soarApi.delete(`/playbooks/${id}`),
    onSuccess: () => {
      setPlaybookActionError(null);
      queryClient.invalidateQueries({ queryKey: ["playbooks"] });
    },
    onError: (err: unknown) => setPlaybookActionError(err),
  });

  const runPlaybook = useMutation({
    mutationFn: async (playbook: PlaybookOut) =>
      (await soarApi.post<PlaybookRunOut>(`/playbooks/${playbook.id}/run`, {})).data,
    onSuccess: (run, playbook) => {
      setRunFeedback({ playbookId: playbook.id, message: `Ejecucion "${run.status}" -- mira el detalle abajo en Ejecuciones.` });
      queryClient.invalidateQueries({ queryKey: ["runs"] });
    },
    onError: (err: unknown, playbook) => {
      setRunFeedback({
        playbookId: playbook.id,
        message: `No se pudo ejecutar el playbook. ${connectionErrorDetail(err)}`,
      });
    },
  });

  function addStep() {
    setSteps((prev) => [...prev, { action: draftAction, params: draftParams }]);
    setDraftParams({});
  }

  function onSubmit() {
    setFormError(null);
    if (!name.trim()) {
      setFormError("Ingresa un nombre para el playbook.");
      return;
    }
    if (steps.length === 0) {
      setFormError("Agrega al menos un paso.");
      return;
    }
    createPlaybook.mutate();
  }

  const activeFields = ACTIONS.find((a) => a.value === draftAction)?.fields ?? [];
  const enabledCount = (playbooks.data ?? []).filter((p) => p.is_enabled).length;
  const successRuns = (runs.data ?? []).filter((r) => r.status === "completed").length;
  const failedRuns = (runs.data ?? []).filter((r) => r.status === "failed").length;

  return (
    <div>
      <PageHeader
        title="SOAR"
        subtitle="Playbooks de respuesta automatizada. Todas las acciones de contencion corren en modo DRY-RUN salvo que un operador lo desactive explicitamente."
      />

      <div className="cards-grid">
        <div className="stat-card">
          <span className="stat-label">Playbooks</span>
          <span className="stat-value">{enabledCount} / {playbooks.data?.length ?? 0}</span>
          <span className="stat-hint">habilitados / totales</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Ejecuciones totales</span>
          <span className="stat-value">{runs.data?.length ?? "-"}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Exitosas</span>
          <span className="stat-value">{successRuns}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Fallidas</span>
          <span className="stat-value">{failedRuns}</span>
        </div>
      </div>

      <div className="panel">
        <h2>Nuevo playbook</h2>
        <div className="inline-form">
          <input placeholder="Nombre" value={name} onChange={(e) => setName(e.target.value)} />
          <select value={minSeverity} onChange={(e) => setMinSeverity(e.target.value)}>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <input
            placeholder="Tags de regla (separados por coma, opcional)"
            value={ruleTags}
            onChange={(e) => setRuleTags(e.target.value)}
          />
        </div>
        <input
          placeholder="Descripcion"
          style={{ width: "100%", marginTop: 8 }}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />

        <div style={{ marginTop: 12 }}>
          <strong>Pasos:</strong>
          {steps.length > 0 && (
            <ol>
              {steps.map((s, idx) => (
                <li key={idx}>
                  {actionLabel(s.action)}
                  {Object.entries(s.params).some(([, v]) => v) && (
                    <span className="empty-hint"> ({Object.entries(s.params).filter(([, v]) => v).map(([k, v]) => `${k}=${v}`).join(", ")})</span>
                  )}
                  <button className="btn-link" onClick={() => setSteps((prev) => prev.filter((_, i) => i !== idx))}>Quitar</button>
                </li>
              ))}
            </ol>
          )}

          <div className="inline-form" style={{ marginTop: 6 }}>
            <select
              value={draftAction}
              onChange={(e) => {
                setDraftAction(e.target.value);
                setDraftParams({});
              }}
            >
              {ACTIONS.map((a) => (
                <option key={a.value} value={a.value}>{a.label}</option>
              ))}
            </select>
          </div>
          {activeFields.map((f) => (
            <input
              key={f.key}
              placeholder={f.label}
              style={{ width: "100%", marginTop: 6 }}
              value={draftParams[f.key] ?? ""}
              onChange={(e) => setDraftParams((prev) => ({ ...prev, [f.key]: e.target.value }))}
            />
          ))}
          <button type="button" className="btn-secondary" style={{ marginTop: 8 }} onClick={addStep}>
            + Agregar paso
          </button>
        </div>

        <div style={{ marginTop: 12 }}>
          <button className="btn-primary" onClick={onSubmit} disabled={createPlaybook.isPending}>
            {createPlaybook.isPending ? "Creando..." : "Crear playbook"}
          </button>
        </div>
        {formError && <p className="error-text">{formError}</p>}
        {createPlaybook.isError && !formError && (
          <p className="error-text">
            No se pudo crear el playbook.{" "}
            <span className="error-detail">{connectionErrorDetail(createPlaybook.error)}</span>
          </p>
        )}
      </div>

      <div className="panel">
        <h2>Playbooks</h2>
        {playbooks.isError && (
          <p className="error-text">
            No se pudo conectar con soar-service.{" "}
            <span className="error-detail">{connectionErrorDetail(playbooks.error)}</span>
          </p>
        )}
        {playbooks.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Severidad minima</th>
                <th>Tags de regla</th>
                <th>Pasos</th>
                <th>Habilitado</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {playbooks.data.map((p) => {
                const isGlobal = isGlobalPlaybook(p);
                const canManage = !isGlobal || isPlatformAdmin;
                const globalHint = "Playbook global (cargado desde YAML) -- solo un administrador de plataforma puede habilitarlo/deshabilitarlo o eliminarlo.";
                return (
                  <tr key={p.id}>
                    <td>{p.name}</td>
                    <td>{p.min_severity}</td>
                    <td className="mono">{p.rule_tags.join(", ")}</td>
                    <td>{p.steps.map((s) => (s as { action?: string }).action).join(", ") || p.steps.length}</td>
                    <td>
                      <input
                        type="checkbox"
                        checked={p.is_enabled}
                        disabled={!canManage}
                        title={canManage ? undefined : globalHint}
                        onChange={(e) => togglePlaybook.mutate({ id: p.id, is_enabled: e.target.checked })}
                      />
                    </td>
                    <td>
                      <button
                        className="btn-link"
                        onClick={() => runPlaybook.mutate(p)}
                        disabled={runPlaybook.isPending}
                      >
                        Ejecutar ahora
                      </button>
                      {canManage && (
                        <>
                          {" / "}
                          <button className="btn-link" onClick={() => deletePlaybook.mutate(p.id)}>Eliminar</button>
                        </>
                      )}
                      {isGlobal && !isPlatformAdmin && (
                        <span className="empty-hint" title={globalHint}> (global)</span>
                      )}
                      {runFeedback && runFeedback.playbookId === p.id && (
                        <p className="empty-hint" style={{ margin: "4px 0 0" }}>{runFeedback.message}</p>
                      )}
                    </td>
                  </tr>
                );
              })}
              {playbooks.data.length === 0 && (
                <tr><td colSpan={6} className="empty-hint">Sin playbooks cargados todavia.</td></tr>
              )}
            </tbody>
          </table>
        )}
        {playbookActionError != null && (
          <p className="error-text">
            No se pudo actualizar el playbook.{" "}
            <span className="error-detail">{connectionErrorDetail(playbookActionError)}</span>
          </p>
        )}
      </div>

      <div className="panel">
        <h2>Ejecuciones</h2>
        {runs.isLoading && <p className="empty-hint">Cargando...</p>}
        {runs.isError && (
          <p className="error-text">
            No se pudo conectar con soar-service.{" "}
            <span className="error-detail">{connectionErrorDetail(runs.error)}</span>
          </p>
        )}
        {runs.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Playbook</th>
                <th>Estado</th>
                <th>Disparado por</th>
                <th>Creada</th>
              </tr>
            </thead>
            <tbody>
              {runs.data.map((r) => (
                <tr key={r.id}>
                  <td>{r.playbook_name}</td>
                  <td><StatusBadge value={r.status} /></td>
                  <td>{r.triggered_by}</td>
                  <td>{new Date(r.created_at).toLocaleString()}</td>
                </tr>
              ))}
              {runs.data.length === 0 && (
                <tr><td colSpan={4} className="empty-hint">Sin ejecuciones todavia.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
