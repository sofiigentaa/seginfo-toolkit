import { Fragment, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { scanApi, vulnApi } from "../services/api";
import type { ScanJobOut, ScanScheduleOut, ScanAgentOut, ScanAgentCreated, AgentScanJobOut, VulnerabilityOut } from "../types";
import PageHeader from "../components/PageHeader";
import { SeverityBadge, StatusBadge } from "../components/Badge";
import { connectionErrorDetail } from "../utils/errors";

const DAY_LABELS = ["Lunes", "Martes", "Miercoles", "Jueves", "Viernes", "Sabado", "Domingo"];

function scheduleWhen(s: ScanScheduleOut): string {
  const time = `${String(s.hour).padStart(2, "0")}:${String(s.minute).padStart(2, "0")}`;
  if (s.frequency === "weekly") {
    return `Todos los ${DAY_LABELS[s.day_of_week ?? 0]} a las ${time}`;
  }
  return `Todos los dias a las ${time}`;
}

type ScannerType = "nmap" | "trivy" | "nuclei" | "openvas";
type NmapMode = "fast" | "full";
type NetworkScope = "lan" | "man" | "wan" | "custom";

const SCOPE_LABELS: Record<NetworkScope, string> = {
  lan: "LAN (red local de la oficina/sede)",
  man: "MAN (enlace entre sedes/edificios)",
  wan: "WAN (internet / IPs publicas)",
  custom: "Personalizado",
};

// Rangos privados (RFC1918) mas comunes -- pensados como punto de partida
// para cubrir una red LAN tipica sin que el usuario tenga que saber de
// memoria la notacion CIDR. Siempre editable antes de lanzar el escaneo.
const LAN_PRESETS = ["192.168.0.0/24", "192.168.1.0/24", "10.0.0.0/24", "172.16.0.0/24"];

const TERMINAL_STATUSES = new Set(["completed", "failed", "scanner_unavailable", "cancelled"]);
const CANCELLABLE_STATUSES = new Set(["pending", "running"]);

function scopeOf(job: ScanJobOut): string {
  const raw = job.options?.network_scope;
  return typeof raw === "string" && raw in SCOPE_LABELS ? raw : "-";
}

function packageLine(v: VulnerabilityOut): string | null {
  if (!v.package) return null;
  let line = v.package;
  if (v.installed_version) line += ` (${v.installed_version}`;
  if (v.fixed_version) line += ` -> ${v.fixed_version}`;
  if (v.installed_version) line += ")";
  return line;
}

// Resultados enriquecidos (severidad, CVSS/EPSS/KEV, remediacion sugerida)
// de UN escaneo puntual -- vuln-service ya hace todo ese trabajo (ver
// pagina Vulnerabilidades); esto solo lo consulta filtrado por
// scan_job_id y lo muestra en el lugar donde el escaneo se lanzo, para no
// tener que ir a buscar "que encontro" a otra pagina. Componente separado
// para poder llamar useQuery solo cuando la fila esta expandida (nunca se
// monta si el escaneo no se abrio).
function ScanResultsPanel({
  scanJobId,
  status,
  errorMessage,
}: {
  scanJobId: string;
  status: string;
  errorMessage: string;
}) {
  const isCompleted = status === "completed";
  const isTerminalFailure = status === "failed" || status === "scanner_unavailable";
  const isCancelled = status === "cancelled";

  const results = useQuery({
    queryKey: ["scan-vulnerabilities", scanJobId],
    queryFn: async () =>
      (await vulnApi.get<VulnerabilityOut[]>("/vulnerabilities", { params: { scan_job_id: scanJobId } })).data,
    enabled: isCompleted,
  });

  if (isCancelled) {
    return <p className="empty-hint">Este escaneo fue cancelado -- no hay resultados.</p>;
  }
  if (isTerminalFailure) {
    return (
      <p className="error-text">
        El escaneo fallo, no hay resultados. <span className="error-detail">{errorMessage || "Sin detalle del error."}</span>
      </p>
    );
  }
  if (!isCompleted) {
    return <p className="empty-hint">El escaneo todavia esta en curso -- los resultados aparecen aca cuando termine.</p>;
  }
  if (results.isLoading) {
    return <p className="empty-hint">Cargando resultados...</p>;
  }
  if (results.isError) {
    return (
      <p className="error-text">
        No se pudo conectar con vuln-service para traer los resultados enriquecidos.{" "}
        <span className="error-detail">{connectionErrorDetail(results.error)}</span>
      </p>
    );
  }
  if (!results.data || results.data.length === 0) {
    return <p className="empty-hint">Este escaneo no encontro hallazgos.</p>;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {results.data.map((v) => {
        const pkgLine = packageLine(v);
        return (
          <div key={v.id} className="panel" style={{ background: "rgba(0,0,0,0.03)" }}>
            <div className="inline-form" style={{ alignItems: "center" }}>
              <SeverityBadge value={v.severity} />
              <strong>{v.title}</strong>
              {v.cve_id && <span className="mono">{v.cve_id}</span>}
            </div>
            {(pkgLine || v.port != null) && (
              <p className="empty-hint" style={{ marginTop: 4, marginBottom: 4 }}>
                {pkgLine && <>Paquete: {pkgLine}. </>}
                {v.port != null && <>Puerto: {v.port}{v.service && ` (${v.service})`}.</>}
              </p>
            )}
            {v.description && <p style={{ marginTop: 4, marginBottom: 4 }}>{v.description}</p>}
            <strong style={{ display: "block", marginTop: 6 }}>Remediacion sugerida:</strong>
            <ul style={{ marginTop: 4, marginBottom: 0 }}>
              {v.remediation_steps.map((step, idx) => (
                <li key={idx}>{step}</li>
              ))}
            </ul>
          </div>
        );
      })}
    </div>
  );
}

export default function Scans() {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [scannerType, setScannerType] = useState<ScannerType>("nmap");
  const [scope, setScope] = useState<NetworkScope>("lan");
  const [nmapMode, setNmapMode] = useState<NmapMode>("full");
  const [targetsText, setTargetsText] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<{ ok: number; failed: number } | null>(null);

  const [schedName, setSchedName] = useState("");
  const [schedScannerType, setSchedScannerType] = useState<ScannerType>("nmap");
  const [schedTarget, setSchedTarget] = useState("");
  const [schedFrequency, setSchedFrequency] = useState<"daily" | "weekly">("daily");
  const [schedDayOfWeek, setSchedDayOfWeek] = useState(0);
  const [schedHour, setSchedHour] = useState(3);
  const [schedMinute, setSchedMinute] = useState(0);

  const [agentName, setAgentName] = useState("");
  const [justCreatedKey, setJustCreatedKey] = useState<{ agentName: string; apiKey: string } | null>(null);
  const [agentJobAgentId, setAgentJobAgentId] = useState("");
  const [agentJobName, setAgentJobName] = useState("");
  const [agentJobTarget, setAgentJobTarget] = useState("");

  // Errores de acciones sobre filas ya existentes (togglear/borrar) --
  // separado de formError/createX.isError, que son solo para los
  // formularios de arriba de cada tabla.
  const [scheduleActionError, setScheduleActionError] = useState<unknown>(null);
  const [agentActionError, setAgentActionError] = useState<unknown>(null);
  const [scanActionError, setScanActionError] = useState<unknown>(null);
  const [agentScanActionError, setAgentScanActionError] = useState<unknown>(null);

  // Fila expandida (a lo sumo una por tabla) mostrando los resultados
  // completos del escaneo -- severidad, CVSS/EPSS/KEV y remediacion
  // sugerida, via ScanResultsPanel.
  const [expandedScanId, setExpandedScanId] = useState<string | null>(null);
  const [expandedAgentScanId, setExpandedAgentScanId] = useState<string | null>(null);

  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: async () => (await scanApi.get<ScanJobOut[]>("/scans")).data,
  });

  const schedules = useQuery({
    queryKey: ["scan-schedules"],
    queryFn: async () => (await scanApi.get<ScanScheduleOut[]>("/scan-schedules")).data,
  });

  const createSchedule = useMutation({
    mutationFn: async () =>
      (
        await scanApi.post<ScanScheduleOut>("/scan-schedules", {
          name: schedName,
          scanner_type: schedScannerType,
          target: schedTarget,
          frequency: schedFrequency,
          hour: schedHour,
          minute: schedMinute,
          day_of_week: schedFrequency === "weekly" ? schedDayOfWeek : null,
        })
      ).data,
    onSuccess: () => {
      setSchedName("");
      setSchedTarget("");
      queryClient.invalidateQueries({ queryKey: ["scan-schedules"] });
    },
  });

  const toggleSchedule = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) =>
      (await scanApi.patch<ScanScheduleOut>(`/scan-schedules/${id}`, { enabled })).data,
    onSuccess: () => {
      setScheduleActionError(null);
      queryClient.invalidateQueries({ queryKey: ["scan-schedules"] });
    },
    onError: (err: unknown) => setScheduleActionError(err),
  });

  const deleteSchedule = useMutation({
    mutationFn: async (id: string) => scanApi.delete(`/scan-schedules/${id}`),
    onSuccess: () => {
      setScheduleActionError(null);
      queryClient.invalidateQueries({ queryKey: ["scan-schedules"] });
    },
    onError: (err: unknown) => setScheduleActionError(err),
  });

  const agents = useQuery({
    queryKey: ["scan-agents"],
    queryFn: async () => (await scanApi.get<ScanAgentOut[]>("/agents")).data,
  });

  const agentScans = useQuery({
    queryKey: ["agent-scans"],
    queryFn: async () => (await scanApi.get<AgentScanJobOut[]>("/agent-scans")).data,
    refetchInterval: 10_000, // los jobs de agente avanzan por polling del lado del agente, no en el momento
  });

  const createAgent = useMutation({
    mutationFn: async () => (await scanApi.post<ScanAgentCreated>("/agents", { name: agentName })).data,
    onSuccess: (created) => {
      setJustCreatedKey({ agentName: created.name, apiKey: created.api_key });
      setAgentName("");
      queryClient.invalidateQueries({ queryKey: ["scan-agents"] });
    },
  });

  const deleteAgent = useMutation({
    mutationFn: async (id: string) => scanApi.delete(`/agents/${id}`),
    onSuccess: () => {
      setAgentActionError(null);
      queryClient.invalidateQueries({ queryKey: ["scan-agents"] });
      queryClient.invalidateQueries({ queryKey: ["agent-scans"] });
    },
    onError: (err: unknown) => setAgentActionError(err),
  });

  const createAgentScan = useMutation({
    mutationFn: async () =>
      (
        await scanApi.post<AgentScanJobOut>("/agent-scans", {
          agent_id: agentJobAgentId,
          name: agentJobName,
          target: agentJobTarget,
        })
      ).data,
    onSuccess: () => {
      setAgentJobName("");
      setAgentJobTarget("");
      queryClient.invalidateQueries({ queryKey: ["agent-scans"] });
    },
  });

  const deleteScan = useMutation({
    mutationFn: async (id: string) => scanApi.delete(`/scans/${id}`),
    onSuccess: () => {
      setScanActionError(null);
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
    onError: (err: unknown) => setScanActionError(err),
  });

  const cancelScan = useMutation({
    mutationFn: async (id: string) => (await scanApi.post<ScanJobOut>(`/scans/${id}/cancel`)).data,
    onSuccess: () => {
      setScanActionError(null);
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
    onError: (err: unknown) => setScanActionError(err),
  });

  const deleteAgentScan = useMutation({
    mutationFn: async (id: string) => scanApi.delete(`/agent-scans/${id}`),
    onSuccess: () => {
      setAgentScanActionError(null);
      queryClient.invalidateQueries({ queryKey: ["agent-scans"] });
    },
    onError: (err: unknown) => setAgentScanActionError(err),
  });

  const createScans = useMutation({
    mutationFn: async () => {
      const targets = targetsText
        .split(/[\n,]/)
        .map((t) => t.trim())
        .filter(Boolean);
      if (targets.length === 0) {
        throw new Error("Ingresa al menos una IP, rango CIDR o hostname.");
      }
      const results = await Promise.allSettled(
        targets.map((target) =>
          scanApi.post("/scans", {
            name: name || `Escaneo ${SCOPE_LABELS[scope]}`,
            scanner_type: scannerType,
            target,
            options: scannerType === "nmap" ? { network_scope: scope, mode: nmapMode } : { network_scope: scope },
          })
        )
      );
      const ok = results.filter((r) => r.status === "fulfilled").length;
      const failed = results.length - ok;
      return { ok, failed };
    },
    onSuccess: (summary) => {
      setLastResult(summary);
      setFormError(null);
      if (summary.failed === 0) {
        setTargetsText("");
      }
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
    onError: (err: unknown) => {
      setFormError(err instanceof Error ? err.message : "No se pudo crear el escaneo.");
    },
  });

  return (
    <div>
      <PageHeader
        title="Escaneos"
        subtitle="Orquestacion de escaneres defensivos (Nmap/Trivy/Nuclei/OpenVAS) -- deteccion, nunca explotacion"
      />

      <div className="panel">
        <h2>Nuevo escaneo</h2>
        <p className="empty-hint">
          Un escaneo por linea de destino. Acepta una IP suelta, un rango CIDR (ej. 192.168.1.0/24) o un hostname --
          usa el ambito para documentar si es red local, entre sedes o internet.
        </p>

        <div className="inline-form">
          <input placeholder="Nombre (opcional)" value={name} onChange={(e) => setName(e.target.value)} />
          <select value={scannerType} onChange={(e) => setScannerType(e.target.value as ScannerType)}>
            <option value="nmap">nmap (descubrimiento de puertos/servicios)</option>
            <option value="trivy">trivy (imagenes/paquetes)</option>
            <option value="nuclei">nuclei (plantillas de deteccion)</option>
            <option value="openvas">openvas</option>
          </select>
          <select value={scope} onChange={(e) => setScope(e.target.value as NetworkScope)}>
            {Object.entries(SCOPE_LABELS).map(([value, label]) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>
          {scannerType === "nmap" && (
            <select
              value={nmapMode}
              onChange={(e) => setNmapMode(e.target.value as NmapMode)}
              title="Rapido: sin scripts NSE, top-100 puertos, mas veloz. Completo: deteccion de version + scripts NSE seguros, mas lento y mas exhaustivo."
            >
              <option value="fast">nmap rapido (top-100 puertos, sin scripts, mas veloz)</option>
              <option value="full">nmap completo (deteccion + scripts seguros, mas lento)</option>
            </select>
          )}
        </div>

        {(scope === "lan" || scope === "man") && (
          <div className="panel" style={{ marginTop: 8, marginBottom: 8, border: "1px solid #d9a900" }}>
            <p style={{ margin: 0 }}>
              <strong>Este escaneo corre DENTRO del contenedor Docker, no en la red real de esta PC.</strong> Docker
              Desktop aisla al contenedor detras de NAT, asi que salvo que Docker tenga acceso directo a esa red, no
              va a llegar a los dispositivos de tu {scope === "lan" ? "LAN" : "MAN"} y el escaneo va a terminar en
              timeout despues de un par de minutos. Para escanear la red real de la oficina/sede, usa{" "}
              <strong>"Escaneos remotos"</strong> mas abajo: un agente liviano corre fuera de Docker (en esta PC o en
              cualquier otra con visibilidad a esa red) y hace polling hacia scan-service, sin que haga falta abrir
              ningun puerto.
            </p>
          </div>
        )}

        <textarea
          className="targets-textarea"
          placeholder={"192.168.1.0/24\n10.0.0.15\nvpn.tuempresa.com"}
          value={targetsText}
          onChange={(e) => setTargetsText(e.target.value)}
          rows={4}
          style={{ width: "100%", marginTop: 8, fontFamily: "monospace" }}
        />

        {scope === "lan" && (
          <button
            type="button"
            className="btn-secondary"
            style={{ marginTop: 8 }}
            onClick={() =>
              setTargetsText((prev) => {
                const existing = new Set(prev.split(/[\n,]/).map((t) => t.trim()).filter(Boolean));
                LAN_PRESETS.forEach((p) => existing.add(p));
                return Array.from(existing).join("\n");
              })
            }
          >
            + Agregar rangos privados comunes (para cubrir toda la LAN)
          </button>
        )}

        <div style={{ marginTop: 10 }}>
          <button
            className="btn-primary"
            onClick={() => createScans.mutate()}
            disabled={createScans.isPending || !targetsText.trim()}
          >
            {createScans.isPending ? "Creando..." : "Lanzar escaneo(s)"}
          </button>
        </div>

        {formError && <p className="error-text">{formError}</p>}
        {lastResult && !formError && (
          <p className={lastResult.failed > 0 ? "error-text" : "empty-hint"}>
            {lastResult.ok} escaneo(s) creado(s){lastResult.failed > 0 ? `, ${lastResult.failed} fallaron` : ""}.
          </p>
        )}
      </div>

      <div className="panel">
        <h2>Escaneos programados</h2>
        <p className="empty-hint">
          Una regla corre solo mientras scan-service este arriba (usa su propio scheduler en proceso, sin
          infraestructura extra) -- si el contenedor se reinicia, las reglas habilitadas se vuelven a cargar solas
          al arrancar.
        </p>

        <div className="inline-form">
          <input placeholder="Nombre" value={schedName} onChange={(e) => setSchedName(e.target.value)} />
          <select value={schedScannerType} onChange={(e) => setSchedScannerType(e.target.value as ScannerType)}>
            <option value="nmap">nmap</option>
            <option value="trivy">trivy</option>
            <option value="nuclei">nuclei</option>
            <option value="openvas">openvas</option>
          </select>
          <input
            className="mono"
            placeholder="Target (IP, CIDR, host, imagen segun el scanner)"
            value={schedTarget}
            onChange={(e) => setSchedTarget(e.target.value)}
          />
        </div>
        <div className="inline-form" style={{ marginTop: 8 }}>
          <select value={schedFrequency} onChange={(e) => setSchedFrequency(e.target.value as "daily" | "weekly")}>
            <option value="daily">Todos los dias</option>
            <option value="weekly">Un dia a la semana</option>
          </select>
          {schedFrequency === "weekly" && (
            <select value={schedDayOfWeek} onChange={(e) => setSchedDayOfWeek(Number(e.target.value))}>
              {DAY_LABELS.map((label, idx) => (
                <option key={label} value={idx}>{label}</option>
              ))}
            </select>
          )}
          <input
            type="number" min={0} max={23} style={{ width: 60 }}
            value={schedHour} onChange={(e) => setSchedHour(Number(e.target.value))}
          />
          <span>:</span>
          <input
            type="number" min={0} max={59} style={{ width: 60 }}
            value={schedMinute} onChange={(e) => setSchedMinute(Number(e.target.value))}
          />
          <button
            className="btn-primary"
            onClick={() => createSchedule.mutate()}
            disabled={createSchedule.isPending || !schedTarget.trim()}
          >
            {createSchedule.isPending ? "Creando..." : "Crear regla"}
          </button>
        </div>
        {createSchedule.isError && (
          <p className="error-text">
            No se pudo crear la regla.{" "}
            <span className="error-detail">{connectionErrorDetail(createSchedule.error)}</span>
          </p>
        )}

        {schedules.data && schedules.data.length > 0 && (
          <table className="data-table" style={{ marginTop: 12 }}>
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Tipo</th>
                <th>Target</th>
                <th>Cuando</th>
                <th>Ultima corrida</th>
                <th>Habilitada</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {schedules.data.map((s) => (
                <tr key={s.id}>
                  <td>{s.name || "-"}</td>
                  <td>{s.scanner_type}</td>
                  <td className="mono">{s.target}</td>
                  <td>{scheduleWhen(s)}</td>
                  <td>
                    {s.last_run_at ? new Date(s.last_run_at).toLocaleString() : "nunca"}
                    {s.last_status && <span className="error-detail">{s.last_status}</span>}
                  </td>
                  <td>
                    <input
                      type="checkbox"
                      checked={s.enabled}
                      onChange={(e) => toggleSchedule.mutate({ id: s.id, enabled: e.target.checked })}
                    />
                  </td>
                  <td>
                    <button className="btn-link" onClick={() => deleteSchedule.mutate(s.id)}>Eliminar</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {scheduleActionError != null && (
          <p className="error-text">
            No se pudo actualizar la regla.{" "}
            <span className="error-detail">{connectionErrorDetail(scheduleActionError)}</span>
          </p>
        )}
        {schedules.isError && (
          <p className="error-text">
            No se pudo conectar con scan-service.{" "}
            <span className="error-detail">{connectionErrorDetail(schedules.error)}</span>
          </p>
        )}
      </div>

      <div className="panel">
        <h2>Agentes de escaneo remoto</h2>
        <p className="empty-hint">
          Docker Desktop aisla a los contenedores detras de NAT: scan-service no llega a la LAN real de la
          oficina/cliente aunque este instalado ahi. Un agente (script Python liviano, ver carpeta remote-agent/ en
          la raiz del repo) corre FUERA de Docker -- en esta PC o en cualquier otra de la LAN -- y hace polling hacia
          este mismo puerto: no hace falta abrir ningun puerto de entrada. La api key se muestra UNA sola vez al
          registrar el agente.
        </p>

        <div className="inline-form">
          <input
            placeholder="Nombre del agente (ej. PC-oficina-recepcion)"
            value={agentName}
            onChange={(e) => setAgentName(e.target.value)}
          />
          <button
            className="btn-primary"
            onClick={() => createAgent.mutate()}
            disabled={createAgent.isPending || !agentName.trim()}
          >
            {createAgent.isPending ? "Registrando..." : "Registrar agente"}
          </button>
        </div>
        {createAgent.isError && (
          <p className="error-text">
            No se pudo registrar el agente.{" "}
            <span className="error-detail">{connectionErrorDetail(createAgent.error)}</span>
          </p>
        )}

        {justCreatedKey && (
          <div className="panel" style={{ marginTop: 8, border: "1px solid #d9a900" }}>
            <p>
              Agente <strong>{justCreatedKey.agentName}</strong> registrado. Copia esta api key ahora -- no se va a
              volver a mostrar (pegala en la variable <code className="mono">AGENT_API_KEY</code> al configurar
              remote-agent/agent.py en la maquina donde va a correr el agente):
            </p>
            <p className="mono" style={{ wordBreak: "break-all", userSelect: "all" }}>{justCreatedKey.apiKey}</p>
            <button className="btn-secondary" onClick={() => setJustCreatedKey(null)}>Ya la copie</button>
          </div>
        )}

        {agents.data && agents.data.length > 0 && (
          <table className="data-table" style={{ marginTop: 12 }}>
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Registrado por</th>
                <th>Ultima vez visto</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {agents.data.map((a) => (
                <tr key={a.id}>
                  <td>{a.name}</td>
                  <td>{a.created_by || "-"}</td>
                  <td>{a.last_seen_at ? new Date(a.last_seen_at).toLocaleString() : "nunca (todavia no hizo polling)"}</td>
                  <td>
                    <button className="btn-link" onClick={() => deleteAgent.mutate(a.id)}>Eliminar</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {agentActionError != null && (
          <p className="error-text">
            No se pudo eliminar el agente.{" "}
            <span className="error-detail">{connectionErrorDetail(agentActionError)}</span>
          </p>
        )}
        {agents.isError && (
          <p className="error-text">
            No se pudo conectar con scan-service.{" "}
            <span className="error-detail">{connectionErrorDetail(agents.error)}</span>
          </p>
        )}
      </div>

      <div className="panel">
        <h2>Escaneos remotos</h2>
        <p className="empty-hint">
          Solo nmap por ahora (es lo unico que sabe correr remote-agent/agent.py). El agente elegido se lo lleva en
          su siguiente polling y manda el resultado solo -- puede tardar unos segundos segun su intervalo de
          polling configurado.
        </p>

        {agents.data && agents.data.length === 0 && (
          <p className="empty-hint">No hay ningun agente registrado todavia (ver panel de arriba).</p>
        )}

        <div className="inline-form">
          <select value={agentJobAgentId} onChange={(e) => setAgentJobAgentId(e.target.value)}>
            <option value="">Elegir agente...</option>
            {(agents.data ?? []).map((a) => (
              <option key={a.id} value={a.id}>{a.name}</option>
            ))}
          </select>
          <input placeholder="Nombre (opcional)" value={agentJobName} onChange={(e) => setAgentJobName(e.target.value)} />
          <input
            className="mono"
            placeholder="Target (IP, CIDR, host visible desde el agente)"
            value={agentJobTarget}
            onChange={(e) => setAgentJobTarget(e.target.value)}
          />
          <button
            className="btn-primary"
            onClick={() => createAgentScan.mutate()}
            disabled={createAgentScan.isPending || !agentJobAgentId || !agentJobTarget.trim()}
          >
            {createAgentScan.isPending ? "Creando..." : "Lanzar escaneo remoto"}
          </button>
        </div>
        {createAgentScan.isError && (
          <p className="error-text">
            No se pudo crear el escaneo remoto.{" "}
            <span className="error-detail">{connectionErrorDetail(createAgentScan.error)}</span>
          </p>
        )}

        {agentScans.data && (
          <table className="data-table" style={{ marginTop: 12 }}>
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Agente</th>
                <th>Target</th>
                <th>Estado</th>
                <th>Hallazgos</th>
                <th>Creado</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {agentScans.data.map((j) => (
                <Fragment key={j.id}>
                  <tr>
                    <td>{j.name || "-"}</td>
                    <td>{(agents.data ?? []).find((a) => a.id === j.agent_id)?.name ?? j.agent_id}</td>
                    <td className="mono">{j.target}</td>
                    <td>
                      <StatusBadge value={j.status} />
                      {j.error_message && <span className="error-detail">{j.error_message}</span>}
                    </td>
                    <td>{j.findings.length}</td>
                    <td>{new Date(j.created_at).toLocaleString()}</td>
                    <td>
                      <button
                        className="btn-link"
                        onClick={() => setExpandedAgentScanId(expandedAgentScanId === j.id ? null : j.id)}
                      >
                        {expandedAgentScanId === j.id ? "Ocultar resultados" : "Ver resultados"}
                      </button>
                      {TERMINAL_STATUSES.has(j.status) && (
                        <button className="btn-link" onClick={() => deleteAgentScan.mutate(j.id)}>Eliminar</button>
                      )}
                    </td>
                  </tr>
                  {expandedAgentScanId === j.id && (
                    <tr key={`${j.id}-detail`}>
                      <td colSpan={7} className="panel" style={{ background: "rgba(0,0,0,0.03)" }}>
                        <ScanResultsPanel scanJobId={j.id} status={j.status} errorMessage={j.error_message} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
              {agentScans.data.length === 0 && (
                <tr><td colSpan={7} className="empty-hint">Sin escaneos remotos todavia.</td></tr>
              )}
            </tbody>
          </table>
        )}
        {agentScanActionError != null && (
          <p className="error-text">
            No se pudo eliminar el escaneo remoto.{" "}
            <span className="error-detail">{connectionErrorDetail(agentScanActionError)}</span>
          </p>
        )}
        {agentScans.isError && (
          <p className="error-text">
            No se pudo conectar con scan-service.{" "}
            <span className="error-detail">{connectionErrorDetail(agentScans.error)}</span>
          </p>
        )}
      </div>

      <div className="panel">
        <h2>Escaneos realizados</h2>
        {scans.isLoading && <p className="empty-hint">Cargando...</p>}
        {scans.isError && (
          <p className="error-text">
            No se pudo conectar con scan-service.{" "}
            <span className="error-detail">{connectionErrorDetail(scans.error)}</span>
          </p>
        )}
        {scans.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Tipo</th>
                <th>Target</th>
                <th>Ambito</th>
                <th>Estado</th>
                <th>Hallazgos</th>
                <th>Creado</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {scans.data.map((s) => (
                <Fragment key={s.id}>
                  <tr>
                    <td>{s.name}</td>
                    <td>{s.scanner_type}</td>
                    <td className="mono">{s.target}</td>
                    <td>{scopeOf(s)}</td>
                    <td>
                      <StatusBadge value={s.status} />
                      {s.error_message && (
                        <span className="error-detail">{s.error_message}</span>
                      )}
                    </td>
                    <td>{s.findings.length}</td>
                    <td>{new Date(s.created_at).toLocaleString()}</td>
                    <td>
                      <button className="btn-link" onClick={() => setExpandedScanId(expandedScanId === s.id ? null : s.id)}>
                        {expandedScanId === s.id ? "Ocultar resultados" : "Ver resultados"}
                      </button>
                      {CANCELLABLE_STATUSES.has(s.status) && (
                        <button
                          className="btn-link"
                          disabled={cancelScan.isPending}
                          onClick={() => cancelScan.mutate(s.id)}
                        >
                          Cancelar
                        </button>
                      )}
                      {TERMINAL_STATUSES.has(s.status) && (
                        <button className="btn-link" onClick={() => deleteScan.mutate(s.id)}>Eliminar</button>
                      )}
                    </td>
                  </tr>
                  {expandedScanId === s.id && (
                    <tr key={`${s.id}-detail`}>
                      <td colSpan={8} className="panel" style={{ background: "rgba(0,0,0,0.03)" }}>
                        <ScanResultsPanel scanJobId={s.id} status={s.status} errorMessage={s.error_message} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
              {scans.data.length === 0 && (
                <tr><td colSpan={8} className="empty-hint">Sin escaneos ejecutados todavia.</td></tr>
              )}
            </tbody>
          </table>
        )}
        {scanActionError != null && (
          <p className="error-text">
            No se pudo eliminar el escaneo.{" "}
            <span className="error-detail">{connectionErrorDetail(scanActionError)}</span>
          </p>
        )}
      </div>
    </div>
  );
}
