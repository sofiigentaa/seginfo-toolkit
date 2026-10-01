import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { reportApi, notificationApi } from "../services/api";
import { useAuthStore } from "../store/auth";
import type { GeneratedReportOut, ReportScheduleOut, ChannelOut } from "../types";
import PageHeader from "../components/PageHeader";
import { connectionErrorDetail, blobExportErrorDetail } from "../utils/errors";

// Mismo criterio que require_role("admin", "soc_manager") en
// POST/PATCH/DELETE /report-schedules (report-service/app/main.py) --
// sin este chequeo, cualquier usuario logueado veia los controles de
// "Reportes programados" igual y solo se enteraba de que no podia usarlos
// por un 403 (silencioso en toggle/borrar, ver los onError de mas abajo).
const CAN_MANAGE_SCHEDULES = ["admin", "soc_manager"];

const REPORT_TYPES = [
  { value: "executive_summary", label: "Resumen ejecutivo" },
  { value: "vulnerabilities", label: "Vulnerabilidades" },
  { value: "incidents", label: "Incidentes" },
  { value: "attack_coverage", label: "Cobertura ATT&CK" },
];

const DAY_LABELS = ["Lunes", "Martes", "Miercoles", "Jueves", "Viernes", "Sabado", "Domingo"];

function scheduleWhen(s: ReportScheduleOut): string {
  const time = `${String(s.hour).padStart(2, "0")}:${String(s.minute).padStart(2, "0")}`;
  if (s.frequency === "weekly") {
    return `Todos los ${DAY_LABELS[s.day_of_week ?? 0]} a las ${time}`;
  }
  return `Todos los dias a las ${time}`;
}

async function downloadExport(reportId: string, format: "csv" | "pdf") {
  const response = await reportApi.get(`/reports/${reportId}/export`, {
    params: { format },
    responseType: "blob",
  });
  const url = window.URL.createObjectURL(
    new Blob([response.data], { type: format === "pdf" ? "application/pdf" : "text/csv" }),
  );
  const link = document.createElement("a");
  link.href = url;
  link.setAttribute("download", `reporte-${reportId}.${format}`);
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
}

export default function Reports() {
  const [reportType, setReportType] = useState(REPORT_TYPES[0].value);
  const queryClient = useQueryClient();

  const claims = useAuthStore((s) => s.claims);
  const canManageSchedules = !!claims?.role && CAN_MANAGE_SCHEDULES.includes(claims.role);

  const [schedReportType, setSchedReportType] = useState(REPORT_TYPES[0].value);
  const [schedChannelId, setSchedChannelId] = useState("");
  const [schedFrequency, setSchedFrequency] = useState<"daily" | "weekly">("daily");
  const [schedDayOfWeek, setSchedDayOfWeek] = useState(0);
  const [schedHour, setSchedHour] = useState(8);
  const [schedMinute, setSchedMinute] = useState(0);

  const reports = useQuery({
    queryKey: ["reports"],
    queryFn: async () => (await reportApi.get<GeneratedReportOut[]>("/reports")).data,
  });

  const channels = useQuery({
    queryKey: ["notification-channels"],
    queryFn: async () => (await notificationApi.get<ChannelOut[]>("/channels")).data,
  });
  const emailChannels = (channels.data ?? []).filter((c) => c.channel_type === "email" && c.enabled);

  const schedules = useQuery({
    queryKey: ["report-schedules"],
    queryFn: async () => (await reportApi.get<ReportScheduleOut[]>("/report-schedules")).data,
  });

  const generate = useMutation({
    mutationFn: async () => (await reportApi.post<GeneratedReportOut>("/reports/generate", { report_type: reportType })).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["reports"] }),
  });

  const deleteReport = useMutation({
    mutationFn: async (id: string) => reportApi.delete(`/reports/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["reports"] }),
  });

  // Antes, los botones CSV/PDF llamaban a downloadCsv/downloadPdf
  // directamente (funciones async sueltas, sin mutation): si la
  // exportacion fallaba (ej. reportlab tira una excepcion armando el PDF,
  // o el report-service esta caido) quedaba como una promesa rechazada
  // sin manejar -- el usuario hacia click en "CSV"/"PDF" y no pasaba
  // nada, sin ningun mensaje de error.
  const [exportErrorState, setExportErrorState] = useState<string | null>(null);
  const exportReport = useMutation({
    mutationFn: async ({ id, format }: { id: string; format: "csv" | "pdf" }) => downloadExport(id, format),
    onMutate: () => setExportErrorState(null),
    onError: async (err) => setExportErrorState(await blobExportErrorDetail(err)),
  });

  const createSchedule = useMutation({
    mutationFn: async () =>
      (
        await reportApi.post<ReportScheduleOut>("/report-schedules", {
          report_type: schedReportType,
          notification_channel_id: schedChannelId,
          frequency: schedFrequency,
          hour: schedHour,
          minute: schedMinute,
          day_of_week: schedFrequency === "weekly" ? schedDayOfWeek : null,
        })
      ).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["report-schedules"] }),
  });

  const toggleSchedule = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) =>
      (await reportApi.patch<ReportScheduleOut>(`/report-schedules/${id}`, { enabled })).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["report-schedules"] }),
  });

  const deleteSchedule = useMutation({
    mutationFn: async (id: string) => reportApi.delete(`/report-schedules/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["report-schedules"] }),
  });

  return (
    <div>
      <PageHeader
        title="Reportes"
        subtitle="Reportes ejecutivos y de cumplimiento generados 100% a partir de datos de otros servicios -- nunca datos inventados"
      />

      <div className="panel">
        <div className="inline-form">
          <select value={reportType} onChange={(e) => setReportType(e.target.value)}>
            {REPORT_TYPES.map((rt) => (
              <option key={rt.value} value={rt.value}>{rt.label}</option>
            ))}
          </select>
          <button className="btn-primary" onClick={() => generate.mutate()} disabled={generate.isPending}>
            {generate.isPending ? "Generando..." : "Generar reporte"}
          </button>
        </div>
        {generate.isError && (
          <p className="error-text">
            No se pudo generar el reporte.{" "}
            <span className="error-detail">{connectionErrorDetail(generate.error)}</span>
          </p>
        )}
      </div>

      <div className="panel">
        <h2>Historial</h2>
        {reports.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Tipo</th>
                <th>Generado por</th>
                <th>Errores</th>
                <th>Fecha</th>
                <th>Export</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {reports.data.map((r) => (
                <tr key={r.id}>
                  <td>{r.report_type}</td>
                  <td>{r.generated_by || "-"}</td>
                  <td>{r.errors.length > 0 ? r.errors.join("; ") : "-"}</td>
                  <td>{new Date(r.created_at).toLocaleString()}</td>
                  <td>
                    <button
                      className="btn-link"
                      onClick={() => exportReport.mutate({ id: r.id, format: "csv" })}
                      disabled={exportReport.isPending}
                    >
                      CSV
                    </button>
                    {" / "}
                    <button
                      className="btn-link"
                      onClick={() => exportReport.mutate({ id: r.id, format: "pdf" })}
                      disabled={exportReport.isPending}
                    >
                      PDF
                    </button>
                  </td>
                  <td>
                    <button className="btn-link" onClick={() => deleteReport.mutate(r.id)}>Eliminar</button>
                  </td>
                </tr>
              ))}
              {reports.data.length === 0 && (
                <tr><td colSpan={6} className="empty-hint">Sin reportes generados todavia.</td></tr>
              )}
            </tbody>
          </table>
        )}
        {deleteReport.isError && (
          <p className="error-text">
            No se pudo eliminar el reporte.{" "}
            <span className="error-detail">{connectionErrorDetail(deleteReport.error)}</span>
          </p>
        )}
        {exportErrorState && (
          <p className="error-text">
            No se pudo exportar el reporte.{" "}
            <span className="error-detail">{exportErrorState}</span>
          </p>
        )}
      </div>

      <div className="panel">
        <h2>Reportes programados</h2>
        <p className="empty-hint">
          Una regla genera el reporte solo y lo manda por email como PDF adjunto al canal elegido (necesita al menos
          un canal de notificaciones tipo "email" ya creado -- ver la pagina de Integraciones/Notificaciones). Corre
          mientras report-service este arriba (scheduler en proceso, sin infraestructura extra); si el contenedor se
          reinicia, las reglas habilitadas se vuelven a cargar solas al arrancar.
        </p>

        {emailChannels.length === 0 && (
          <p className="empty-hint">No hay ningun canal de notificaciones tipo "email" habilitado todavia.</p>
        )}

        {canManageSchedules ? (
          <>
            <div className="inline-form">
              <select value={schedReportType} onChange={(e) => setSchedReportType(e.target.value)}>
                {REPORT_TYPES.map((rt) => (
                  <option key={rt.value} value={rt.value}>{rt.label}</option>
                ))}
              </select>
              <select value={schedChannelId} onChange={(e) => setSchedChannelId(e.target.value)}>
                <option value="">Elegir canal de email...</option>
                {emailChannels.map((c) => (
                  <option key={c.id} value={c.id}>{c.name}</option>
                ))}
              </select>
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
                disabled={createSchedule.isPending || !schedChannelId}
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
          </>
        ) : (
          <p className="empty-hint">
            Tu usuario ({claims?.role ?? "sin rol"}) no puede crear ni administrar reglas de reporte programado -- lo
            puede hacer un admin o soc_manager.
          </p>
        )}

        {schedules.data && schedules.data.length > 0 && (
          <table className="data-table" style={{ marginTop: 12 }}>
            <thead>
              <tr>
                <th>Tipo</th>
                <th>Canal</th>
                <th>Cuando</th>
                <th>Ultima corrida</th>
                <th>Habilitada</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {schedules.data.map((s) => (
                <tr key={s.id}>
                  <td>{REPORT_TYPES.find((rt) => rt.value === s.report_type)?.label ?? s.report_type}</td>
                  <td>{(channels.data ?? []).find((c) => c.id === s.notification_channel_id)?.name ?? s.notification_channel_id}</td>
                  <td>{scheduleWhen(s)}</td>
                  <td>
                    {s.last_run_at ? new Date(s.last_run_at).toLocaleString() : "nunca"}
                    {s.last_status && <span className="error-detail">{s.last_status}</span>}
                  </td>
                  <td>
                    {canManageSchedules ? (
                      <input
                        type="checkbox"
                        checked={s.enabled}
                        onChange={(e) => toggleSchedule.mutate({ id: s.id, enabled: e.target.checked })}
                      />
                    ) : (
                      s.enabled ? "si" : "no"
                    )}
                  </td>
                  <td>
                    {canManageSchedules && (
                      <button className="btn-link" onClick={() => deleteSchedule.mutate(s.id)}>Eliminar</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {toggleSchedule.isError && (
          <p className="error-text">
            No se pudo actualizar la regla.{" "}
            <span className="error-detail">{connectionErrorDetail(toggleSchedule.error)}</span>
          </p>
        )}
        {deleteSchedule.isError && (
          <p className="error-text">
            No se pudo eliminar la regla.{" "}
            <span className="error-detail">{connectionErrorDetail(deleteSchedule.error)}</span>
          </p>
        )}
      </div>
    </div>
  );
}
