import axios from "axios";

/**
 * Convierte cualquier error de una llamada a un microservicio en un
 * texto legible con el detalle real (status HTTP, mensaje del backend,
 * o el motivo de que no haya habido respuesta), en vez de un generico
 * "no se pudo conectar" que no permite distinguir un contenedor caido
 * de un 401/403/500. Pensado para mostrarse debajo del mensaje
 * amigable, asi el usuario puede copiar/pegar el detalle si necesita
 * soporte.
 */
export function connectionErrorDetail(error: unknown): string {
  if (axios.isAxiosError(error)) {
    if (error.response) {
      const detail =
        typeof error.response.data === "object" && error.response.data !== null && "detail" in error.response.data
          ? String((error.response.data as { detail?: unknown }).detail)
          : JSON.stringify(error.response.data);
      return `HTTP ${error.response.status}: ${detail}`.slice(0, 300);
    }
    if (error.code === "ERR_NETWORK" || error.message?.toLowerCase().includes("network")) {
      return `Sin respuesta (${error.message}) -- el contenedor de este servicio probablemente no esta corriendo o todavia se esta reiniciando.`;
    }
    if (error.code === "ECONNABORTED" || error.message?.toLowerCase().includes("timeout")) {
      return `Tiempo de espera agotado (${error.message}).`;
    }
    return error.message;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

/**
 * Igual que connectionErrorDetail, pero para un request hecho con
 * `responseType: "blob"` (ej. GET /reports/{id}/export?format=csv|pdf en
 * Reports.tsx). Con responseType:"blob" axios entrega el body de un
 * error tal cual: error.response.data queda como un Blob, nunca como el
 * JSON {detail: "..."} que devuelve FastAPI -- JSON.stringify(blob) da
 * "{}" y connectionErrorDetail sola nunca puede mostrar el detail real
 * (ej. "Reporte no encontrado"). Esta funcion lee el Blob como texto y,
 * si es JSON valido con `detail`, lo usa; para cualquier otro caso (sin
 * respuesta, timeout, blob vacio/no-JSON) se apoya en
 * connectionErrorDetail.
 */
export async function blobExportErrorDetail(error: unknown): Promise<string> {
  if (axios.isAxiosError(error) && error.response?.data instanceof Blob) {
    try {
      const text = await error.response.data.text();
      try {
        const parsed = JSON.parse(text);
        const detail =
          typeof parsed === "object" && parsed !== null && "detail" in parsed ? String((parsed as { detail?: unknown }).detail) : text;
        return `HTTP ${error.response.status}: ${detail}`.slice(0, 300);
      } catch {
        return `HTTP ${error.response.status}: ${text || "sin detalle"}`.slice(0, 300);
      }
    } catch {
      // no se pudo ni leer el blob -- se cae al mensaje generico de abajo
    }
  }
  return connectionErrorDetail(error);
}
