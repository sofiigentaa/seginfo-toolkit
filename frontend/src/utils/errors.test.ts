import { describe, expect, it } from "vitest";
import { connectionErrorDetail, blobExportErrorDetail } from "./errors";

/** Construye un objeto que `axios.isAxiosError` reconoce como AxiosError
 * sin depender de un servidor real ni de los tipos internos de axios. */
function fakeAxiosError(overrides: Record<string, unknown>) {
  return { isAxiosError: true, message: "request failed", ...overrides };
}

describe("connectionErrorDetail", () => {
  it("formats a backend error response with its detail message", () => {
    const error = fakeAxiosError({
      response: { status: 401, data: { detail: "credenciales invalidas" } },
    });
    expect(connectionErrorDetail(error)).toBe("HTTP 401: credenciales invalidas");
  });

  it("falls back to JSON.stringify when the response body has no detail field", () => {
    const error = fakeAxiosError({
      response: { status: 500, data: { error: "boom" } },
    });
    expect(connectionErrorDetail(error)).toBe('HTTP 500: {"error":"boom"}');
  });

  it("explains a network error (service likely down) in plain terms", () => {
    const error = fakeAxiosError({ code: "ERR_NETWORK", message: "Network Error" });
    expect(connectionErrorDetail(error)).toContain("Sin respuesta");
    expect(connectionErrorDetail(error)).toContain("no esta corriendo");
  });

  it("explains a timeout distinctly from a generic network error", () => {
    const error = fakeAxiosError({ code: "ECONNABORTED", message: "timeout of 10000ms exceeded" });
    expect(connectionErrorDetail(error)).toContain("Tiempo de espera agotado");
  });

  it("truncates a very long response detail to avoid overflowing the UI", () => {
    const longDetail = "x".repeat(1000);
    const error = fakeAxiosError({ response: { status: 400, data: { detail: longDetail } } });
    expect(connectionErrorDetail(error).length).toBe(300);
  });

  it("handles a plain (non-axios) Error", () => {
    expect(connectionErrorDetail(new Error("algo generico fallo"))).toBe("algo generico fallo");
  });

  it("handles a value that is not an Error at all", () => {
    expect(connectionErrorDetail("solo un string")).toBe("solo un string");
  });
});


describe("blobExportErrorDetail", () => {
  it("extracts the real backend detail from a Blob error body (GET .../export)", async () => {
    const error = fakeAxiosError({
      response: {
        status: 404,
        data: new Blob([JSON.stringify({ detail: "Reporte no encontrado" })], { type: "application/json" }),
      },
    });
    expect(await blobExportErrorDetail(error)).toBe("HTTP 404: Reporte no encontrado");
  });

  it("falls back to the raw text when the Blob body is not JSON", async () => {
    const error = fakeAxiosError({
      response: { status: 500, data: new Blob(["Internal Server Error"], { type: "text/plain" }) },
    });
    expect(await blobExportErrorDetail(error)).toBe("HTTP 500: Internal Server Error");
  });

  it("falls back to connectionErrorDetail for a non-blob error (network down, no response)", async () => {
    const error = fakeAxiosError({ code: "ERR_NETWORK", message: "Network Error" });
    expect(await blobExportErrorDetail(error)).toBe(connectionErrorDetail(error));
  });
});
