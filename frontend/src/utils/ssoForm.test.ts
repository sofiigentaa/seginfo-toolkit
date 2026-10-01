import { describe, expect, it } from "vitest";
import { resolveSsoFormValues, SSO_FORM_DEFAULTS } from "./ssoForm";
import type { SsoConfigOut } from "../types";

describe("resolveSsoFormValues", () => {
  it("returns the 'not configured yet' defaults when there is no config", () => {
    expect(resolveSsoFormValues(null)).toEqual(SSO_FORM_DEFAULTS);
    expect(resolveSsoFormValues(undefined)).toEqual(SSO_FORM_DEFAULTS);
  });

  it("maps every field from an existing config", () => {
    const config: SsoConfigOut = {
      organization_id: "org-a",
      issuer: "https://login.microsoftonline.com/tenant/v2.0",
      client_id: "client-abc",
      default_role: "soc_manager",
      enabled: false,
    };
    expect(resolveSsoFormValues(config)).toEqual({
      issuer: "https://login.microsoftonline.com/tenant/v2.0",
      clientId: "client-abc",
      defaultRole: "soc_manager",
      enabled: false,
    });
  });

  it("does not leak a previous organization's values when switching to one with no config (regression)", () => {
    const orgAConfig: SsoConfigOut = {
      organization_id: "org-a",
      issuer: "https://org-a.example.com",
      client_id: "org-a-client",
      default_role: "admin",
      enabled: true,
    };
    // Simula: el admin de plataforma ya cargo la config de la org A en el
    // formulario, y ahora elige la org B, que todavia no tiene SSO
    // configurado (el backend devuelve null para ella).
    const formAfterA = resolveSsoFormValues(orgAConfig);
    expect(formAfterA.issuer).toBe("https://org-a.example.com");

    const formAfterB = resolveSsoFormValues(null);
    expect(formAfterB).toEqual(SSO_FORM_DEFAULTS);
    expect(formAfterB.issuer).not.toBe(orgAConfig.issuer);
    expect(formAfterB.clientId).not.toBe(orgAConfig.client_id);
  });
});
