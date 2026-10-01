import type { SsoConfigOut } from "../types";

/**
 * Resuelve los valores que debe mostrar el formulario de SSO (issuer,
 * client_id, rol por defecto, habilitado) a partir de la configuracion
 * que devuelve el backend para la organizacion ACTUALMENTE elegida.
 *
 * BUG que esto corrige: Organizations.tsx seteaba estos campos de estado
 * dentro del queryFn de la query de SSO, pero solo cuando el backend
 * devolvia una config (`if (data) { ... }`). Si un platform_admin elegia
 * primero una organizacion CON SSO configurado y despues otra SIN
 * configurar, los campos se quedaban con los valores de la organizacion
 * anterior en pantalla -- al guardar, se podia terminar escribiendo el
 * issuer/client_id de la organizacion A en la configuracion de la
 * organizacion B por error. Esta funcion siempre devuelve un valor
 * explicito (los defaults de "sin configurar" cuando la respuesta es
 * null/undefined), para que el componente pueda resetear el formulario
 * completo cada vez que cambia la organizacion elegida, no solo
 * completarlo cuando hay datos.
 *
 * Extraida como funcion pura (sin red, sin estado de React) para poder
 * testearla sin renderizar el componente.
 */
export interface SsoFormValues {
  issuer: string;
  clientId: string;
  defaultRole: string;
  enabled: boolean;
}

export const SSO_FORM_DEFAULTS: SsoFormValues = {
  issuer: "",
  clientId: "",
  defaultRole: "analyst",
  enabled: true,
};

export function resolveSsoFormValues(config: SsoConfigOut | null | undefined): SsoFormValues {
  if (!config) {
    return { ...SSO_FORM_DEFAULTS };
  }
  return {
    issuer: config.issuer,
    clientId: config.client_id,
    defaultRole: config.default_role,
    enabled: config.enabled,
  };
}
