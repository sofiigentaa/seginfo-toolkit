import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { authApi } from "../services/api";
import { useAuthStore } from "../store/auth";
import type { OrganizationCreateResult, OrganizationOut, SsoConfigOut } from "../types";
import PageHeader from "../components/PageHeader";
import { resolveSsoFormValues } from "../utils/ssoForm";

// Esta pagina cubre dos cosas relacionadas pero con permisos distintos
// (ver backend/services/auth-service/app/dependencies.py):
//
// 1. Gestion de organizaciones (crear, listar): solo un platform_admin
//    puede hacerlo -- administra la plataforma entera, no una empresa
//    en particular.
// 2. Configuracion de SSO (OIDC) de UNA organizacion: la puede tocar un
//    admin de ESA organizacion (su propia empresa) o cualquier
//    platform_admin (que puede tocar la de cualquiera). Por eso el
//    selector de organizacion para SSO se oculta para un admin comun
//    (ya sabe cual es la suya, viene de sus claims) y se muestra para
//    un platform_admin (tiene que elegir a cual le configura SSO).
//
// La suscripcion / facturacion de la organizacion (ver cuando vence,
// pagar, cancelar) vive en su propia pagina, Billing.tsx -- no aca.

export default function Organizations() {
  const claims = useAuthStore((s) => s.claims);
  const isPlatformAdmin = claims?.platform_admin === true;
  const isOrgAdmin = claims?.role === "admin";
  const ownOrgId = typeof claims?.org_id === "string" ? claims.org_id : null;

  const queryClient = useQueryClient();

  // --- Organizaciones (solo platform_admin) ---

  const [newOrgName, setNewOrgName] = useState("");
  const [adminEmail, setAdminEmail] = useState("");
  const [adminPassword, setAdminPassword] = useState("");
  const [adminFullName, setAdminFullName] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);
  const [createResult, setCreateResult] = useState<OrganizationCreateResult | null>(null);

  const organizations = useQuery({
    queryKey: ["organizations"],
    queryFn: async () => (await authApi.get<OrganizationOut[]>("/auth/organizations")).data,
    enabled: isPlatformAdmin,
  });

  const createOrganization = useMutation({
    mutationFn: async () =>
      (
        await authApi.post<OrganizationCreateResult>("/auth/organizations", {
          name: newOrgName,
          admin_email: adminEmail,
          admin_password: adminPassword,
          admin_full_name: adminFullName,
        })
      ).data,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["organizations"] });
      setCreateResult(data);
      setCreateError(null);
      setNewOrgName("");
      setAdminEmail("");
      setAdminPassword("");
      setAdminFullName("");
    },
    onError: () => {
      setCreateError("No se pudo crear la organizacion. Revisa que el email no este ya registrado y que la contrasena tenga al menos 12 caracteres.");
      setCreateResult(null);
    },
  });

  // --- SSO (OIDC) de una organizacion ---

  const [selectedOrgId, setSelectedOrgId] = useState<string>("");
  const activeOrgId = isPlatformAdmin ? selectedOrgId : ownOrgId ?? "";

  const [issuer, setIssuer] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [defaultRole, setDefaultRole] = useState("analyst");
  const [ssoEnabled, setSsoEnabled] = useState(true);
  const [ssoSaveError, setSsoSaveError] = useState<string | null>(null);
  const [ssoSaved, setSsoSaved] = useState(false);

  const ssoConfig = useQuery({
    queryKey: ["sso-config", activeOrgId],
    queryFn: async () => {
      const { data } = await authApi.get<SsoConfigOut | null>(`/auth/organizations/${activeOrgId}/sso`);
      return data;
    },
    enabled: !!activeOrgId && (isPlatformAdmin || isOrgAdmin),
  });

  // BUG (corregido aca): antes, los campos del formulario se completaban
  // "a mano" dentro del queryFn de arriba, y SOLO cuando el backend
  // devolvia una config (`if (data) {...}`). Si un platform_admin elegia
  // primero una organizacion CON SSO configurado y despues otra SIN
  // configurar, los campos se quedaban con los valores de la organizacion
  // anterior (issuer/client_id/rol/enabled) en vez de volver a los
  // defaults -- riesgo real de guardar por error la config de una
  // organizacion en OTRA. Este efecto corre cada vez que cambia la
  // organizacion elegida o llega una respuesta nueva, y siempre resuelve
  // un valor explicito (resolveSsoFormValues, ver utils/ssoForm.ts) en vez
  // de solo completar cuando hay datos.
  useEffect(() => {
    const values = resolveSsoFormValues(ssoConfig.data);
    setIssuer(values.issuer);
    setClientId(values.clientId);
    setDefaultRole(values.defaultRole);
    setSsoEnabled(values.enabled);
    setClientSecret("");
  }, [activeOrgId, ssoConfig.data]);

  // Idem para los carteles de exito/error de guardado: son especificos de
  // la organizacion que se estaba editando cuando se guardo, asi que si el
  // admin cambia de organizacion elegida no tiene que seguir viendo
  // "Configuracion de SSO guardada" (o un error) que corresponde a la
  // organizacion anterior. A diferencia del efecto de arriba, este NO
  // debe depender de ssoConfig.data -- el guardado exitoso invalida esa
  // query (ver saveSsoConfig.onSuccess) y el refetch resultante no tiene
  // que borrar el cartel que ese mismo guardado acaba de mostrar.
  useEffect(() => {
    setSsoSaveError(null);
    setSsoSaved(false);
  }, [activeOrgId]);

  const saveSsoConfig = useMutation({
    mutationFn: async () =>
      (
        await authApi.put<SsoConfigOut>(`/auth/organizations/${activeOrgId}/sso`, {
          issuer,
          client_id: clientId,
          client_secret: clientSecret,
          default_role: defaultRole,
          enabled: ssoEnabled,
        })
      ).data,
    onSuccess: () => {
      setSsoSaveError(null);
      setSsoSaved(true);
      setClientSecret("");
      queryClient.invalidateQueries({ queryKey: ["sso-config", activeOrgId] });
    },
    onError: () => {
      setSsoSaveError("No se pudo guardar la configuracion de SSO. Revisa el issuer y el client_id.");
      setSsoSaved(false);
    },
  });

  const orgSlugForLogin = isPlatformAdmin
    ? organizations.data?.find((o) => o.id === activeOrgId)?.slug
    : undefined;

  if (!isPlatformAdmin && !isOrgAdmin) {
    return (
      <div>
        <PageHeader title="Organizaciones" subtitle="Gestion de tenants y SSO empresarial." />
        <div className="panel">
          <p className="empty-hint">
            Tu usuario ({claims?.role ?? "sin rol"}) no tiene acceso a esta seccion -- la administra un admin de tu
            organizacion o un administrador de plataforma.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title="Organizaciones"
        subtitle="Multi-tenancy por fila (organization_id) y SSO empresarial (OIDC) por organizacion."
      />

      {isPlatformAdmin && (
        <div className="panel">
          <h2>Organizaciones existentes</h2>
          {organizations.data && (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Nombre</th>
                  <th>Slug</th>
                  <th>Activa</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {organizations.data.map((org) => (
                  <tr key={org.id}>
                    <td>{org.name}</td>
                    <td className="mono">{org.slug}</td>
                    <td>{org.is_active ? "si" : "no"}</td>
                    <td>
                      <button className="btn-secondary" onClick={() => setSelectedOrgId(org.id)}>
                        Configurar SSO
                      </button>
                    </td>
                  </tr>
                ))}
                {organizations.data.length === 0 && (
                  <tr>
                    <td colSpan={4} className="empty-hint">
                      No hay organizaciones todavia (fuera de "default", que se crea sola con el primer usuario).
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}

          <h2 style={{ marginTop: 20 }}>Crear organizacion nueva</h2>
          <p className="empty-hint">
            Crea la empresa y su primer usuario admin en un solo paso. No hay auto-registro publico de organizaciones
            a proposito -- solo un administrador de plataforma puede darle de alta un tenant nuevo a un cliente.
          </p>
          <div className="field">
            <label htmlFor="org-name">Nombre de la organizacion</label>
            <input id="org-name" value={newOrgName} onChange={(e) => setNewOrgName(e.target.value)} placeholder="Acme Corp" />
          </div>
          <div className="field">
            <label htmlFor="admin-email">Email del admin</label>
            <input id="admin-email" type="email" value={adminEmail} onChange={(e) => setAdminEmail(e.target.value)} placeholder="admin@acme.com" />
          </div>
          <div className="field">
            <label htmlFor="admin-full-name">Nombre completo del admin</label>
            <input id="admin-full-name" value={adminFullName} onChange={(e) => setAdminFullName(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="admin-password">Contrasena inicial del admin (min. 12 caracteres)</label>
            <input id="admin-password" type="password" value={adminPassword} onChange={(e) => setAdminPassword(e.target.value)} />
          </div>
          <button
            className="btn-primary"
            onClick={() => createOrganization.mutate()}
            disabled={createOrganization.isPending || !newOrgName || !adminEmail || adminPassword.length < 12}
          >
            {createOrganization.isPending ? "Creando..." : "Crear organizacion"}
          </button>
          {createError && <p className="error-text">{createError}</p>}
          {createResult && (
            <p className="empty-hint">
              Organizacion "{createResult.organization.name}" creada (slug: {createResult.organization.slug}) con
              admin {createResult.admin_user.email}.
            </p>
          )}
        </div>
      )}

      <div className="panel">
        <h2>Configuracion de SSO (OIDC)</h2>
        {isPlatformAdmin && !activeOrgId && (
          <p className="empty-hint">Elegi una organizacion de la tabla de arriba para ver/editar su SSO.</p>
        )}
        {activeOrgId && (
          <>
            <p className="empty-hint">
              Compatible con cualquier proveedor OIDC estandar (Azure AD / Entra ID, Okta, Google Workspace, Keycloak,
              etc.). El client_secret nunca se vuelve a mostrar una vez guardado -- para cambiarlo, se sobreescribe.
            </p>
            <div className="field">
              <label htmlFor="sso-issuer">Issuer</label>
              <input
                id="sso-issuer"
                value={issuer}
                onChange={(e) => setIssuer(e.target.value)}
                placeholder="https://login.microsoftonline.com/<tenant>/v2.0"
              />
            </div>
            <div className="field">
              <label htmlFor="sso-client-id">Client ID</label>
              <input id="sso-client-id" value={clientId} onChange={(e) => setClientId(e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="sso-client-secret">
                Client secret {ssoConfig.data ? "(deja en blanco para no cambiarlo)" : ""}
              </label>
              <input
                id="sso-client-secret"
                type="password"
                value={clientSecret}
                onChange={(e) => setClientSecret(e.target.value)}
              />
            </div>
            <div className="field">
              <label htmlFor="sso-default-role">Rol por defecto para usuarios nuevos via SSO</label>
              <select id="sso-default-role" value={defaultRole} onChange={(e) => setDefaultRole(e.target.value)}>
                <option value="analyst">analyst</option>
                <option value="soc_manager">soc_manager</option>
                <option value="admin">admin</option>
              </select>
            </div>
            <div className="field">
              <label htmlFor="sso-enabled">
                <input
                  id="sso-enabled"
                  type="checkbox"
                  checked={ssoEnabled}
                  onChange={(e) => setSsoEnabled(e.target.checked)}
                  style={{ marginRight: 8, width: "auto" }}
                />
                Habilitado
              </label>
            </div>
            <button
              className="btn-primary"
              onClick={() => saveSsoConfig.mutate()}
              disabled={saveSsoConfig.isPending || !issuer || !clientId || (!ssoConfig.data && !clientSecret)}
            >
              {saveSsoConfig.isPending ? "Guardando..." : "Guardar configuracion de SSO"}
            </button>
            {ssoSaveError && <p className="error-text">{ssoSaveError}</p>}
            {ssoSaved && !ssoSaveError && <p className="empty-hint">Configuracion de SSO guardada.</p>}
            {ssoConfig.data && ssoEnabled && (
              <p className="empty-hint" style={{ marginTop: 12 }}>
                URL de login SSO para esta organizacion:{" "}
                <span className="mono">
                  {(authApi.defaults.baseURL ?? "")}/auth/oidc/{orgSlugForLogin ?? "<slug>"}/login
                </span>
              </p>
            )}
          </>
        )}
      </div>
    </div>
  );
}
