import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { authApi } from "../services/api";
import { useAuthStore } from "../store/auth";
import type {
  OrganizationOut,
  SubscriptionCancelOut,
  SubscriptionHistoryOut,
  SubscriptionPayLinkOut,
} from "../types";
import PageHeader from "../components/PageHeader";
import { formatDate } from "../utils/format";

// Pagos, licencia y baja del servicio -- todo lo que un admin de
// organizacion (o un platform_admin) necesita para administrar su propia
// suscripcion sin tener que escribirle al operador. Antes esto vivia
// mezclado con SSO en Organizations.tsx; se separo a su propia pagina
// porque es una tarea distinta (facturacion, no gestion de tenants/SSO)
// y para que sea facil de encontrar en el menu.
//
// Permisos: mismo criterio que Organizations.tsx -- un admin comun ve y
// administra SOLO la suya (ownOrgId, de sus claims); un platform_admin
// elige de la lista, porque puede administrar la de cualquier cliente.
export default function Billing() {
  const claims = useAuthStore((s) => s.claims);
  const isPlatformAdmin = claims?.platform_admin === true;
  const isOrgAdmin = claims?.role === "admin";
  const ownOrgId = typeof claims?.org_id === "string" ? claims.org_id : null;

  const queryClient = useQueryClient();

  const [selectedOrgId, setSelectedOrgId] = useState("");
  const activeOrgId = isPlatformAdmin ? selectedOrgId : ownOrgId ?? "";

  const organizations = useQuery({
    queryKey: ["organizations"],
    queryFn: async () => (await authApi.get<OrganizationOut[]>("/auth/organizations")).data,
    enabled: isPlatformAdmin,
  });

  const subscription = useQuery({
    queryKey: ["subscription", activeOrgId],
    queryFn: async () => (await authApi.get<OrganizationOut>(`/auth/organizations/${activeOrgId}/subscription`)).data,
    enabled: !!activeOrgId,
  });

  const history = useQuery({
    queryKey: ["subscription-history", activeOrgId],
    queryFn: async () =>
      (await authApi.get<SubscriptionHistoryOut>(`/auth/organizations/${activeOrgId}/subscription/history`)).data,
    enabled: !!activeOrgId,
  });

  // --- Pagar / renovar ---

  const [payError, setPayError] = useState<string | null>(null);
  const [payUrl, setPayUrl] = useState<string | null>(null);

  const payLink = useMutation({
    mutationFn: async () =>
      (await authApi.post<SubscriptionPayLinkOut>(`/auth/organizations/${activeOrgId}/subscription/pay-link`)).data,
    onSuccess: (data) => {
      setPayError(null);
      setPayUrl(data.payment_url);
      window.open(data.payment_url, "_blank", "noopener,noreferrer");
    },
    onError: (error: unknown) => {
      const detail =
        (error as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
        "No se pudo generar el link de pago. Intenta de nuevo en unos minutos o contacta al operador.";
      setPayError(detail);
      setPayUrl(null);
    },
  });

  // --- Dar de baja ---

  const [cancelError, setCancelError] = useState<string | null>(null);
  const [cancelResult, setCancelResult] = useState<SubscriptionCancelOut | null>(null);
  const [confirmingCancel, setConfirmingCancel] = useState(false);

  const cancelSubscription = useMutation({
    mutationFn: async () =>
      (
        await authApi.post<SubscriptionCancelOut>(`/auth/organizations/${activeOrgId}/subscription/cancel-payment`)
      ).data,
    onSuccess: (data) => {
      setCancelError(null);
      setCancelResult(data);
      setConfirmingCancel(false);
      queryClient.invalidateQueries({ queryKey: ["subscription", activeOrgId] });
      queryClient.invalidateQueries({ queryKey: ["subscription-history", activeOrgId] });
    },
    onError: (error: unknown) => {
      const detail =
        (error as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
        "No se pudo cancelar la suscripcion. Intenta de nuevo en unos minutos o contacta al operador.";
      setCancelError(detail);
      setCancelResult(null);
      setConfirmingCancel(false);
    },
  });

  // BUG (corregido aca): ninguno de estos estados (link de pago
  // generado/error, resultado/error de cancelacion, el paso de
  // "¿confirmas?" a mitad de cancelar) se reseteaba al cambiar la
  // organizacion elegida (un platform_admin puede administrar la
  // facturacion de cualquier cliente desde el mismo selector). Si
  // cancelaba la suscripcion de la organizacion A y despues elegia la
  // organizacion B, seguia viendo "Listo, se cancelo el proximo cobro..."
  // como si acabara de cancelar la de B -- un cartel de exito/error que
  // en realidad es de OTRA organizacion. Todo esto es estado propio de
  // esta pagina (no de la query cacheada por organizacion), asi que se
  // limpia a mano cada vez que cambia activeOrgId.
  useEffect(() => {
    setPayError(null);
    setPayUrl(null);
    setCancelError(null);
    setCancelResult(null);
    setConfirmingCancel(false);
  }, [activeOrgId]);

  if (!isPlatformAdmin && !isOrgAdmin) {
    return (
      <div>
        <PageHeader title="Pagos y licencia" subtitle="Suscripcion, pagos y baja del servicio." />
        <div className="panel">
          <p className="empty-hint">
            Tu usuario ({claims?.role ?? "sin rol"}) no tiene acceso a esta seccion -- la administra un admin de tu
            organizacion o un administrador de plataforma.
          </p>
        </div>
      </div>
    );
  }

  const isExpired = !!subscription.data?.subscription_expires_at && new Date(subscription.data.subscription_expires_at) <= new Date();

  return (
    <div>
      <PageHeader title="Pagos y licencia" subtitle="Estado de la suscripcion, pagar/renovar, y dar de baja." />

      {isPlatformAdmin && (
        <div className="panel">
          <h2>Elegir organizacion</h2>
          <div className="field">
            <label htmlFor="billing-org">Organizacion</label>
            <select id="billing-org" value={selectedOrgId} onChange={(e) => setSelectedOrgId(e.target.value)}>
              <option value="">-- elegir --</option>
              {organizations.data?.map((org) => (
                <option key={org.id} value={org.id}>
                  {org.name}
                </option>
              ))}
            </select>
          </div>
        </div>
      )}

      {isPlatformAdmin && !activeOrgId && (
        <div className="panel">
          <p className="empty-hint">Elegi una organizacion arriba para ver su facturacion.</p>
        </div>
      )}

      {activeOrgId && (
        <>
          <div className="panel">
            <h2>Estado de la licencia</h2>
            {subscription.isLoading && <p className="empty-hint">Consultando...</p>}
            {subscription.data && (
              <p>
                {isExpired ? (
                  <span className="text-danger">Vencida</span>
                ) : (
                  <span className="badge badge-success" style={{ padding: "2px 8px", borderRadius: 4 }}>
                    Activa
                  </span>
                )}{" "}
                hasta el <strong>{formatDate(subscription.data.subscription_expires_at)}</strong>.
                {subscription.data.license_last_checked_at && (
                  <span className="empty-hint">
                    {" "}
                    Ultimo chequeo contra el servidor central: {new Date(subscription.data.license_last_checked_at).toLocaleString("es-AR")}.
                  </span>
                )}
              </p>
            )}
          </div>

          <div className="panel">
            <h2>Pagar / renovar</h2>
            <p className="empty-hint">
              Genera un link de Mercado Pago para pagar por primera vez, o para volver a suscribirte si habias
              cancelado el cobro automatico.
            </p>
            <button className="btn-primary" onClick={() => payLink.mutate()} disabled={payLink.isPending}>
              {payLink.isPending ? "Generando link..." : "Generar link de pago"}
            </button>
            {payError && <p className="error-text">{payError}</p>}
            {payUrl && !payError && (
              <p className="empty-hint">
                Se abrio Mercado Pago en una pestana nueva. Si no se abrio,{" "}
                <a href={payUrl} target="_blank" rel="noopener noreferrer">
                  hace click aca
                </a>
                .
              </p>
            )}
          </div>

          <div className="panel">
            <h2>Dar de baja</h2>
            <p className="empty-hint">
              Cancela el PROXIMO cobro automatico. No te bloquea ahora -- segui con acceso normal hasta que venza el
              periodo ya pagado.
            </p>
            {!confirmingCancel && (
              <button
                className="btn-secondary"
                onClick={() => setConfirmingCancel(true)}
                disabled={cancelSubscription.isPending}
              >
                Cancelar suscripcion
              </button>
            )}
            {confirmingCancel && (
              <div>
                <p className="empty-hint">
                  ¿Confirmas que querés cancelar el cobro automatico? Seguis con acceso hasta que venza el periodo ya
                  pagado.
                </p>
                <button
                  className="btn-primary"
                  onClick={() => cancelSubscription.mutate()}
                  disabled={cancelSubscription.isPending}
                >
                  {cancelSubscription.isPending ? "Cancelando..." : "Si, cancelar el proximo cobro"}
                </button>{" "}
                <button
                  className="btn-secondary"
                  onClick={() => setConfirmingCancel(false)}
                  disabled={cancelSubscription.isPending}
                >
                  Volver
                </button>
              </div>
            )}
            {cancelError && <p className="error-text">{cancelError}</p>}
            {cancelResult && !cancelError && (
              <p className="empty-hint">
                Listo, se cancelo el proximo cobro automatico. Seguis con acceso hasta el{" "}
                {formatDate(cancelResult.valid_until)}.
              </p>
            )}
          </div>

          <div className="panel">
            <h2>Historial</h2>
            {history.isLoading && <p className="empty-hint">Consultando...</p>}
            {history.data && history.data.history.length > 0 ? (
              history.data.history.map((line, i) => (
                <p key={i} className="mono" style={{ marginBottom: 4 }}>
                  {line}
                </p>
              ))
            ) : (
              !history.isLoading && <p className="empty-hint">Todavia no hay eventos registrados para esta licencia.</p>
            )}
          </div>
        </>
      )}
    </div>
  );
}
