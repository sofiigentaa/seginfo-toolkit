import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { cloudApi } from "../services/api";
import { useAuthStore } from "../store/auth";
import type { CloudAccountOut, CloudResourceOut, CloudFindingOut } from "../types";
import PageHeader from "../components/PageHeader";
import { SeverityBadge, StatusBadge } from "../components/Badge";
import { connectionErrorDetail } from "../utils/errors";

// Igual que en Notifications.tsx/Reports.tsx: conectar una cuenta de AWS
// requiere credenciales reales, asi que solo admin/soc_manager pueden
// hacerlo (ver require_role("admin", "soc_manager") esperado en
// POST /accounts del backend -- si igual se llega a mandar el request
// sin el rol, el backend devuelve 403 y ese caso lo cubre el mismo patron
// de error de mutation que el resto de esta pagina).
const CAN_MANAGE_ACCOUNTS = ["admin", "soc_manager"];

const RESOURCE_TYPE_LABELS: Record<string, string> = {
  ec2_instance: "Instancia EC2",
  security_group: "Grupo de seguridad",
  s3_bucket: "Bucket S3",
};

const FINDING_TYPE_LABELS: Record<string, string> = {
  s3_bucket_public: "Bucket S3 publico",
  security_group_open_world: "Grupo de seguridad abierto al mundo",
};

function resourceTypeLabel(value: string): string {
  return RESOURCE_TYPE_LABELS[value] ?? value;
}

function findingTypeLabel(value: string): string {
  return FINDING_TYPE_LABELS[value] ?? value;
}

// resource_metadata no tiene una forma fija confirmada por servicio/tipo de
// recurso (EC2 vs security group vs S3) -- en vez de asumir nombres de
// campo puntuales que todavia no se pudieron confirmar contra el backend
// real de cloud-service, se muestra como una lista generica "clave: valor"
// que sirve para cualquier forma que termine teniendo.
function formatMetadataValue(value: unknown): string {
  if (value === null || value === undefined) return "-";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function MetadataList({ metadata }: { metadata: Record<string, unknown> }) {
  const entries = Object.entries(metadata ?? {});
  if (entries.length === 0) {
    return <span className="empty-hint">--</span>;
  }
  return (
    <span className="mono">
      {entries.map(([key, value]) => `${key}: ${formatMetadataValue(value)}`).join(" | ")}
    </span>
  );
}

export default function Cloud() {
  const queryClient = useQueryClient();
  const claims = useAuthStore((s) => s.claims);
  const canManageAccounts = !!claims?.role && CAN_MANAGE_ACCOUNTS.includes(claims.role);

  // --- Formulario "Conectar cuenta de AWS" -------------------------------
  const [accountName, setAccountName] = useState("");
  const [accountRegion, setAccountRegion] = useState("us-east-1");
  const [accessKeyId, setAccessKeyId] = useState("");
  const [secretAccessKey, setSecretAccessKey] = useState("");
  const [connectFormError, setConnectFormError] = useState<string | null>(null);
  const [connectAccountError, setConnectAccountError] = useState<unknown>(null);

  // --- Cuentas conectadas -------------------------------------------------
  const [deleteAccountError, setDeleteAccountError] = useState<unknown>(null);
  const [syncAccountError, setSyncAccountError] = useState<unknown>(null);
  const [syncFeedback, setSyncFeedback] = useState<{ accountId: string; message: string } | null>(null);

  // --- Recursos descubiertos ----------------------------------------------
  const [selectedAccountId, setSelectedAccountId] = useState<string>("");
  const [resourceTypeFilter, setResourceTypeFilter] = useState<string>("");

  // --- Hallazgos peligrosos -------------------------------------------------
  const [findingsFilter, setFindingsFilter] = useState<"all" | "pending">("pending");
  const [acknowledgeFindingError, setAcknowledgeFindingError] = useState<unknown>(null);

  const accounts = useQuery({
    queryKey: ["cloud-accounts"],
    queryFn: async () => (await cloudApi.get<CloudAccountOut[]>("/accounts")).data,
  });

  const resources = useQuery({
    queryKey: ["cloud-resources", selectedAccountId, resourceTypeFilter],
    queryFn: async () =>
      (
        await cloudApi.get<CloudResourceOut[]>("/resources", {
          params: {
            ...(selectedAccountId ? { cloud_account_id: selectedAccountId } : {}),
            ...(resourceTypeFilter ? { resource_type: resourceTypeFilter } : {}),
          },
        })
      ).data,
  });

  const findings = useQuery({
    queryKey: ["cloud-findings", findingsFilter],
    queryFn: async () =>
      (
        await cloudApi.get<CloudFindingOut[]>("/findings", {
          params: { all: findingsFilter === "all" },
        })
      ).data,
  });

  const connectAccount = useMutation({
    mutationFn: async () =>
      (
        await cloudApi.post<CloudAccountOut>("/accounts", {
          name: accountName,
          region: accountRegion,
          access_key_id: accessKeyId,
          secret_access_key: secretAccessKey,
        })
      ).data,
    onSuccess: () => {
      setAccountName("");
      setAccountRegion("us-east-1");
      setAccessKeyId("");
      setSecretAccessKey("");
      setConnectFormError(null);
      setConnectAccountError(null);
      queryClient.invalidateQueries({ queryKey: ["cloud-accounts"] });
    },
    onError: (err: unknown) => setConnectAccountError(err),
  });

  const deleteAccount = useMutation({
    mutationFn: async (accountId: string) => {
      await cloudApi.delete(`/accounts/${accountId}`);
    },
    onSuccess: (_data, accountId) => {
      setDeleteAccountError(null);
      if (selectedAccountId === accountId) {
        setSelectedAccountId("");
      }
      queryClient.invalidateQueries({ queryKey: ["cloud-accounts"] });
      queryClient.invalidateQueries({ queryKey: ["cloud-resources"] });
      queryClient.invalidateQueries({ queryKey: ["cloud-findings"] });
    },
    onError: (err: unknown) => setDeleteAccountError(err),
  });

  const syncAccount = useMutation({
    mutationFn: async (accountId: string) => {
      await cloudApi.post(`/accounts/${accountId}/sync-now`);
      return accountId;
    },
    onSuccess: (accountId) => {
      setSyncAccountError(null);
      setSyncFeedback({
        accountId,
        message: "Sincronizacion disparada -- los recursos y hallazgos pueden tardar unos segundos en actualizarse.",
      });
      queryClient.invalidateQueries({ queryKey: ["cloud-accounts"] });
      queryClient.invalidateQueries({ queryKey: ["cloud-resources"] });
      queryClient.invalidateQueries({ queryKey: ["cloud-findings"] });
    },
    onError: (err: unknown, accountId) => {
      setSyncAccountError(err);
      setSyncFeedback(null);
      void accountId;
    },
  });

  const acknowledgeFinding = useMutation({
    mutationFn: async (findingId: string) =>
      (await cloudApi.patch<CloudFindingOut>(`/findings/${findingId}`, { is_acknowledged: true })).data,
    onSuccess: () => {
      setAcknowledgeFindingError(null);
      queryClient.invalidateQueries({ queryKey: ["cloud-findings"] });
    },
    onError: (err: unknown) => setAcknowledgeFindingError(err),
  });

  function onConnectAccount() {
    setConnectFormError(null);
    if (!accountName.trim()) {
      setConnectFormError("Ingresa un nombre para identificar la cuenta (ej. \"AWS Produccion\").");
      return;
    }
    if (!accountRegion.trim()) {
      setConnectFormError("Ingresa la region de AWS (ej. us-east-1).");
      return;
    }
    if (!accessKeyId.trim() || !secretAccessKey.trim()) {
      setConnectFormError("Ingresa el access key id y el secret access key de la cuenta de AWS.");
      return;
    }
    connectAccount.mutate();
  }

  const accountsById = new Map((accounts.data ?? []).map((a) => [a.id, a]));

  return (
    <div>
      <PageHeader
        title="Cloud (AWS)"
        subtitle="Inventario automatico de cuentas de AWS (EC2, S3, grupos de seguridad) y deteccion de configuraciones peligrosas"
      />

      <div className="panel">
        <h2>Conectar cuenta de AWS</h2>
        <p className="empty-hint">
          La cuenta de AWS que conectes necesita una politica IAM de <strong>solo lectura</strong>, con unicamente
          estos permisos: <code>ec2:DescribeInstances</code>, <code>ec2:DescribeSecurityGroups</code>,{" "}
          <code>s3:ListAllMyBuckets</code>, <code>s3:GetBucketAcl</code>, <code>s3:GetBucketPolicyStatus</code>,{" "}
          <code>s3:GetPublicAccessBlock</code> y <code>s3:GetBucketLocation</code>. SentinelOps nunca necesita ni usa
          permisos de escritura, y nunca modifica nada en la cuenta de AWS del cliente -- solo lee inventario y
          reporta configuraciones riesgosas.
        </p>

        {canManageAccounts ? (
          <>
            <div className="inline-form">
              <input
                placeholder="Nombre (ej. AWS Produccion)"
                value={accountName}
                onChange={(e) => setAccountName(e.target.value)}
              />
              <input
                placeholder="Region (ej. us-east-1)"
                value={accountRegion}
                onChange={(e) => setAccountRegion(e.target.value)}
              />
            </div>
            <div className="inline-form" style={{ marginTop: 8 }}>
              <input
                placeholder="Access key ID"
                value={accessKeyId}
                onChange={(e) => setAccessKeyId(e.target.value)}
              />
              <input
                type="password"
                placeholder="Secret access key"
                value={secretAccessKey}
                onChange={(e) => setSecretAccessKey(e.target.value)}
              />
            </div>
            <div style={{ marginTop: 10 }}>
              <button className="btn-primary" onClick={onConnectAccount} disabled={connectAccount.isPending}>
                {connectAccount.isPending ? "Conectando..." : "Conectar cuenta"}
              </button>
            </div>
            {connectFormError && <p className="error-text">{connectFormError}</p>}
            {connectAccountError != null && !connectFormError && (
              <p className="error-text">
                No se pudo conectar la cuenta.{" "}
                <span className="error-detail">{connectionErrorDetail(connectAccountError)}</span>
              </p>
            )}
          </>
        ) : (
          <p className="empty-hint" style={{ marginTop: 12 }}>
            Tu usuario ({claims?.role ?? "sin rol"}) no puede conectar cuentas de AWS -- lo puede hacer un admin o
            soc_manager.
          </p>
        )}
      </div>

      <div className="panel">
        <h2>Cuentas conectadas</h2>
        {accounts.isLoading && <p className="empty-hint">Cargando...</p>}
        {accounts.isError && (
          <p className="error-text">
            No se pudo conectar con cloud-service.{" "}
            <span className="error-detail">{connectionErrorDetail(accounts.error)}</span>
          </p>
        )}
        {accounts.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Region</th>
                <th>Access key</th>
                <th>Ultimo sync</th>
                <th>Fecha ultimo sync</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {accounts.data.map((a) => (
                <tr key={a.id}>
                  <td>{a.name}</td>
                  <td className="mono">{a.region}</td>
                  <td className="mono">{a.access_key_id_masked}</td>
                  <td>
                    <StatusBadge value={a.last_sync_status} />
                    {a.last_sync_status === "error" && a.last_sync_error && (
                      <div className="empty-hint" style={{ margin: "4px 0 0" }}>
                        <span className="error-detail">{a.last_sync_error}</span>
                      </div>
                    )}
                  </td>
                  <td>{a.last_sync_at ? new Date(a.last_sync_at).toLocaleString() : "Nunca"}</td>
                  <td>
                    <button
                      className="btn-link"
                      onClick={() => syncAccount.mutate(a.id)}
                      disabled={syncAccount.isPending && syncAccount.variables === a.id}
                    >
                      {syncAccount.isPending && syncAccount.variables === a.id ? "Sincronizando..." : "Sincronizar ahora"}
                    </button>{" "}
                    <button
                      className="btn-link"
                      onClick={() => {
                        if (window.confirm(`Desconectar la cuenta "${a.name}"? Se van a dejar de sincronizar sus recursos.`)) {
                          deleteAccount.mutate(a.id);
                        }
                      }}
                    >
                      Eliminar
                    </button>
                    {syncFeedback && syncFeedback.accountId === a.id && (
                      <p className="empty-hint" style={{ margin: "4px 0 0" }}>
                        {syncFeedback.message}
                      </p>
                    )}
                  </td>
                </tr>
              ))}
              {accounts.data.length === 0 && (
                <tr>
                  <td colSpan={6} className="empty-hint">
                    Sin cuentas de AWS conectadas todavia. Conecta una arriba.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
        {syncAccountError != null && (
          <p className="error-text">
            No se pudo disparar la sincronizacion.{" "}
            <span className="error-detail">{connectionErrorDetail(syncAccountError)}</span>
          </p>
        )}
        {deleteAccountError != null && (
          <p className="error-text">
            No se pudo eliminar la cuenta.{" "}
            <span className="error-detail">{connectionErrorDetail(deleteAccountError)}</span>
          </p>
        )}
      </div>

      <div className="panel">
        <div className="inline-form" style={{ justifyContent: "space-between" }}>
          <h2 style={{ margin: 0 }}>Recursos descubiertos</h2>
          <div className="inline-form">
            {(accounts.data ?? []).length > 1 && (
              <select value={selectedAccountId} onChange={(e) => setSelectedAccountId(e.target.value)}>
                <option value="">Todas las cuentas</option>
                {accounts.data!.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name}
                  </option>
                ))}
              </select>
            )}
            <select value={resourceTypeFilter} onChange={(e) => setResourceTypeFilter(e.target.value)}>
              <option value="">Todos los tipos</option>
              {Object.entries(RESOURCE_TYPE_LABELS).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </div>
        </div>
        {resources.isLoading && <p className="empty-hint">Cargando...</p>}
        {resources.isError && (
          <p className="error-text">
            No se pudo cargar los recursos.{" "}
            <span className="error-detail">{connectionErrorDetail(resources.error)}</span>
          </p>
        )}
        {resources.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Cuenta</th>
                <th>Tipo</th>
                <th>Nombre</th>
                <th>Region</th>
                <th>ID externo</th>
                <th>Detalle</th>
                <th>Activo</th>
                <th>Ultima vez visto</th>
              </tr>
            </thead>
            <tbody>
              {resources.data.map((r) => (
                <tr key={r.id}>
                  <td>{accountsById.get(r.cloud_account_id)?.name ?? r.cloud_account_id}</td>
                  <td>{resourceTypeLabel(r.resource_type)}</td>
                  <td>{r.name || "-"}</td>
                  <td className="mono">{r.region}</td>
                  <td className="mono">{r.external_id}</td>
                  <td>
                    <MetadataList metadata={r.resource_metadata} />
                  </td>
                  <td>{r.is_active ? "si" : "no"}</td>
                  <td>{new Date(r.last_seen_at).toLocaleString()}</td>
                </tr>
              ))}
              {resources.data.length === 0 && (
                <tr>
                  <td colSpan={8} className="empty-hint">
                    Sin recursos descubiertos todavia -- conecta una cuenta y usa "Sincronizar ahora".
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <div className="inline-form" style={{ justifyContent: "space-between" }}>
          <h2 style={{ margin: 0 }}>Hallazgos peligrosos</h2>
          <select value={findingsFilter} onChange={(e) => setFindingsFilter(e.target.value as "all" | "pending")}>
            <option value="pending">Sin reconocer</option>
            <option value="all">Todos</option>
          </select>
        </div>
        {findings.isLoading && <p className="empty-hint">Cargando...</p>}
        {findings.isError && (
          <p className="error-text">
            No se pudo cargar los hallazgos.{" "}
            <span className="error-detail">{connectionErrorDetail(findings.error)}</span>
          </p>
        )}
        {findings.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Severidad</th>
                <th>Tipo</th>
                <th>Cuenta</th>
                <th>Recurso</th>
                <th>Detalle</th>
                <th>Creado</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {findings.data.map((f) => (
                <tr key={f.id}>
                  <td><SeverityBadge value={f.severity} /></td>
                  <td>{findingTypeLabel(f.finding_type)}</td>
                  <td>{accountsById.get(f.cloud_account_id)?.name ?? f.cloud_account_id}</td>
                  <td className="mono">{f.resource_external_id}</td>
                  <td>{f.detail}</td>
                  <td>{new Date(f.created_at).toLocaleString()}</td>
                  <td>
                    {f.is_acknowledged ? (
                      <span className="empty-hint">Reconocido por {f.acknowledged_by}</span>
                    ) : (
                      <button
                        className="btn-link"
                        onClick={() => acknowledgeFinding.mutate(f.id)}
                        disabled={acknowledgeFinding.isPending && acknowledgeFinding.variables === f.id}
                      >
                        {acknowledgeFinding.isPending && acknowledgeFinding.variables === f.id
                          ? "Reconociendo..."
                          : "Reconocer"}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {findings.data.length === 0 && (
                <tr>
                  <td colSpan={7} className="empty-hint">
                    Sin hallazgos{findingsFilter === "pending" ? " sin reconocer" : ""} por el momento.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
        {acknowledgeFindingError != null && (
          <p className="error-text">
            No se pudo reconocer el hallazgo.{" "}
            <span className="error-detail">{connectionErrorDetail(acknowledgeFindingError)}</span>
          </p>
        )}
      </div>
    </div>
  );
}
