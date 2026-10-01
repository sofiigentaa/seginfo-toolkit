import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { coderepoApi } from "../services/api";
import { useAuthStore } from "../store/auth";
import type { RepoTargetOut, SecretFindingOut } from "../types";
import PageHeader from "../components/PageHeader";
import { SeverityBadge, StatusBadge } from "../components/Badge";
import { connectionErrorDetail } from "../utils/errors";

// Igual que en Cloud.tsx: conectar un repositorio (potencialmente con un
// token de acceso a un repo privado) requiere el mismo nivel de
// confianza que conectar una cuenta de AWS, asi que solo admin/soc_manager
// pueden hacerlo (ver require_role("admin", "soc_manager") esperado en
// POST /repos del backend -- si igual se llega a mandar el request sin el
// rol, el backend devuelve 403 y ese caso lo cubre el mismo patron de
// error de mutation que el resto de esta pagina).
const CAN_MANAGE_REPOS = ["admin", "soc_manager"];

function truncateHash(hash: string): string {
  return hash.length > 8 ? hash.slice(0, 8) : hash;
}

function formatFileLocation(filePath: string, startLine: number | null): string {
  return startLine != null ? `${filePath}:${startLine}` : filePath;
}

export default function CodeRepos() {
  const queryClient = useQueryClient();
  const claims = useAuthStore((s) => s.claims);
  const canManageRepos = !!claims?.role && CAN_MANAGE_REPOS.includes(claims.role);

  // --- Formulario "Conectar repositorio" ----------------------------------
  const [repoName, setRepoName] = useState("");
  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("main");
  const [githubToken, setGithubToken] = useState("");
  const [connectFormError, setConnectFormError] = useState<string | null>(null);
  const [connectRepoError, setConnectRepoError] = useState<unknown>(null);

  // --- Repositorios conectados ---------------------------------------------
  const [deleteRepoError, setDeleteRepoError] = useState<unknown>(null);
  const [scanRepoError, setScanRepoError] = useState<unknown>(null);
  const [scanFeedback, setScanFeedback] = useState<{ repoId: string; message: string } | null>(null);

  // --- Secretos encontrados --------------------------------------------------
  const [selectedRepoId, setSelectedRepoId] = useState<string>("");
  const [secretsFilter, setSecretsFilter] = useState<"all" | "pending">("pending");
  const [acknowledgeSecretError, setAcknowledgeSecretError] = useState<unknown>(null);

  const repos = useQuery({
    queryKey: ["code-repos"],
    queryFn: async () => (await coderepoApi.get<RepoTargetOut[]>("/repos")).data,
  });

  const secrets = useQuery({
    queryKey: ["code-repo-secrets", selectedRepoId, secretsFilter],
    queryFn: async () =>
      (
        await coderepoApi.get<SecretFindingOut[]>("/secrets", {
          params: {
            ...(selectedRepoId ? { repo_target_id: selectedRepoId } : {}),
            all: secretsFilter === "all",
          },
        })
      ).data,
  });

  const connectRepo = useMutation({
    mutationFn: async () =>
      (
        await coderepoApi.post<RepoTargetOut>("/repos", {
          name: repoName,
          repo_url: repoUrl,
          branch,
          ...(githubToken.trim() ? { github_token: githubToken } : {}),
        })
      ).data,
    onSuccess: () => {
      setRepoName("");
      setRepoUrl("");
      setBranch("main");
      setGithubToken("");
      setConnectFormError(null);
      setConnectRepoError(null);
      queryClient.invalidateQueries({ queryKey: ["code-repos"] });
    },
    onError: (err: unknown) => setConnectRepoError(err),
  });

  const deleteRepo = useMutation({
    mutationFn: async (repoId: string) => {
      await coderepoApi.delete(`/repos/${repoId}`);
    },
    onSuccess: (_data, repoId) => {
      setDeleteRepoError(null);
      if (selectedRepoId === repoId) {
        setSelectedRepoId("");
      }
      queryClient.invalidateQueries({ queryKey: ["code-repos"] });
      queryClient.invalidateQueries({ queryKey: ["code-repo-secrets"] });
    },
    onError: (err: unknown) => setDeleteRepoError(err),
  });

  const scanRepo = useMutation({
    mutationFn: async (repoId: string) => {
      await coderepoApi.post(`/repos/${repoId}/scan-now`);
      return repoId;
    },
    onSuccess: (repoId) => {
      setScanRepoError(null);
      setScanFeedback({
        repoId,
        message: "Escaneo disparado -- clonar el repositorio y correr gitleaks/trivy puede tardar varios minutos.",
      });
      queryClient.invalidateQueries({ queryKey: ["code-repos"] });
    },
    onError: (err: unknown, repoId) => {
      setScanRepoError(err);
      setScanFeedback(null);
      void repoId;
    },
  });

  const acknowledgeSecret = useMutation({
    mutationFn: async (secretId: string) =>
      (await coderepoApi.patch<SecretFindingOut>(`/secrets/${secretId}`, { is_acknowledged: true })).data,
    onSuccess: () => {
      setAcknowledgeSecretError(null);
      queryClient.invalidateQueries({ queryKey: ["code-repo-secrets"] });
    },
    onError: (err: unknown) => setAcknowledgeSecretError(err),
  });

  function onConnectRepo() {
    setConnectFormError(null);
    if (!repoName.trim()) {
      setConnectFormError("Ingresa un nombre para identificar el repositorio (ej. \"API principal\").");
      return;
    }
    if (!repoUrl.trim()) {
      setConnectFormError("Ingresa la URL del repositorio (ej. https://github.com/tuempresa/tu-repo).");
      return;
    }
    if (!repoUrl.trim().startsWith("https://")) {
      setConnectFormError("La URL del repositorio tiene que empezar con https://.");
      return;
    }
    if (!branch.trim()) {
      setConnectFormError("Ingresa la rama a escanear (ej. main).");
      return;
    }
    connectRepo.mutate();
  }

  const reposById = new Map((repos.data ?? []).map((r) => [r.id, r]));

  return (
    <div>
      <PageHeader
        title="Repositorios de codigo"
        subtitle="Escaneo periodico de repositorios de codigo para detectar contraseñas/claves commiteadas por error y dependencias con vulnerabilidades conocidas"
      />

      <div className="panel">
        <h2>Conectar repositorio</h2>
        <p className="empty-hint">
          SentinelOps solo <strong>lee</strong> el repositorio que conectes -- nunca escribe en el, nunca ejecuta
          codigo del repositorio ni corre instalacion de dependencias. Con esa lectura clona el repositorio
          periodicamente y corre <code>gitleaks</code> (busca contraseñas y claves commiteadas por error,
          revisando tambien todo el historial de git, no solo el codigo actual) y <code>trivy</code> (busca
          dependencias con vulnerabilidades conocidas en manifiestos como package-lock.json/requirements.txt/go.mod).
          Los hallazgos de dependencias vulnerables se ven en la pagina{" "}
          <Link to="/vulnerabilities">Vulnerabilidades</Link>; los de contraseñas/claves se ven abajo, en esta
          pagina.
        </p>

        {canManageRepos ? (
          <>
            <div className="inline-form">
              <input
                placeholder="Nombre (ej. API principal)"
                value={repoName}
                onChange={(e) => setRepoName(e.target.value)}
              />
              <input
                placeholder="https://github.com/tuempresa/tu-repo"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
              />
              <input placeholder="Rama (ej. main)" value={branch} onChange={(e) => setBranch(e.target.value)} />
            </div>
            <div className="inline-form" style={{ marginTop: 8 }}>
              <input
                type="password"
                placeholder="Token de acceso (opcional)"
                value={githubToken}
                onChange={(e) => setGithubToken(e.target.value)}
              />
            </div>
            <p className="empty-hint" style={{ marginTop: 4 }}>
              Dejalo vacio si el repositorio es publico. Si es privado, el token necesita solo permiso de lectura
              del codigo.
            </p>
            <div style={{ marginTop: 10 }}>
              <button className="btn-primary" onClick={onConnectRepo} disabled={connectRepo.isPending}>
                {connectRepo.isPending ? "Conectando..." : "Conectar repositorio"}
              </button>
            </div>
            {connectFormError && <p className="error-text">{connectFormError}</p>}
            {connectRepoError != null && !connectFormError && (
              <p className="error-text">
                No se pudo conectar el repositorio.{" "}
                <span className="error-detail">{connectionErrorDetail(connectRepoError)}</span>
              </p>
            )}
          </>
        ) : (
          <p className="empty-hint" style={{ marginTop: 12 }}>
            Tu usuario ({claims?.role ?? "sin rol"}) no puede conectar repositorios -- lo puede hacer un admin o
            soc_manager.
          </p>
        )}
      </div>

      <div className="panel">
        <h2>Repositorios conectados</h2>
        {repos.isLoading && <p className="empty-hint">Cargando...</p>}
        {repos.isError && (
          <p className="error-text">
            No se pudo conectar con coderepo-service.{" "}
            <span className="error-detail">{connectionErrorDetail(repos.error)}</span>
          </p>
        )}
        {repos.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Nombre</th>
                <th>URL</th>
                <th>Rama</th>
                <th>Acceso</th>
                <th>Ultimo escaneo</th>
                <th>Fecha ultimo escaneo</th>
                <th>Secretos</th>
                <th>Vulnerabilidades</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {repos.data.map((r) => (
                <tr key={r.id}>
                  <td>{r.name}</td>
                  <td className="mono">{r.repo_url}</td>
                  <td className="mono">{r.branch}</td>
                  <td>{r.has_token ? "Privado" : "Publico"}</td>
                  <td>
                    <StatusBadge value={r.last_scan_status} />
                    {r.last_scan_status === "error" && r.last_scan_error && (
                      <div className="empty-hint" style={{ margin: "4px 0 0" }}>
                        <span className="error-detail">{r.last_scan_error}</span>
                      </div>
                    )}
                  </td>
                  <td>{r.last_scan_at ? new Date(r.last_scan_at).toLocaleString() : "Nunca"}</td>
                  <td>{r.last_scan_secrets_found}</td>
                  <td>
                    {r.last_scan_vulnerabilities_found}{" "}
                    {r.last_scan_vulnerabilities_found > 0 && (
                      <Link to="/vulnerabilities" className="btn-link">
                        ver en Vulnerabilidades
                      </Link>
                    )}
                  </td>
                  <td>
                    <button
                      className="btn-link"
                      title="Puede tardar varios minutos: clona el repositorio y corre gitleaks y trivy"
                      onClick={() => scanRepo.mutate(r.id)}
                      disabled={scanRepo.isPending && scanRepo.variables === r.id}
                    >
                      {scanRepo.isPending && scanRepo.variables === r.id ? "Escaneando..." : "Escanear ahora"}
                    </button>{" "}
                    <button
                      className="btn-link"
                      onClick={() => {
                        if (
                          window.confirm(
                            `Eliminar el repositorio "${r.name}"? Se va a dejar de escanear y clonar.`,
                          )
                        ) {
                          deleteRepo.mutate(r.id);
                        }
                      }}
                    >
                      Eliminar
                    </button>
                    {scanFeedback && scanFeedback.repoId === r.id && (
                      <p className="empty-hint" style={{ margin: "4px 0 0" }}>
                        {scanFeedback.message}
                      </p>
                    )}
                  </td>
                </tr>
              ))}
              {repos.data.length === 0 && (
                <tr>
                  <td colSpan={9} className="empty-hint">
                    Sin repositorios conectados todavia. Conecta uno arriba.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
        {scanRepoError != null && (
          <p className="error-text">
            No se pudo disparar el escaneo.{" "}
            <span className="error-detail">{connectionErrorDetail(scanRepoError)}</span>
          </p>
        )}
        {deleteRepoError != null && (
          <p className="error-text">
            No se pudo eliminar el repositorio.{" "}
            <span className="error-detail">{connectionErrorDetail(deleteRepoError)}</span>
          </p>
        )}
      </div>

      <div className="panel">
        <div className="inline-form" style={{ justifyContent: "space-between" }}>
          <h2 style={{ margin: 0 }}>Secretos encontrados</h2>
          <div className="inline-form">
            {(repos.data ?? []).length > 1 && (
              <select value={selectedRepoId} onChange={(e) => setSelectedRepoId(e.target.value)}>
                <option value="">Todos los repositorios</option>
                {repos.data!.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name}
                  </option>
                ))}
              </select>
            )}
            <select value={secretsFilter} onChange={(e) => setSecretsFilter(e.target.value as "all" | "pending")}>
              <option value="pending">Sin reconocer</option>
              <option value="all">Todos</option>
            </select>
          </div>
        </div>
        {secrets.isLoading && <p className="empty-hint">Cargando...</p>}
        {secrets.isError && (
          <p className="error-text">
            No se pudo cargar los secretos.{" "}
            <span className="error-detail">{connectionErrorDetail(secrets.error)}</span>
          </p>
        )}
        {secrets.data && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Severidad</th>
                <th>Repositorio</th>
                <th>Regla</th>
                <th>Descripcion</th>
                <th>Archivo</th>
                <th>Commit</th>
                <th>Valor (parcialmente oculto)</th>
                <th>Creado</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {secrets.data.map((s) => (
                <tr key={s.id}>
                  <td><SeverityBadge value={s.severity} /></td>
                  <td>{reposById.get(s.repo_target_id)?.name ?? s.repo_target_id}</td>
                  <td className="mono">{s.rule_id}</td>
                  <td>{s.description}</td>
                  <td className="mono">{formatFileLocation(s.file_path, s.start_line)}</td>
                  <td className="mono" title={s.commit_hash}>
                    {truncateHash(s.commit_hash)}
                  </td>
                  <td>
                    <code>{s.match_redacted}</code>
                  </td>
                  <td>{new Date(s.created_at).toLocaleString()}</td>
                  <td>
                    {s.is_acknowledged ? (
                      <span className="empty-hint">Reconocido por {s.acknowledged_by}</span>
                    ) : (
                      <button
                        className="btn-link"
                        onClick={() => acknowledgeSecret.mutate(s.id)}
                        disabled={acknowledgeSecret.isPending && acknowledgeSecret.variables === s.id}
                      >
                        {acknowledgeSecret.isPending && acknowledgeSecret.variables === s.id
                          ? "Reconociendo..."
                          : "Reconocer"}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {secrets.data.length === 0 && (
                <tr>
                  <td colSpan={9} className="empty-hint">
                    Sin secretos{secretsFilter === "pending" ? " sin reconocer" : ""} por el momento.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
        {acknowledgeSecretError != null && (
          <p className="error-text">
            No se pudo reconocer el secreto.{" "}
            <span className="error-detail">{connectionErrorDetail(acknowledgeSecretError)}</span>
          </p>
        )}
      </div>
    </div>
  );
}
