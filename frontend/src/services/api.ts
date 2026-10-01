import axios, { AxiosError, AxiosInstance, InternalAxiosRequestConfig } from "axios";
import { useAuthStore } from "../store/auth";

function serviceUrl(envVar: string, port: number): string {
  const fromEnv = (import.meta.env as Record<string, string | undefined>)[envVar];
  return fromEnv ?? `http://localhost:${port}`;
}

// El access_token dura poco a proposito (15 min por defecto, ver
// ACCESS_TOKEN_EXPIRE_MINUTES en backend/shared/security.py) -- sin este
// refresh automatico, cualquier sesion de mas de 15 minutos terminaba
// viendo "Token invalido o expirado" en cada pagina hasta cerrar sesion y
// volver a entrar.
const authBaseURL = serviceUrl("VITE_API_BASE_URL", 8001);

let refreshPromise: Promise<string> | null = null;

// Pide un access_token nuevo con el refresh_token guardado. Usa un axios
// "pelado" (sin los interceptores de abajo) para no entrar en loop si
// /auth/refresh mismo devolviera 401, y cachea la promesa en curso para
// que varios requests que fallan al mismo tiempo (por ejemplo, al volver
// a la pestaña despues de un rato) disparen un solo refresh en vez de uno
// por cada uno.
async function refreshAccessToken(): Promise<string> {
  if (!refreshPromise) {
    refreshPromise = (async () => {
      const refreshToken = useAuthStore.getState().refreshToken;
      if (!refreshToken) {
        throw new Error("No hay refresh_token guardado");
      }
      try {
        const { data } = await axios.post<{ access_token: string; refresh_token: string }>(
          `${authBaseURL}/auth/refresh`,
          { refresh_token: refreshToken },
        );
        useAuthStore.getState().setTokens(data.access_token, data.refresh_token);
        return data.access_token;
      } finally {
        refreshPromise = null;
      }
    })();
  }
  return refreshPromise;
}

function makeClient(baseURL: string): AxiosInstance {
  const client = axios.create({ baseURL });
  client.interceptors.request.use((config) => {
    const token = useAuthStore.getState().accessToken;
    if (token) {
      config.headers = config.headers ?? {};
      (config.headers as Record<string, string>).Authorization = `Bearer ${token}`;
    }
    return config;
  });
  client.interceptors.response.use(
    (response) => response,
    async (error: AxiosError) => {
      const original = error.config as (InternalAxiosRequestConfig & { _retriedAfterRefresh?: boolean }) | undefined;
      if (error.response?.status === 401 && original && !original._retriedAfterRefresh) {
        original._retriedAfterRefresh = true;
        try {
          const newAccessToken = await refreshAccessToken();
          original.headers = original.headers ?? {};
          (original.headers as Record<string, string>).Authorization = `Bearer ${newAccessToken}`;
          return client(original);
        } catch {
          // El refresh_token tambien esta vencido (7 dias por defecto) o
          // no existe -- no hay como recuperar la sesion sin volver a
          // loguearse. logout() limpia el store; ProtectedRoute (que lee
          // accessToken de forma reactiva) redirige solo a /login.
          useAuthStore.getState().logout();
        }
      }
      return Promise.reject(error);
    },
  );
  return client;
}

// Cada microservicio corre en su propio puerto (ver docker-compose.yml);
// en produccion detras de un API gateway/reverse proxy estas URLs se
// reemplazan por variables de entorno VITE_*_SERVICE_URL en build time.
// Mismo esquema de nombres que ya definia .env.example en Fase 1
// (VITE_API_BASE_URL, VITE_ASSET_API_BASE_URL, etc.) -- se completan aca
// las variables para los servicios agregados en Fases 3-5.
export const authApi = makeClient(serviceUrl("VITE_API_BASE_URL", 8001));
export const assetApi = makeClient(serviceUrl("VITE_ASSET_API_BASE_URL", 8002));
export const scanApi = makeClient(serviceUrl("VITE_SCAN_API_BASE_URL", 8003));
export const vulnApi = makeClient(serviceUrl("VITE_VULN_API_BASE_URL", 8004));
export const siemApi = makeClient(serviceUrl("VITE_SIEM_API_BASE_URL", 8005));
export const soarApi = makeClient(serviceUrl("VITE_SOAR_API_BASE_URL", 8006));
export const caseApi = makeClient(serviceUrl("VITE_CASE_API_BASE_URL", 8007));
export const purpleApi = makeClient(serviceUrl("VITE_PURPLE_API_BASE_URL", 8008));
export const reportApi = makeClient(serviceUrl("VITE_REPORT_API_BASE_URL", 8009));
export const notificationApi = makeClient(serviceUrl("VITE_NOTIFICATION_API_BASE_URL", 8010));
export const integrationApi = makeClient(serviceUrl("VITE_INTEGRATION_API_BASE_URL", 8011));
export const threatIntelApi = makeClient(serviceUrl("VITE_THREATINTEL_API_BASE_URL", 8012));
export const asmApi = makeClient(serviceUrl("VITE_ASM_API_BASE_URL", 8013));
export const cloudApi = makeClient(serviceUrl("VITE_CLOUD_API_BASE_URL", 8014));
export const coderepoApi = makeClient(serviceUrl("VITE_CODEREPO_API_BASE_URL", 8015));

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export async function loginWithGoogle(credential: string): Promise<TokenPair> {
  const { data } = await authApi.post<TokenPair>("/auth/google", { credential });
  return data;
}

export async function login(email: string, password: string, totpCode?: string): Promise<TokenPair> {
  const { data } = await authApi.post<TokenPair>("/auth/login", {
    email,
    password,
    totp_code: totpCode ?? null,
  });
  return data;
}

// Auto-registro publico (ver POST /auth/register en auth-service): siempre
// crea al usuario como "analyst" en la organizacion "default" -- el primer
// usuario que exista en toda la base queda como admin automaticamente. No
// devuelve tokens (a diferencia de login/loginWithGoogle): Login.tsx llama
// a login() con las mismas credenciales justo despues, para no duplicar la
// logica de "que hacer con el TokenPair" en dos lugares.
export async function register(email: string, password: string, fullName: string): Promise<void> {
  await authApi.post("/auth/register", {
    email,
    password,
    full_name: fullName,
  });
}
