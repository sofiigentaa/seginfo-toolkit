import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { login, loginWithGoogle, register } from "../services/api";
import { useAuthStore } from "../store/auth";
import { parseLoginError } from "../utils/loginError";

const GOOGLE_CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID as string | undefined;

// Mismo criterio que en services/api.ts (serviceUrl): la URL base de
// auth-service en runtime, no en build-time, para no duplicar la logica
// de fallback a localhost:8001.
const AUTH_BASE_URL = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "http://localhost:8001";

// La libreria de Google Identity Services se carga con un <script> en
// index.html y expone window.google en runtime; no tiene tipos propios
// instalados aca, asi que se accede de forma laxa (unknown) en vez de
// agregar una dependencia npm nueva solo para esto.
declare global {
  interface Window {
    google?: {
      accounts: {
        id: {
          initialize: (config: { client_id: string; callback: (resp: { credential: string }) => void }) => void;
          renderButton: (parent: HTMLElement, options: Record<string, unknown>) => void;
        };
      };
    };
  }
}

export default function Login() {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [paymentUrl, setPaymentUrl] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [orgSlug, setOrgSlug] = useState("");
  const setTokens = useAuthStore((s) => s.setTokens);
  const navigate = useNavigate();
  const googleButtonRef = useRef<HTMLDivElement>(null);

  // El login (email/password, Google o SSO) devuelve 402 cuando la
  // organizacion no tiene la suscripcion al dia (ver
  // _reject_if_org_inactive en auth-service/app/main.py). Ese 402 trae
  // el "detail" como objeto ({message, payment_url}), no como string
  // plano -- payment_url viene armado por el servidor central de
  // licencias (Mercado Pago) si esta configurado, o null si esta
  // instalacion todavia gestiona los pagos a mano (ahi solo se muestra
  // el mensaje, sin boton).
  function applyLoginError(err: unknown, fallback: string) {
    // Logica de interpretacion del error extraida a utils/loginError.ts
    // (funcion pura, testeada sin renderizar este componente) -- aca solo
    // queda volcar el resultado al estado del formulario.
    const { message, paymentUrl: url } = parseLoginError(err, fallback);
    setError(message);
    setPaymentUrl(url);
  }

  function handleSsoLogin(e: React.FormEvent) {
    e.preventDefault();
    if (!orgSlug.trim()) return;
    // Redirect completo del navegador (no XHR/fetch): auth-service arma la
    // URL de autorizacion del proveedor OIDC de esta organizacion y
    // redirige para alla; el flujo entero pasa por fuera de esta SPA hasta
    // volver a /sso/callback con los tokens en el fragmento de la URL.
    window.location.href = `${AUTH_BASE_URL}/auth/oidc/${encodeURIComponent(orgSlug.trim())}/login`;
  }

  useEffect(() => {
    if (!GOOGLE_CLIENT_ID || !googleButtonRef.current) return;

    async function handleGoogleCredential(response: { credential: string }) {
      setLoading(true);
      setError(null);
      setPaymentUrl(null);
      try {
        const tokens = await loginWithGoogle(response.credential);
        setTokens(tokens.access_token, tokens.refresh_token);
        navigate("/");
      } catch (err) {
        applyLoginError(err, "No se pudo iniciar sesion con Google.");
      } finally {
        setLoading(false);
      }
    }

    // El script de Google puede tardar un instante en cargar; reintenta
    // un par de veces antes de rendirse en vez de asumir que ya esta listo.
    let attempts = 0;
    const tryInit = () => {
      if (window.google?.accounts?.id && googleButtonRef.current) {
        window.google.accounts.id.initialize({
          client_id: GOOGLE_CLIENT_ID,
          callback: handleGoogleCredential,
        });
        window.google.accounts.id.renderButton(googleButtonRef.current, {
          theme: "outline",
          size: "large",
          width: 280,
          text: "continue_with",
        });
      } else if (attempts < 20) {
        attempts += 1;
        setTimeout(tryInit, 250);
      }
    };
    tryInit();
  }, [navigate, setTokens]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setPaymentUrl(null);
    try {
      const tokens = await login(email, password, totpCode || undefined);
      setTokens(tokens.access_token, tokens.refresh_token);
      navigate("/");
    } catch (err) {
      applyLoginError(err, "Credenciales invalidas o MFA requerido.");
    } finally {
      setLoading(false);
    }
  }

  // Auto-registro (ver POST /auth/register): crea el usuario como
  // "analyst" en la organizacion "default" (el primer usuario que exista
  // en toda la base queda de admin solo). Justo despues, loguea con las
  // mismas credenciales -- asi quien se registra entra directo, sin tener
  // que volver a escribir el email/contrasena en el formulario de login.
  async function handleRegisterSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setPaymentUrl(null);
    // BUG (corregido aca): antes esto envolvia register() Y el login()
    // posterior en el mismo try/catch, asi que si la cuenta se creaba bien
    // pero el login automatico fallaba (ej. 402 porque la organizacion
    // "default" no tiene la suscripcion al dia), el usuario veia "No se
    // pudo crear la cuenta" -- un mensaje falso, la cuenta SI se creo -- y
    // nunca se le mostraba el link de pago (a diferencia del login manual,
    // que si usa parseLoginError/paymentUrl). Ahora cada paso tiene su
    // propio catch: uno para el registro en si, y otro (con la misma
    // logica de 402 que el login normal) para el login automatico que le
    // sigue.
    try {
      await register(email, password, fullName);
    } catch (err) {
      const axiosErr = err as { response?: { data?: { detail?: unknown } } };
      const detail = axiosErr?.response?.data?.detail;
      setError(
        typeof detail === "string"
          ? detail
          : "No se pudo crear la cuenta. Revisa que el email no este ya registrado y que la contrasena tenga al menos 12 caracteres.",
      );
      setLoading(false);
      return;
    }
    try {
      const tokens = await login(email, password);
      setTokens(tokens.access_token, tokens.refresh_token);
      navigate("/");
    } catch (err) {
      // La cuenta ya se creo con exito en este punto -- este error es del
      // login automatico que le sigue (ej. 402 de organizacion sin
      // suscripcion al dia), no del registro.
      applyLoginError(err, "La cuenta se creo, pero no se pudo iniciar sesion automaticamente. Ingresa con tu email y contrasena.");
    } finally {
      setLoading(false);
    }
  }

  function toggleMode() {
    setMode((m) => (m === "login" ? "register" : "login"));
    setError(null);
    setPaymentUrl(null);
  }

  return (
    <div className="app-shell">
      <form className="login-card" onSubmit={mode === "login" ? handleSubmit : handleRegisterSubmit}>
        <h1>SentinelOps</h1>
        <p>{mode === "login" ? "Acceso a la plataforma de seguridad" : "Crear una cuenta nueva"}</p>

        {mode === "register" && (
          <div className="field">
            <label htmlFor="full-name">Nombre completo</label>
            <input id="full-name" value={fullName} onChange={(e) => setFullName(e.target.value)} />
          </div>
        )}

        <div className="field">
          <label htmlFor="email">Email</label>
          <input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </div>

        <div className="field">
          <label htmlFor="password">Contrasena{mode === "register" ? " (minimo 12 caracteres)" : ""}</label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            minLength={mode === "register" ? 12 : undefined}
            required
          />
        </div>

        {mode === "login" && (
          <div className="field">
            <label htmlFor="totp">Codigo MFA (si esta activado)</label>
            <input id="totp" type="text" value={totpCode} onChange={(e) => setTotpCode(e.target.value)} placeholder="123456" />
          </div>
        )}

        <button
          className="btn-primary"
          type="submit"
          disabled={loading || (mode === "register" && password.length > 0 && password.length < 12)}
        >
          {mode === "login" ? (loading ? "Ingresando..." : "Ingresar") : loading ? "Creando cuenta..." : "Crear cuenta"}
        </button>

        {error && <p className="error-text">{error}</p>}

        {paymentUrl && (
          <>
            <a
              className="btn-primary"
              href={paymentUrl}
              target="_blank"
              rel="noopener noreferrer"
              style={{ display: "block", textAlign: "center", textDecoration: "none", marginTop: 8 }}
            >
              Pagar membresia
            </a>
            <p className="empty-hint" style={{ marginTop: 8 }}>
              Se abre la pagina de Mercado Pago en una pestana nueva. Despues de pagar, esperá un minuto y volvé a
              intentar ingresar -- el acceso se reactiva solo, no hace falta avisarle a nadie.
            </p>
          </>
        )}

        <p className="empty-hint" style={{ marginTop: 12 }}>
          {mode === "login" ? "¿No tenes cuenta todavia? " : "¿Ya tenes cuenta? "}
          <button type="button" className="btn-link" onClick={toggleMode}>
            {mode === "login" ? "Creala con tu email" : "Iniciar sesion"}
          </button>
        </p>

        {mode === "login" && GOOGLE_CLIENT_ID && (
          <div className="google-signin-wrap">
            <div className="divider"><span>o</span></div>
            <div ref={googleButtonRef} />
          </div>
        )}

        {mode === "login" && (
          <>
            <div className="divider"><span>o</span></div>
            <div className="field">
              <label htmlFor="org-slug">SSO empresarial (tu organizacion)</label>
              <input
                id="org-slug"
                value={orgSlug}
                onChange={(e) => setOrgSlug(e.target.value)}
                placeholder="slug de tu organizacion, ej. acme-corp"
              />
            </div>
            <button className="btn-secondary" type="button" onClick={handleSsoLogin} disabled={!orgSlug.trim()}>
              Continuar con SSO
            </button>
          </>
        )}
      </form>
    </div>
  );
}
