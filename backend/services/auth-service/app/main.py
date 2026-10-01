"""auth-service entrypoint: identidad, organizaciones (tenants), JWT
issuance, MFA (TOTP), SSO empresarial (OIDC), RBAC."""
import asyncio
import os
import secrets
from contextlib import asynccontextmanager
from datetime import timedelta
from urllib.parse import urlencode
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests
from jose import JWTError
from sqlalchemy import text
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, make_asgi_app
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db, engine, Base, SessionLocal
from backend.shared.logging import configure_logging
from backend.shared.cors import get_cors_origins
from backend.shared.security_headers import SecurityHeadersMiddleware
from backend.shared.rate_limit import check_rate_limit
from backend.shared.security import decode_token, create_token
from backend.shared import license_check
from app.schemas import (
    UserCreate,
    UserOut,
    LoginRequest,
    TokenPair,
    MfaEnrollRequest,
    MfaEnrollResponse,
    MfaVerifyRequest,
    GoogleAuthRequest,
    RefreshRequest,
    OrganizationCreate,
    OrganizationOut,
    SsoConfigIn,
    SsoConfigOut,
    SubscriptionExtendRequest,
    SubscriptionCancelOut,
    SubscriptionPayLinkOut,
    SubscriptionHistoryOut,
)
from app.dependencies import get_current_claims, require_role, require_platform_admin, require_org_admin_or_platform_admin
from app import services, oidc

logger = configure_logging("auth-service")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
# A donde se redirige al navegador despues de un login SSO exitoso (con los
# tokens en el fragmento de la URL, ver /auth/oidc/{slug}/callback). El
# frontend tiene que tener una ruta que los lea de ahi -- ver
# frontend/src/pages/SsoCallback.tsx.
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")
login_attempts_total = Counter("auth_login_attempts_total", "Login attempts", ["outcome"])
LICENSE_CHECK_INTERVAL_HOURS = float(os.getenv("LICENSE_CHECK_INTERVAL_HOURS", "6"))


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


async def _reject_if_org_inactive(db: AsyncSession, org, actor_email: str) -> None:
    """402 (Payment Required) si la organizacion de este usuario no tiene
    la suscripcion al dia -- ver services.is_org_active() para el
    criterio exacto. Se llama en los 4 caminos que emiten tokens
    (login, Google, SSO, refresh); bloqueo total por decision del
    operador, no un downgrade a solo-lectura.

    A quien llega hasta aca ya se le verificaron sus credenciales (esta
    funcion se llama DESPUES de authenticate()/Google/SSO, nunca
    antes) -- por eso alcanza esa confianza para, ademas de bloquearlo,
    ofrecerle de una un link de pago (Mercado Pago) generado al vuelo
    contra el servidor central de licencias, con actor_email como
    payer_email. El campo "detail" del 402 pasa a ser un objeto (no un
    string plano) para que el frontend pueda mostrar un boton "Pagar
    membresia" en vez de solo un cartel de error -- ver Login.tsx."""
    if services.is_org_active(org):
        return
    login_attempts_total.labels(outcome="failure").inc()
    await services.record_audit_event(db, actor_email, "auth.login.blocked_subscription", org.id)
    await db.commit()

    payment_url = None
    if license_check.is_configured():
        try:
            payment_url = await license_check.get_mercadopago_payment_link(actor_email)
        except license_check.LicenseCheckError as exc:
            logger.warning("no se pudo generar el link de pago de Mercado Pago para %s: %s", org.id, exc)

    message = "La suscripcion de esta organizacion no esta al dia."
    if payment_url:
        message += " Paga la membresia para recuperar el acceso."
    else:
        message += " Contacta al administrador de la plataforma para renovarla."

    raise HTTPException(
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        detail={"message": message, "payment_url": payment_url},
    )


async def _license_check_loop() -> None:
    """Tarea de fondo: cada LICENSE_CHECK_INTERVAL_HOURS horas, refresca
    subscription_expires_at de TODAS las organizaciones contra el
    servidor central de licencias (ver backend/shared/license_check.py).
    No hace nada (ni loguea) si LICENSE_SERVER_URL no esta configurado --
    instalaciones que gestionan la suscripcion solo a mano via
    /auth/organizations/{id}/subscription/extend."""
    if not license_check.is_configured():
        return
    while True:
        try:
            async with SessionLocal() as session:
                orgs = await services.list_organizations(session)
                for org in orgs:
                    await services.refresh_license_from_central_server(session, org.id)
                await session.commit()
        except Exception:
            logger.exception("fallo inesperado en el ciclo de chequeo de licencia")
        await asyncio.sleep(LICENSE_CHECK_INTERVAL_HOURS * 3600)


async def _enforce_rate_limit(key: str, limit: int, window_seconds: int = 300) -> None:
    """429 si se supero el limite -- ver backend/shared/rate_limit.py.
    window_seconds=300 (5 min) por defecto en todos los usos de este
    modulo: alcanza para frenar fuerza bruta sostenida sin molestar a un
    usuario real que se equivoca la contraseña un par de veces."""
    if not await check_rate_limit(key, limit, window_seconds):
        raise HTTPException(
            status_code=429,
            detail="Demasiados intentos. Espera unos minutos antes de volver a intentar.",
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Migracion liviana para bases ya existentes (creadas antes de que
        # existiera el login con Google): agrega auth_provider si falta y
        # permite password nulo para cuentas que solo entran por Google.
        # create_all no altera tablas ya creadas, por eso el ALTER a mano.
        await conn.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider VARCHAR(20) NOT NULL DEFAULT 'local'"
        ))
        await conn.execute(text(
            "ALTER TABLE users ALTER COLUMN hashed_password DROP NOT NULL"
        ))
        # Idem para multi-tenancy: create_all crea las tablas organizations
        # y sso_configs (son nuevas), pero la tabla users ya existia en
        # cualquier instalacion previa a esto, asi que sus columnas nuevas
        # necesitan el mismo ALTER a mano. organization_id se backfillea
        # aparte, mas abajo (no puede ir en el mismo ALTER porque todavia
        # no existe la organizacion "default" a la que asignarselo).
        await conn.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36) REFERENCES organizations(id)"
        ))
        await conn.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_platform_admin BOOLEAN NOT NULL DEFAULT FALSE"
        ))
        # Suscripcion/licencia (ver app/models.py::Organization): las
        # organizaciones creadas antes de este cambio no tienen estas
        # columnas -- se agregan con un default de "30 dias desde ahora"
        # (mismo criterio que Organization.subscription_expires_at para
        # una fila nueva) en vez de dejarlas NULL, para no bloquear de
        # golpe a nadie que ya estaba usando la plataforma el dia que
        # esto se despliega.
        await conn.execute(text(
            "ALTER TABLE organizations ADD COLUMN IF NOT EXISTS subscription_expires_at "
            "TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '30 days')"
        ))
        await conn.execute(text(
            "ALTER TABLE organizations ADD COLUMN IF NOT EXISTS license_last_checked_at TIMESTAMPTZ"
        ))
    async with SessionLocal() as session:
        await services.promote_first_user_to_admin_if_needed(session)
        await services.backfill_users_without_organization(session)
        await session.commit()
    license_task = asyncio.create_task(_license_check_loop())
    logger.info("auth-service iniciado", extra={"license_server_configured": license_check.is_configured()})
    yield
    license_task.cancel()


app = FastAPI(title="SentinelOps Auth Service", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.mount("/metrics", make_asgi_app())


@app.get("/health")
async def health():
    return {"status": "ok", "service": "auth-service"}


@app.post("/auth/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(payload: UserCreate, db: AsyncSession = Depends(get_db)):
    """Auto-registro publico: siempre crea el usuario como "analyst" en la
    organizacion "default" (el auto-registro abierto no tiene forma segura
    de saber a que EMPRESA pertenece quien se registra -- para clientes que
    necesitan su propia organizacion separada, un platform_admin usa
    POST /auth/organizations, que crea la empresa y su primer admin en un
    solo paso). Si es el primer usuario que existe en toda la base, el
    lifespan lo asciende a admin (y platform_admin) automaticamente la
    proxima vez que arranque el servicio (o ya lo hizo si esto es lo
    primero que corre)."""
    existing = await services.get_user_by_email(db, payload.email)
    if existing:
        raise HTTPException(status_code=400, detail="El email ya esta registrado")
    default_org = await services.get_default_organization(db)
    user = await services.create_user(db, payload.email, payload.password, payload.full_name, default_org.id)
    await services.promote_first_user_to_admin_if_needed(db)
    await services.record_audit_event(db, payload.email, "user.register")
    await db.commit()
    # Recargar con el rol ya resuelto (create_user no lo trae eager-loaded,
    # y promote_first_user_to_admin_if_needed puede haberlo cambiado).
    user = await services.get_user_by_email(db, payload.email)
    role_name = user.role.name if user.role else "analyst"
    return UserOut(
        id=user.id, email=user.email, full_name=user.full_name,
        role_name=role_name, is_active=user.is_active, mfa_enabled=user.mfa_enabled,
        organization_id=user.organization_id,
    )


@app.post("/auth/login", response_model=TokenPair)
async def login(payload: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    # Dos limites en paralelo: por IP (frena a un atacante probando muchas
    # cuentas, o muchas passwords contra una) y por email (frena fuerza
    # bruta distribuida en varias IPs contra UNA cuenta puntual).
    await _enforce_rate_limit(f"login:ip:{_client_ip(request)}", limit=20)
    await _enforce_rate_limit(f"login:email:{payload.email.lower()}", limit=10)
    user = await services.authenticate(db, payload.email, payload.password, payload.totp_code)
    if user is None:
        login_attempts_total.labels(outcome="failure").inc()
        await services.record_audit_event(db, payload.email, "auth.login.failure")
        await db.commit()
        raise HTTPException(status_code=401, detail="Credenciales invalidas o MFA requerido")
    org = await services.get_organization_by_id(db, user.organization_id) if user.organization_id else None
    if org is not None:
        await _reject_if_org_inactive(db, org, payload.email)
    role_name = user.role.name if user.role else "analyst"
    access, refresh = services.issue_tokens(user, role_name)
    login_attempts_total.labels(outcome="success").inc()
    await services.record_audit_event(db, payload.email, "auth.login.success")
    await db.commit()
    return TokenPair(access_token=access, refresh_token=refresh)


@app.post("/auth/google", response_model=TokenPair)
async def google_login(payload: GoogleAuthRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """Login o registro con Google: el frontend manda el credential (ID token)
    que devuelve Google Identity Services; lo validamos contra los servers de
    Google (firma + audiencia == nuestro client id) antes de confiar en el
    email. No hay password ni MFA en este camino porque Google ya verifico
    al usuario."""
    await _enforce_rate_limit(f"google_login:ip:{_client_ip(request)}", limit=20)
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=503, detail="Login con Google no esta configurado en este servidor (falta GOOGLE_CLIENT_ID)")
    try:
        claims = google_id_token.verify_oauth2_token(payload.credential, google_requests.Request(), GOOGLE_CLIENT_ID)
    except ValueError:
        login_attempts_total.labels(outcome="failure").inc()
        raise HTTPException(status_code=401, detail="Token de Google invalido o expirado")
    if not claims.get("email_verified", False):
        raise HTTPException(status_code=401, detail="El email de esa cuenta de Google no esta verificado")
    email = claims["email"]
    full_name = claims.get("name", "")
    user = await services.get_or_create_google_user(db, email, full_name)
    org = await services.get_organization_by_id(db, user.organization_id) if user.organization_id else None
    if org is not None:
        await _reject_if_org_inactive(db, org, email)
    role_name = user.role.name if user.role else "analyst"
    access, refresh = services.issue_tokens(user, role_name)
    login_attempts_total.labels(outcome="success").inc()
    await services.record_audit_event(db, email, "auth.google.login")
    await db.commit()
    return TokenPair(access_token=access, refresh_token=refresh)


@app.post("/auth/refresh", response_model=TokenPair)
async def refresh(payload: RefreshRequest, db: AsyncSession = Depends(get_db)):
    """Cambia un refresh_token vigente por un access_token nuevo (y un
    refresh_token nuevo). El access_token dura poco a proposito
    (ACCESS_TOKEN_EXPIRE_MINUTES, 15 minutos por defecto) -- sin este
    endpoint, el usuario quedaba con 401 ("Token invalido o expirado") en
    toda la plataforma pasados esos 15 minutos, sin otra opcion que cerrar
    sesion y volver a entrar. El frontend llama esto automaticamente
    (ver frontend/src/services/api.ts) apenas ve un 401."""
    try:
        claims = decode_token(payload.refresh_token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Refresh token invalido o expirado")
    if claims.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Tipo de token incorrecto")
    user = await services.get_user_by_id(db, claims["sub"])
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Usuario no encontrado o inactivo")
    org = await services.get_organization_by_id(db, user.organization_id) if user.organization_id else None
    if org is not None:
        await _reject_if_org_inactive(db, org, user.email)
    role_name = user.role.name if user.role else "analyst"
    access, new_refresh = services.issue_tokens(user, role_name)
    return TokenPair(access_token=access, refresh_token=new_refresh)


@app.post("/auth/mfa/enroll", response_model=MfaEnrollResponse)
async def mfa_enroll(
    payload: MfaEnrollRequest = MfaEnrollRequest(),
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    # BUG DE SEGURIDAD (corregido aca): antes esto pisaba mfa_secret sin
    # ninguna condicion -- cualquiera con un access_token valido (15 min,
    # robado via XSS, un dispositivo prestado, un token que quedo en un
    # log) podia llamar este endpoint para generarle a la victima un
    # secret de MFA NUEVO que el atacante ya conoce, y confirmarlo el
    # mismo con /auth/mfa/confirm -- sin necesitar el codigo TOTP real ni
    # la contrasena. mfa_enabled seguia en True todo el tiempo, asi que la
    # victima no veia ninguna señal de que su segundo factor cambio.
    # Ahora, si el usuario YA tiene MFA activo, re-enrolar (generar un
    # secret nuevo) exige probar primero que quien lo pide todavia
    # controla el dispositivo YA enrolado (un codigo TOTP valido del
    # secret actual) -- exactamente lo mismo que ya se le exige para
    # cualquier otra accion sensible de la cuenta.
    user = await db.get(services.User, claims["sub"])
    if user.mfa_enabled:
        await _enforce_rate_limit(f"mfa_reenroll:user:{claims['sub']}", limit=10)
        if not services.verify_current_totp(user, payload.totp_code):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Para reemplazar el MFA actual, primero confirma un codigo TOTP valido del dispositivo ya enrolado.",
            )
    secret, otpauth_url = await services.enroll_mfa(db, user)
    await db.commit()
    return MfaEnrollResponse(secret=secret, otpauth_url=otpauth_url)


@app.post("/auth/mfa/confirm")
async def mfa_confirm(payload: MfaVerifyRequest, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    # Un codigo TOTP son 6 digitos (10^6 combinaciones) y valid_window=1
    # deja ~3 codigos validos en cualquier momento -- sin limite, alguien
    # con un access_token robado/filtrado podria intentar habilitar MFA
    # con un codigo adivinado en vez del real.
    await _enforce_rate_limit(f"mfa_confirm:user:{claims['sub']}", limit=10)
    user = await db.get(services.User, claims["sub"])
    ok = await services.confirm_mfa(db, user, payload.totp_code)
    await db.commit()
    if not ok:
        raise HTTPException(status_code=400, detail="Codigo TOTP invalido")
    return {"mfa_enabled": True}


@app.get("/auth/admin/ping")
async def admin_ping(claims: dict = Depends(require_role("admin"))):
    return {"pong": True, "role": claims["role"]}


# --- Organizaciones (tenants) ---

@app.post("/auth/organizations", status_code=status.HTTP_201_CREATED)
async def create_organization(
    payload: OrganizationCreate,
    claims: dict = Depends(require_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    """Crea una organizacion nueva y su primer usuario admin en un solo
    paso (ver el comentario en schemas.OrganizationCreate del por que no
    hay auto-registro publico de organizaciones)."""
    existing_user = await services.get_user_by_email(db, payload.admin_email)
    if existing_user:
        raise HTTPException(status_code=400, detail="El email ya esta registrado")
    org = await services.create_organization(db, payload.name)
    admin_user = await services.create_user(
        db, payload.admin_email, payload.admin_password, payload.admin_full_name,
        org.id, role_name="admin",
    )
    await services.record_audit_event(db, claims.get("sub", ""), "organization.create", org.id)
    await db.commit()
    return {
        "organization": OrganizationOut.model_validate(org),
        "admin_user": UserOut(
            id=admin_user.id, email=admin_user.email, full_name=admin_user.full_name,
            role_name="admin", is_active=admin_user.is_active, mfa_enabled=admin_user.mfa_enabled,
            organization_id=admin_user.organization_id,
        ),
    }


@app.get("/auth/organizations", response_model=list[OrganizationOut])
async def list_organizations(claims: dict = Depends(require_platform_admin), db: AsyncSession = Depends(get_db)):
    return await services.list_organizations(db)


@app.get("/internal/organizations")
async def internal_list_organizations(db: AsyncSession = Depends(get_db)):
    """Endpoint interno (sin auth de usuario -- servicio-a-servicio dentro
    de la red de docker-compose, mismo patron que /internal/rule-tags de
    siem-service o /internal/notify de notification-service). Solo expone
    ids, nada sensible: pensado para que otro servicio pueda recorrer
    "todas las organizaciones" sin necesitar un JWT de platform_admin
    (ej. case-service, para sincronizar pending-cases de soar-service de
    cada tenant en un ciclo de fondo -- ver case-service/app/main.py::
    _soar_sync_loop)."""
    orgs = await services.list_organizations(db)
    return [{"id": org.id} for org in orgs]


@app.get("/auth/organizations/{org_id}/sso", response_model=SsoConfigOut | None)
async def get_sso_config(
    org_id: str,
    claims: dict = Depends(require_org_admin_or_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    config = await services.get_sso_config(db, org_id)
    return config


@app.put("/auth/organizations/{org_id}/sso", response_model=SsoConfigOut)
async def set_sso_config(
    org_id: str,
    payload: SsoConfigIn,
    claims: dict = Depends(require_org_admin_or_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    org = await services.get_organization_by_id(db, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organizacion no encontrada")
    config = await services.upsert_sso_config(
        db, org_id, payload.issuer, payload.client_id, payload.client_secret,
        payload.default_role, payload.enabled,
    )
    await services.record_audit_event(db, claims.get("sub", ""), "sso_config.update", org_id)
    await db.commit()
    return config


# --- Suscripcion / licencia (ver app/models.py::Organization y
# backend/shared/license_check.py para el diseño completo) ---

@app.get("/auth/organizations/{org_id}/subscription", response_model=OrganizationOut)
async def get_subscription(
    org_id: str,
    claims: dict = Depends(require_org_admin_or_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    """Solo lectura -- el admin de la propia organizacion puede ver
    cuando vence su suscripcion (para no tener que preguntarle al
    operador), pero no puede extenderla el mismo (ver el endpoint de
    abajo, que exige platform_admin)."""
    org = await services.get_organization_by_id(db, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organizacion no encontrada")
    return org


@app.post("/auth/organizations/{org_id}/subscription/extend", response_model=OrganizationOut)
async def extend_subscription(
    org_id: str,
    payload: SubscriptionExtendRequest,
    claims: dict = Depends(require_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    """Renovacion manual -- SOLO el operador de la plataforma (nunca el
    admin de la propia organizacion: extender su propia suscripcion
    "gratis" es exactamente lo que este gate existe para evitar). Es lo
    que se usa hoy, a mano, al confirmar un pago; el dia que el webhook
    de Mercado Pago este conectado al servidor central de licencias, ese
    webhook llama al equivalente de esto en licensing-server (ver
    licensing-server/app/main.py::extend_client), no a este endpoint
    directamente -- este endpoint sigue sirviendo para instalaciones sin
    servidor central (LICENSE_SERVER_URL vacio) o para ajustes manuales
    puntuales."""
    org = await services.extend_subscription(db, org_id, payload.days)
    if org is None:
        raise HTTPException(status_code=404, detail="Organizacion no encontrada")
    await services.record_audit_event(
        db, claims.get("sub", ""), "organization.subscription.extend", f"{org_id}:+{payload.days}d"
    )
    await db.commit()
    return org


@app.post("/auth/organizations/{org_id}/subscription/cancel-payment", response_model=SubscriptionCancelOut)
async def cancel_subscription_payment(
    org_id: str,
    claims: dict = Depends(require_org_admin_or_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    """Autoservicio -- a diferencia de extend_subscription (arriba), esto
    NO otorga ningun beneficio gratis (no toca subscription_expires_at),
    solo corta el PROXIMO cobro automatico de Mercado Pago -- por eso el
    admin de la propia organizacion puede llamarlo el mismo, sin
    necesitar a un platform_admin. El acceso sigue activo hasta que
    venza el periodo ya pagado (ver cancel_mercadopago_subscription en
    backend/shared/license_check.py)."""
    org = await services.get_organization_by_id(db, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organizacion no encontrada")
    if not license_check.is_configured():
        raise HTTPException(
            status_code=503,
            detail="Esta instalacion no tiene un servidor central de licencias configurado -- "
            "para cancelar la suscripcion, contacta al operador.",
        )
    try:
        await license_check.cancel_mercadopago_subscription()
    except license_check.LicenseCheckError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    await services.record_audit_event(
        db, claims.get("sub", ""), "organization.subscription.cancel_payment", org_id
    )
    await db.commit()
    return SubscriptionCancelOut(cancelled=True, valid_until=org.subscription_expires_at)


@app.post("/auth/organizations/{org_id}/subscription/pay-link", response_model=SubscriptionPayLinkOut)
async def get_subscription_pay_link(
    org_id: str,
    claims: dict = Depends(require_org_admin_or_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    """Autoservicio -- genera un link de pago de Mercado Pago para esta
    organizacion, tanto para pagar por primera vez como para volver a
    suscribirse despues de haber cancelado (ver cancel_subscription_payment
    arriba) mientras el periodo ya pagado todavia no vencio. payer_email
    es el email de QUIEN ESTA LOGUEADO pidiendolo (se resuelve del JWT,
    nunca se le pide al frontend que lo mande) -- Mercado Pago lo pide
    solo para vincular el pago, no hace falta que sea el admin de la
    organizacion en particular."""
    org = await services.get_organization_by_id(db, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organizacion no encontrada")
    if not license_check.is_configured():
        raise HTTPException(
            status_code=503,
            detail="Esta instalacion no tiene un servidor central de licencias configurado -- "
            "para pagar o renovar, contacta al operador.",
        )
    user = await services.get_user_by_id(db, claims.get("sub", ""))
    if user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    try:
        payment_url = await license_check.get_mercadopago_payment_link(user.email)
    except license_check.LicenseCheckError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    if not payment_url:
        raise HTTPException(
            status_code=503,
            detail="Mercado Pago no esta configurado del lado del servidor central de licencias.",
        )
    await services.record_audit_event(db, claims.get("sub", ""), "organization.subscription.pay_link", org_id)
    await db.commit()
    return SubscriptionPayLinkOut(payment_url=payment_url)


@app.get("/auth/organizations/{org_id}/subscription/history", response_model=SubscriptionHistoryOut)
async def get_subscription_history(
    org_id: str,
    claims: dict = Depends(require_org_admin_or_platform_admin),
    db: AsyncSession = Depends(get_db),
):
    """Solo lectura -- historial de pagos/cancelaciones/renovaciones de
    esta licencia, para que el admin de la organizacion no tenga que
    pedirselo al operador. Lista vacia (nunca error) si no hay servidor
    central configurado -- el frontend ya sabe mostrar "sin historial"
    en ese caso."""
    org = await services.get_organization_by_id(db, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organizacion no encontrada")
    if not license_check.is_configured():
        return SubscriptionHistoryOut(history=[])
    try:
        history = await license_check.get_subscription_history()
    except license_check.LicenseCheckError as exc:
        logger.warning("no se pudo traer el historial de licencia para %s: %s", org_id, exc)
        return SubscriptionHistoryOut(history=[])
    return SubscriptionHistoryOut(history=history)


# --- SSO empresarial (OIDC) ---
#
# state es un JWT propio de vida MUY corta (5 min, tipo "oidc_state") que
# viaja ida y vuelta por la URL a traves del proveedor de identidad -- hace
# de proteccion CSRF (nadie mas puede fabricar uno valido sin nuestra
# JWT_SECRET_KEY) y de forma de pasar el org_id/nonce sin necesitar sesiones
# de servidor (esta API es stateless, como el resto de la plataforma).

def _oidc_redirect_uri(request: Request, org_slug: str) -> str:
    return str(request.url_for("oidc_callback", org_slug=org_slug))


@app.get("/auth/oidc/{org_slug}/login")
async def oidc_login(org_slug: str, request: Request, db: AsyncSession = Depends(get_db)):
    org = await services.get_organization_by_slug(db, org_slug)
    if org is None:
        raise HTTPException(status_code=404, detail="Organizacion no encontrada")
    config = await services.get_sso_config(db, org.id)
    if config is None or not config.enabled:
        raise HTTPException(status_code=404, detail="Esta organizacion no tiene SSO configurado/habilitado")

    nonce = secrets.token_urlsafe(16)
    state = create_token(org.id, timedelta(minutes=5), {"type": "oidc_state", "nonce": nonce})
    try:
        authorize_url = await oidc.build_authorize_url(config, _oidc_redirect_uri(request, org_slug), state, nonce)
    except oidc.OidcError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return RedirectResponse(authorize_url)


@app.get("/auth/oidc/{org_slug}/callback", name="oidc_callback")
async def oidc_callback(org_slug: str, request: Request, code: str, state: str, db: AsyncSession = Depends(get_db)):
    org = await services.get_organization_by_slug(db, org_slug)
    if org is None:
        raise HTTPException(status_code=404, detail="Organizacion no encontrada")
    config = await services.get_sso_config(db, org.id)
    if config is None or not config.enabled:
        raise HTTPException(status_code=404, detail="Esta organizacion no tiene SSO configurado/habilitado")

    try:
        state_claims = decode_token(state)
    except JWTError:
        raise HTTPException(status_code=401, detail="state invalido o expirado -- volve a intentar el login")
    if state_claims.get("type") != "oidc_state" or state_claims.get("sub") != org.id:
        raise HTTPException(status_code=401, detail="state no corresponde a esta organizacion")
    nonce = state_claims.get("nonce", "")

    try:
        tokens = await oidc.exchange_code(config, code, _oidc_redirect_uri(request, org_slug))
        id_token = tokens.get("id_token")
        if not id_token:
            raise oidc.OidcError("el proveedor no devolvio id_token")
        id_claims = await oidc.validate_id_token(config, id_token, nonce)
    except oidc.OidcError as exc:
        login_attempts_total.labels(outcome="failure").inc()
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    email = id_claims["email"]
    full_name = id_claims.get("name", "")
    user = await services.get_or_create_oidc_user(db, email, full_name, org, config.default_role)
    if user.organization_id != org.id:
        # Un email que ya existe en OTRA organizacion no puede "entrar" a
        # esta via SSO -- evita que alguien con SSO mal configurado en la
        # empresa B termine autenticado como un usuario de la empresa A.
        login_attempts_total.labels(outcome="failure").inc()
        raise HTTPException(status_code=403, detail="Este email ya pertenece a otra organizacion")
    await _reject_if_org_inactive(db, org, email)

    role_name = user.role.name if user.role else config.default_role
    access, refresh = services.issue_tokens(user, role_name)
    login_attempts_total.labels(outcome="success").inc()
    await services.record_audit_event(db, email, "auth.oidc.login", org.id)
    await db.commit()

    fragment = urlencode({"access_token": access, "refresh_token": refresh})
    return RedirectResponse(f"{FRONTEND_URL}/sso/callback#{fragment}")
