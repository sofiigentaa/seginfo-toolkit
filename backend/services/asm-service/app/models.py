"""SQLAlchemy models for asm-service: monitoreo pasivo de superficie externa
(dominios/subdominios via Certificate Transparency y certificados SSL que
un host ya esta sirviendo publicamente). Ver docs/architecture.md."""
import enum
import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Boolean, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column
from backend.shared.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class SurfaceAlertType(str, enum.Enum):
    new_subdomain = "new_subdomain"
    cert_expiring = "cert_expiring"
    cert_expired = "cert_expired"
    cert_check_failed = "cert_check_failed"


class AlertSeverity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class MonitoredDomain(Base):
    """Dominio raiz que el usuario registro para vigilar (ej. 'empresa.com',
    sin protocolo/path). Es el punto de partida de cada corrida del
    scheduler: a partir de aca se descubren subdominios via crt.sh."""

    __tablename__ = "monitored_domains"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # Nullable a nivel de columna SQL por el mismo motivo que en asset-service
    # (Asset.organization_id): la migracion ALTER TABLE de una instalacion
    # existente no puede rellenar esto atomicamente para filas viejas -- ver
    # el backfill en app/main.py::lifespan. A nivel de aplicacion, toda fila
    # nueva SIEMPRE recibe organization_id (ver services.create_domain).
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True, default="")
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class DiscoveredAsset(Base):
    """Un hostname visto para un MonitoredDomain (el dominio raiz mismo, o un
    subdominio descubierto via Certificate Transparency). Nunca se borra --
    is_active=False marca que dejo de aparecer en la ultima corrida, para
    no perder el historico de que estuvo expuesto en algun momento."""

    __tablename__ = "discovered_assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    # FK logico (no ForeignKey de SQLAlchemy) a MonitoredDomain.id -- mismo
    # criterio que AssetGroup.asset_ids en asset-service: este servicio no
    # necesita integridad referencial a nivel de DB para esto, y evita un
    # ON DELETE explicito que tendria que decidir que hacer con el
    # historico si se borra el dominio (ver services.delete_domain).
    monitored_domain_id: Mapped[str] = mapped_column(String(36), index=True, default="")
    hostname: Mapped[str] = mapped_column(String(255), index=True, default="")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class SslCertificate(Base):
    """Ultimo certificado TLS visto para un hostname (upsert por hostname en
    cada corrida, ver services.run_domain_check) -- no se guarda historico
    de certificados anteriores, solo el estado actual."""

    __tablename__ = "ssl_certificates"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True, default="")
    issuer: Mapped[str] = mapped_column(String(500), default="")
    subject: Mapped[str] = mapped_column(String(500), default="")
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), default="")
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Si el ultimo intento de conexion/handshake fallo (timeout, connection
    # refused, DNS no resuelve, etc), el motivo corto queda aca en vez de
    # quedar en silencio -- para poder mostrarlo en la UI (ver
    # services.fetch_tls_certificate, que es quien puebla esto). Vacio
    # significa que el ultimo chequeo salio bien.
    last_error: Mapped[str] = mapped_column(String(500), default="")


class SurfaceAlert(Base):
    """Alerta generada por una corrida de monitoreo: subdominio nuevo,
    certificado por vencer/vencido, o chequeo de certificado que fallo.
    should_create_alert() evita duplicar una sin reconocer del mismo tipo
    para el mismo host en cada corrida del scheduler (cooldown)."""

    __tablename__ = "surface_alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    monitored_domain_id: Mapped[str] = mapped_column(String(36), index=True, default="")
    alert_type: Mapped[SurfaceAlertType] = mapped_column(
        SAEnum(SurfaceAlertType, native_enum=False), default=SurfaceAlertType.new_subdomain
    )
    hostname: Mapped[str] = mapped_column(String(255), index=True, default="")
    severity: Mapped[AlertSeverity] = mapped_column(
        SAEnum(AlertSeverity, native_enum=False), default=AlertSeverity.info
    )
    detail: Mapped[str] = mapped_column(String(1000), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    is_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    acknowledged_by: Mapped[str] = mapped_column(String(255), default="")
