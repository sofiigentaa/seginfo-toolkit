"""SQLAlchemy models for coderepo-service: escaneo de repositorios de
codigo del cliente en modo SOLO LECTURA/analisis.

Alcance no negociable: este servicio clona un repositorio via HTTPS (con
git) y lo analiza con dos herramientas de deteccion (gitleaks/trivy).
NUNCA escribe nada en el repositorio del cliente, ni ejecuta codigo del
repositorio clonado (nunca se corre npm/pip install, un build, un test,
ni se importa/ejecuta nada del contenido clonado) -- solo se lee como
texto/archivos para las dos herramientas de analisis estatico. El
directorio temporal donde se clona cada repo se borra siempre al
terminar (ver app/services.py::run_repo_scan).

Sigue el mismo patron que cloud-service: tabla de "targets" configurados
por el cliente + credencial cifrada + scheduler periodico que itera
todos los targets habilitados de todas las organizaciones, y una tabla
de hallazgos propios (SecretFinding) con dedup/cooldown igual que
CloudFinding. Las dependencias vulnerables NO se duplican aca -- se
reenvian a vuln-service (fuente unica de verdad de vulnerabilidades en
toda la plataforma) y solo se guarda el contador del ultimo escaneo."""
import enum
import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Boolean, Integer, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column
from backend.shared.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class RepoScanStatus(str, enum.Enum):
    never = "never"
    ok = "ok"
    error = "error"


class SecretSeverity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"


class RepoTarget(Base):
    """Un repositorio configurado para escaneo periodico. El token de
    GitHub (si el repo es privado) se cifra con backend.shared.crypto
    antes de guardarse -- ver app/services.py::_clone_repo -- y jamas se
    devuelve en texto plano ni cifrado por ningun endpoint (ver
    RepoTargetOut en schemas.py, que solo expone has_token)."""

    __tablename__ = "repo_targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # Nullable a nivel de columna SQL por el mismo motivo que en el resto
    # de los servicios (ver CloudAccount.organization_id en cloud-service):
    # toda fila nueva SIEMPRE recibe organization_id a nivel de aplicacion.
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    repo_url: Mapped[str] = mapped_column(String(500), default="")
    branch: Mapped[str] = mapped_column(String(100), default="main")
    # "" si el repo es publico (sin token).
    github_token_encrypted: Mapped[str] = mapped_column(String, default="")
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_scan_status: Mapped[RepoScanStatus] = mapped_column(
        SAEnum(RepoScanStatus, native_enum=False), default=RepoScanStatus.never
    )
    last_scan_error: Mapped[str] = mapped_column(String(2000), default="")
    # Contador del ULTIMO escaneo (no acumulado) -- se recalcula en cada
    # corrida de run_repo_scan.
    last_scan_secrets_found: Mapped[int] = mapped_column(Integer, default=0)
    last_scan_vulnerabilities_found: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class SecretFinding(Base):
    """Un secreto/credencial detectado por gitleaks en el historial de git
    de un RepoTarget. JAMAS se guarda el secreto real -- match_redacted es
    siempre una version redactada (ver services.redact_secret_match).
    services.should_create_secret_finding evita duplicar un hallazgo
    pendiente de la misma clave (repo_target_id, rule_id, file_path,
    start_line) en cada escaneo, mismo criterio que
    cloud-service::should_create_finding."""

    __tablename__ = "secret_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    # FK logico (no ForeignKey de SQLAlchemy) a RepoTarget.id -- mismo
    # criterio que CloudResource.cloud_account_id en cloud-service.
    repo_target_id: Mapped[str] = mapped_column(String(36), index=True, default="")
    rule_id: Mapped[str] = mapped_column(String(100), default="")
    description: Mapped[str] = mapped_column(String(500), default="")
    file_path: Mapped[str] = mapped_column(String(500), default="")
    start_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Hash de commit reportado por gitleaks, si lo tiene -- puede ser un
    # commit ya "borrado" de la rama actual (el secreto sigue expuesto en
    # el historial aunque un commit posterior lo haya quitado).
    commit_hash: Mapped[str] = mapped_column(String(100), default="")
    severity: Mapped[SecretSeverity] = mapped_column(SAEnum(SecretSeverity, native_enum=False))
    # JAMAS el secreto real -- ver services.redact_secret_match.
    match_redacted: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    is_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    acknowledged_by: Mapped[str] = mapped_column(String(255), default="")
