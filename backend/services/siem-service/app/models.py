"""SQLAlchemy models for siem-service: metadatos estructurados (reglas Sigma
y alertas). Los eventos de log crudos/normalizados viven en OpenSearch
(ver app/opensearch_client.py); Postgres guarda solo lo que necesita
consultas relacionales, RBAC y referencias desde otros servicios (soar,
case)."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Enum as SAEnum, JSON, Boolean, Text
from sqlalchemy.orm import Mapped, mapped_column
from backend.shared.database import Base
import enum


def _now() -> datetime:
    return datetime.now(timezone.utc)


class RuleSeverity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class AlertStatus(str, enum.Enum):
    new = "new"
    acknowledged = "acknowledged"
    closed = "closed"


class SigmaRule(Base):
    """Regla de deteccion estilo Sigma (ver app/sigma.py para el motor de
    evaluacion). `detection` guarda selections + condition en JSON."""

    __tablename__ = "sigma_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[RuleSeverity] = mapped_column(SAEnum(RuleSeverity, native_enum=False), default=RuleSeverity.medium)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    detection: Mapped[dict] = mapped_column(JSON, default=dict)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class Alert(Base):
    """Alerta generada cuando un evento ingresado hace match con una
    SigmaRule habilitada. `matched_event` guarda una copia del documento ECS
    que disparo la regla, para contexto sin tener que volver a OpenSearch."""

    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    rule_id: Mapped[str] = mapped_column(String(36), index=True)
    rule_name: Mapped[str] = mapped_column(String(255), default="")
    severity: Mapped[RuleSeverity] = mapped_column(SAEnum(RuleSeverity, native_enum=False), default=RuleSeverity.medium)
    matched_event: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[AlertStatus] = mapped_column(SAEnum(AlertStatus, native_enum=False), default=AlertStatus.new)
    soar_triggered: Mapped[bool] = mapped_column(Boolean, default=False)
    # Poblado best-effort al crear la alerta (ver
    # app/services.py::_enrich_alert_with_threat_intel) llamando a
    # threatintel-service con las IPs presentes en el evento que la
    # disparo -- solo guarda las IPs que vinieron marcadas como
    # maliciosas conocidas (is_malicious=True), para no inflar la
    # columna con ruido de IPs limpias. {} si threatintel-service no
    # respondio o ninguna IP del evento resulto maliciosa.
    threat_intel: Mapped[dict] = mapped_column(JSON, default=dict)
    acknowledged_by: Mapped[str] = mapped_column(String(255), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)
