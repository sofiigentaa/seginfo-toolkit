"""Pydantic schemas for siem-service."""
from datetime import datetime
from pydantic import BaseModel, Field
from app.models import RuleSeverity, AlertStatus


class LogEventIn(BaseModel):
    timestamp: str | None = None
    host: str = ""
    source_ip: str = ""
    dest_ip: str = ""
    user: str = ""
    event_action: str = ""
    event_category: str = ""
    event_outcome: str = ""
    message: str = ""
    source_type: str = "generic"
    asset_id: str | None = None
    severity: str = "info"
    raw: str = ""


class IngestLogsRequest(BaseModel):
    # Opcional a proposito -- este endpoint (POST /logs/ingest) es para
    # agentes/forwarders externos, no lleva JWT de usuario; si el cliente no
    # manda organization_id, se asume la organizacion default (ver
    # backend/shared/tenancy.py). En un deploy multi-tenant real, cada
    # forwarder del cliente se configura con el organization_id de ese
    # cliente (visible en la UI, panel de organizacion).
    organization_id: str | None = None
    events: list[LogEventIn] = Field(default_factory=list)


class IngestLogsResponse(BaseModel):
    indexed: int
    alerts_created: int


class SigmaRuleCreate(BaseModel):
    name: str
    description: str = ""
    severity: RuleSeverity = RuleSeverity.medium
    tags: list[str] = Field(default_factory=list)
    detection: dict = Field(..., description="Bloques selection_* + 'condition', ver app/sigma.py")
    is_enabled: bool = True


class SigmaRuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    severity: RuleSeverity | None = None
    tags: list[str] | None = None
    detection: dict | None = None
    is_enabled: bool | None = None


class SigmaRuleOut(BaseModel):
    id: str
    name: str
    description: str
    severity: RuleSeverity
    tags: list[str]
    detection: dict
    is_enabled: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AlertUpdate(BaseModel):
    status: AlertStatus
    # None = "no toques las notas" (ver app/services.py::update_alert /
    # _resolve_alert_update): un PATCH que solo cambia el estado (ej. los
    # botones Reconocer/Cerrar de la UI, que mandan solo {status}) no debe
    # borrar una nota ya guardada por pisarla con "".
    notes: str | None = None


class AlertOut(BaseModel):
    id: str
    rule_id: str
    rule_name: str
    severity: RuleSeverity
    matched_event: dict
    status: AlertStatus
    soar_triggered: bool
    # {} si threatintel-service no respondio o ninguna IP del evento
    # resulto maliciosa conocida -- ver app/models.py::Alert.threat_intel.
    threat_intel: dict = {}
    acknowledged_by: str
    notes: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
