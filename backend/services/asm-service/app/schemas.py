"""Pydantic schemas for asm-service."""
from datetime import datetime
from pydantic import BaseModel
from app.models import SurfaceAlertType, AlertSeverity


class MonitoredDomainCreate(BaseModel):
    domain: str


class MonitoredDomainOut(BaseModel):
    id: str
    domain: str
    is_enabled: bool
    created_by: str
    created_at: datetime

    class Config:
        from_attributes = True


class DiscoveredAssetOut(BaseModel):
    id: str
    monitored_domain_id: str
    hostname: str
    first_seen_at: datetime
    last_seen_at: datetime
    is_active: bool

    class Config:
        from_attributes = True


class SurfaceAlertOut(BaseModel):
    id: str
    monitored_domain_id: str
    alert_type: SurfaceAlertType
    hostname: str
    severity: AlertSeverity
    detail: str
    created_at: datetime
    is_acknowledged: bool
    acknowledged_by: str

    class Config:
        from_attributes = True
