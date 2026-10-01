"""Pydantic schemas for cloud-service. CloudAccountOut jamas incluye las
credenciales (ni en texto plano ni cifradas) -- solo access_key_id_masked,
ver app/services.py::mask_access_key_id."""
from datetime import datetime
from pydantic import BaseModel
from app.models import CloudFindingType, CloudProvider, CloudResourceType, FindingSeverity


class CloudAccountCreate(BaseModel):
    name: str
    region: str = "us-east-1"
    access_key_id: str
    secret_access_key: str


class CloudAccountOut(BaseModel):
    id: str
    name: str
    provider: CloudProvider
    region: str
    access_key_id_masked: str
    is_enabled: bool
    last_sync_at: datetime | None
    last_sync_status: str
    last_sync_error: str
    created_by: str
    created_at: datetime

    class Config:
        from_attributes = True


class CloudResourceOut(BaseModel):
    id: str
    cloud_account_id: str
    resource_type: CloudResourceType
    external_id: str
    name: str
    region: str
    resource_metadata: dict
    is_active: bool
    first_seen_at: datetime
    last_seen_at: datetime

    class Config:
        from_attributes = True


class CloudFindingOut(BaseModel):
    id: str
    cloud_account_id: str
    resource_external_id: str
    finding_type: CloudFindingType
    severity: FindingSeverity
    detail: str
    created_at: datetime
    is_acknowledged: bool
    acknowledged_by: str

    class Config:
        from_attributes = True


class CloudFindingUpdate(BaseModel):
    is_acknowledged: bool
