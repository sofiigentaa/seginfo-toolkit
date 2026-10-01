"""Pydantic schemas for coderepo-service. RepoTargetOut jamas incluye el
token de GitHub (ni en texto plano ni cifrado) -- solo has_token, mismo
criterio que CloudAccountOut::access_key_id_masked en cloud-service."""
from datetime import datetime
from pydantic import BaseModel
from app.models import RepoScanStatus, SecretSeverity


class RepoTargetCreate(BaseModel):
    name: str
    repo_url: str
    branch: str = "main"
    github_token: str | None = None


class RepoTargetOut(BaseModel):
    id: str
    name: str
    repo_url: str
    branch: str
    has_token: bool
    is_enabled: bool
    last_scan_at: datetime | None
    last_scan_status: RepoScanStatus
    last_scan_error: str
    last_scan_secrets_found: int
    last_scan_vulnerabilities_found: int
    created_by: str
    created_at: datetime

    class Config:
        from_attributes = True


class SecretFindingOut(BaseModel):
    id: str
    repo_target_id: str
    rule_id: str
    description: str
    file_path: str
    start_line: int | None
    commit_hash: str
    severity: SecretSeverity
    match_redacted: str
    created_at: datetime
    is_acknowledged: bool
    acknowledged_by: str

    class Config:
        from_attributes = True


class SecretFindingUpdate(BaseModel):
    is_acknowledged: bool
