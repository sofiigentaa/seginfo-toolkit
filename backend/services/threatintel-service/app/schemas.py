"""Pydantic schemas for threatintel-service."""
from pydantic import BaseModel, Field


class IpReputationOut(BaseModel):
    ip: str
    # None = "no se pudo chequear" (ver app/models.py::IpReputationCache.is_malicious),
    # nunca se debe pintar en la UI como "IP limpia" (eso es False).
    is_malicious: bool | None
    score: int | None = None
    source: str
    categories: list[str] = Field(default_factory=list)
    cached: bool = False


class LookupBatchRequest(BaseModel):
    ips: list[str] = Field(default_factory=list)


class LookupBatchResponse(BaseModel):
    results: list[IpReputationOut]
