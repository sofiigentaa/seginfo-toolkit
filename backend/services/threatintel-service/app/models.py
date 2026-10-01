"""SQLAlchemy models for threatintel-service: cache de reputacion de IPs
consultada contra fuentes externas (AbuseIPDB, MISP)."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Boolean, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column
from backend.shared.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class IpReputationCache(Base):
    """Cache de resultados de threat intel por IP. NO lleva organization_id
    a proposito -- a diferencia del resto de las tablas de la plataforma,
    la reputacion de una IP es un hecho global (AbuseIPDB/MISP no
    distinguen tenants de SentinelOps): dos organizaciones que consultan la
    misma IP comparten la misma fila de cache, en vez de gastar cupo de la
    API externa dos veces para el mismo dato. El cache dura 24hs por
    defecto (ver services.py::is_cache_fresh/CACHE_TTL_HOURS)."""

    __tablename__ = "ip_reputation_cache"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ip: Mapped[str] = mapped_column(String(45), unique=True, index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(50), default="")
    # None = "no se pudo chequear contra ninguna fuente" (sin API key
    # configurada, timeout, error de red) -- NUNCA confundir con False, que
    # significa "se chequeo contra al menos una fuente y viene limpia". La
    # UI tiene que distinguir los dos casos (ver ThreatIntel widget en
    # frontend/src/pages/Siem.tsx).
    is_malicious: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    categories: Mapped[list] = mapped_column(JSON, default=list)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    ttl_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
