"""SQLAlchemy models for scan-service: orquestacion de escaneos DEFENSIVOS.

Alcance deliberado: este servicio solo dispara escaneres en modo deteccion
(descubrimiento de puertos/servicios, CVEs conocidos en imagenes/paquetes,
plantillas de deteccion no invasivas). NUNCA ejecuta modulos de explotacion.
Ver docs/architecture.md, seccion "Fuera de alcance"."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Enum as SAEnum, JSON, Text, Boolean, Integer
from sqlalchemy.orm import Mapped, mapped_column
from backend.shared.database import Base
import enum


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ScannerType(str, enum.Enum):
    nmap = "nmap"
    trivy = "trivy"
    nuclei = "nuclei"
    openvas = "openvas"


class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    scanner_unavailable = "scanner_unavailable"
    cancelled = "cancelled"


class ScanSchedule(Base):
    """Una regla de escaneo recurrente (ej. "todos los lunes a las 3am").
    scan-service la corre con su propio scheduler en proceso (APScheduler,
    ver app/main.py) -- cada disparo crea un ScanJob nuevo, igual que si un
    usuario lo hubiera lanzado a mano."""

    __tablename__ = "scan_schedules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    scanner_type: Mapped[ScannerType] = mapped_column(SAEnum(ScannerType, native_enum=False))
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    frequency: Mapped[str] = mapped_column(String(20), nullable=False)  # daily | weekly
    hour: Mapped[int] = mapped_column(Integer, default=3)
    minute: Mapped[int] = mapped_column(Integer, default=0)
    day_of_week: Mapped[int | None] = mapped_column(Integer, nullable=True)  # 0=lunes .. 6=domingo (solo weekly)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str] = mapped_column(String(500), default="")


class ScanJob(Base):
    """Un job de escaneo. `target` es un host/CIDR/imagen segun `scanner_type`.
    `raw_result` guarda la salida cruda (XML/JSON) del scanner; `findings`
    guarda los hallazgos ya normalizados que se reenvian a vuln-service."""

    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    scanner_type: Mapped[ScannerType] = mapped_column(SAEnum(ScannerType, native_enum=False))
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    asset_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    status: Mapped[ScanStatus] = mapped_column(SAEnum(ScanStatus, native_enum=False), default=ScanStatus.pending)
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    raw_result: Mapped[str] = mapped_column(Text, default="")
    findings: Mapped[list] = mapped_column(JSON, default=list)
    error_message: Mapped[str] = mapped_column(String(2000), default="")
    created_by: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ScanAgent(Base):
    """Un agente de escaneo remoto: un proceso liviano (ver
    remote-agent/agent.py en la raiz del repo) que corre FUERA del
    contenedor de scan-service -- tipicamente en la misma PC del
    cliente pero fuera de Docker Desktop, o en cualquier maquina con
    visibilidad real a la LAN que se quiere escanear -- y que hace
    POLLING hacia scan-service (nunca al reves): asi no hace falta
    abrir ningun puerto de entrada en la red del cliente para que esto
    funcione, alcanza con que el agente pueda llegar al puerto ya
    publicado de scan-service (8003). Se autentica con su propia api
    key (nunca con el JWT de un usuario humano); aca solo se guarda su
    hash (sha256 alcanza porque la propia key ya es un secreto de alta
    entropia generado por el servidor -- no es una contraseña elegida
    por una persona, asi que no hace falta un hash lento tipo bcrypt en
    cada poll, que en este caso ocurre cada pocos segundos)."""

    __tablename__ = "scan_agents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    created_by: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentScanJob(Base):
    """Un job de escaneo para que lo ejecute un ScanAgent remoto, no el
    propio contenedor de scan-service. Tabla separada de ScanJob a
    proposito: no comparten ciclo de vida (a este lo ejecuta un proceso
    externo por polling, con sus propios estados) y asi se evita tocar
    ScanJob -- que create_all no puede alterar en instalaciones que ya
    tengan esa tabla con datos."""

    __tablename__ = "agent_scan_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    agent_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    scanner_type: Mapped[str] = mapped_column(String(20), default="nmap")
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|assigned|completed|failed
    findings: Mapped[list] = mapped_column(JSON, default=list)
    error_message: Mapped[str] = mapped_column(String(2000), default="")
    created_by: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    assigned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
