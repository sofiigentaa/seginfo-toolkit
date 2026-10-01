"""SQLAlchemy models for cloud-service: inventario de solo LECTURA de una
cuenta de AWS del cliente (instancias EC2, security groups, buckets S3) y
hallazgos de configuracion peligrosa (bucket publico, security group
abierto a 0.0.0.0/0). Este servicio NUNCA crea, modifica ni borra nada en
la cuenta de AWS del cliente -- solo llama APIs de lectura (Describe*/
List*/Get*), ver el docstring de app/services.py y la politica IAM de
solo lectura documentada para .env.example.

Sigue el mismo patron que asm-service: tabla propia de "recursos
descubiertos" separada de la CMDB de asset-service (este inventario es de
otra naturaleza -- viene de una cuenta cloud del cliente, no de un activo
que alguien cargo a mano), con is_active para marcar lo que dejo de
aparecer sin perder el historico."""
import enum
import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Boolean, Enum as SAEnum, JSON
from sqlalchemy.orm import Mapped, mapped_column
from backend.shared.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class CloudProvider(str, enum.Enum):
    aws = "aws"  # unico soportado por ahora; el campo queda para Azure/GCP a futuro


class CloudResourceType(str, enum.Enum):
    ec2_instance = "ec2_instance"
    security_group = "security_group"
    s3_bucket = "s3_bucket"


class CloudFindingType(str, enum.Enum):
    s3_bucket_public = "s3_bucket_public"
    security_group_open_world = "security_group_open_world"


class FindingSeverity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"


class CloudAccount(Base):
    """Una cuenta de AWS del cliente conectada para inventario/sync
    periodico. Las credenciales (access_key_id/secret_access_key) se
    cifran con backend.shared.crypto antes de guardarse -- ver
    app/services.py::_get_boto3_session -- y jamas se devuelven en texto
    plano ni cifrado por ningun endpoint (ver CloudAccountOut en
    schemas.py, que solo expone access_key_id_masked)."""

    __tablename__ = "cloud_accounts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # Nullable a nivel de columna SQL por el mismo motivo que en el resto
    # de los servicios (ver Asset.organization_id en asset-service): toda
    # fila nueva SIEMPRE recibe organization_id a nivel de aplicacion (ver
    # services.create_account).
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    provider: Mapped[CloudProvider] = mapped_column(SAEnum(CloudProvider, native_enum=False), default=CloudProvider.aws)
    region: Mapped[str] = mapped_column(String(50), default="us-east-1")
    access_key_id_encrypted: Mapped[str] = mapped_column(String, default="")
    secret_access_key_encrypted: Mapped[str] = mapped_column(String, default="")
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # never|ok|error
    last_sync_status: Mapped[str] = mapped_column(String(20), default="never")
    last_sync_error: Mapped[str] = mapped_column(String(2000), default="")
    created_by: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class CloudResource(Base):
    """Un recurso descubierto en una cuenta de AWS (instancia EC2, security
    group o bucket S3). Nunca se borra -- is_active=False marca que dejo
    de aparecer en la ultima corrida de sync, para no perder el historico
    de que existio en algun momento (mismo criterio que
    DiscoveredAsset en asm-service)."""

    __tablename__ = "cloud_resources"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    # FK logico (no ForeignKey de SQLAlchemy) a CloudAccount.id -- mismo
    # criterio que MonitoredDomain/DiscoveredAsset en asm-service.
    cloud_account_id: Mapped[str] = mapped_column(String(36), index=True, default="")
    resource_type: Mapped[CloudResourceType] = mapped_column(SAEnum(CloudResourceType, native_enum=False))
    # instance-id / nombre de bucket / sg-id
    external_id: Mapped[str] = mapped_column(String(255), index=True, default="")
    name: Mapped[str] = mapped_column(String(255), default="")
    region: Mapped[str] = mapped_column(String(50), default="")
    # OJO: el atributo Python no puede llamarse `metadata` -- choca con
    # Base.metadata de SQLAlchemy (el registro de tablas de la clase
    # declarativa). Se mapea explicitamente a la columna SQL "metadata"
    # (que es el nombre que tiene sentido para quien mire la tabla desde
    # afuera) con un nombre de atributo Python distinto.
    resource_metadata: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class CloudFinding(Base):
    """Hallazgo de configuracion peligrosa detectado en un recurso: bucket
    S3 publico, o security group con puertos abiertos a 0.0.0.0/0 (o
    ::/0). services.should_create_finding evita duplicar un hallazgo
    pendiente del mismo tipo para el mismo recurso en cada sync
    (permite que una condicion resuelta y reaparecida vuelva a alertar)."""

    __tablename__ = "cloud_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    cloud_account_id: Mapped[str] = mapped_column(String(36), index=True, default="")
    resource_external_id: Mapped[str] = mapped_column(String(255), index=True, default="")
    finding_type: Mapped[CloudFindingType] = mapped_column(SAEnum(CloudFindingType, native_enum=False))
    severity: Mapped[FindingSeverity] = mapped_column(SAEnum(FindingSeverity, native_enum=False))
    detail: Mapped[str] = mapped_column(String(2000), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    is_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    acknowledged_by: Mapped[str] = mapped_column(String(255), default="")
