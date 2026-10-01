"""Business logic for cloud-service: inventario de solo LECTURA de una
cuenta de AWS del cliente (instancias EC2, security groups, buckets S3) y
deteccion de configuraciones peligrosas (bucket S3 publico, security
group con puertos abiertos a 0.0.0.0/0 o ::/0).

Alcance no negociable: este servicio NUNCA crea, modifica ni borra ningun
recurso en la cuenta de AWS del cliente. Todas las llamadas a boto3 de
este modulo son de lectura (Describe*/List*/Get*) -- ver la politica IAM
de solo lectura documentada para .env.example. Si algo en el futuro
sugiere agregar una llamada de escritura (Create*/Modify*/Delete*/Put*
salvo las excepciones de lectura ya listadas), esa sugerencia esta fuera
de alcance y no debe implementarse aca.

Funciones puras (testeables sin boto3/red/DB) arriba; funciones de I/O
(boto3, con manejo de error acotado -- NUNCA deben tumbar el sync
completo ni el servicio) despues; scheduler y CRUD al final. Mismo patron
estructural que asm-service/app/services.py."""
import os
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.crypto import decrypt_secret, encrypt_secret
from backend.shared.logging import configure_logging
from app.models import (
    CloudAccount,
    CloudFinding,
    CloudFindingType,
    CloudResource,
    CloudResourceType,
    FindingSeverity,
)

logger = configure_logging("cloud-service")

SIEM_SERVICE_URL = os.getenv("SIEM_SERVICE_URL", "http://siem-service:8000")

# Puertos habitualmente asociados a servicios de administracion/datos --
# si alguno de estos queda abierto a 0.0.0.0/0 el riesgo es mucho mayor
# que un puerto de aplicacion cualquiera (ssh, rdp, bases de datos
# comunes, cache, motores de busqueda/documentos).
_RISKY_PORTS = {22, 3389, 3306, 5432, 6379, 9200, 27017}

_PUBLIC_ACL_GRANTEE_URIS = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --- Logica pura ------------------------------------------------------

def is_public_cidr(cidr: str) -> bool:
    return cidr in ("0.0.0.0/0", "::/0")


def extract_public_ingress_rules(security_group_raw: dict) -> list[dict]:
    """Recibe un dict con forma de un item de
    ec2.describe_security_groups()["SecurityGroups"] y devuelve solo las
    reglas de entrada que abren un rango publico (0.0.0.0/0 o ::/0).
    IpProtocol == "-1" significa "todos los protocolos/puertos" -- en ese
    caso from_port/to_port vienen None y se dejan pasar tal cual."""
    public_rules: list[dict] = []
    for permission in security_group_raw.get("IpPermissions", []) or []:
        protocol = permission.get("IpProtocol", "-1")
        from_port = permission.get("FromPort")
        to_port = permission.get("ToPort")
        cidrs = [r.get("CidrIp") for r in permission.get("IpRanges", []) or []]
        cidrs += [r.get("CidrIpv6") for r in permission.get("Ipv6Ranges", []) or []]
        for cidr in cidrs:
            if cidr and is_public_cidr(cidr):
                public_rules.append(
                    {"protocol": protocol, "from_port": from_port, "to_port": to_port, "cidr": cidr}
                )
    return public_rules


def classify_security_group_finding(public_rules: list[dict]) -> tuple[FindingSeverity, str] | None:
    """None si no hay reglas publicas. critical si alguna regla abre TODOS
    los protocolos/puertos (IpProtocol == "-1") o un puerto de la lista
    riesgosa (_RISKY_PORTS); medium si hay algo abierto al mundo pero
    ninguna de esas dos condiciones aplica."""
    if not public_rules:
        return None

    def _describe(rule: dict) -> str:
        protocol = rule["protocol"]
        if protocol == "-1":
            proto_desc = "todos los protocolos/puertos"
        elif rule["from_port"] is None and rule["to_port"] is None:
            proto_desc = f"{protocol}"
        elif rule["from_port"] == rule["to_port"]:
            proto_desc = f"{protocol}/{rule['from_port']}"
        else:
            proto_desc = f"{protocol}/{rule['from_port']}-{rule['to_port']}"
        return f"{proto_desc} desde {rule['cidr']}"

    has_all_traffic = any(r["protocol"] == "-1" for r in public_rules)
    risky_port_rules = [
        r for r in public_rules
        if r["protocol"] != "-1" and (
            (r["from_port"] is not None and r["from_port"] in _RISKY_PORTS)
            or (r["to_port"] is not None and r["to_port"] in _RISKY_PORTS)
            or (
                r["from_port"] is not None and r["to_port"] is not None
                and any(r["from_port"] <= p <= r["to_port"] for p in _RISKY_PORTS)
            )
        )
    ]

    descriptions = ", ".join(_describe(r) for r in public_rules)
    if has_all_traffic or risky_port_rules:
        return (
            FindingSeverity.critical,
            f"Security group con acceso critico abierto al mundo: {descriptions}",
        )
    return (
        FindingSeverity.medium,
        f"Security group con puertos abiertos al mundo: {descriptions}",
    )


def normalize_ec2_instance(raw: dict) -> dict:
    """Recibe un item de ec2.describe_instances()["Reservations"][i]
    ["Instances"][j] y lo aplana a un dict simple para guardar en
    CloudResource.resource_metadata."""
    name = ""
    for tag in raw.get("Tags", []) or []:
        if tag.get("Key") == "Name":
            name = tag.get("Value", "")
            break
    launch_time = raw.get("LaunchTime")
    return {
        "instance_id": raw.get("InstanceId", ""),
        "name": name,
        "state": (raw.get("State") or {}).get("Name", ""),
        "instance_type": raw.get("InstanceType", ""),
        "private_ip": raw.get("PrivateIpAddress", ""),
        "public_ip": raw.get("PublicIpAddress", ""),
        "launch_time": launch_time.isoformat() if hasattr(launch_time, "isoformat") else (launch_time or ""),
    }


def bucket_public_access_block_blocks_all(pab: dict | None) -> bool:
    """True solo si las 4 flags del Public Access Block del bucket estan
    en True -- eso bloquea explicitamente cualquier acceso publico, sin
    importar lo que diga la bucket policy o los ACLs."""
    if pab is None:
        return False
    return all(
        pab.get(flag) is True
        for flag in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    )


def bucket_is_public(policy_status: dict | None, public_access_block: dict | None, acl_grants: list[dict]) -> bool:
    """Un Public Access Block que bloquea todo gana siempre (bucket
    bloqueado explicitamente, sin importar lo que diga la policy). Si no,
    el bucket es publico si S3 Policy Status dice IsPublic=True, o si
    algun ACL grant es para AllUsers/AuthenticatedUsers."""
    if bucket_public_access_block_blocks_all(public_access_block):
        return False
    if (policy_status or {}).get("PolicyStatus", {}).get("IsPublic") is True:
        return True
    for grant in acl_grants or []:
        uri = (grant.get("Grantee") or {}).get("URI", "")
        if uri in _PUBLIC_ACL_GRANTEE_URIS:
            return True
    return False


def diff_external_ids(previous_ids: set[str], current_ids: set[str]) -> tuple[set[str], set[str]]:
    """(new_ids, removed_ids): ids nuevos que no estaban antes, e ids que
    estaban antes y ya no aparecen en la corrida actual."""
    new_ids = current_ids - previous_ids
    removed_ids = previous_ids - current_ids
    return new_ids, removed_ids


def should_create_finding(existing_findings_same_key: list[dict]) -> bool:
    """Recibe los hallazgos previos para la misma
    (cloud_account_id, resource_external_id, finding_type), cada uno con
    {"is_acknowledged": bool}. True si la lista esta vacia o el ULTIMO
    (el mas reciente) esta reconocido -- evita espamear la misma alerta
    pendiente en cada sync, pero permite que una condicion resuelta y
    reaparecida vuelva a alertar."""
    if not existing_findings_same_key:
        return True
    return bool(existing_findings_same_key[-1].get("is_acknowledged"))


def mask_access_key_id(access_key_id: str) -> str:
    """Nunca se muestra ni se loguea el secret_access_key en ningun
    formato -- ni siquiera enmascarado. Esto es solo para el
    access_key_id, que por si solo no permite autenticarse."""
    if len(access_key_id) >= 8:
        return f"{access_key_id[:4]}…{access_key_id[-4:]}"
    return "••••"


def _severity_value(severity) -> str:
    return getattr(severity, "value", severity)


# --- I/O (boto3) --------------------------------------------------------
# Ninguna de estas funciones debe tumbar el sync completo ni el servicio
# si falla -- ver run_account_sync, que envuelve todo en un try/except
# amplio, y discover_s3_buckets, que ademas aisla cada bucket individual
# (un AccessDenied en un bucket no debe frenar el resto).

def _get_boto3_session(account: CloudAccount):
    import boto3

    access_key_id = decrypt_secret(account.access_key_id_encrypted)
    secret_access_key = decrypt_secret(account.secret_access_key_encrypted)
    return boto3.Session(
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        region_name=account.region,
    )


def discover_ec2_instances(session) -> list[dict]:
    """Lista TODAS las instancias EC2 de la region configurada (raw, sin
    normalizar -- ver normalize_ec2_instance)."""
    ec2 = session.client("ec2")
    instances: list[dict] = []
    for page in ec2.get_paginator("describe_instances").paginate():
        for reservation in page.get("Reservations", []):
            instances.extend(reservation.get("Instances", []))
    return instances


def discover_security_groups(session) -> list[dict]:
    """Lista TODOS los security groups de la region configurada (raw, sin
    normalizar -- ver extract_public_ingress_rules/classify_security_group_finding)."""
    ec2 = session.client("ec2")
    groups: list[dict] = []
    for page in ec2.get_paginator("describe_security_groups").paginate():
        groups.extend(page.get("SecurityGroups", []))
    return groups


def discover_s3_buckets(session) -> list[dict]:
    """Lista todos los buckets S3 de la cuenta (list_buckets no es
    regional) y, para CADA uno, en su propio try/except, junta el estado
    de acceso publico. Un bucket con AccessDenied en alguna de estas
    llamadas (permisos IAM mas restrictivos que los del resto de la
    cuenta, bucket de otra cuenta con bucket policy cross-account, etc.)
    NUNCA debe frenar el resto -- solo queda con esa parte en None/[] y se
    loguea un warning."""
    s3 = session.client("s3")
    buckets: list[dict] = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket.get("Name", "")

        public_access_block = None
        try:
            public_access_block = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        except Exception as exc:  # noqa: BLE001 -- ClientError (NoSuchPublicAccessBlockConfiguration/AccessDenied) u otro
            if "NoSuchPublicAccessBlockConfiguration" not in str(exc):
                logger.warning("no se pudo leer public access block de bucket S3", extra={"bucket": name, "error": str(exc)})

        policy_status = None
        try:
            policy_status = s3.get_bucket_policy_status(Bucket=name)
        except Exception as exc:  # noqa: BLE001 -- ClientError (NoSuchBucketPolicy/AccessDenied) u otro
            if "NoSuchBucketPolicy" not in str(exc):
                logger.warning("no se pudo leer bucket policy status de bucket S3", extra={"bucket": name, "error": str(exc)})

        acl_grants: list[dict] = []
        try:
            acl_grants = s3.get_bucket_acl(Bucket=name).get("Grants", [])
        except Exception as exc:  # noqa: BLE001 -- ClientError (AccessDenied) u otro
            logger.warning("no se pudo leer ACL de bucket S3", extra={"bucket": name, "error": str(exc)})

        buckets.append(
            {
                "name": name,
                "creation_date": bucket.get("CreationDate"),
                "public_access_block": public_access_block,
                "policy_status": policy_status,
                "acl_grants": acl_grants,
            }
        )
    return buckets


async def _forward_finding_to_siem(finding: CloudFinding, organization_id: str | None) -> None:
    """Best-effort, mismo patron que asm-service::_forward_alert_to_siem:
    si siem-service no responde, el hallazgo ya quedo guardado igual en
    este servicio. Solo se reenvian severidades high/critical."""
    severity = _severity_value(finding.severity)
    if severity not in ("high", "critical"):
        return
    payload = {
        "organization_id": organization_id,
        "events": [
            {
                "host": finding.resource_external_id,
                "event_action": "cloud_finding",
                "event_category": "network",
                "event_outcome": "success",
                "message": finding.detail,
                "source_type": "cloud",
                "asset_id": None,
                "severity": severity,
            }
        ],
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(f"{SIEM_SERVICE_URL}/logs/ingest", json=payload)
    except httpx.HTTPError as exc:
        logger.warning("no se pudo reenviar hallazgo a siem-service", extra={"finding_id": finding.id, "error": str(exc)})


async def _existing_findings_for_key(
    db: AsyncSession, organization_id: str | None, cloud_account_id: str, resource_external_id: str,
    finding_type: CloudFindingType,
) -> list[CloudFinding]:
    result = await db.execute(
        select(CloudFinding)
        .where(
            CloudFinding.organization_id == organization_id,
            CloudFinding.cloud_account_id == cloud_account_id,
            CloudFinding.resource_external_id == resource_external_id,
            CloudFinding.finding_type == finding_type,
        )
        .order_by(CloudFinding.created_at.asc())
    )
    return list(result.scalars().all())


async def _create_finding_if_needed(
    db: AsyncSession, account: CloudAccount, resource_external_id: str, finding_type: CloudFindingType,
    severity: FindingSeverity, detail: str,
) -> CloudFinding | None:
    existing = await _existing_findings_for_key(
        db, account.organization_id, account.id, resource_external_id, finding_type
    )
    existing_dicts = [{"is_acknowledged": f.is_acknowledged} for f in existing]
    if not should_create_finding(existing_dicts):
        return None
    finding = CloudFinding(
        organization_id=account.organization_id,
        cloud_account_id=account.id,
        resource_external_id=resource_external_id,
        finding_type=finding_type,
        severity=severity,
        detail=detail[:2000],
    )
    db.add(finding)
    await db.flush()
    await _forward_finding_to_siem(finding, account.organization_id)
    return finding


async def _upsert_resources(
    db: AsyncSession, account: CloudAccount, resource_type: CloudResourceType, items: list[dict], now: datetime,
) -> dict[str, CloudResource]:
    """Upsert de CloudResource por (cloud_account_id, resource_type,
    external_id): items es una lista de {"external_id", "name", "region",
    "metadata"}. Marca is_active=False en los que ya no aparecen (via
    diff_external_ids), sin borrarlos. Devuelve el mapa external_id ->
    CloudResource resultante (solo los que siguen activos)."""
    result = await db.execute(
        select(CloudResource).where(
            CloudResource.cloud_account_id == account.id,
            CloudResource.resource_type == resource_type,
        )
    )
    existing_by_external_id = {r.external_id: r for r in result.scalars().all()}
    current_ids = {item["external_id"] for item in items if item.get("external_id")}
    _new_ids, removed_ids = diff_external_ids(set(existing_by_external_id.keys()), current_ids)

    active_by_external_id: dict[str, CloudResource] = {}
    for item in items:
        external_id = item.get("external_id")
        if not external_id:
            continue
        resource = existing_by_external_id.get(external_id)
        if resource is None:
            resource = CloudResource(
                organization_id=account.organization_id,
                cloud_account_id=account.id,
                resource_type=resource_type,
                external_id=external_id,
                first_seen_at=now,
            )
            db.add(resource)
        resource.name = item.get("name", "")
        resource.region = item.get("region", account.region)
        resource.resource_metadata = item.get("metadata", {})
        resource.is_active = True
        resource.last_seen_at = now
        active_by_external_id[external_id] = resource

    for external_id in removed_ids:
        existing_by_external_id[external_id].is_active = False

    await db.flush()
    return active_by_external_id


async def run_account_sync(db: AsyncSession, account: CloudAccount) -> None:
    """Orquesta un sync completo de una cuenta de AWS: descubre EC2/security
    groups/buckets S3, hace upsert del inventario, calcula hallazgos
    nuevos y los reenvia a siem-service (best-effort). Si algo revienta
    (credenciales invalidas, sin permisos, boto3 no puede resolver la
    region, etc.) se captura en un try/except amplio: deja
    last_sync_status="error" con el detalle, y NUNCA propaga la excepcion
    -- ni tumba el servicio ni el loop del scheduler."""
    now = _now()
    try:
        session = _get_boto3_session(account)

        instances_raw = discover_ec2_instances(session)
        instance_items = [
            {
                "external_id": normalized["instance_id"],
                "name": normalized["name"],
                "region": account.region,
                "metadata": normalized,
            }
            for normalized in (normalize_ec2_instance(raw) for raw in instances_raw)
            if normalized["instance_id"]
        ]
        await _upsert_resources(db, account, CloudResourceType.ec2_instance, instance_items, now)

        sg_raw = discover_security_groups(session)
        sg_items = []
        for raw in sg_raw:
            group_id = raw.get("GroupId", "")
            if not group_id:
                continue
            sg_items.append(
                {
                    "external_id": group_id,
                    "name": raw.get("GroupName", ""),
                    "region": account.region,
                    "metadata": {"group_id": group_id, "group_name": raw.get("GroupName", ""), "vpc_id": raw.get("VpcId", "")},
                }
            )
        await _upsert_resources(db, account, CloudResourceType.security_group, sg_items, now)

        for raw in sg_raw:
            group_id = raw.get("GroupId", "")
            if not group_id:
                continue
            public_rules = extract_public_ingress_rules(raw)
            classification = classify_security_group_finding(public_rules)
            if classification is None:
                continue
            severity, detail = classification
            await _create_finding_if_needed(
                db, account, group_id, CloudFindingType.security_group_open_world, severity, detail
            )

        buckets_raw = discover_s3_buckets(session)
        bucket_items = [
            {
                "external_id": bucket["name"],
                "name": bucket["name"],
                "region": account.region,
                "metadata": {
                    "creation_date": bucket["creation_date"].isoformat() if hasattr(bucket["creation_date"], "isoformat") else "",
                },
            }
            for bucket in buckets_raw
            if bucket.get("name")
        ]
        await _upsert_resources(db, account, CloudResourceType.s3_bucket, bucket_items, now)

        for bucket in buckets_raw:
            name = bucket.get("name")
            if not name:
                continue
            if bucket_is_public(bucket.get("policy_status"), bucket.get("public_access_block"), bucket.get("acl_grants") or []):
                await _create_finding_if_needed(
                    db, account, name, CloudFindingType.s3_bucket_public, FindingSeverity.critical,
                    f"El bucket S3 '{name}' es publico (bucket policy o ACL permiten acceso a AllUsers/AuthenticatedUsers)",
                )

        account.last_sync_at = now
        account.last_sync_status = "ok"
        account.last_sync_error = ""
        await db.flush()
    except Exception as exc:  # noqa: BLE001 -- una cuenta rota (credenciales invalidas, sin permisos IAM, etc.) nunca debe tumbar el sync ni el scheduler
        logger.error("error sincronizando cuenta de AWS", extra={"cloud_account_id": account.id, "error": str(exc)})
        account.last_sync_at = now
        account.last_sync_status = "error"
        account.last_sync_error = str(exc)[:2000]
        await db.flush()


# --- Scheduler ------------------------------------------------------------

async def sync_all_enabled_accounts(session_factory) -> None:
    """Llamado por el scheduler en proceso (APScheduler, ver app/main.py)
    cada CLOUD_SYNC_INTERVAL_HOURS. Itera TODAS las CloudAccount
    habilitadas de TODAS las organizaciones -- una cuenta rota nunca frena
    el sync de las demas (mismo patron que
    asm-service::check_all_enabled_domains)."""
    async with session_factory() as db:
        result = await db.execute(select(CloudAccount).where(CloudAccount.is_enabled.is_(True)))
        account_ids = [a.id for a in result.scalars().all()]

    for account_id in account_ids:
        await run_account_sync_now(session_factory, account_id)


async def run_account_sync_now(session_factory, account_id: str) -> None:
    """Corre un sync para UNA cuenta, con su propia sesion de DB -- usado
    tanto por el job periodico (sync_all_enabled_accounts) como por
    POST /accounts/{id}/sync-now (via BackgroundTasks, ver app/main.py)."""
    async with session_factory() as db:
        account = await db.get(CloudAccount, account_id)
        if account is None or not account.is_enabled:
            return
        try:
            await run_account_sync(db, account)
            await db.commit()
        except Exception as exc:  # noqa: BLE001 -- una cuenta no debe tumbar el scheduler ni dejar la sesion colgada
            logger.error("error en sync de cuenta de AWS", extra={"cloud_account_id": account_id, "error": str(exc)})
            await db.rollback()


# --- CRUD ------------------------------------------------------------------

async def create_account(db: AsyncSession, payload, organization_id: str | None, created_by: str) -> CloudAccount:
    account = CloudAccount(
        name=payload.name,
        region=payload.region,
        access_key_id_encrypted=encrypt_secret(payload.access_key_id) or "",
        secret_access_key_encrypted=encrypt_secret(payload.secret_access_key) or "",
        organization_id=organization_id,
        created_by=created_by,
    )
    db.add(account)
    await db.flush()
    await db.refresh(account)
    return account


async def list_accounts(db: AsyncSession, organization_id: str | None) -> list[CloudAccount]:
    result = await db.execute(
        select(CloudAccount).where(CloudAccount.organization_id == organization_id).order_by(CloudAccount.name)
    )
    return list(result.scalars().all())


async def get_account(db: AsyncSession, account_id: str, organization_id: str | None) -> CloudAccount | None:
    """organization_id obligatorio, mismo criterio que asm-service::get_domain:
    devuelve None tanto si la cuenta no existe como si es de otra
    organizacion."""
    account = await db.get(CloudAccount, account_id)
    if account is None or account.organization_id != organization_id:
        return None
    return account


async def delete_account(db: AsyncSession, account: CloudAccount) -> None:
    await db.delete(account)
    await db.flush()


async def list_resources(
    db: AsyncSession, organization_id: str | None, cloud_account_id: str | None = None,
    resource_type: CloudResourceType | None = None, is_active: bool | None = None,
) -> list[CloudResource]:
    query = select(CloudResource).where(CloudResource.organization_id == organization_id)
    if cloud_account_id is not None:
        query = query.where(CloudResource.cloud_account_id == cloud_account_id)
    if resource_type is not None:
        query = query.where(CloudResource.resource_type == resource_type)
    if is_active is not None:
        query = query.where(CloudResource.is_active.is_(is_active))
    result = await db.execute(query.order_by(CloudResource.resource_type, CloudResource.name))
    return list(result.scalars().all())


async def list_findings(
    db: AsyncSession, organization_id: str | None, is_acknowledged: bool | None = False,
) -> list[CloudFinding]:
    query = select(CloudFinding).where(CloudFinding.organization_id == organization_id)
    if is_acknowledged is not None:
        query = query.where(CloudFinding.is_acknowledged.is_(is_acknowledged))
    result = await db.execute(query.order_by(CloudFinding.created_at.desc()))
    return list(result.scalars().all())


async def get_finding(db: AsyncSession, finding_id: str, organization_id: str | None) -> CloudFinding | None:
    finding = await db.get(CloudFinding, finding_id)
    if finding is None or finding.organization_id != organization_id:
        return None
    return finding


async def acknowledge_finding(db: AsyncSession, finding: CloudFinding, is_acknowledged: bool, acknowledged_by: str) -> CloudFinding:
    finding.is_acknowledged = is_acknowledged
    finding.acknowledged_by = acknowledged_by if is_acknowledged else ""
    await db.flush()
    await db.refresh(finding)
    return finding
