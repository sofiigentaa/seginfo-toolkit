"""vuln-service entrypoint: prioriza vulnerabilidades combinando CVSS, EPSS
y CISA KEV, y expone el workflow de triage (confirmar, falso positivo,
riesgo aceptado, remediado). Ver app/enrichment.py para el detalle de las
fuentes de datos, todas de solo lectura."""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, make_asgi_app
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.database import get_db, engine, Base
from backend.shared.logging import configure_logging
from backend.shared.cors import get_cors_origins
from backend.shared.security_headers import SecurityHeadersMiddleware
from backend.shared.tenancy import DEFAULT_ORGANIZATION_ID, org_id_from_claims
from app.schemas import IngestRequest, IngestResponse, TriageRequest, VulnerabilityOut, VulnerabilityStatsOut
from app.dependencies import get_current_claims, require_role
from app import services

logger = configure_logging("vuln-service")
vulns_ingested_total = Counter("vulns_ingested_total", "Hallazgos ingeridos", ["scanner_type"])
vulns_triaged_total = Counter("vulns_triaged_total", "Vulnerabilidades triadas", ["new_status"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text(
            "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36)"
        ))
        await conn.execute(text(
            f"UPDATE vulnerabilities SET organization_id = '{DEFAULT_ORGANIZATION_ID}' WHERE organization_id IS NULL"
        ))
    logger.info("vuln-service iniciado")
    yield


app = FastAPI(title="SentinelOps Vulnerability Service", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.mount("/metrics", make_asgi_app())


@app.get("/health")
async def health():
    return {"status": "ok", "service": "vuln-service"}


@app.post("/vulnerabilities/ingest", response_model=IngestResponse, status_code=status.HTTP_201_CREATED)
async def ingest(payload: IngestRequest, db: AsyncSession = Depends(get_db)):
    """Llamado por scan-service al terminar un job (comunicacion
    servicio-a-servicio; no requiere el JWT interactivo de un usuario)."""
    created, updated = await services.ingest_findings(db, payload)
    await db.commit()
    vulns_ingested_total.labels(scanner_type=payload.scanner_type or "desconocido").inc(len(payload.findings))
    logger.info("hallazgos ingeridos", extra={"creados": created, "actualizados": updated})
    return IngestResponse(created=created, updated=updated)


@app.get("/vulnerabilities", response_model=list[VulnerabilityOut])
async def list_vulnerabilities(
    status_filter: str | None = None,
    severity: str | None = None,
    asset_id: str | None = None,
    min_priority: float | None = None,
    scan_job_id: str | None = None,
    claims: dict = Depends(get_current_claims),
    db: AsyncSession = Depends(get_db),
):
    return await services.list_vulnerabilities(
        db, org_id_from_claims(claims), status_filter, severity, asset_id, min_priority, scan_job_id
    )


@app.get("/vulnerabilities/stats", response_model=VulnerabilityStatsOut)
async def stats(claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    return await services.get_stats(db, org_id_from_claims(claims))


@app.get("/vulnerabilities/{vuln_id}", response_model=VulnerabilityOut)
async def get_vulnerability(vuln_id: str, claims: dict = Depends(get_current_claims), db: AsyncSession = Depends(get_db)):
    vuln = await services.get_vulnerability(db, vuln_id, org_id_from_claims(claims))
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerabilidad no encontrada")
    return vuln


@app.post("/vulnerabilities/{vuln_id}/enrich", response_model=VulnerabilityOut)
async def enrich(
    vuln_id: str,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    vuln = await services.get_vulnerability(db, vuln_id, org_id_from_claims(claims))
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerabilidad no encontrada")
    vuln = await services.reenrich_vulnerability(db, vuln)
    await db.commit()
    return vuln


@app.patch("/vulnerabilities/{vuln_id}/triage", response_model=VulnerabilityOut)
async def triage(
    vuln_id: str,
    payload: TriageRequest,
    claims: dict = Depends(require_role("admin", "soc_manager", "analyst")),
    db: AsyncSession = Depends(get_db),
):
    vuln = await services.get_vulnerability(db, vuln_id, org_id_from_claims(claims))
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerabilidad no encontrada")
    vuln = await services.triage_vulnerability(db, vuln, payload, claims.get("sub", ""))
    await db.commit()
    vulns_triaged_total.labels(new_status=payload.status.value).inc()
    logger.info("vulnerabilidad triada", extra={"vuln_id": vuln_id, "status": payload.status.value, "actor": claims.get("sub")})
    return vuln
