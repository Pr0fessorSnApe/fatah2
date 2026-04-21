"""
Fatah2 REST API — FastAPI application.
All routes require Bearer token authentication.

Start: python3 fatah2.py serve --port 8080
Docs:  http://localhost:8080/api/v1/docs
"""

import asyncio
import logging
import os
import secrets
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, field_validator

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Fatah2 API",
    description="Advanced subdomain & endpoint enumeration — authorized assessments only.",
    version="2.0.0",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
)

_bearer = HTTPBearer(auto_error=False)

def _verify(creds: HTTPAuthorizationCredentials = Security(_bearer)):
    token = os.environ.get("FATAH2_API_TOKEN", "")

    # ❌ No credentials provided → 403 Forbidden
    if creds is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden"
        )

    # ❌ Invalid / wrong token → 401 Unauthorized
    if not token or not secrets.compare_digest(creds.credentials, token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API token"
        )

    # ✅ Valid token
    return creds.credentials

# ── Job store ─────────────────────────────────────────────────────────────────

class JobStatus(str, Enum):
    PENDING  = "pending"
    RUNNING  = "running"
    COMPLETE = "complete"
    FAILED   = "failed"


@dataclass
class Job:
    id:          str
    domain:      str
    status:      JobStatus     = JobStatus.PENDING
    created_at:  str           = field(default_factory=lambda: datetime.utcnow().isoformat())
    finished_at: Optional[str] = None
    result:      Optional[dict]= None
    error:       Optional[str] = None


_jobs: dict[str, Job] = {}


# ── Models ────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    domain:              str
    scan_depth:          str  = "standard"
    concurrency:         int  = 50
    timeout:             int  = 30
    enable_dns_history:  bool = True
    enable_http_probe:   bool = True
    enable_risk_scoring: bool = True
    output_formats:      list[str] = ["json"]
    api_keys:            dict = {}

    @field_validator("scan_depth")
    @classmethod
    def _depth(cls, v):
        if v not in ("quick", "standard", "deep"):
            raise ValueError("scan_depth must be: quick | standard | deep")
        return v

    @field_validator("concurrency")
    @classmethod
    def _concurrency(cls, v):
        if not (1 <= v <= 200):
            raise ValueError("concurrency must be 1–200")
        return v


class JobResponse(BaseModel):
    job_id:      str
    domain:      str
    status:      str
    created_at:  str
    finished_at: Optional[str] = None
    result:      Optional[dict]= None
    error:       Optional[str] = None


# ── Background task ───────────────────────────────────────────────────────────

async def _run_scan(job_id: str, req: ScanRequest):
    job = _jobs[job_id]
    job.status = JobStatus.RUNNING
    try:
        from src.core.orchestrator import ReconOrchestrator, ScanConfig
        config = ScanConfig(
            domain=req.domain,
            scan_depth=req.scan_depth,
            concurrency=req.concurrency,
            timeout=req.timeout,
            enable_dns_history=req.enable_dns_history,
            enable_http_probe=req.enable_http_probe,
            enable_risk_scoring=req.enable_risk_scoring,
            output_formats=req.output_formats,
            output_dir=Path("reports"),
            api_keys=req.api_keys,
        )
        result = await ReconOrchestrator(config).run()
        job.result = {
            "statistics":  result.statistics,
            "subdomains":  [
                sd.get("subdomain", sd) if isinstance(sd, dict) else sd
                for sd in result.subdomains
            ],
            "endpoints":   result.endpoints[:1000],
            "risk_scores": {k: asdict(v) for k, v in result.risk_scores.items()},
            "errors":      result.errors,
        }
        job.status = JobStatus.COMPLETE
    except Exception as exc:
        logger.error(f"Job {job_id} failed: {exc}", exc_info=True)
        job.status = JobStatus.FAILED
        job.error  = str(exc)
    finally:
        job.finished_at = datetime.utcnow().isoformat()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/api/v1/health")
async def health():
    return {"status": "ok", "tool": "Fatah2", "author": "Pr0fessor SnApe",
            "version": "2.0.0"}


@app.post("/api/v1/scan", response_model=JobResponse, status_code=202)
async def create_scan(req: ScanRequest, _: str = Depends(_verify)):
    """Start a new scan. Returns job_id immediately; poll GET /api/v1/scan/{job_id}."""
    from src.core.target import Target
    try:
        Target(req.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    job_id = str(uuid.uuid4())
    _jobs[job_id] = Job(id=job_id, domain=req.domain)
    asyncio.create_task(_run_scan(job_id, req))

    return JobResponse(job_id=job_id, domain=req.domain,
                       status=_jobs[job_id].status,
                       created_at=_jobs[job_id].created_at)


@app.get("/api/v1/scan/{job_id}", response_model=JobResponse)
async def get_scan(job_id: str, _: str = Depends(_verify)):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return JobResponse(job_id=job.id, domain=job.domain, status=job.status,
                       created_at=job.created_at, finished_at=job.finished_at,
                       result=job.result, error=job.error)


@app.get("/api/v1/scans", response_model=list[JobResponse])
async def list_scans(_: str = Depends(_verify)):
    return [
        JobResponse(job_id=j.id, domain=j.domain, status=j.status,
                    created_at=j.created_at, finished_at=j.finished_at,
                    error=j.error)
        for j in sorted(_jobs.values(), key=lambda x: x.created_at, reverse=True)
    ]
