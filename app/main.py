"""FastAPI application for Morpheus Red-Teaming Framework."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.config import get_settings
from app.orchestrator import AuditOrchestrator

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger(__name__)

orchestrator: AuditOrchestrator | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global orchestrator
    settings = get_settings()
    orchestrator = AuditOrchestrator(settings)
    logger.info("Morpheus ready")
    yield
    logger.info("Shutting down")


app = FastAPI(
    title="Morpheus",
    description="Automated LLM Red-Teaming and Vulnerability Assessment Framework",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -- Models --

class AuditRequest(BaseModel):
    target_model: str = Field(default="gpt-4", description="Model to audit")
    categories: list[str] = Field(
        default=["jailbreak", "injection", "bias", "extraction", "hallucination"],
        description="Attack categories to run",
    )
    probes_per_category: int = Field(default=10, ge=1, le=20)
    system_prompt: str = Field(
        default="",
        description="The system prompt of the target model (if known)",
    )


class CategoryAuditRequest(BaseModel):
    category: str = Field(..., description="Single attack category to run")
    probes_count: int = Field(default=10, ge=1, le=20)
    system_prompt: str = Field(default="")


class AuditResponse(BaseModel):
    audit_id: str
    target_model: str
    total_probes: int
    overall_robustness: float
    category_scores: dict
    critical_failures: int
    total_time_seconds: float


class HealthResponse(BaseModel):
    status: str
    target_model: str
    available_categories: list[str]


# -- Endpoints --

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health():
    settings = get_settings()
    return HealthResponse(
        status="healthy",
        target_model=settings.target_model,
        available_categories=list(settings.all_categories),
    )


@app.get("/attacks", tags=["System"])
async def list_attacks():
    """List all available attack categories and their descriptions."""
    return {"attacks": orchestrator.get_available_attacks()}


@app.post("/audit/run", response_model=AuditResponse, tags=["Audit"])
async def run_full_audit(request: AuditRequest):
    """
    Run a full red-team audit across multiple attack categories.

    Generates adversarial probes, fires them at the target model,
    evaluates responses, scores robustness, and produces an audit report.
    """
    try:
        result = orchestrator.run_audit(
            categories=request.categories,
            probes_per_category=request.probes_per_category,
            system_prompt=request.system_prompt,
        )
        return AuditResponse(
            audit_id=result["audit_id"],
            target_model=result["target_model"],
            total_probes=result["total_probes"],
            overall_robustness=result["overall_robustness"],
            category_scores=result["category_scores"],
            critical_failures=result["critical_failures"],
            total_time_seconds=result["total_time_seconds"],
        )
    except Exception as e:
        logger.error(f"Audit failed: {e}")
        raise HTTPException(status_code=500, detail=f"Audit failed: {str(e)}")


@app.post("/audit/category", response_model=AuditResponse, tags=["Audit"])
async def run_category_audit(request: CategoryAuditRequest):
    """Run probes from a single attack category only."""
    valid = get_settings().all_categories
    if request.category not in valid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid category: {request.category}. Valid: {valid}",
        )

    try:
        result = orchestrator.run_category(
            category=request.category,
            probes_count=request.probes_count,
            system_prompt=request.system_prompt,
        )
        return AuditResponse(
            audit_id=result["audit_id"],
            target_model=result["target_model"],
            total_probes=result["total_probes"],
            overall_robustness=result["overall_robustness"],
            category_scores=result["category_scores"],
            critical_failures=result["critical_failures"],
            total_time_seconds=result["total_time_seconds"],
        )
    except Exception as e:
        logger.error(f"Category audit failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/reports/{audit_id}", tags=["Reports"])
async def get_report(audit_id: str):
    """Retrieve a completed audit report by ID."""
    settings = get_settings()
    json_path = Path(settings.report_dir) / f"{audit_id}.json"

    if not json_path.exists():
        raise HTTPException(status_code=404, detail=f"Report {audit_id} not found")

    import json
    with open(json_path, "r") as f:
        return json.load(f)


if __name__ == "__main__":
    import uvicorn
    settings = get_settings()
    uvicorn.run("app.main:app", host=settings.api_host, port=settings.api_port, reload=True)
