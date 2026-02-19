from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.campaigns import (
    build_orchestrator_payloads,
    correlate_campaigns,
    dmarc_evidence_for_campaign,
    execute_orchestrator_actions,
    find_campaign,
)
from app.config import settings
from app.database import Base, SessionLocal, engine, get_db
from app.seed_data import seed_database
from app.services import build_dashboard_payload


ROOT_DIR = Path(__file__).resolve().parent.parent
FRONTEND_FILE = ROOT_DIR / "lrx_radar_v6.html"

app = FastAPI(title=settings.app_name)


def ensure_initialized() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_database(db)
    finally:
        db.close()


@app.on_event("startup")
def on_startup() -> None:
    ensure_initialized()


@app.get("/")
def dashboard_page():
    return FileResponse(FRONTEND_FILE)


@app.get("/api/health")
def health_check():
    return {"status": "ok", "app": settings.app_name}


@app.get("/api/dashboard")
def dashboard_data(db: Session = Depends(get_db)):
    ensure_initialized()
    return build_dashboard_payload(db)


@app.get("/api/campaigns")
def campaign_list(
    hours: int = Query(default=48, ge=1, le=720),
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    ensure_initialized()
    campaigns = correlate_campaigns(db, hours=hours, limit=limit)
    return {"campaigns": campaigns, "hours": hours, "count": len(campaigns)}


@app.get("/api/campaigns/{campaign_id}")
def campaign_detail(
    campaign_id: str,
    hours: int = Query(default=168, ge=1, le=1440),
    db: Session = Depends(get_db),
):
    ensure_initialized()
    campaign = find_campaign(db, campaign_id=campaign_id, hours=hours)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign


@app.get("/api/campaigns/{campaign_id}/orchestrator-payloads")
def campaign_orchestrator_payloads(
    campaign_id: str,
    hours: int = Query(default=168, ge=1, le=1440),
    db: Session = Depends(get_db),
):
    ensure_initialized()
    campaign = find_campaign(db, campaign_id=campaign_id, hours=hours)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return {"campaign": campaign, "orchestrator_payloads": build_orchestrator_payloads(campaign)}


@app.post("/api/campaigns/{campaign_id}/orchestrate")
def campaign_orchestrate(
    campaign_id: str,
    dry_run: bool = Query(default=True),
    hours: int = Query(default=168, ge=1, le=1440),
    db: Session = Depends(get_db),
):
    ensure_initialized()
    campaign = find_campaign(db, campaign_id=campaign_id, hours=hours)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return {"campaign_id": campaign_id, **execute_orchestrator_actions(campaign, dry_run=dry_run)}


@app.get("/api/campaigns/{campaign_id}/evidence/dmarc")
def campaign_dmarc_evidence(
    campaign_id: str,
    hours: int = Query(default=168, ge=1, le=1440),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    ensure_initialized()
    campaign = find_campaign(db, campaign_id=campaign_id, hours=hours)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    evidence = dmarc_evidence_for_campaign(db, campaign=campaign, hours=hours, limit=limit)
    return {"campaign_id": campaign_id, "evidence": evidence, "count": len(evidence)}
