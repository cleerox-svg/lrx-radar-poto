from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

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
