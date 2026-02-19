import uuid
from datetime import date, datetime

from sqlalchemy import JSON, Date, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Client(Base):
    __tablename__ = "clients"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    primary_domain: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    monitored_brands: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ThreatEvent(Base):
    __tablename__ = "threat_events"
    __table_args__ = (UniqueConstraint("dedupe_hash", name="uq_threat_events_dedupe_hash"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    indicator_type: Mapped[str] = mapped_column(String(32), nullable=False)
    indicator_value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    country: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    country_code: Mapped[str] = mapped_column(String(4), nullable=False, default="--")
    brand_target: Mapped[str] = mapped_column(String(255), nullable=False, default="Unknown")
    attack_type: Mapped[str] = mapped_column(String(255), nullable=False, default="Unknown")
    primary_target: Mapped[str] = mapped_column(String(255), nullable=False, default="Unknown")
    volume: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    ato_hits: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    dedupe_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    event_meta: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    alerts: Mapped[list["Alert"]] = relationship(
        "Alert",
        back_populates="threat_event",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    threat_event_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("threat_events.id", ondelete="CASCADE"), nullable=False, index=True
    )
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )

    threat_event: Mapped[ThreatEvent] = relationship("ThreatEvent", back_populates="alerts")


class AtoEvent(Base):
    __tablename__ = "ato_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    loc1: Mapped[str] = mapped_column(String(64), nullable=False)
    loc2: Mapped[str] = mapped_column(String(64), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    action_taken: Mapped[str] = mapped_column(String(128), nullable=False, default="monitor")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )


class DmarcReport(Base):
    __tablename__ = "dmarc_reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    reporting_org: Mapped[str] = mapped_column(String(255), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    disposition: Mapped[str] = mapped_column(String(32), nullable=False)
    spf_result: Mapped[str] = mapped_column(String(32), nullable=False)
    dkim_result: Mapped[str] = mapped_column(String(32), nullable=False)
    msg_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    report_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    raw_payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
