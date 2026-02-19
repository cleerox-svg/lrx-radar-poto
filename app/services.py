import hashlib
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.models import Alert, AtoEvent, DmarcReport, ThreatEvent


COUNTRY_COORDINATES: dict[str, dict[str, int]] = {
    "United States": {"top": 37, "left": 23},
    "Canada": {"top": 28, "left": 22},
    "Brazil": {"top": 67, "left": 32},
    "United Kingdom": {"top": 28, "left": 47},
    "Germany": {"top": 31, "left": 52},
    "France": {"top": 34, "left": 49},
    "Russia": {"top": 22, "left": 62},
    "India": {"top": 50, "left": 69},
    "China": {"top": 42, "left": 75},
    "Japan": {"top": 39, "left": 84},
    "Australia": {"top": 74, "left": 84},
    "South Africa": {"top": 76, "left": 55},
    "UAE": {"top": 51, "left": 60},
}


VECTOR_COLORS = [
    "bg-red-500",
    "bg-orange-500",
    "bg-yellow-500",
    "bg-radar-500",
    "bg-blue-500",
]


BRAND_ICONS = {
    "Microsoft": "fa-brands fa-microsoft",
    "Google": "fa-brands fa-google",
    "Adobe": "fa-brands fa-adobe",
    "PayPal": "fa-brands fa-paypal",
    "Amazon": "fa-brands fa-amazon",
    "Okta": "fa-solid fa-shield-halved",
    "BankOfAmerica": "fa-solid fa-building-columns",
}


def build_dedupe_hash(payload: dict) -> str:
    key = "|".join(
        [
            str(payload.get("source", "")),
            str(payload.get("indicator_type", "")),
            str(payload.get("indicator_value", "")),
            str(payload.get("brand_target", "")),
            str(payload.get("country", "")),
            str(payload.get("category", "")),
        ]
    )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _stable_position(country: str) -> dict[str, int]:
    if country in COUNTRY_COORDINATES:
        return COUNTRY_COORDINATES[country]
    digest = hashlib.md5(country.encode("utf-8")).hexdigest()
    top = 15 + int(digest[:2], 16) % 65
    left = 10 + int(digest[2:4], 16) % 80
    return {"top": top, "left": left}


def upsert_threat_event(db: Session, payload: dict) -> ThreatEvent:
    dedupe_hash = payload.get("dedupe_hash") or build_dedupe_hash(payload)
    event = db.scalar(select(ThreatEvent).where(ThreatEvent.dedupe_hash == dedupe_hash))
    now = datetime.utcnow()

    if event:
        event.volume += int(payload.get("volume", 1))
        event.ato_hits += int(payload.get("ato_hits", 0))
        event.confidence = max(event.confidence, int(payload.get("confidence", event.confidence)))
        event.last_seen = now
        event.occurred_at = now
        incoming_meta = payload.get("event_meta", {})
        if isinstance(incoming_meta, dict):
            merged = {**(event.event_meta or {}), **incoming_meta}
            event.event_meta = merged
        db.add(event)
        return event

    event = ThreatEvent(
        source=payload.get("source", "unknown"),
        indicator_type=payload.get("indicator_type", "domain"),
        indicator_value=payload.get("indicator_value", "unknown"),
        category=payload.get("category", "Unknown"),
        country=payload.get("country", "Unknown"),
        country_code=payload.get("country_code", "--"),
        brand_target=payload.get("brand_target", "Unknown"),
        attack_type=payload.get("attack_type", "Unknown"),
        primary_target=payload.get("primary_target", "Unknown"),
        volume=int(payload.get("volume", 1)),
        ato_hits=int(payload.get("ato_hits", 0)),
        confidence=int(payload.get("confidence", 50)),
        dedupe_hash=dedupe_hash,
        event_meta=payload.get("event_meta", {}),
        occurred_at=_safe_datetime(payload.get("occurred_at")) or now,
    )
    db.add(event)
    return event


def create_alert_if_needed(db: Session, event: ThreatEvent) -> None:
    if event.confidence < 85:
        return

    existing = db.scalar(
        select(Alert).where(Alert.threat_event_id == event.id, Alert.status == "open").limit(1)
    )
    if existing:
        return

    severity = "critical" if event.confidence >= 95 else "high"
    title = f"{event.brand_target} targeted by {event.category}"
    description = (
        f"{event.indicator_value} observed from {event.country} with confidence {event.confidence}%."
    )
    db.add(
        Alert(
            threat_event_id=event.id,
            severity=severity,
            title=title,
            description=description,
        )
    )


def insert_ato_event(db: Session, payload: dict) -> AtoEvent:
    event = AtoEvent(
        user_email=payload.get("user_email", "unknown@unknown.local"),
        loc1=payload.get("loc1", "Unknown"),
        loc2=payload.get("loc2", "Unknown"),
        risk_score=int(payload.get("risk_score", 50)),
        action_taken=payload.get("action_taken", "monitor"),
        created_at=_safe_datetime(payload.get("created_at")) or datetime.utcnow(),
    )
    db.add(event)
    return event


def insert_dmarc_report(db: Session, payload: dict) -> DmarcReport:
    report = DmarcReport(
        domain=payload.get("domain", "unknown.local"),
        reporting_org=payload.get("reporting_org", "unknown"),
        source_ip=payload.get("source_ip", "0.0.0.0"),
        disposition=payload.get("disposition", "none"),
        spf_result=payload.get("spf_result", "fail"),
        dkim_result=payload.get("dkim_result", "fail"),
        msg_count=int(payload.get("msg_count", 1)),
        report_date=_safe_date(payload.get("report_date")),
        raw_payload=payload.get("raw_payload", {}),
    )
    db.add(report)
    return report


def _safe_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def _safe_date(value: str | None) -> date:
    if not value:
        return datetime.utcnow().date()
    try:
        return datetime.fromisoformat(value).date()
    except ValueError:
        return datetime.utcnow().date()


def build_dashboard_payload(db: Session) -> dict:
    now = datetime.utcnow()
    since = now - timedelta(hours=24)

    threats = db.scalars(
        select(ThreatEvent)
        .where(ThreatEvent.occurred_at >= since)
        .order_by(desc(ThreatEvent.occurred_at))
        .limit(500)
    ).all()
    ato_events = db.scalars(
        select(AtoEvent).where(AtoEvent.created_at >= since).order_by(desc(AtoEvent.created_at)).limit(100)
    ).all()
    dmarc_reports = db.scalars(
        select(DmarcReport).where(DmarcReport.created_at >= since).order_by(desc(DmarcReport.created_at)).limit(500)
    ).all()

    return {
        "updated_at": now.isoformat(),
        "heatmap": _build_heatmap(threats),
        "ato": _build_ato(ato_events, threats),
        "email": _build_email(dmarc_reports),
    }


def _build_heatmap(threats: list[ThreatEvent]) -> dict:
    by_country: dict[str, dict] = defaultdict(
        lambda: {"volume": 0, "atos": 0, "target_counter": Counter(), "id": ""}
    )
    category_volume: dict[str, int] = defaultdict(int)
    category_tags: dict[str, Counter] = defaultdict(Counter)

    for event in threats:
        row = by_country[event.country]
        row["id"] = event.country
        row["volume"] += event.volume
        row["atos"] += event.ato_hits
        row["target_counter"][event.primary_target] += event.volume

        category_volume[event.category] += event.volume
        tags = event.event_meta.get("tags", []) if isinstance(event.event_meta, dict) else []
        for tag in tags:
            category_tags[event.category][tag] += 1

    threat_map = []
    for country, aggregate in by_country.items():
        coords = _stable_position(country)
        volume = aggregate["volume"]
        if volume >= 550:
            size_class = "w-12 h-12"
            inner_size_class = "w-5 h-5"
            color_class = "bg-red-500 text-red-500"
        elif volume >= 300:
            size_class = "w-10 h-10"
            inner_size_class = "w-4 h-4"
            color_class = "bg-orange-500 text-orange-500"
        else:
            size_class = "w-8 h-8"
            inner_size_class = "w-3 h-3"
            color_class = "bg-yellow-500 text-yellow-500"

        primary_target = aggregate["target_counter"].most_common(1)
        threat_map.append(
            {
                "id": country.lower().replace(" ", "-"),
                "country": country,
                "top": coords["top"],
                "left": coords["left"],
                "volume": volume,
                "atos": aggregate["atos"],
                "primary_target": primary_target[0][0] if primary_target else "Unknown",
                "sizeClass": size_class,
                "innerSizeClass": inner_size_class,
                "colorClass": color_class,
            }
        )

    sorted_categories = sorted(category_volume.items(), key=lambda item: item[1], reverse=True)
    total = sum(category_volume.values()) or 1
    categories = []
    for idx, (name, count) in enumerate(sorted_categories):
        tags = [tag for tag, _ in category_tags[name].most_common(3)] or ["new", "watch"]
        categories.append(
            {
                "name": name,
                "count": count,
                "percent": round((count / total) * 100),
                "color": VECTOR_COLORS[idx % len(VECTOR_COLORS)],
                "tags": tags,
            }
        )

    high_value_targets = []
    for event in threats[:10]:
        high_value_targets.append(
            {
                "id": event.id,
                "brand": event.brand_target,
                "domain": event.indicator_value,
                "type": event.attack_type,
                "confidence": event.confidence,
                "icon": BRAND_ICONS.get(event.brand_target, "fa-solid fa-crosshairs"),
            }
        )

    rejects = sum(event.volume for event in threats if event.category == "Email Spoofing")
    total_volume = sum(event.volume for event in threats) or 1
    spf_fail_pct = min(99, round((rejects / total_volume) * 100))
    dkim_fail_pct = max(5, min(95, round(spf_fail_pct * 0.72)))
    dmarc_fail_pct = max(1, 100 - spf_fail_pct - dkim_fail_pct)

    return {
        "threatMap": threat_map,
        "categories": categories,
        "highValueTargets": high_value_targets,
        "emailStats": {
            "rejects": rejects,
            "spf_fail_pct": spf_fail_pct,
            "dkim_fail_pct": dkim_fail_pct,
            "dmarc_fail_pct": dmarc_fail_pct,
        },
    }


def _build_ato(ato_events: list[AtoEvent], threats: list[ThreatEvent]) -> dict:
    recent_ato = ato_events[:8]
    compromised_accounts = len({entry.user_email for entry in ato_events if entry.risk_score >= 90})
    impossible_travel = [entry for entry in ato_events if entry.loc1 != entry.loc2]
    high_risk_alerts = len([entry for entry in ato_events if entry.risk_score >= 85])

    stuffing_volume = sum(
        event.volume for event in threats if event.category in {"Credential Stuffing", "Brute Force"}
    )
    credential_rate = max(10, stuffing_volume // 12 if stuffing_volume else 45)

    velocity = []
    source_values = [max(5, event.ato_hits * 10 + event.volume // 20) for event in threats[:12]]
    if not source_values:
        source_values = [45, 52, 48, 60, 55, 72, 66, 64, 58, 53, 61, 57]
    while len(source_values) < 12:
        source_values.append(source_values[-1])
    velocity = source_values[:12]

    impossible_travel_events = []
    for event in recent_ato:
        impossible_travel_events.append(
            {
                "id": event.id,
                "user": event.user_email,
                "time": event.created_at.strftime("%H:%M:%S"),
                "loc1": event.loc1,
                "loc2": event.loc2,
            }
        )

    return {
        "alerts": high_risk_alerts,
        "compromised_accounts": compromised_accounts,
        "credential_rate_per_min": credential_rate,
        "impossible_travel_flags": len(impossible_travel),
        "avg_remediation_seconds": 45,
        "velocity": velocity,
        "impossibleTravelEvents": impossible_travel_events,
    }


def _build_email(reports: list[DmarcReport]) -> dict:
    total_traffic = sum(report.msg_count for report in reports)
    spf_fail = sum(report.msg_count for report in reports if report.spf_result != "pass")
    dkim_fail = sum(report.msg_count for report in reports if report.dkim_result != "pass")
    rejects = sum(report.msg_count for report in reports if report.disposition == "reject")

    if total_traffic == 0:
        total_traffic = 50000
        spf_fail = 22500
        dkim_fail = 16000
        rejects = 1204

    spf_pass = max(0, total_traffic - spf_fail)
    dkim_pass = max(0, total_traffic - dkim_fail)
    dmarc_enforced = max(0, rejects)

    report_rows = []
    for row in reports[:10]:
        report_rows.append(
            {
                "id": row.id,
                "domain": row.domain,
                "reporting_org": row.reporting_org,
                "source_ip": row.source_ip,
                "disposition": row.disposition,
                "msg_count": row.msg_count,
            }
        )

    return {
        "total_traffic": total_traffic,
        "spf_fail": spf_fail,
        "dkim_fail": dkim_fail,
        "dmarc_enforced": dmarc_enforced,
        "spf_pass": spf_pass,
        "dkim_pass": dkim_pass,
        "reports": report_rows,
    }
