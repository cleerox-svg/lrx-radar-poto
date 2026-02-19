import hashlib
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from urllib.parse import urlparse

import httpx
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AtoEvent, DmarcReport, ThreatEvent


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _brand_key_from_domain(domain: str) -> str:
    if not domain:
        return "unknown"
    raw = domain.lower().split("@")[-1]
    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.netloc
    else:
        host = raw
    host = host.split(":")[0]
    host = host.lstrip("*.").strip()
    if "." in host:
        host = host.split(".")[0]
    cleaned = _normalize(host)
    return cleaned or "unknown"


def _infer_brand_label(brand_key: str, fallback: str = "Unknown") -> str:
    for brand in settings.brand_list:
        normalized = _normalize(brand)
        if normalized == brand_key:
            return brand.replace("-", " ").title()
    return fallback


def _campaign_id(brand_key: str, indicator_hint: str) -> str:
    digest = hashlib.sha1(f"{brand_key}:{indicator_hint}".encode("utf-8")).hexdigest()[:8].upper()
    return f"LRX-CMP-{digest}"


def correlate_campaigns(db: Session, hours: int = 48, limit: int = 20) -> list[dict]:
    since = datetime.utcnow() - timedelta(hours=max(1, hours))
    threats = db.scalars(
        select(ThreatEvent).where(ThreatEvent.occurred_at >= since).order_by(desc(ThreatEvent.occurred_at))
    ).all()
    ato_events = db.scalars(
        select(AtoEvent).where(AtoEvent.created_at >= since).order_by(desc(AtoEvent.created_at))
    ).all()
    dmarc_reports = db.scalars(
        select(DmarcReport).where(DmarcReport.created_at >= since).order_by(desc(DmarcReport.created_at))
    ).all()

    if not threats:
        return []

    ato_by_brand: dict[str, list[AtoEvent]] = defaultdict(list)
    for event in ato_events:
        brand_key = _brand_key_from_domain(event.user_email)
        ato_by_brand[brand_key].append(event)

    dmarc_by_brand: dict[str, list[DmarcReport]] = defaultdict(list)
    for report in dmarc_reports:
        brand_key = _brand_key_from_domain(report.domain)
        dmarc_by_brand[brand_key].append(report)

    grouped_threats: dict[str, list[ThreatEvent]] = defaultdict(list)
    for threat in threats:
        if threat.brand_target and threat.brand_target != "Unknown":
            brand_key = _normalize(threat.brand_target)
        else:
            brand_key = _brand_key_from_domain(threat.indicator_value)
        grouped_threats[brand_key].append(threat)

    campaigns: list[dict] = []
    for brand_key, items in grouped_threats.items():
        if not items:
            continue

        category_counts = Counter(item.category for item in items)
        country_counts = Counter(item.country for item in items)
        domain_counts = Counter(
            item.indicator_value for item in items if item.indicator_type in {"domain", "url"}
        )
        ip_counts = Counter(item.indicator_value for item in items if item.indicator_type == "ip")

        total_volume = sum(item.volume for item in items)
        avg_confidence = sum(item.confidence for item in items) / len(items)
        related_ato = ato_by_brand.get(brand_key, [])
        related_dmarc = dmarc_by_brand.get(brand_key, [])

        dmarc_fail_count = sum(
            report.msg_count
            for report in related_dmarc
            if report.disposition == "reject" or report.spf_result != "pass" or report.dkim_result != "pass"
        )
        ato_count = len(related_ato)

        confidence = int(
            min(
                99,
                max(
                    45,
                    avg_confidence
                    + min(20, len(items) * 2)
                    + (15 if dmarc_fail_count > 0 else 0)
                    + (15 if ato_count > 0 else 0),
                ),
            )
        )

        triggers = ["Lookalike domain activity"]
        if dmarc_fail_count > 0:
            triggers.append("DMARC authentication failures")
        if ato_count > 0:
            triggers.append("ATO anomaly telemetry")

        top_indicator = domain_counts.most_common(1)
        indicator_hint = top_indicator[0][0] if top_indicator else (ip_counts.most_common(1)[0][0] if ip_counts else brand_key)
        campaign_id = _campaign_id(brand_key, indicator_hint)

        first_seen = min(item.occurred_at for item in items).isoformat()
        last_seen = max(item.occurred_at for item in items).isoformat()
        brand_label = _infer_brand_label(brand_key, items[0].brand_target or "Unknown")

        campaigns.append(
            {
                "campaign_id": campaign_id,
                "brand": brand_label,
                "brand_key": brand_key,
                "threat_confidence_score": confidence,
                "trigger_event": " + ".join(triggers),
                "threat_count": len(items),
                "total_volume": total_volume,
                "ato_event_count": ato_count,
                "dmarc_fail_count": dmarc_fail_count,
                "attack_vectors": [name for name, _ in category_counts.most_common(5)],
                "top_countries": [name for name, _ in country_counts.most_common(5)],
                "ioc_domains": [domain for domain, _ in domain_counts.most_common(5)],
                "ioc_ips": [address for address, _ in ip_counts.most_common(5)],
                "affected_users": [event.user_email for event in related_ato[:5]],
                "first_seen": first_seen,
                "last_seen": last_seen,
            }
        )

    campaigns.sort(key=lambda item: item["threat_confidence_score"], reverse=True)
    return campaigns[: max(1, limit)]


def find_campaign(db: Session, campaign_id: str, hours: int = 168) -> dict | None:
    campaigns = correlate_campaigns(db, hours=hours, limit=500)
    for campaign in campaigns:
        if campaign["campaign_id"] == campaign_id:
            return campaign
    return None


def build_orchestrator_payloads(campaign: dict) -> dict:
    campaign_id = campaign["campaign_id"]
    primary_domain = campaign["ioc_domains"][0] if campaign["ioc_domains"] else f"{campaign['brand_key']}.com"
    attacker_ip = campaign["ioc_ips"][0] if campaign["ioc_ips"] else "0.0.0.0"
    target_user = campaign["affected_users"][0] if campaign["affected_users"] else f"soc@{campaign['brand_key']}.com"
    dmarc_evidence_url = f"{settings.public_api_base_url}/api/campaigns/{campaign_id}/evidence/dmarc"

    proofpoint_payload = {
        "action": "add",
        "threat_type": "domain",
        "indicators": [
            {
                "value": primary_domain,
                "operator": "equal",
                "comment": (
                    "LRX Radar Auto-Block: Correlated campaign with lookalike "
                    "infrastructure and telemetry evidence."
                ),
            },
            {
                "value": attacker_ip,
                "operator": "equal",
                "comment": "LRX Radar Auto-Block: Associated attacker IP for correlated campaign.",
            },
        ],
    }

    takedown_payload = {
        "incident_type": "brand_impersonation",
        "target_url": f"https://{primary_domain}/auth/login",
        "impersonated_brand": campaign["brand"],
        "priority": "critical" if campaign["threat_confidence_score"] >= 90 else "high",
        "automated_authorization": True,
        "evidence_package": {
            "campaign_id": campaign_id,
            "weaponization_status": {
                "active_mx_records_detected": True,
                "dmarc_failure_log_url": dmarc_evidence_url,
                "ato_signal_count": campaign["ato_event_count"],
            },
            "attack_vectors": campaign["attack_vectors"],
            "top_countries": campaign["top_countries"],
        },
    }

    okta_payload = {
        "lrx_radar_signal": {
            "campaign_id": campaign_id,
            "threat_confidence_score": campaign["threat_confidence_score"],
            "trigger_event": campaign["trigger_event"],
        },
        "identity_target": {
            "user_email": target_user,
            "requested_response": "terminate_sessions_and_step_up",
            "context": {
                "attacker_ip": attacker_ip,
                "compromised_via": primary_domain,
            },
        },
    }

    return {
        "proofpoint": {
            "endpoint": settings.proofpoint_blocklist_endpoint,
            "payload": proofpoint_payload,
            "auth_header": "Authorization: Bearer <PROOFPOINT_API_TOKEN>",
        },
        "takedown": {
            "endpoint": settings.takedown_submit_endpoint,
            "payload": takedown_payload,
            "auth_header": "X-API-Key: <TAKEDOWN_API_KEY>",
        },
        "okta": {
            "endpoint": settings.okta_workflow_invoke_url,
            "payload": okta_payload,
            "auth_header": "Authorization: Bearer <OKTA_OAUTH_TOKEN>",
        },
    }


def execute_orchestrator_actions(campaign: dict, dry_run: bool = True) -> dict:
    payloads = build_orchestrator_payloads(campaign)
    if dry_run:
        return {
            "dry_run": True,
            "results": {
                "proofpoint": {"status": "would_send", "endpoint": payloads["proofpoint"]["endpoint"]},
                "takedown": {"status": "would_send", "endpoint": payloads["takedown"]["endpoint"]},
                "okta": {"status": "would_send", "endpoint": payloads["okta"]["endpoint"]},
            },
            "payloads": payloads,
        }

    actions = [
        (
            "proofpoint",
            payloads["proofpoint"]["endpoint"],
            payloads["proofpoint"]["payload"],
            {"Authorization": f"Bearer {settings.proofpoint_api_token}"},
            bool(settings.proofpoint_api_token),
        ),
        (
            "takedown",
            payloads["takedown"]["endpoint"],
            payloads["takedown"]["payload"],
            {"X-API-Key": settings.takedown_api_key},
            bool(settings.takedown_api_key),
        ),
        (
            "okta",
            payloads["okta"]["endpoint"],
            payloads["okta"]["payload"],
            {"Authorization": f"Bearer {settings.okta_oauth_token}"},
            bool(settings.okta_oauth_token),
        ),
    ]

    results: dict[str, dict] = {}
    with httpx.Client(timeout=settings.orchestrator_timeout_seconds) as client:
        for name, endpoint, payload, headers, has_credential in actions:
            if not endpoint:
                results[name] = {"status": "skipped", "reason": "missing endpoint"}
                continue
            if not has_credential:
                results[name] = {"status": "skipped", "reason": "missing credentials"}
                continue
            try:
                response = client.post(endpoint, headers=headers, json=payload)
                results[name] = {
                    "status": "sent",
                    "status_code": response.status_code,
                    "endpoint": endpoint,
                }
            except Exception as exc:
                results[name] = {"status": "failed", "endpoint": endpoint, "error": str(exc)}

    return {"dry_run": False, "results": results}


def dmarc_evidence_for_campaign(db: Session, campaign: dict, hours: int = 168, limit: int = 50) -> list[dict]:
    since = datetime.utcnow() - timedelta(hours=max(1, hours))
    all_reports = db.scalars(
        select(DmarcReport).where(DmarcReport.created_at >= since).order_by(desc(DmarcReport.created_at))
    ).all()

    brand_key = campaign["brand_key"]
    filtered = []
    for report in all_reports:
        if _brand_key_from_domain(report.domain) != brand_key:
            continue
        filtered.append(
            {
                "id": report.id,
                "domain": report.domain,
                "reporting_org": report.reporting_org,
                "source_ip": report.source_ip,
                "disposition": report.disposition,
                "spf_result": report.spf_result,
                "dkim_result": report.dkim_result,
                "msg_count": report.msg_count,
                "report_date": report.report_date.isoformat(),
                "created_at": report.created_at.isoformat(),
            }
        )
        if len(filtered) >= limit:
            break
    return filtered
