from datetime import date, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AtoEvent, DmarcReport, ThreatEvent
from app.services import build_dedupe_hash


SEED_THREATS = [
    {
        "source": "seed",
        "indicator_type": "domain",
        "indicator_value": "micr0soft-login-support.com",
        "category": "Typosquatting",
        "country": "Russia",
        "country_code": "RU",
        "brand_target": "Microsoft",
        "attack_type": "Credential Harvesting",
        "primary_target": "Microsoft 365 Administrators",
        "volume": 620,
        "ato_hits": 8,
        "confidence": 97,
        "event_meta": {"tags": ["certstream", "mx-active", "phishing-kit"]},
    },
    {
        "source": "seed",
        "indicator_type": "url",
        "indicator_value": "https://okta-sso-security-check.net/verify",
        "category": "Phishing URL",
        "country": "United States",
        "country_code": "US",
        "brand_target": "Okta",
        "attack_type": "Session Hijack",
        "primary_target": "SAML SSO Users",
        "volume": 210,
        "ato_hits": 3,
        "confidence": 91,
        "event_meta": {"tags": ["urlhaus", "otx-pulse", "spoofed-sso"]},
    },
    {
        "source": "seed",
        "indicator_type": "domain",
        "indicator_value": "paypaI-verification-center.com",
        "category": "Brand Impersonation",
        "country": "Brazil",
        "country_code": "BR",
        "brand_target": "PayPal",
        "attack_type": "Invoice Fraud",
        "primary_target": "Finance Teams",
        "volume": 370,
        "ato_hits": 1,
        "confidence": 89,
        "event_meta": {"tags": ["lookalike", "email-lure"]},
    },
    {
        "source": "seed",
        "indicator_type": "ip",
        "indicator_value": "185.220.101.24",
        "category": "Credential Stuffing",
        "country": "Germany",
        "country_code": "DE",
        "brand_target": "Adobe",
        "attack_type": "Brute Force",
        "primary_target": "Identity Portals",
        "volume": 490,
        "ato_hits": 6,
        "confidence": 86,
        "event_meta": {"tags": ["tor-exit", "password-spray"]},
    },
    {
        "source": "seed",
        "indicator_type": "domain",
        "indicator_value": "amazon-security-billing-alert.com",
        "category": "Email Spoofing",
        "country": "India",
        "country_code": "IN",
        "brand_target": "Amazon",
        "attack_type": "Business Email Compromise",
        "primary_target": "Procurement",
        "volume": 540,
        "ato_hits": 2,
        "confidence": 88,
        "event_meta": {"tags": ["dmarc-fail", "exec-impersonation"]},
    },
]


SEED_ATO_EVENTS = [
    ("s.james@microsoft.com", "Toronto", "Moscow", 96, "terminate_sessions"),
    ("a.chen@okta.com", "San Jose", "Tokyo", 91, "step_up_auth"),
    ("f.rivera@paypal.com", "Madrid", "Sao Paulo", 89, "require_reset"),
    ("d.ikeda@adobe.com", "Sydney", "Berlin", 84, "monitor"),
]


def seed_database(db: Session) -> None:
    has_threats = db.scalar(select(ThreatEvent.id).limit(1))
    if has_threats:
        return

    for payload in SEED_THREATS:
        dedupe_hash = build_dedupe_hash(payload)
        event = ThreatEvent(
            dedupe_hash=dedupe_hash,
            occurred_at=datetime.utcnow() - timedelta(minutes=15),
            **payload,
        )
        db.add(event)

    for user_email, loc1, loc2, risk, action in SEED_ATO_EVENTS:
        db.add(
            AtoEvent(
                user_email=user_email,
                loc1=loc1,
                loc2=loc2,
                risk_score=risk,
                action_taken=action,
                created_at=datetime.utcnow() - timedelta(minutes=5),
            )
        )

    report_date = date.today()
    for domain in settings.brand_list[:4]:
        db.add(
            DmarcReport(
                domain=f"{domain}.com",
                reporting_org="Google",
                source_ip="35.190.247.3",
                disposition="reject",
                spf_result="fail",
                dkim_result="pass",
                msg_count=50,
                report_date=report_date,
                raw_payload={"source": "seed"},
            )
        )

    db.commit()
