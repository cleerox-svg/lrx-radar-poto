import random
from datetime import date, datetime

import redis

from app.config import settings


COUNTRIES = [
    ("United States", "US"),
    ("Russia", "RU"),
    ("India", "IN"),
    ("Germany", "DE"),
    ("Brazil", "BR"),
    ("United Kingdom", "GB"),
    ("Japan", "JP"),
    ("Australia", "AU"),
    ("South Africa", "ZA"),
    ("Canada", "CA"),
]

ATTACK_TEMPLATES = [
    ("Typosquatting", "Credential Harvesting", ["lookalike", "mx-active", "certstream"]),
    ("Phishing URL", "Token Theft", ["urlhaus", "email-lure", "redirect-chain"]),
    ("Credential Stuffing", "Brute Force", ["combo-list", "tor-exit", "spray-pattern"]),
    ("Brand Impersonation", "Business Email Compromise", ["exec-spoof", "invoice-fraud", "dmarc-fail"]),
    ("Email Spoofing", "Mailbox Compromise", ["spf-fail", "dkim-fail", "dmarc-none"]),
]

USERS = [
    "j.doe",
    "s.james",
    "a.chen",
    "f.rivera",
    "m.ali",
    "n.singh",
    "d.ikeda",
    "r.barnes",
]

CITY_PAIRS = [
    ("Toronto", "Moscow"),
    ("San Jose", "Tokyo"),
    ("New York", "Berlin"),
    ("Vancouver", "Delhi"),
    ("Madrid", "Sao Paulo"),
    ("Sydney", "London"),
]


def redis_client() -> redis.Redis:
    return redis.from_url(settings.redis_url, decode_responses=True)


def to_base_domain(brand: str) -> str:
    clean = brand.lower().replace(" ", "").replace("-", "")
    return clean + ".com"


def typo_variation(brand: str) -> str:
    base = brand.lower().replace(" ", "").replace("-", "")
    substitutions = {"o": "0", "i": "1", "l": "1", "e": "3", "a": "4", "s": "5"}
    chars = list(base)
    if chars:
        idx = random.randint(0, len(chars) - 1)
        chars[idx] = substitutions.get(chars[idx], chars[idx])
    mutated = "".join(chars)
    suffix = random.choice(["-secure", "-login", "-support", "-verify", "-billing"])
    return f"{mutated}{suffix}.com"


def generate_threat_event() -> dict:
    brand = random.choice(settings.brand_list).replace("-", "")
    category, attack_type, tags = random.choice(ATTACK_TEMPLATES)
    country, country_code = random.choice(COUNTRIES)
    indicator_domain = typo_variation(brand)
    indicator_type = "domain"
    indicator_value = indicator_domain
    if category == "Phishing URL":
        indicator_type = "url"
        indicator_value = f"https://{indicator_domain}/auth/session"
    elif category == "Credential Stuffing":
        indicator_type = "ip"
        indicator_value = ".".join(str(random.randint(1, 254)) for _ in range(4))

    volume = random.randint(15, 130)
    ato_hits = random.randint(0, 8)
    confidence = random.randint(72, 99)
    primary_target = random.choice(
        [
            "Microsoft 365 users",
            "Finance team",
            "Remote workers",
            "Identity admins",
            "Support staff",
        ]
    )

    return {
        "type": "threat_event",
        "source": "certstream-sim",
        "indicator_type": indicator_type,
        "indicator_value": indicator_value,
        "category": category,
        "country": country,
        "country_code": country_code,
        "brand_target": brand.title(),
        "attack_type": attack_type,
        "primary_target": primary_target,
        "volume": volume,
        "ato_hits": ato_hits,
        "confidence": confidence,
        "event_meta": {"tags": tags, "generated_at": datetime.utcnow().isoformat()},
        "occurred_at": datetime.utcnow().isoformat(),
    }


def generate_ato_event() -> dict:
    user = random.choice(USERS)
    brand = random.choice(settings.brand_list).replace("-", "")
    loc1, loc2 = random.choice(CITY_PAIRS)
    return {
        "type": "ato_event",
        "user_email": f"{user}@{to_base_domain(brand)}",
        "loc1": loc1,
        "loc2": loc2,
        "risk_score": random.randint(75, 99),
        "action_taken": random.choice(["step_up_auth", "terminate_sessions", "require_reset", "monitor"]),
        "created_at": datetime.utcnow().isoformat(),
    }


def generate_dmarc_report() -> dict:
    brand = random.choice(settings.brand_list).replace("-", "")
    domain = to_base_domain(brand)
    disposition = random.choices(["none", "quarantine", "reject"], weights=[20, 25, 55])[0]
    return {
        "type": "dmarc_report",
        "domain": domain,
        "reporting_org": random.choice(["Google", "Microsoft", "Yahoo", "Proofpoint"]),
        "source_ip": ".".join(str(random.randint(1, 254)) for _ in range(4)),
        "disposition": disposition,
        "spf_result": random.choice(["pass", "fail"]),
        "dkim_result": random.choice(["pass", "fail"]),
        "msg_count": random.randint(5, 120),
        "report_date": date.today().isoformat(),
        "raw_payload": {"source": "simulator"},
    }
