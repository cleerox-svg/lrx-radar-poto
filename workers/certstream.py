import argparse
import asyncio
import hashlib
import json
import random
import re
from difflib import SequenceMatcher

import websockets

from app.config import settings
from workers.common import COUNTRIES, redis_client


TLD_COUNTRY_MAP = {
    "ru": ("Russia", "RU"),
    "de": ("Germany", "DE"),
    "br": ("Brazil", "BR"),
    "in": ("India", "IN"),
    "jp": ("Japan", "JP"),
    "uk": ("United Kingdom", "GB"),
    "au": ("Australia", "AU"),
    "za": ("South Africa", "ZA"),
    "ca": ("Canada", "CA"),
    "us": ("United States", "US"),
}


def _clean_text(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _levenshtein_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    if len(a) < len(b):
        a, b = b, a

    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            insert_cost = current[j - 1] + 1
            delete_cost = previous[j] + 1
            replace_cost = previous[j - 1] + (char_a != char_b)
            current.append(min(insert_cost, delete_cost, replace_cost))
        previous = current
    return previous[-1]


def _find_brand_match(domain: str) -> tuple[str | None, float]:
    host = domain.lower().lstrip("*.").split(":")[0]
    first_label = host.split(".")[0]
    normalized_label = _clean_text(first_label)
    if not normalized_label:
        return None, 0.0

    tokens = [token for token in re.split(r"[^a-z0-9]+", first_label) if token]
    candidates = [normalized_label] + [_clean_text(token) for token in tokens]

    best_brand = None
    best_score = 0.0

    for brand in settings.brand_list:
        normalized_brand = _clean_text(brand)
        if not normalized_brand:
            continue

        for candidate in candidates:
            if not candidate:
                continue
            if normalized_brand in candidate:
                if candidate == normalized_brand and not settings.certstream_emit_on_exact_brand:
                    continue
                return brand.title(), 0.99

            ratio = SequenceMatcher(None, normalized_brand, candidate).ratio()
            distance = _levenshtein_distance(normalized_brand, candidate)
            is_lookalike = distance <= 1 and len(normalized_brand) >= 4
            if is_lookalike:
                ratio = max(ratio, 0.9)

            if ratio >= settings.certstream_lookalike_similarity and ratio > best_score:
                best_score = ratio
                best_brand = brand.title()

    return best_brand, best_score


def _infer_country(domain: str) -> tuple[str, str]:
    host = domain.lower().lstrip("*.")
    tld = host.split(".")[-1] if "." in host else ""
    if tld in TLD_COUNTRY_MAP:
        return TLD_COUNTRY_MAP[tld]

    digest = hashlib.md5(host.encode("utf-8")).hexdigest()
    idx = int(digest[:2], 16) % len(COUNTRIES)
    return COUNTRIES[idx]


def _build_payload(message: dict) -> dict | None:
    if message.get("message_type") != "certificate_update":
        return None
    data = message.get("data", {})
    leaf_cert = data.get("leaf_cert", {})
    all_domains = leaf_cert.get("all_domains", [])
    if not all_domains:
        return None

    for raw_domain in all_domains:
        domain = str(raw_domain).lower().lstrip("*.")
        brand, score = _find_brand_match(domain)
        if not brand:
            continue

        country, country_code = _infer_country(domain)
        confidence = min(99, max(80, int(score * 100)))
        return {
            "type": "threat_event",
            "source": "certstream",
            "indicator_type": "domain",
            "indicator_value": domain,
            "category": "Typosquatting",
            "country": country,
            "country_code": country_code,
            "brand_target": brand,
            "attack_type": "Phishing Infrastructure Prep",
            "primary_target": f"{brand} identities",
            "volume": random.randint(5, 40),
            "ato_hits": random.randint(0, 2),
            "confidence": confidence,
            "event_meta": {
                "tags": ["certstream", "ct-log", "lookalike-domain"],
                "issuer": leaf_cert.get("issuer", {}).get("O", "unknown"),
                "cert_index": data.get("cert_index"),
            },
            "occurred_at": data.get("seen"),
        }
    return None


async def run(once: bool = False, max_events: int = 0) -> None:
    if not settings.certstream_enabled:
        print("CertStream worker disabled. Set CERTSTREAM_ENABLED=true to enable.")
        return

    try:
        queue_client = redis_client()
        queue_client.ping()
    except Exception as exc:
        print(f"Redis connection failed: {exc}")
        print("Start Redis (or docker compose) before running certstream worker.")
        return

    print(f"CertStream worker started. Queue={settings.raw_event_queue}")
    emitted = 0
    backoff = 1

    while True:
        try:
            async with websockets.connect(
                settings.certstream_ws_url,
                ping_interval=20,
                ping_timeout=20,
                close_timeout=10,
            ) as ws:
                print(f"Connected to {settings.certstream_ws_url}")
                backoff = 1
                async for raw_message in ws:
                    try:
                        message = json.loads(raw_message)
                    except json.JSONDecodeError:
                        continue
                    payload = _build_payload(message)
                    if not payload:
                        continue

                    queue_client.lpush(settings.raw_event_queue, json.dumps(payload))
                    emitted += 1
                    print(f"Enqueued CertStream event #{emitted}: {payload['indicator_value']}")

                    if once:
                        return
                    if max_events and emitted >= max_events:
                        return
        except Exception as exc:
            print(f"CertStream connection error: {exc}")
            if once:
                return
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, settings.certstream_reconnect_max_seconds)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LRX Radar CertStream ingestion worker")
    parser.add_argument("--once", action="store_true", help="Exit after first matched event")
    parser.add_argument("--max-events", type=int, default=0, help="Exit after N matched events")
    args = parser.parse_args()
    asyncio.run(run(once=args.once, max_events=args.max_events))
