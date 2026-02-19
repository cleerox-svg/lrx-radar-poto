import argparse
import json
import random
import time

import httpx

from app.config import settings
from workers.common import (
    generate_ato_event,
    generate_dmarc_report,
    generate_threat_event,
    redis_client,
)


URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


def push_event(client, payload: dict) -> None:
    client.lpush(settings.raw_event_queue, json.dumps(payload))


def maybe_pull_live_urls(max_items: int = 3) -> list[dict]:
    if not settings.live_feed_enabled:
        return []
    try:
        response = httpx.post(URLHAUS_ENDPOINT, timeout=10.0)
        response.raise_for_status()
        data = response.json()
    except Exception:
        return []

    urls = data.get("urls", [])
    if not urls:
        return []

    sampled = random.sample(urls, k=min(max_items, len(urls)))
    events = []
    for item in sampled:
        domain = item.get("url", "http://unknown.local")
        events.append(
            {
                "type": "threat_event",
                "source": "urlhaus",
                "indicator_type": "url",
                "indicator_value": domain,
                "category": "Phishing URL",
                "country": random.choice(["United States", "Germany", "India", "Brazil"]),
                "country_code": random.choice(["US", "DE", "IN", "BR"]),
                "brand_target": "Unknown",
                "attack_type": "Malware Delivery",
                "primary_target": "Endpoint Users",
                "volume": random.randint(10, 60),
                "ato_hits": random.randint(0, 3),
                "confidence": random.randint(78, 95),
                "event_meta": {"tags": ["urlhaus", "malware-feed"]},
                "occurred_at": item.get("date_added"),
            }
        )
    return events


def run(once: bool = False) -> None:
    try:
        client = redis_client()
        client.ping()
    except Exception as exc:
        print(f"Redis connection failed: {exc}")
        print("Start Redis (or docker compose) before running producer.")
        return
    print(f"Producer connected. Queue={settings.raw_event_queue}")
    while True:
        events = [generate_threat_event(), generate_ato_event(), generate_dmarc_report()]
        events.extend(maybe_pull_live_urls())
        for payload in events:
            push_event(client, payload)
        print(f"Enqueued {len(events)} events")
        if once:
            break
        time.sleep(settings.producer_loop_sleep_seconds)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LRX Radar ingestion producer")
    parser.add_argument("--once", action="store_true", help="Run one enqueue cycle and exit")
    args = parser.parse_args()
    run(once=args.once)
