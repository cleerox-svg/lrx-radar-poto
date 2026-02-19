import argparse
import json
from contextlib import suppress

from sqlalchemy.exc import IntegrityError

from app.config import settings
from app.database import Base, SessionLocal, engine
from app.services import create_alert_if_needed, insert_ato_event, insert_dmarc_report, upsert_threat_event
from workers.common import redis_client


def process_payload(payload: dict) -> None:
    event_type = payload.get("type")
    db = SessionLocal()
    try:
        if event_type == "threat_event":
            threat = upsert_threat_event(db, payload)
            db.flush()
            create_alert_if_needed(db, threat)
        elif event_type == "ato_event":
            insert_ato_event(db, payload)
        elif event_type == "dmarc_report":
            insert_dmarc_report(db, payload)
        else:
            return
        db.commit()
    except IntegrityError:
        db.rollback()
    except Exception as exc:
        db.rollback()
        print(f"Processor error: {exc}")
    finally:
        db.close()


def run(once: bool = False) -> None:
    Base.metadata.create_all(bind=engine)
    try:
        client = redis_client()
        client.ping()
    except Exception as exc:
        print(f"Redis connection failed: {exc}")
        print("Start Redis (or docker compose) before running processor.")
        return
    print(f"Processor listening. Queue={settings.raw_event_queue}")

    while True:
        message = client.brpop(settings.raw_event_queue, timeout=5)
        if not message:
            if once:
                break
            continue

        _, raw_payload = message
        with suppress(json.JSONDecodeError):
            payload = json.loads(raw_payload)
            process_payload(payload)

        if once:
            break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LRX Radar ingestion processor")
    parser.add_argument("--once", action="store_true", help="Process at most one event and exit")
    args = parser.parse_args()
    run(once=args.once)
