import argparse
import email
import gzip
import imaplib
import io
import json
import time
import zipfile
from datetime import datetime, timezone
from email import policy
from pathlib import Path
from typing import Iterable
from xml.etree import ElementTree

from app.config import settings
from workers.common import redis_client


def _extract_xml_documents(name: str, data: bytes) -> list[bytes]:
    lower_name = name.lower()
    docs: list[bytes] = []

    if lower_name.endswith(".xml"):
        docs.append(data)
    elif lower_name.endswith(".gz") or lower_name.endswith(".gzip"):
        try:
            docs.append(gzip.decompress(data))
        except OSError:
            return []
    elif lower_name.endswith(".zip"):
        try:
            with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
                for member in archive.infolist():
                    if member.filename.lower().endswith(".xml"):
                        docs.append(archive.read(member.filename))
        except zipfile.BadZipFile:
            return []
    elif lower_name.endswith(".eml"):
        docs.extend(_extract_xml_from_email(data))

    return docs


def _extract_xml_from_email(raw_email: bytes) -> list[bytes]:
    try:
        message = email.message_from_bytes(raw_email, policy=policy.default)
    except Exception:
        return []

    documents: list[bytes] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        filename = part.get_filename() or "attachment.xml"
        content_type = (part.get_content_type() or "").lower()
        if (
            "xml" in content_type
            or filename.lower().endswith(".xml")
            or filename.lower().endswith(".zip")
            or filename.lower().endswith(".gz")
            or filename.lower().endswith(".gzip")
            or filename.lower().endswith(".eml")
        ):
            documents.extend(_extract_xml_documents(filename, payload))
    return documents


def _safe_text(node: ElementTree.Element | None, path: str, default: str = "") -> str:
    if node is None:
        return default
    value = node.findtext(path)
    if value is None:
        return default
    stripped = value.strip()
    return stripped if stripped else default


def _report_date_from_root(root: ElementTree.Element) -> str:
    date_end = _safe_text(root, "report_metadata/date_range/end")
    if date_end.isdigit():
        timestamp = datetime.fromtimestamp(int(date_end), tz=timezone.utc)
        return timestamp.date().isoformat()
    return datetime.now(timezone.utc).date().isoformat()


def _parse_dmarc_xml(xml_bytes: bytes) -> list[dict]:
    try:
        root = ElementTree.fromstring(xml_bytes)
    except ElementTree.ParseError:
        return []

    report_date = _report_date_from_root(root)
    reporting_org = _safe_text(root, "report_metadata/org_name", "unknown")
    domain = _safe_text(root, "policy_published/domain", "unknown.local")

    records = []
    for record in root.findall("record"):
        source_ip = _safe_text(record, "row/source_ip", "0.0.0.0")
        disposition = _safe_text(record, "row/policy_evaluated/disposition", "none")
        spf_result = _safe_text(record, "row/policy_evaluated/spf", "fail")
        dkim_result = _safe_text(record, "row/policy_evaluated/dkim", "fail")
        count_raw = _safe_text(record, "row/count", "1")
        try:
            msg_count = int(count_raw)
        except ValueError:
            msg_count = 1

        payload = {
            "type": "dmarc_report",
            "domain": domain,
            "reporting_org": reporting_org,
            "source_ip": source_ip,
            "disposition": disposition,
            "spf_result": spf_result,
            "dkim_result": dkim_result,
            "msg_count": msg_count,
            "report_date": report_date,
            "raw_payload": {
                "source": "dmarc-mailbox",
                "identifier_header_from": _safe_text(record, "identifiers/header_from", domain),
            },
        }
        records.append(payload)

    return records


def _enqueue_reports(queue_client, reports: Iterable[dict]) -> int:
    total = 0
    for report in reports:
        queue_client.lpush(settings.raw_event_queue, json.dumps(report))
        total += 1
    return total


def _process_local_drop_dir(queue_client) -> int:
    if not settings.dmarc_local_drop_dir:
        return 0

    drop_dir = Path(settings.dmarc_local_drop_dir)
    if not drop_dir.exists() or not drop_dir.is_dir():
        return 0

    processed = 0
    for file_path in sorted(drop_dir.glob("*")):
        if not file_path.is_file():
            continue
        marker = f"file:{file_path.resolve()}:{file_path.stat().st_mtime_ns}"
        if queue_client.sismember(settings.dmarc_imap_processed_set, marker):
            continue

        raw_bytes = file_path.read_bytes()
        docs = _extract_xml_documents(file_path.name, raw_bytes)
        if not docs and file_path.suffix.lower() == ".xml":
            docs = [raw_bytes]

        for xml_doc in docs:
            processed += _enqueue_reports(queue_client, _parse_dmarc_xml(xml_doc))

        queue_client.sadd(settings.dmarc_imap_processed_set, marker)
    return processed


def _process_imap_mailbox(queue_client) -> int:
    if not settings.dmarc_imap_enabled:
        return 0
    if not settings.dmarc_imap_host or not settings.dmarc_imap_username:
        print("DMARC IMAP enabled but credentials/host are missing.")
        return 0

    created = 0
    with imaplib.IMAP4_SSL(settings.dmarc_imap_host, settings.dmarc_imap_port) as mailbox:
        mailbox.login(settings.dmarc_imap_username, settings.dmarc_imap_password)
        mailbox.select(settings.dmarc_imap_folder)
        status, response = mailbox.search(None, settings.dmarc_imap_search_query)
        if status != "OK":
            return 0

        message_ids = response[0].split()
        for msg_id in message_ids:
            uid = msg_id.decode("utf-8")
            marker = f"imap:{settings.dmarc_imap_host}:{settings.dmarc_imap_folder}:{uid}"
            if queue_client.sismember(settings.dmarc_imap_processed_set, marker):
                continue

            status, payload = mailbox.fetch(msg_id, "(RFC822)")
            if status != "OK":
                continue

            raw_message = b""
            for row in payload:
                if isinstance(row, tuple):
                    raw_message += row[1]

            for xml_doc in _extract_xml_from_email(raw_message):
                created += _enqueue_reports(queue_client, _parse_dmarc_xml(xml_doc))

            queue_client.sadd(settings.dmarc_imap_processed_set, marker)
    return created


def run(once: bool = False) -> None:
    if not settings.dmarc_imap_enabled and not settings.dmarc_local_drop_dir:
        print("DMARC mailbox worker disabled. Set DMARC_IMAP_ENABLED=true or DMARC_LOCAL_DROP_DIR.")
        return

    try:
        queue_client = redis_client()
        queue_client.ping()
    except Exception as exc:
        print(f"Redis connection failed: {exc}")
        print("Start Redis (or docker compose) before running DMARC mailbox worker.")
        return

    print(f"DMARC mailbox worker started. Queue={settings.raw_event_queue}")
    while True:
        total_reports = 0
        try:
            total_reports += _process_local_drop_dir(queue_client)
            total_reports += _process_imap_mailbox(queue_client)
        except Exception as exc:
            print(f"DMARC mailbox worker error: {exc}")

        print(f"DMARC mailbox cycle complete. Enqueued reports: {total_reports}")
        if once:
            break
        time.sleep(settings.dmarc_imap_poll_seconds)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LRX Radar DMARC mailbox ingestion worker")
    parser.add_argument("--once", action="store_true", help="Run one mailbox scan and exit")
    args = parser.parse_args()
    run(once=args.once)
