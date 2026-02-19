# LRX Radar V6 - Working App + DB + Workers

This repository now contains a runnable LRX Radar platform with:

- **Frontend:** `lrx_radar_v6.html` (Alpine.js + Tailwind + Chart.js)
- **API:** FastAPI backend (`/api/dashboard`, `/api/health`)
- **Database:** PostgreSQL (Docker) or SQLite fallback (local)
- **Queue:** Redis
- **Workers:** producer + processor + CertStream + DMARC mailbox ingestion

## Architecture

1. **Producer worker** (`workers/producer.py`)
   - Simulates live threat feeds (CertStream-style, ATO signals, DMARC reports)
   - Optionally pulls URLhaus feed if `LIVE_FEED_ENABLED=true`
   - Pushes events into Redis list queue

2. **Processor worker** (`workers/processor.py`)
   - Reads from Redis queue
   - Deduplicates/upserts threat events
   - Persists ATO and DMARC events
   - Auto-creates high-confidence alerts

3. **CertStream worker** (`workers/certstream.py`)
   - Connects to real CertStream WebSocket feed
   - Filters certificate updates for monitored brand lookalikes
   - Pushes matched events into Redis queue

4. **DMARC mailbox worker** (`workers/dmarc_mailbox.py`)
   - Polls IMAP mailbox for DMARC report emails
   - Parses XML/XML.GZ/ZIP attachments
   - Emits normalized DMARC report events into Redis queue

5. **API service** (`app/main.py`)
   - Reads and aggregates data from DB
   - Exposes unified dashboard payload for the frontend
   - Exposes campaign-correlation and orchestrator payload endpoints
   - Serves `lrx_radar_v6.html` at `/`

## Quick Start (Docker Compose)

```bash
cp .env.example .env
docker compose up --build
```

Then open:

- Dashboard: `http://localhost:8000`
- API health: `http://localhost:8000/api/health`
- API dashboard JSON: `http://localhost:8000/api/dashboard`
- Correlated campaigns: `http://localhost:8000/api/campaigns`

## Local Start (without Docker)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

In another terminal (with Redis running locally):

```bash
python -m workers.producer
python -m workers.processor
```

Optional workers:

```bash
# real certstream ingestion
CERTSTREAM_ENABLED=true python -m workers.certstream

# mailbox ingestion
DMARC_IMAP_ENABLED=true DMARC_IMAP_HOST=... DMARC_IMAP_USERNAME=... DMARC_IMAP_PASSWORD=... python -m workers.dmarc_mailbox
```

You can also run profile-scoped workers in compose:

```bash
docker compose --profile feeds up --build
docker compose --profile mail up --build
```

> Local default DB is SQLite (`lrx_radar.db`) unless `DATABASE_URL` is set.

## Important Files

- `lrx_radar_v6.html` - V6 merged dashboard landing on **Threat Heatmap**
- `app/models.py` - database schema (threats, alerts, ATO, DMARC, clients)
- `app/services.py` - ingestion/upsert logic + dashboard aggregations
- `app/campaigns.py` - campaign correlation + orchestrator payload builders
- `workers/producer.py` - feed generator / feeder
- `workers/processor.py` - queue consumer / DB writer
- `workers/certstream.py` - real CertStream WebSocket worker
- `workers/dmarc_mailbox.py` - DMARC mailbox parser worker
- `docker-compose.yml` - full stack orchestration

## New API Endpoints

- `GET /api/campaigns?hours=48&limit=20`
  - Returns correlated multi-signal phishing/ATO campaigns.
- `GET /api/campaigns/{campaign_id}`
  - Returns a specific campaign record.
- `GET /api/campaigns/{campaign_id}/orchestrator-payloads`
  - Returns generated payloads for:
    - Proofpoint blocklist API
    - Takedown/DRP incident API
    - Okta workflow invoke API
- `POST /api/campaigns/{campaign_id}/orchestrate?dry_run=true`
  - Dry-run by default. If `dry_run=false` and credentials are set, sends payloads.
- `GET /api/campaigns/{campaign_id}/evidence/dmarc`
  - Returns DMARC evidence rows used for campaign correlation.
