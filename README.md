# LRX Radar V6 - Working App + DB + Workers

This repository now contains a runnable LRX Radar platform with:

- **Frontend:** `lrx_radar_v6.html` (Alpine.js + Tailwind + Chart.js)
- **API:** FastAPI backend (`/api/dashboard`, `/api/health`)
- **Database:** PostgreSQL (Docker) or SQLite fallback (local)
- **Queue:** Redis
- **Workers:** producer + processor ingestion pipeline

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

3. **API service** (`app/main.py`)
   - Reads and aggregates data from DB
   - Exposes unified dashboard payload for the frontend
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

> Local default DB is SQLite (`lrx_radar.db`) unless `DATABASE_URL` is set.

## Important Files

- `lrx_radar_v6.html` - V6 merged dashboard landing on **Threat Heatmap**
- `app/models.py` - database schema (threats, alerts, ATO, DMARC, clients)
- `app/services.py` - ingestion/upsert logic + dashboard aggregations
- `workers/producer.py` - feed generator / feeder
- `workers/processor.py` - queue consumer / DB writer
- `docker-compose.yml` - full stack orchestration
