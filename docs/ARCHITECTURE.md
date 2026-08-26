# Architecture

## Layers

```
┌─────────────────────────────────────────────────────────────┐
│  Interfaces:  CLI (Typer)   REST API (FastAPI)   Dashboard  │
├─────────────────────────────────────────────────────────────┤
│  Services:    project/target/scan management, exports       │
├─────────────────────────────────────────────────────────────┤
│  Engine:      pipeline · context · normalization ·          │
│               correlation · scoring · scope · profiles      │
├─────────────────────────────────────────────────────────────┤
│  Plugins:     adapters per stage (crtsh, dns, http, nmap,   │
│               tech-heuristic, …) behind ReconAdapter        │
├─────────────────────────────────────────────────────────────┤
│  Persistence: SQLAlchemy models → PostgreSQL (SQLite tests) │
└─────────────────────────────────────────────────────────────┘
```

The engine depends only on its own abstractions (`ScanContext`,
`ReconAdapter`); the API depends on the engine and services; plugins depend on
nothing but their interface. Adding a tool never touches the engine.

## Scan lifecycle

1. `POST /projects/{id}/scans` inserts a scan row with status `queued`.
2. The worker claims the oldest queued scan (atomic UPDATE … WHERE status=queued)
   and runs `engine.pipeline.run_scan`.
3. The pipeline resolves the profile into an ordered stage list.
4. Authorized targets are seeded as assets. For each stage:
   - adapters run with bounded concurrency via `gather_adapters`
   - one failing adapter is recorded; the stage continues; the scan can end
     `PARTIAL` instead of `FAILED`
   - normalized context items are persisted with dedup + scope classification
5. `_finalize`: correlation builds relationships, scoring annotates every
   asset with score + reasons, stats + hostname diff vs the previous scan are
   stored, terminal status set (`completed` / `partial` / `stopped`).

### Stop semantics

`POST /scans/{id}/stop` sets `stop_requested`. Queued scans become `stopped`
immediately; running scans stop between stages.

## Scope enforcement points

| Point | Enforcement |
|---|---|
| Discovery | all findings stored with `scope_status` (IN_SCOPE / OUT_OF_SCOPE / UNKNOWN) |
| Active stages | nmap gate: IP must be IN_SCOPE **and** no associated hostname may be DENY'd |
| Default | UNKNOWN assets are never actively scanned |

## Data model

See `backend/models/entities.py`. Key tables: `projects`, `targets`,
`scope_rules`, `assets` (unique per project+type+value), `services`,
`dns_records`, `technologies`, `findings`, `relationships`, `scans`,
`scan_tasks`.

JSON columns (`assets.extra_data`) hold genuinely semi-structured evidence
(HTTP headers, TLS metadata, source attribution); everything queryable is a
real column or relation.

## Correlation

`engine/correlation.py` rebuilds the relationship set from normalized data:

- subdomain/domain → closest known parent (`SUBDOMAIN_OF`)
- A/AAAA records → `RESOLVES_TO` (creates IP links)
- CNAME records → `CNAME_TO`
- URLs → `HOSTS_URL`

Shared infrastructure (multiple hostnames → same IP) is exposed at
`GET /projects/{id}/infrastructure/shared` and feeds the hub-asset scoring
signal. The graph endpoint expands relationships (+ services/technologies)
into nodes/edges JSON rendered by the dashboard.

## Scoring

`engine/scoring.py` applies weighted signals — public resolution, uncommon
ports, dev/staging indicators, live HTTP, multiple technologies, shared-infra
hub, novelty — minus a penalty when evidence is low-confidence only. Every
point is justified by a reason object stored alongside the score. This ranks
*investigation priority*, it does not assert vulnerabilities.

## Job system

MVP uses a PostgreSQL-backed queue polled by the worker process. The contract
is one function (`run_scan(session_factory, scan_id)`), so swapping in Celery
or RQ later requires only a new worker entry point.

## Extensibility roadmap hooks (not implemented)

Continuous monitoring = scheduled scan creation + diff stats (already stored).
AI analysis layer = read-only consumption of normalized tables/graph API.
New OSINT providers = new `subdomain`-stage adapter registration.
