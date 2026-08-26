# Development guide

## Requirements

- Python ≥ 3.11, Node ≥ 18
- PostgreSQL 14+ (tests use in-memory SQLite)
- nmap binary for the ports stage (optional for development)

## Setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cd frontend && npm install && cd ..
```

Configuration is environment-based (prefix `RECONPULSE_`), see
`backend/core/config.py`. Minimum for local dev:

```
RECONPULSE_DATABASE_URL=postgresql+psycopg2://reconpulse:reconpulse@localhost:5432/reconpulse
```

## Running

```bash
alembic upgrade head          # create/migrate schema
reconpulse-api                # FastAPI on :8000 (/docs for OpenAPI)
reconpulse-worker             # scan consumer
cd frontend && npm run dev    # Vite dev server on :5173 (proxies /api)
```

## Tests

```bash
pytest                        # unit + integration, SQLite, no network
ruff check .                  # lint
```

Integration tests use fake adapters (see `tests/test_pipeline.py`) and mocked
`execute()` calls; external tools are never invoked by the test suite.

## Migrations

The initial revision creates the schema from metadata so models cannot drift
during MVP. Later changes: edit `entities.py`, then generate and review a
handwritten revision:

```bash
alembic revision -m "add x"
```

## Project layout

```
backend/    api routes, core config/logging, database session,
            ORM models, Pydantic schemas
engine/     pipeline, context, normalization, correlation, scoring,
            scope, profiles
plugins/    ReconAdapter base + registry + one package per stage
cli/        Typer CLI
workers/    scan consumer process
services/   export/report generation
frontend/   React + TS dashboard
tests/      pytest suite + fixtures of representative tool output
docker/     Dockerfiles + nginx config
```

## Conventions

- Type hints everywhere; small focused modules.
- No comments unless explaining *why*.
- Structured logging via `log_event(logger, level, event, **ctx)`; never log
  secrets or raw credentials.
- Errors in one module must not crash the scan — fail the module, record it.
