# ReconPulse

> **Know your target before you attack.**

ReconPulse is a modular reconnaissance and attack-surface discovery platform for
**authorized** penetration testers, bug-bounty hunters (where testing is
permitted), CTF players, and lab environments.

Give ReconPulse an authorized target and an explicit scope; it orchestrates
reconnaissance capabilities, normalizes their output, correlates the results,
and presents a prioritized, queryable map of the attack surface.

It is **not** an exploitation framework — there are no exploitation,
credential, persistence, or evasion capabilities by design.

---

## Features (MVP)

- **Projects / targets / explicit scope** (`ALLOW`/`DENY` wildcards + CIDR;
  deny wins; out-of-scope assets are never actively scanned)
- **Pipeline orchestration** with profiles:
  - `quick`: subdomain → dns → http
  - `standard`: + ports → technology
  - `full`: same stages as standard (extend via config)
- **Adapters** (pluggable):
  | Stage | Adapter | Kind |
  |---|---|---|
  | subdomain | crt.sh (Certificate Transparency) | passive HTTP |
  | dns | dnspython resolver (A/AAAA/CNAME/MX/NS/TXT) | active |
  | http | httpx probe (status/title/headers/TLS) | active |
  | ports | nmap (argument-array exec, XML parsing) | active |
  | technology | heuristic evidence analyzer | passive |
- **Normalization & deduplication** of all tool output into a relational model
- **Correlation engine**: `SUBDOMAIN_OF`, `RESOLVES_TO`, `CNAME_TO`,
  `HOSTS_URL`, shared-infrastructure detection
- **Transparent priority scoring** with per-reason justification (not severity!)
- **REST API** (FastAPI/OpenAPI), **CLI**, **worker process**
- **Web dashboard** (React/TS): stats, priority queue, scan history with
  new/removed diffs, SVG attack-surface graph, scope management
- **Exports**: JSON / CSV / Markdown / HTML
- **PostgreSQL persistence** with Alembic migrations
- **Structured JSON logging** bound to scan IDs
- **Partial-failure tolerant scans** (a failing module degrades to PARTIAL)

## Architecture

```
CLI / Web UI ──► REST API ──► PostgreSQL ◄──── Worker
                                  │              │ runs pipeline:
                                  │ claims scans │ subdomain → dns → http
                                  │              │ → ports → technology
                        normalization + correlation + scoring
```

See [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick start (Docker)

```bash
docker compose up --build
# Dashboard:   http://localhost:8080
# API docs:    http://localhost:8000/docs
```

Then in the dashboard: create a project → add your authorized target → start a
scan. Or use the CLI against the same database.

## Quick start (local development)

```bash
# 1. Database
docker run -d --name reconpulse-db -p 5432:5432 \
  -e POSTGRES_USER=reconpulse -e POSTGRES_PASSWORD=reconpulse \
  -e POSTGRES_DB=reconpulse postgres:16-alpine

# 2. Backend + CLI
python -m venv .venv && .venv\Scripts\activate    # Linux: source .venv/bin/activate
pip install -e ".[dev]"
export RECONPULSE_DATABASE_URL=postgresql+psycopg2://reconpulse:reconpulse@localhost:5432/reconpulse
alembic upgrade head

# 3. Run API and worker (two terminals)
reconpulse-api
reconpulse-worker

# 4. Frontend
cd frontend && npm install && npm run dev         # http://localhost:5173
```

## CLI usage

```bash
reconpulse project create acme
reconpulse target add acme example.com
reconpulse scope add acme --rule-type DENY admin.example.com
reconpulse scan start acme --profile standard [--wait]
reconpulse scan list acme
reconpulse asset list acme --min-score 40
reconpulse asset show acme api.example.com
reconpulse finding list acme
reconpulse report export acme --output report.html
reconpulse scope check acme dev.example.com     # how would this be classified?
```

## Plugin architecture

Adding a tool = one adapter class, no engine changes:

```python
from plugins.base import ReconAdapter
from plugins.registry import register

@register
class SubfinderAdapter(ReconAdapter):
    stage = "subdomain"
    requires_binary = True
    def name(self): return "subfinder"
    def check_installation(self): return shutil.which("subfinder") is not None
    async def run(self, ctx):
        for host in self.discover(ctx.inputs["targets"]):
            ctx.add_hostname(host, source=self.name())
        ...
```

Details: [PLUGIN_DEVELOPMENT.md](docs/PLUGIN_DEVELOPMENT.md).

## Screenshots

| Dashboard | Attack surface graph |
|---|---|
| _(placeholder — run `docker compose up` and visit :8080)_ | _(placeholder)_ |

## Legal / authorized use

You are responsible for ensuring you have **explicit authorization** before
scanning any target. ReconPulse enforces project scope as configured, but it
cannot obtain permission for you. Unauthorized scanning may be illegal in your
jurisdiction. The software is provided under the MIT license without warranty.

## Docs

- [ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [DEVELOPMENT.md](docs/DEVELOPMENT.md)
- [PLUGIN_DEVELOPMENT.md](docs/PLUGIN_DEVELOPMENT.md)
- [API.md](docs/API.md)
- [SECURITY.md](docs/SECURITY.md)
