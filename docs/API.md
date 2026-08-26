# API reference

Interactive OpenAPI docs ship with the app at `/docs`. Base URL: `/`.

## Projects, targets & scope

| Method | Path | Description |
|---|---|---|
| POST | `/projects` | create project `{name, description}` |
| GET | `/projects` | list projects |
| GET/PATCH/DELETE | `/projects/{id}` | read/update/delete |
| POST | `/projects/{id}/targets` | add targets `[{"value","target_type"}]`; auto-seeds ALLOW rules |
| GET | `/projects/{id}/targets` | list targets |
| POST | `/projects/{id}/scope` | add scope rules `[{"pattern","rule_type","comment"}]` |
| GET | `/projects/{id}/scope` | list rules |
| DELETE | `/projects/{id}/scope/{rule_id}` | remove rule |

## Scans

| Method | Path | Description |
|---|---|---|
| POST | `/projects/{id}/scans` | queue scan `{profile: quick\|standard\|full\|custom, config}` → 202 |
| GET | `/projects/{id}/scans` | scan history incl. stats + hostname diffs |
| GET | `/scans/{id}` | scan detail |
| GET | `/scans/{id}/tasks` | per-module task status |
| POST | `/scans/{id}/stop` | request stop |

## Results

| Method | Path | Description |
|---|---|---|
| GET | `/projects/{id}/assets` | filters: `asset_type`, `scope_status`, `search`, `min_score`, pagination |
| GET | `/projects/{id}/assets/{asset_id}` | asset detail incl. services/DNS/technologies |
| GET | `/projects/{id}/findings` | findings with `finding_type`, `min_priority` filters |
| GET | `/projects/{id}/graph` | nodes/edges JSON (assets + services + technologies + relationships) |
| GET | `/projects/{id}/infrastructure/shared` | IPs shared by multiple hostnames |
| GET | `/projects/{id}/statistics` | dashboard counters |
| GET | `/projects/{id}/report?format=json\|csv\|markdown\|html` | export report |

## Conventions

- Errors: 404 unknown id, 409 conflict (duplicate project / concurrent scan /
  stopping finished scan), 422 validation.
- All responses validated through Pydantic schemas (`backend/schemas/api.py`).
