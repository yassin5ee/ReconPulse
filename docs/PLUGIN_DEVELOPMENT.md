# Plugin development

ReconPulse never hard-codes external tools. Every capability is an adapter
implementing `ReconAdapter` (`plugins/base.py`):

```python
class ReconAdapter(ABC):
    stage: ClassVar[str]              # "subdomain" | "dns" | "http" | "ports" | "technology"
    requires_binary: ClassVar[bool]   # skip gracefully when the binary is missing

    def name(self) -> str: ...
    def version(self) -> str: ...                       # recorded for reproducibility
    def check_installation(self) -> bool: ...
    async def run(self, ctx: ScanContext) -> AdapterResult: ...
```

For wrappers around external binaries, implement the full conceptual interface
inside your adapter (see `plugins/ports/nmap_adapter.py` as the reference):

- `build_command(targets, profile) -> list[str]` — **argument array only**,
  never a shell string; targets arrive scope-validated
- `execute(cmd)` — subprocess with hard timeout, output size cap and a
  controlled environment (`PATH` restricted)
- `parse_output(raw) -> list[dict]` — tolerant parsing (tool error pages are a
  normal occurrence)

## Emitting normalized data

Adapters push into `ScanContext`; the pipeline persists with dedup + scoping:

```python
ctx.add_hostname("api.example.com", source="subfinder")
ctx.add_ip("1.2.3.4", hostname="api.example.com", source=self.name())
ctx.add_dns_record(host, "CNAME", target)
ctx.add_service(host="1.2.3.4", port=8443, service_name="https")
ctx.add_http_result(url=..., status_code=..., headers={...}, ...)
ctx.add_technology(host, "nginx", version="1.24", confidence=0.5, source=...)
```

Normalization is applied by the context (hostnames lowercased, IPs validated,
URLs canonicalized), so adapters can pass raw tool values.

## Registering

```python
from plugins.registry import register

@register
class SubfinderAdapter(ReconAdapter):
    stage = "subdomain"
    requires_binary = True
    ...

```

The registry maps stage → adapters. Scan config can pass per-adapter options:

```json
{ "adapters": { "ports": { "nmap": { "extra_args": ["--max-rate", "50"] } } } }
```

## Rules of thumb

- **Never** actively probe anything not confirmed IN_SCOPE via
  `ctx.scope.allows_active_scan(value)`.
- One adapter failure must never raise out of `run()` — return an
  `AdapterResult(success=False, error=...)`; `gather_adapters` also catches.
- Attribute every emitted item with its `source`.
- Confidence values are honest estimates; weak evidence stays < 0.5 (the
  scorer penalizes assets supported only by low-confidence evidence).
- Add representative fixtures + parser tests under `tests/fixtures/`.
