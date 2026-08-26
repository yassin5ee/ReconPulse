# Security

ReconPulse executes external security tooling; the execution path is treated
as a security-sensitive subsystem.

## Command execution hardening

- External tools are launched with **subprocess argument arrays** —
  `shell=True` is never used and no command strings are assembled from
  untrusted input.
- Targets passed to tools are scope-validated and normalized before use;
  nmap targets are appended after a `--` separator.
- **Hard process timeouts** kill hung tools (`RECONPULSE_TOOL_TIMEOUT`, default 300s).
- **Output size caps** (`max_output_bytes`) protect against runaway output.
- Controlled environment for child processes (restricted `PATH`), safe temp
  handling, no inherited secrets in worker images.
- The web UI cannot invoke arbitrary commands; it can only create scans whose
  behavior is determined by server-side profiles and validated config.

## Scope as a safety boundary

- Every asset is classified `IN_SCOPE` / `OUT_OF_SCOPE` / `UNKNOWN`.
  DENY rules always win over ALLOW rules.
- Active stages only touch assets explicitly IN_SCOPE; UNKNOWN is treated as
  out of scope for active probing.
- The nmap gate additionally excludes IPs whose *associated hostnames* are
  DENY'd.

## Secrets & data hygiene

- No API keys are hardcoded; provider credentials belong in environment
  configuration, never in project data or reports.
- Structured logs contain values/hosts and module outcomes only. Never pass
  credentials to logging calls.
- Reports export reconnaissance data only.

## Known MVP limitations

- No authentication/RBAC yet: bind the API to localhost or an internal network
  when deploying. Authentication is on the roadmap.
- Worker runs sequentially; resource limits per scan are coarse (timeouts +
  output caps).
- `extra_args` adapter options are operator-supplied configuration from
  trusted sources (CLI/config file), not end-user input.

## Reporting a vulnerability

Open a private advisory / contact the maintainers directly. Do not open a
public issue for exploitable findings.
