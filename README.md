# ULPF — Universal Log Pre-processing Framework

Smart India Hackathon 2026 · Problem Statement 26156 · NTRO · Blockchain & Cybersecurity

Ingest perimeter network device logs (firewalls, IDS/IPS, proxies, VPN, WAF,
routers, flow logs) in any format, preserve the raw event losslessly with a
cryptographic hash, parse it, normalize it into the OCSF schema, and make it
queryable and ML-ready — deployable in an air-gapped container.

See [CLAUDE.md](CLAUDE.md) for full project context, requirements, tech stack,
and engineering rules.

## Layout

```
ulpf/        framework package
  config/    settings loading
  core/      shared models, errors, ids, time, logging
  ingest/    listeners and intake
  detect/    format sniffing and routing
  parse/     parse engines
  normalize/ OCSF mapping
  enrich/    geoip, ioc, attack
  integrity/ hashing, merkle, ledger
  sinks/     parquet, duckdb, clickhouse, dlq
  ml/        features and anomaly detection
  api/       FastAPI app
  cli/       command line entrypoints
configs/     global config + one YAML per source
data/        samples/ (synthetic) and runtime/ (gitignored)
tests/       unit tests, golden/, fixtures/
bench/       benchmarks
deploy/      container / compose assets
docs/        documentation
ui/          frontend (empty for now)
```

Status: scaffolding only — no logic implemented yet.
