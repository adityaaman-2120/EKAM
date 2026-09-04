# ULPF — Universal Log Pre-processing Framework

Smart India Hackathon 2026 · Problem Statement 26156 · NTRO · Blockchain & Cybersecurity

Ingest perimeter network device logs (firewalls, IDS/IPS, proxies, VPN, WAF,
routers, flow logs) in any format, preserve the raw event losslessly with a
cryptographic hash, parse it, normalize it into the OCSF schema, and make it
queryable and ML-ready — deployable in an air-gapped container.

See [CLAUDE.md](CLAUDE.md) for full project context, requirements, tech stack,
and engineering rules.

## Prerequisites

- **Python 3.11 exactly** (`>=3.11,<3.12`). The version is pinned via
  `pyproject.toml`, a repo-root `.python-version` file, and CI so local dev and
  air-gapped deployment cannot drift apart. `ulpf run` logs a warning if the
  running interpreter is not 3.11.

## Dev setup

```bash
pip install -e ".[dev]"
pre-commit install     # one-time: runs `ruff format` + `ruff check --fix` on every commit
```

CI enforces the same: a `ruff format --check .` step runs **before** lint and
fails the build on any drift. `make format` fixes it locally; `make
format-check` verifies without writing.

## Target schema

- **OCSF 1.5.0.** Every normalized event is mapped to OCSF 1.5.0 and carries the
  version in `metadata.version`. The pin lives in `ulpf/normalize/ocsf/base.py`
  (`OCSF_VERSION`); change it only together with the class definitions in
  `ulpf/normalize/ocsf/`.

## Adding a new log source

Onboarding a perimeter source is one YAML file in `configs/sources/` — no code,
no restart (the registry hot-reloads). Each file has `detect` (is this line
mine?), `parse` (envelope + engine + options), `normalize` (OCSF class + field
mappings), and `validate`. See `ulpf/parse/dsl/schema.py` for the full schema
and the existing files for worked examples.

**Verify it:** `ulpf sources verify` runs every definition against a sample
fixture and prints a pass/fail table (match, class_uid, validity, completeness,
unmapped count). `ulpf inspect --file <sample>` traces one line end to end.

**When a vendor reorders a positional format between versions** (PAN-OS TRAFFIC
adds/moves CSV columns from 10.x → 11.x), ship one YAML per major version, each
pointing `parse.options.column_map` at the matching map in
`ulpf/parse/column_maps.py`. If the format carries no version field, tell the
two definitions apart in `detect` with a `field_count` rule — the standard
record has a fixed, version-specific column count
(`field_count: {delimiter: ",", equals: 47}`). A custom/truncated log format
then matches neither definition and is dead-lettered rather than silently
decoded with the wrong map. For a fleet that mixes custom formats, the correct
answer is an explicit device→version binding at ingest (not yet wired).

**Field mapping — a list-valued `from:`** has two explicit behaviours:

| form | meaning |
| --- | --- |
| `from: [a, b, c]` (no `join`) | **coalesce** — the first present, non-empty field wins |
| `from: [a, b, c]` + `join: " "` | **concatenate** — every present field, in the listed order, joined by the separator, then coerced as one value |

Use `join` when several fields make one value, e.g. FortiGate's split
`date` + `time` → one `%Y-%m-%d %H:%M:%S` timestamp. `join` is only valid with
a list `from`.

**Encoding:** the decode boundary strips a leading UTF-8/UTF-16 BOM from the
working copy before detection (`ParsedEvent.bom_stripped` records it); the raw
bytes and `raw_hash` keep the BOM as evidence.

## Reprocessing — correcting history instead of losing it

Parsers get bugs, and OCSF mappings get better. Most log pipelines cannot fix
their own past: once a bad mapping has run, the only record of what actually
happened is the flawed derived output. ULPF can, because of three choices made
earlier in the pipeline:

1. **The raw event is preserved losslessly** (requirement a) — every byte
   that arrived is written to the bronze store, hashed, and never modified.
2. **Every derived event stays traceable to its raw source** (requirement d)
   via a content-addressed `event_uid`/`raw_hash` that a reprocess run carries
   through unchanged.
3. **Sources onboard as data, not code** (requirement e) — a YAML fix to a
   `configs/sources/*.yaml` definition (or a new source version) takes effect
   immediately, with no redeploy.

Put together: fix the YAML, then replay the untouched bronze evidence through
the current parse → normalize → enrich → validate → sink chain with
`ulpf reprocess`. It never re-ingests and never re-hashes — the integrity
ledger's signed Merkle leaves for that evidence are untouched, because
reprocessing doesn't mint new evidence, only a corrected interpretation of it.

```bash
# Replay one day's bronze evidence through the current source definitions
ulpf reprocess --date 2026-09-04

# Only one source type
ulpf reprocess --date 2026-09-04 --source-type fortigate_traffic

# Preview counts without writing anything (isolated dead-letter queue too)
ulpf reprocess --date 2026-09-04 --dry-run

# After fixing a parser bug: how many events changed, and did completeness improve?
ulpf reprocess --date 2026-09-04 --source-type fortigate_traffic --compare
```

Each reprocess run writes to the silver tier under a new `mapping_version`
(`<source_version>+reprocess-<run_id>`) so old and new output are always
distinguishable — nothing already written is overwritten or deleted.
`--compare` reads back the previous generation's rows for the same date and
source type and reports how many events changed vs. stayed identical, and how
average OCSF completeness moved between generations.

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
