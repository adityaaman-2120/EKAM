# CLAUDE.md — ULPF Project Context

This file is the persistent context for this project. Read it before starting work.

## Project

**ULPF — Universal Log Pre-processing Framework**

- Event: Smart India Hackathon 2026
- Problem Statement: **26156**
- Sponsor: NTRO (National Technical Research Organisation)
- Theme: Blockchain & Cybersecurity

## Goal

Ingest perimeter network device logs (firewalls, IDS/IPS, proxies, VPN, WAF,
routers, flow logs) in **any format**, then:

1. Preserve the raw event **losslessly** with a cryptographic hash.
2. Parse it.
3. Normalize it into the **OCSF schema**.
4. Make it queryable and ML-ready.

The whole system must be deployable as an **air-gapped container**.

## Scope Rule

**Perimeter network devices ONLY.** Firewalls, IDS/IPS, proxies, VPN, WAF,
routers, and flow logs are in scope. Do **not** add endpoint / Windows / Sysmon
parsing, or any other host-level log source.

## Requirements the code must satisfy

| ID | Requirement |
|----|-------------|
| a | Preserve complete raw event data without information loss |
| b | Extract and parse source-specific attributes |
| c | Normalize fields into a common event taxonomy (OCSF) |
| d | Maintain traceability between normalized and original events |
| e | Plug-and-play onboarding of new log sources |
| f | Unified visibility across sources |
| g | Efficient SIEM and data lake integration |
| h | AI/ML-ready analytics |
| i | Reduced parser development effort |
| j | Deployable in an air-gapped network |
| k | Packaged in a container |

## Tech Stack

- **Language:** Python 3.11
- **Async:** asyncio
- **API:** FastAPI
- **Validation / models:** Pydantic v2
- **Columnar storage:** pyarrow / Parquet
- **Embedded analytics:** DuckDB
- **Analytical database:** ClickHouse
- **Log template mining:** Drain3
- **Frontend:** React + Vite + Tailwind
- **Orchestration:** Docker Compose

## Engineering Rules

- Type hints on **every** function. Docstrings on **every** public function.
- **No global mutable state.** Dependency-inject config.
- Every module gets a matching test file under `tests/`.
- **Never drop an event silently.** Unparseable events go to the dead-letter queue.
- **Never modify the raw event. It is evidence.**
- All timestamps stored internally as **UTC epoch nanoseconds**.
- **No network calls at runtime in the hot path** (air-gap requirement).
- Keep functions under **50 lines**. Split when longer.
