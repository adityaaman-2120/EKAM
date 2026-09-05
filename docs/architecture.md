# ULPF Architecture

This document describes storage tiers, partitioning, and the small-file /
compaction / reprocessing story. It reflects the actual behavior of the code
under `ulpf/` — where a claim here and a docstring disagree, the code and its
tests are authoritative and this file is out of date.

See [CLAUDE.md](../CLAUDE.md) for the project's scope, requirements, and
engineering rules.

## Pipeline

```
ingest -> RawStoreStage (bronze) -> ParseStage -> NormalizeStage -> EnrichStage
       -> ValidateStage -> SinkManager (silver: Parquet, + ClickHouse/OpenSearch/Splunk)
```

Every stage either returns the (possibly transformed) event or `None` to stop
it; a stage that raises sends the *original* event to the dead-letter queue
tagged with that stage's name (`ulpf/core/pipeline.py`). No event is ever
silently dropped — it is written, dead-lettered, or passed on as
`source_type="unknown"` for later template mining.

## Storage tiers

| Tier | Format | Module | Contains |
|---|---|---|---|
| Bronze | gzipped NDJSON, append-only | `ulpf/sinks/raw_store.py` | The raw bytes, verbatim, plus their SHA-256. Evidence. |
| Silver | Parquet, ZSTD | `ulpf/sinks/parquet_sink.py` | Normalized OCSF events, flattened to columns. Analytics / ML-ready. |
| Dead-letter | `ulpf/sinks/dlq.py` | Every event a stage could not process, with the reason. |

## Partition key semantics — bronze = ingest date, silver = event date

This is the one rule in this document every other section depends on, so it is
stated here explicitly rather than left implicit in two separate docstrings:

> **Bronze partitions by INGEST date. Silver partitions by EVENT date.**

- **Bronze** (`RawStore`, `<bronze_path>/date=YYYY-MM-DD/events.ndjson.gz`)
  partitions by `RawEvent.ingest_time_ns` — the moment ULPF received the byte
  stream. This is evidence: "what did we receive, and when did we receive it"
  is a question about our own system's clock, and it only ever advances
  monotonically with wall-clock time, which is what makes it a stable,
  append-only partition key.
- **Silver** (`ParquetSink`,
  `<silver_path>/date=YYYY-MM-DD/source_type=<name>/part-*.parquet`) partitions
  by the OCSF `time` field on the *normalized* record — i.e. when the
  underlying network activity actually happened, as the source device itself
  reported it (FortiGate's own `date=`/`time=` fields, PAN-OS's own CSV
  timestamp column, and so on). This is analytics: "every deny on 2026-09-04"
  has to mean the 4th by event time, not by whichever day ULPF happened to
  receive the syslog line for it.

**Why this creates a deliberate mismatch.** A source with clock skew, a
delayed forwarder, store-and-forward buffering, or a batch upload can emit an
event whose reported time is days before ULPF ever sees it. That event is
correctly bronze-partitioned under the day it arrived, and correctly
silver-partitioned under the day it says it happened. The two dates
legitimately differ. This is not a defect to reconcile — collapsing them onto
one key would make one of the two tiers answer the wrong question.

**Where this bites: `ulpf reprocess`.** `ulpf reprocess --date D` selects
bronze evidence by *ingest* date `D` and replays it through the current
source definitions. Because the corrected output is written back to silver
under *each event's own* event date, one `--date D` run can write to several
different silver date partitions — none of which need equal `D`. `ulpf
reprocess` prints this explicitly on every run:

```
reading bronze date=2026-09-05  ·  scope all sources  ·  applied
writing silver dates=2026-09-03, 2026-09-04, 2026-09-05
mapping_version tag: reprocess-20260905T120000Z-ab12cd
```

so the operator never has to infer which silver partitions were touched by a
run scoped to a bronze date. See `ulpf/cli/reprocess.py` (module docstring,
section "`--date` IS AN INGEST DATE, NOT AN EVENT DATE") and
`ulpf/sinks/parquet_sink.py` (module docstring, section "PARTITION KEY: EVENT
DATE, NOT INGEST DATE") for the code-level statement of this rule, and
`tests/test_cli_reprocess.py::test_reprocess_writes_to_silver_under_the_event_date_not_the_bronze_date`
for the regression test that pins it down: an event whose event time and
ingest time fall on different days lands in the ingest-date bronze partition
and the event-date silver partition, not the same date in both.

## The small-file problem and compaction

`ParquetSink` flushes on a row-count or time threshold (defaults: 10,000 rows
or 60 seconds), whichever comes first, so that recently-ingested events become
queryable quickly. Over a busy day that is on the order of a thousand flushes
per `(date, source_type)` partition — many small Parquet files, each carrying
its own footer (schema, row-group statistics, column chunk offsets) that a
query engine must open and parse regardless of how little data the file holds.
At scale this dominates query time: I/O becomes bookkeeping, not column reads.

`Compactor` (`ulpf/sinks/compaction.py`) rewrites a partition's
`part-*.parquet` files into a small number of ~128 MB files, preserving every
row and unifying any schema drift between the inputs, then deletes the
originals only after every merged output has been safely renamed into place.
It is idempotent and safe to re-run.

By default, `Compactor` only touches a partition with 2 or more part files
(`min_files=2`) — merging a single file into itself is pure churn on a
healthy partition. `ulpf compact --min-files 1` forces a rewrite even of
single-file partitions, which is useful when demonstrating the merge path
against a small or synthetic dataset where a normal run never produces more
than one file per partition before it ends.

**End-to-end evidence, not just unit coverage of the merge algorithm.**
`tests/test_compaction.py::test_write_then_compact_preserves_every_row_and_event_uid`
drives a real `ParquetSink` (with its flush threshold deliberately lowered) to
produce many real small part files from ordinary writes — reproducing the
actual small-file scenario, not a hand-built `pyarrow.Table` — then runs the
real `Compactor` over them and asserts: the file count dropped, the row count
is identical, and the set of `event_uid`s is unchanged. That is the claim this
document makes about compaction; that test is what backs it.

## Reprocessing

See `ulpf/cli/reprocess.py`'s module docstring and the "Reprocessing" section
of [README.md](../README.md) for the full mechanics (content-addressed
`event_uid`/`raw_hash`, versioned `mapping_version` tags, `--dry-run` and
`--compare`). The one addition this document makes is the partition-key
interaction above: reprocessing reads bronze by ingest date and writes silver
by event date, and the command reports both.
