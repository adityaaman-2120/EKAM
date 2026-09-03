#!/usr/bin/env bash
#
# bench/tamper_demo.sh — the tamper-evidence demo shown in the video.
#
# It:
#   1. verifies the signed integrity ledger over a DEMO COPY of the bronze store
#      (`ulpf verify chain` + `ulpf verify events`) — all green;
#   2. warns loudly, then backs the demo store up;
#   3. flips exactly one byte inside one randomly-chosen stored raw event, and
#      prints which event_uid it picked;
#   4. re-runs `ulpf verify events` — now RED, naming that exact event_uid;
#   5. restores the file from the backup and re-verifies — green again.
#
# SAFETY
#   * Every `ulpf` call is pinned, via ULPF_* env vars, to data/runtime/demo/.
#     The script never reads or writes the real data/runtime/{bronze,ledger,...}.
#   * It REFUSES to run unless data/runtime/demo/ already exists — you opt in:
#         mkdir -p data/runtime/demo
#   * An EXIT/INT/TERM trap restores the demo store if the run is interrupted.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$REPO_ROOT"

DEMO_REL="data/runtime/demo"

# ---------------------------------------------------------------- colours
if [[ -t 1 ]]; then
  BOLD=$'\e[1m'; DIM=$'\e[2m'; RED=$'\e[31m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; RESET=$'\e[0m'
else
  BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; RESET=""
fi
rule() { printf '%s\n' "${DIM}────────────────────────────────────────────────────────────────────────${RESET}"; }

# ---------------------------------------------------------- safety gate
if [[ ! -d "$DEMO_REL" ]]; then
  echo "${RED}${BOLD}REFUSING TO RUN${RESET}: ${DEMO_REL}/ does not exist." >&2
  echo "This demo only ever touches a disposable copy of the evidence store." >&2
  echo "Create the demo directory first (it is gitignored):" >&2
  echo "    ${BOLD}mkdir -p ${DEMO_REL}${RESET}" >&2
  exit 2
fi

DEMO_ABS="$(cd "$DEMO_REL" && pwd -P)"
EXPECTED_ABS="$(cd "$REPO_ROOT/data/runtime" && pwd -P)/demo"
if [[ "$DEMO_ABS" != "$EXPECTED_ABS" ]]; then
  echo "${RED}${BOLD}REFUSING TO RUN${RESET}: ${DEMO_REL} resolves to ${DEMO_ABS}," >&2
  echo "which is not ${EXPECTED_ABS}. Not touching that." >&2
  exit 2
fi

BRONZE_DIR="$DEMO_ABS/bronze"
LEDGER_DIR="$DEMO_ABS/ledger"
KEYS_DIR="$DEMO_ABS/keys"
BACKUP_DIR="$DEMO_ABS/.backup"

# every `ulpf` invocation below is pinned to the demo copy — never the real store
export ULPF_STORAGE__BRONZE_PATH="$BRONZE_DIR"
export ULPF_STORAGE__LEDGER_PATH="$LEDGER_DIR"
export ULPF_INTEGRITY__SIGNING_KEY_PATH="$KEYS_DIR/ulpf_ed25519_private.pem"
export ULPF_INTEGRITY__PUBLIC_KEY_PATH="$KEYS_DIR/ulpf_ed25519_public.pem"
export ULPF_PARSE__SOURCES_DIR="$REPO_ROOT/configs/sources"

PY="${PYTHON:-python}"
ULPF=("$PY" -m ulpf.cli.main)

# ------------------------------------------------------- restore-on-exit
BACKUP_MADE=0
restore_demo() {
  if [[ "$BACKUP_MADE" -eq 1 && -d "$BACKUP_DIR/bronze" ]]; then
    echo "${DIM}(restoring demo bronze store from backup)${RESET}"
    rm -rf "$BRONZE_DIR"
    cp -a "$BACKUP_DIR/bronze" "$BRONZE_DIR"
    rm -rf "$BACKUP_DIR"
  fi
}
trap restore_demo EXIT INT TERM

# --------------------------------------------------- seed the demo copy
if ! compgen -G "$BRONZE_DIR/date=*/events.ndjson.gz" > /dev/null; then
  echo "${DIM}Seeding a fresh demo dataset under ${DEMO_REL}/ (synthetic RFC 5737 events)…${RESET}"
  "$PY" - <<'PY'
from pathlib import Path

from ulpf.config.settings import get_settings
from ulpf.integrity.hashing import make_raw_event
from ulpf.integrity.index import IntegrityIndex
from ulpf.integrity.ledger import IntegrityLedger
from ulpf.integrity.signing import Signer, generate_keypair
from ulpf.sinks.raw_store import RawStore

s = get_settings()
key = Path(s.integrity.signing_key_path)
if not key.is_file():
    generate_keypair(key.parent)

lines = [
    (
        f'<189>date=2026-09-04 time=09:{i // 60:02d}:{i % 60:02d} devname="FGT-demo" '
        f'logid="0000000013" type="traffic" subtype="forward" '
        f"srcip=192.0.2.{i % 254 + 1} srcport={20000 + i} "
        f"dstip=198.51.100.{i % 254 + 1} dstport=443 proto=6 "
        f'action="{"deny" if i % 5 == 0 else "accept"}" policyid=9 '
        f"sentbyte={100 + i} rcvdbyte={200 + i}"
    ).encode()
    for i in range(40)
]

store = RawStore(s)
events = [make_raw_event(line, source_id="demo", transport="udp") for line in lines]
for event in events:
    store.write(event)
store.flush()

ledger = IntegrityLedger(s, Signer.load(key))
index = IntegrityIndex(Path(s.storage.ledger_path) / "event_index.sqlite")
batch = 10
for start in range(0, len(events), batch):
    chunk = events[start : start + batch]
    uids = [e.event_uid for e in chunk]
    entry = ledger.append_batch([bytes.fromhex(e.raw_hash) for e in chunk], event_uids=uids)
    index.add_batch(entry.seq, uids)
index.close()
print(f"  seeded {len(events)} events in {len(events) // batch} sealed batches")
PY
fi

# =====================================================================
# 1. baseline verification — expect all green
# =====================================================================
rule
echo "${BOLD}Running integrity verification…${RESET}   ${DIM}(demo copy: ${DEMO_REL}/)${RESET}"
rule
"${ULPF[@]}" verify chain
"${ULPF[@]}" verify events
echo "${GREEN}${BOLD}✔ baseline: ledger intact, every stored event verified${RESET}"

# =====================================================================
# 2. deliberate corruption — with a loud warning + a backup
# =====================================================================
rule
echo "${YELLOW}${BOLD}⚠  ABOUT TO DELIBERATELY CORRUPT ONE STORED RAW EVENT  ⚠${RESET}"
echo "${YELLOW}   This edits ONE byte of ONE event inside ${DEMO_REL}/bronze/.${RESET}"
echo "${YELLOW}   A backup is taken first and restored at the end — real data is never touched.${RESET}"
rule
rm -rf "$BACKUP_DIR"
mkdir -p "$BACKUP_DIR"
cp -a "$BRONZE_DIR" "$BACKUP_DIR/bronze"
BACKUP_MADE=1
echo "${DIM}backup: ${BACKUP_DIR#$REPO_ROOT/}/bronze${RESET}"

# =====================================================================
# 3. flip exactly one byte in one randomly-chosen event
# =====================================================================
VICTIM_UID="$(
  "$PY" - <<'PY'
import base64
import gzip
import json
import random
import sys
from pathlib import Path

from ulpf.config.settings import get_settings

bronze = Path(get_settings().storage.bronze_path)
partitions = sorted(bronze.glob("date=*/events.ndjson.gz"))

records: list[tuple[Path, dict]] = []
for partition in partitions:
    with gzip.open(partition, "rb") as handle:
        for line in handle:
            if line.strip():
                records.append((partition, json.loads(line)))
if not records:
    sys.exit("no events in the demo bronze store")

rng = random.Random()  # unseeded: a genuinely random pick each run
target_file, target = rng.choice(records)

raw = bytearray(base64.b64decode(target["raw_b64"]))
offset = rng.randrange(len(raw))
before = raw[offset]
raw[offset] ^= 0xFF  # flip exactly one byte; raw_hash is left unchanged
target["raw_b64"] = base64.b64encode(bytes(raw)).decode("ascii")

by_file: dict[Path, list[dict]] = {}
for partition, record in records:
    by_file.setdefault(partition, []).append(record)
with gzip.open(target_file, "wb") as handle:  # rewrite only the affected partition
    for record in by_file[target_file]:
        handle.write((json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode())

sys.stderr.write(
    f"  picked event : {target['event_uid']}\n"
    f"  in partition : {target_file.parent.name}/{target_file.name}\n"
    f"  flipped byte : offset {offset} of {len(raw)}  "
    f"(0x{before:02x} -> 0x{raw[offset]:02x})\n"
)
print(target["event_uid"])
PY
)"
echo "${BOLD}Corrupted event_uid: ${RED}${VICTIM_UID}${RESET}"

# =====================================================================
# 4. re-verify — expect RED, naming the corrupted event
# =====================================================================
rule
echo "${BOLD}Re-running \`ulpf verify events\`…${RESET}"
rule
set +e
"${ULPF[@]}" verify events
EVENTS_RC=$?
set -e
if [[ "$EVENTS_RC" -eq 0 ]]; then
  echo "${RED}${BOLD}x UNEXPECTED: verification passed after corruption${RESET}" >&2
  exit 1
fi
# `verify events` exits 1 on a failure; capture its JSON without tripping set -e
EVENTS_JSON="$("${ULPF[@]}" verify events --json || true)"
if ! grep -q "$VICTIM_UID" <<<"$EVENTS_JSON"; then
  echo "${RED}${BOLD}x UNEXPECTED: the failure report did not name ${VICTIM_UID}${RESET}" >&2
  exit 1
fi
echo "${RED}${BOLD}x tamper detected — verification FAILED and named ${VICTIM_UID}${RESET}"

# =====================================================================
# 5. restore from backup and re-verify — green again
# =====================================================================
rule
echo "${BOLD}Restoring from backup and re-verifying…${RESET}"
rule
restore_demo
BACKUP_MADE=0
trap - EXIT INT TERM
"${ULPF[@]}" verify chain
"${ULPF[@]}" verify events
echo "${GREEN}${BOLD}✔ restored: ledger intact, every stored event verified again${RESET}"
rule
echo "${GREEN}${BOLD}Tamper-evidence demo complete.${RESET}"
