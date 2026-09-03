"""ATT&CK tagger — annotate a record with MITRE ATT&CK techniques.

Loads ``configs/attack_map.yaml`` (path from
``settings.enrich.attack_map_path``): a list of ``rules``, each mapping a
condition pattern to one or more ATT&CK technique IDs. A rule's ``when:`` block
may test the **Suricata category**, a **Suricata signature substring**, an
**OCSF class + action** combination, the **destination port** (exact set or
range), an outbound byte threshold, and the connection direction — every
condition present must match (AND).

On one or more rule hits the enricher adds::

    {"attack": {"technique_ids": ["T1110", ...],
                "technique_names": ["Brute Force", ...],
                "tactics": ["credential-access", ...]}}

Technique names and tactics come from :data:`_BUNDLED_TECHNIQUES` — a static,
in-repo lookup — so **no network access** is ever needed (air-gap safe). The map
file may add or override entries via a top-level ``techniques:`` block.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ulpf.config.settings import Settings

_log = logging.getLogger(__name__)

# ATT&CK tactics in kill-chain order, for stable output sorting.
_TACTIC_ORDER = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
)

# Static technique_id -> (name, tactics). Bundled so lookups never touch the
# network. Extend via the map file's `techniques:` block.
_BUNDLED_TECHNIQUES: dict[str, tuple[str, tuple[str, ...]]] = {
    "T1046": ("Network Service Discovery", ("discovery",)),
    "T1595": ("Active Scanning", ("reconnaissance",)),
    "T1110": ("Brute Force", ("credential-access",)),
    "T1133": ("External Remote Services", ("persistence", "initial-access")),
    "T1190": ("Exploit Public-Facing Application", ("initial-access",)),
    "T1210": ("Exploitation of Remote Services", ("lateral-movement",)),
    "T1071": ("Application Layer Protocol", ("command-and-control",)),
    "T1571": ("Non-Standard Port", ("command-and-control",)),
    "T1090": ("Proxy", ("command-and-control",)),
    "T1219": ("Remote Access Software", ("command-and-control",)),
    "T1041": ("Exfiltration Over C2 Channel", ("exfiltration",)),
    "T1048": ("Exfiltration Over Alternative Protocol", ("exfiltration",)),
    "T1021": ("Remote Services", ("lateral-movement",)),
    "T1498": ("Network Denial of Service", ("impact",)),
}


@dataclass(frozen=True)
class TechniqueInfo:
    """Display name and ATT&CK tactics for one technique ID."""

    name: str
    tactics: tuple[str, ...]


@dataclass(frozen=True)
class AttackRule:
    """One ``rules:`` entry: an AND of conditions -> technique IDs."""

    rule_id: str
    technique_ids: tuple[str, ...]
    tactics: tuple[str, ...] = ()  # explicit override, merged with bundled tactics
    class_uid: int | None = None
    actions: frozenset[str] = frozenset()
    dst_ports: frozenset[int] = frozenset()
    dst_port_min: int | None = None
    dst_port_max: int | None = None
    min_bytes_out: int | None = None
    direction: str | None = None
    suricata_categories: tuple[str, ...] = ()
    signature_substrings: tuple[str, ...] = ()

    def has_condition(self) -> bool:
        """Whether this rule tests anything at all (an empty ``when:`` never fires)."""
        return any(
            (
                self.class_uid is not None,
                self.actions,
                self.dst_ports,
                self.dst_port_min is not None,
                self.dst_port_max is not None,
                self.min_bytes_out is not None,
                self.direction is not None,
                self.suricata_categories,
                self.signature_substrings,
            )
        )

    def matches(self, view: _RecordView) -> bool:
        """True when every condition present on this rule is satisfied by ``view``."""
        if not self.has_condition():
            return False
        if self.class_uid is not None and view.class_uid != self.class_uid:
            return False
        if self.actions and (view.action is None or view.action not in self.actions):
            return False
        if self.dst_ports and (view.dst_port is None or view.dst_port not in self.dst_ports):
            return False
        if not _in_range(view.dst_port, self.dst_port_min, self.dst_port_max):
            return False
        if self.min_bytes_out is not None and (
            view.bytes_out is None or view.bytes_out < self.min_bytes_out
        ):
            return False
        if self.direction is not None and view.direction != self.direction:
            return False
        if self.suricata_categories and not any(
            cat in view.categories for cat in self.suricata_categories
        ):
            return False
        if self.signature_substrings and (
            view.signature is None
            or not any(sub in view.signature for sub in self.signature_substrings)
        ):
            return False
        return True


@dataclass
class _RecordView:
    """The handful of record facts the rules test, extracted once per event."""

    class_uid: int | None
    action: str | None
    dst_port: int | None
    bytes_out: int | None
    direction: str | None
    signature: str | None
    categories: list[str] = field(default_factory=list)


class AttackMap:
    """The loaded rule set plus the technique-name lookup."""

    def __init__(
        self, rules: list[AttackRule], techniques: dict[str, TechniqueInfo] | None = None
    ) -> None:
        """Take parsed rules and an optional technique-lookup override layer."""
        self.rules = tuple(rules)
        self.techniques: dict[str, TechniqueInfo] = {
            tid: TechniqueInfo(name, tactics)
            for tid, (name, tactics) in _BUNDLED_TECHNIQUES.items()
        }
        if techniques:
            self.techniques.update(techniques)

    @classmethod
    def from_yaml(cls, path: str | Path) -> AttackMap:
        """Load from ``attack_map.yaml``; empty (no-op) rule set if the file is absent."""
        file = Path(path)
        if not file.is_file():
            _log.warning(
                "attack_tagger: map file %s not found; enricher active but tags nothing", file
            )
            return cls([])
        document = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
        rules = [
            rule
            for raw in document.get("rules") or []
            if (rule := _parse_rule(raw)) is not None
        ]
        return cls(rules, _parse_techniques(document.get("techniques") or {}))

    def tag(self, record: dict[str, Any]) -> dict[str, Any]:
        """Return ``{"attack": {...}}`` for the matching rules, or ``{}``."""
        view = _build_view(record)
        technique_ids: set[str] = set()
        tactics: set[str] = set()
        for rule in self.rules:
            if not rule.matches(view):
                continue
            technique_ids.update(rule.technique_ids)
            tactics.update(rule.tactics)
        if not technique_ids:
            return {}

        ordered_ids = sorted(technique_ids)
        names: list[str] = []
        for tid in ordered_ids:
            info = self.techniques.get(tid)
            names.append(info.name if info else tid)
            if info:
                tactics.update(info.tactics)
        return {
            "attack": {
                "technique_ids": ordered_ids,
                "technique_names": names,
                "tactics": sorted(tactics, key=_tactic_sort_key),
            }
        }


class AttackTagger:
    """Enricher that maps record conditions to MITRE ATT&CK techniques."""

    name = "attack_tagger"

    def __init__(self, attack_map: AttackMap) -> None:
        """Wrap a loaded :class:`AttackMap`."""
        self._map = attack_map

    @classmethod
    def from_settings(cls, settings: Settings) -> AttackTagger:
        """Build from ``settings.enrich.attack_map_path``."""
        return cls(AttackMap.from_yaml(settings.enrich.attack_map_path))

    @property
    def attack_map(self) -> AttackMap:
        """The loaded rule set (for introspection)."""
        return self._map

    def describe(self) -> dict[str, Any]:
        """Readiness summary for the /health endpoint."""
        rules = len(self._map.rules)
        return {"ready": rules > 0, "detail": f"{rules} rules, {len(self._map.techniques)} techniques"}

    def enrich(self, record: dict[str, Any]) -> dict[str, Any]:
        """Return ``{"attack": {...}}`` on a rule hit, else ``{}``."""
        return self._map.tag(record)


# -- parsing ----------------------------------------------------------------


def _parse_rule(raw: Any) -> AttackRule | None:
    """Turn one ``rules:`` mapping into an :class:`AttackRule`; skip if malformed."""
    if not isinstance(raw, dict):
        return None
    try:
        when = raw.get("when") or {}
        ports = when.get("dst_ports") or []
        actions = when.get("actions") or ([when["action"]] if "action" in when else [])
        return AttackRule(
            rule_id=str(raw.get("id", "unnamed")),
            technique_ids=tuple(str(t).strip() for t in raw["technique_ids"]),
            tactics=tuple(str(t).strip().lower() for t in raw.get("tactics") or []),
            class_uid=_opt_int(when.get("class_uid")),
            actions=frozenset(str(a).strip().lower() for a in actions),
            dst_ports=frozenset(int(p) for p in ports),
            dst_port_min=_opt_int(when.get("dst_port_min")),
            dst_port_max=_opt_int(when.get("dst_port_max")),
            min_bytes_out=_opt_int(when.get("min_bytes_out")),
            direction=_opt_lower(when.get("direction")),
            suricata_categories=tuple(
                str(c).strip().lower() for c in when.get("suricata_categories") or []
            ),
            signature_substrings=tuple(
                str(s).strip().lower() for s in when.get("suricata_signature_contains") or []
            ),
        )
    except (KeyError, TypeError, ValueError) as exc:
        _log.error("attack_tagger: skipping malformed rule %r: %s", raw.get("id"), exc)
        return None


def _parse_techniques(raw: Any) -> dict[str, TechniqueInfo]:
    """Parse the optional ``techniques:`` override block."""
    out: dict[str, TechniqueInfo] = {}
    if not isinstance(raw, dict):
        return out
    for tid, spec in raw.items():
        if not isinstance(spec, dict):
            continue
        out[str(tid)] = TechniqueInfo(
            name=str(spec.get("name", tid)),
            tactics=tuple(str(t).strip().lower() for t in spec.get("tactics") or []),
        )
    return out


# -- record extraction ----------------------------------------------------


def _build_view(record: dict[str, Any]) -> _RecordView:
    """Pull the fields the rules test out of one OCSF record."""
    dst = record.get("dst_endpoint")
    traffic = record.get("traffic")
    conn = record.get("connection_info")
    return _RecordView(
        class_uid=_opt_int(record.get("class_uid")),
        action=_opt_lower(record.get("action")),
        dst_port=_opt_int(dst.get("port")) if isinstance(dst, dict) else None,
        bytes_out=_opt_int(traffic.get("bytes_out")) if isinstance(traffic, dict) else None,
        direction=_opt_lower(conn.get("direction")) if isinstance(conn, dict) else None,
        signature=_signature(record),
        categories=_categories(record),
    )


def _signature(record: dict[str, Any]) -> str | None:
    """The Suricata rule message: ``finding_info.title`` or ``unmapped['alert.signature']``."""
    finding = record.get("finding_info")
    unmapped = record.get("unmapped") or {}
    for candidate in (
        finding.get("title") if isinstance(finding, dict) else None,
        unmapped.get("alert.signature"),
    ):
        if isinstance(candidate, str) and candidate:
            return candidate.lower()
    return None


def _categories(record: dict[str, Any]) -> list[str]:
    """Every Suricata category string on the record, lower-cased."""
    values: list[str] = []
    finding = record.get("finding_info")
    if isinstance(finding, dict):
        types = finding.get("types")
        if isinstance(types, str):
            values.append(types)
        elif isinstance(types, list):
            values.extend(item for item in types if isinstance(item, str))
    unmapped = record.get("unmapped") or {}
    for key in ("alert.category", "category"):
        if isinstance(unmapped.get(key), str):
            values.append(unmapped[key])
    return [value.lower() for value in values]


# -- small helpers -------------------------------------------------------


def _in_range(value: int | None, low: int | None, high: int | None) -> bool:
    """True unless a bound is set and ``value`` is missing or outside it."""
    if low is None and high is None:
        return True
    if value is None:
        return False
    return (low is None or value >= low) and (high is None or value <= high)


def _tactic_sort_key(tactic: str) -> tuple[int, str]:
    """Sort tactics in kill-chain order, unknown ones last (alphabetical)."""
    return (_TACTIC_ORDER.index(tactic), "") if tactic in _TACTIC_ORDER else (len(_TACTIC_ORDER), tactic)


def _opt_int(value: Any) -> int | None:
    """``int(value)`` when possible, else ``None`` (bools rejected)."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _opt_lower(value: Any) -> str | None:
    """Lower-cased string, or ``None``."""
    return value.strip().lower() if isinstance(value, str) and value.strip() else None
