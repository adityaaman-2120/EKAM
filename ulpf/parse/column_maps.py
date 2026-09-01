"""Named positional column maps for delimited logs, keyed by ``(product, version)``.

PAN-OS (and several other appliances) writes its logs as headerless CSV where a
field's *meaning is its position*. Palo Alto **adds and reorders fields between
releases** — e.g. PAN-OS 11.0 inserts ``tunnel_inspection_rule`` into the
TRAFFIC log right after ``rule_name`` and appends more fields at the end, which
shifts roughly thirty downstream columns by one. A single map would therefore
mislabel most fields on one of the two versions, so maps are keyed by
``(product, version)`` and a source must declare which version it is running.

The lists below are the common TRAFFIC-log ordering, abbreviated for the
reference implementation; the authoritative full field lists are in the PAN-OS
Administrator's Guide "Syslog Field Descriptions".
"""

from __future__ import annotations

_PANOS_TRAFFIC_10_1: list[str] = [
    "future_use_1", "receive_time", "serial_number", "type", "threat_content_type",
    "future_use_2", "generated_time", "src_ip", "dst_ip", "nat_src_ip",
    "nat_dst_ip", "rule_name", "src_user", "dst_user", "app",
    "vsys", "src_zone", "dst_zone", "ingress_interface", "egress_interface",
    "log_action", "future_use_3", "session_id", "repeat_count", "src_port",
    "dst_port", "nat_src_port", "nat_dst_port", "flags", "protocol",
    "action", "bytes", "bytes_sent", "bytes_received", "packets",
    "start_time", "elapsed_time", "category", "future_use_4", "sequence_number",
    "action_flags", "src_location", "dst_location", "future_use_5", "packets_sent",
    "packets_received", "session_end_reason",
]

# PAN-OS 11.0: `tunnel_inspection_rule` is inserted right after `rule_name`
# (index 11), shifting every later column by one, and three fields are appended.
_PANOS_TRAFFIC_11_0: list[str] = (
    _PANOS_TRAFFIC_10_1[:12]
    + ["tunnel_inspection_rule"]
    + _PANOS_TRAFFIC_10_1[12:]
    + ["link_change_count", "policy_id", "link_switches"]
)

COLUMN_MAPS: dict[tuple[str, str], list[str]] = {
    ("panos_traffic", "10.1"): _PANOS_TRAFFIC_10_1,
    ("panos_traffic", "11.0"): _PANOS_TRAFFIC_11_0,
}


def get_column_map(product: str, version: str) -> list[str]:
    """Return a copy of the column map for ``(product, version)``.

    Raises:
        KeyError: If no map is registered for that product/version pair.
    """
    try:
        return list(COLUMN_MAPS[(product, version)])
    except KeyError:
        raise KeyError(f"no column map for product={product!r} version={version!r}") from None


def list_column_maps() -> list[tuple[str, str]]:
    """Return every registered ``(product, version)`` key, sorted."""
    return sorted(COLUMN_MAPS)
