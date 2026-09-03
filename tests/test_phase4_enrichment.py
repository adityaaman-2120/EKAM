"""Phase-4 integration: normalize -> enrich -> validate for one FortiGate event.

One deny event whose source IP is a loaded IOC, going from a private asset zone
to a public address, on RDP/3389. The pipeline must emit a valid OCSF record
that carries a threat-intel hit, an inferred outbound direction (promoted into
``connection_info``), and a MITRE ATT&CK tag.
"""

from __future__ import annotations

import json
from pathlib import Path

from ulpf.config.settings import EnrichSettings, Settings, StorageSettings
from ulpf.core.models import NormalizedEvent, ParsedEvent
from ulpf.enrich.attack_tagger import AttackMap, AttackTagger
from ulpf.enrich.network_context import NetworkContextEnricher, ZoneMap
from ulpf.enrich.pipeline import EnrichmentPipeline
from ulpf.enrich.stage import EnrichStage
from ulpf.enrich.threat_intel import IndicatorStore, ThreatIntelEnricher
from ulpf.integrity.hashing import make_raw_event
from ulpf.normalize.ocsf.base import finalize
from ulpf.normalize.stage import NormalizeStage, ValidateStage
from ulpf.normalize.validator import OcsfValidator
from ulpf.parse.dsl.loader import SourceRegistry
from ulpf.parse.engines.kv_engine import KvEngine
from ulpf.parse.engines.util import flatten
from ulpf.parse.syslog_envelope import parse_syslog_envelope

_CONFIGS = Path(__file__).parent.parent / "configs"

# type="traffic" + logid= -> matches fortigate_traffic.yaml; action=deny + dst 3389
# -> ATT&CK T1110; 10.10.20.5 (crown-jewels zone) -> 8.8.8.8 -> direction outbound.
_FORTI_LINE = (
    b'<189>date=2026-08-15 time=22:14:15 level="warning" devname="FGT60F" '
    b'devid="FGT60FTK20000001" logid="0000000013" type="traffic" subtype="forward" '
    b"vd=\"root\" srcip=10.10.20.5 srcport=51111 srcintf=\"internal1\" "
    b'dstip=8.8.8.8 dstport=3389 dstintf="wan1" sessionid=104512 proto=6 '
    b'service="RDP" action="deny" policyid=9 sentbyte=0 rcvdbyte=0 sentpkt=1 rcvdpkt=0'
)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        storage=StorageSettings(dlq_path=tmp_path / "dlq", bronze_path=tmp_path / "b"),
        enrich=EnrichSettings(geoip=False),
    )


def _registry(tmp_path: Path) -> SourceRegistry:
    sources = tmp_path / "sources"
    sources.mkdir()
    (sources / "fortigate_traffic.yaml").write_text(
        (_CONFIGS / "sources" / "fortigate_traffic.yaml").read_text("utf-8"), encoding="utf-8"
    )
    registry = SourceRegistry()
    registry.load_all(sources)
    return registry


def _ioc_store(tmp_path: Path) -> IndicatorStore:
    iocs = tmp_path / "iocs"
    iocs.mkdir()
    (iocs / "test_ips.json").write_text(
        json.dumps(
            {"type": "ip", "source": "test-ioc", "confidence": "high", "indicators": ["10.10.20.5"]}
        ),
        encoding="utf-8",
    )
    store = IndicatorStore()
    store.load_all(iocs)
    return store


def _parsed(tmp_path: Path) -> ParsedEvent:
    raw = make_raw_event(_FORTI_LINE, source_id="fgt", transport="udp")
    envelope, message = parse_syslog_envelope(_FORTI_LINE)
    fields = dict(KvEngine().parse(message.decode("utf-8"), {}))
    fields.update(flatten(envelope, prefix="envelope"))
    return ParsedEvent(**raw.model_dump(), format="kv", fields=fields)


async def test_fortigate_deny_event_is_normalized_enriched_and_validated(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    registry = _registry(tmp_path)
    enrichers = [
        NetworkContextEnricher(ZoneMap.from_yaml(_CONFIGS / "assets.yaml")),
        ThreatIntelEnricher(_ioc_store(tmp_path)),
        AttackTagger(AttackMap.from_yaml(_CONFIGS / "attack_map.yaml")),
    ]
    enrich = EnrichmentPipeline(settings, enrichers)
    try:
        normalized = await NormalizeStage(settings, registry).process(_parsed(tmp_path))
        assert isinstance(normalized, NormalizedEvent) and normalized.source_type == "fortigate_traffic"

        enriched = await EnrichStage(settings, enrich).process(normalized)
        validated = await ValidateStage(settings, registry).process(enriched)
    finally:
        enrich.close()

    # the record survived validation
    assert isinstance(validated, NormalizedEvent)
    assert validated is enriched
    assert OcsfValidator(record_metrics=False).validate(validated.ocsf).valid is True

    ocsf, enr = validated.ocsf, validated.enrichment

    # base normalization
    assert ocsf["class_uid"] == 4001
    assert ocsf["src_endpoint"]["ip"] == "10.10.20.5"
    assert ocsf["dst_endpoint"]["port"] == 3389
    assert ocsf["action"] == "Denied"

    # 1. threat-intel hit on the source IP
    assert enr["threat_intel"] == {
        "matched": True,
        "indicator": "10.10.20.5",
        "ioc_type": "ip",
        "ioc_source": "test-ioc",
        "confidence": "high",
        "matched_on": "src_endpoint.ip",
    }

    # 2. network direction inferred (private asset zone -> public) and promoted
    assert enr["network_context"]["direction"] == "outbound"
    assert enr["network_context"]["src_zone"] == "crown-jewels"
    assert ocsf["connection_info"]["direction"] == "Outbound"
    assert ocsf["connection_info"]["direction_id"] == 2

    # 3. ATT&CK tag: brute force on RDP
    assert enr["attack"]["technique_ids"] == ["T1110"]
    assert enr["attack"]["technique_names"] == ["Brute Force"]
    assert "credential-access" in enr["attack"]["tactics"]

    # full fidelity is also on the OCSF record
    assert set(ocsf["enrichments"]) == {"threat_intel", "network_context", "attack"}


async def test_same_event_without_the_ioc_still_normalizes_cleanly(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    registry = _registry(tmp_path)
    enrich = EnrichmentPipeline(
        settings, [NetworkContextEnricher(ZoneMap.from_yaml(_CONFIGS / "assets.yaml"))]
    )
    try:
        normalized = await NormalizeStage(settings, registry).process(_parsed(tmp_path))
        enriched = await EnrichStage(settings, enrich).process(normalized)
        validated = await ValidateStage(settings, registry).process(enriched)
    finally:
        enrich.close()

    assert isinstance(validated, NormalizedEvent)
    assert "threat_intel" not in validated.enrichment
    assert validated.enrichment["network_context"]["direction"] == "outbound"
