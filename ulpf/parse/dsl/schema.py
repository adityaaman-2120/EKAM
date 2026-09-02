"""The YAML source-definition language (Pydantic v2 models).

Dropping a ``*.yaml`` file describing a new perimeter log source into the
sources directory is the entire onboarding step (requirement *e*). This module
defines what that file may contain. It is a **public interface** — field names,
enums, and structure are a compatibility surface — so:

* every model forbids unknown keys (``extra="forbid"``) so a typo is a loud,
  located error rather than a silently ignored setting;
* enums are ``Literal`` so an invalid value lists the allowed set;
* regexes and ``from``/``type`` combinations are checked at load time, not first
  use.

Sections of a :class:`SourceDefinition`:

* ``detect``    — a :class:`DetectRule` tree deciding whether a line is this source.
* ``parse``     — envelope handling + which engine + its options.
* ``normalize`` — the OCSF class/category/activity and field mappings.
* ``validate``  — which OCSF fields must be present, and what to do if not.

:func:`json_schema` exports the whole thing as JSON Schema for editor validation
and CI linting of the YAML files.
"""

from __future__ import annotations

from typing import Any, Literal

import regex
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

DSL_SCHEMA_VERSION = "1.0"

_ENVELOPES = Literal["none", "syslog"]
_ENGINES = Literal["json", "kv", "csv", "dissect", "grok", "cef", "leef", "tsv"]
_FIELD_TYPES = Literal["str", "int", "float", "bool", "ip", "timestamp"]
_ON_FAILURE = Literal["dead_letter", "warn"]
_DETECT_KEYS = ("contains", "regex", "starts_with", "all", "any", "field_equals")


class _Model(BaseModel):
    """Base config for every DSL model: reject unknown keys, allow field names."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class FieldEquals(_Model):
    """Match when an already-parsed field equals a value: ``{name, value}``."""

    name: str = Field(min_length=1)
    value: Any


class DetectRule(_Model):
    """One detection rule. Exactly one of the alternatives must be set.

    * ``contains``     — substring test on the raw line.
    * ``regex``        — regular expression search on the raw line.
    * ``starts_with``  — prefix test on the raw line.
    * ``all``          — every child rule must match.
    * ``any``          — at least one child rule must match.
    * ``field_equals`` — a parsed field equals a value.
    """

    contains: str | None = None
    regex: str | None = None
    starts_with: str | None = None
    all: list[DetectRule] | None = None
    any: list[DetectRule] | None = None
    field_equals: FieldEquals | None = None

    @field_validator("regex")
    @classmethod
    def _regex_compiles(cls, value: str | None) -> str | None:
        """Reject a pattern that will not compile."""
        if value is None:
            return value
        try:
            regex.compile(value)
        except regex.error as exc:
            raise ValueError(f"invalid regex: {exc}") from None
        return value

    @model_validator(mode="after")
    def _exactly_one_alternative(self) -> DetectRule:
        """Require exactly one rule alternative to be present."""
        present = [key for key in _DETECT_KEYS if getattr(self, key) is not None]
        if len(present) != 1:
            raise ValueError(
                "a detect rule must set exactly one of "
                + "/".join(_DETECT_KEYS)
                + f"; got {present or 'none'}"
            )
        for combinator in ("all", "any"):
            children = getattr(self, combinator)
            if children is not None and not children:
                raise ValueError(f"'{combinator}' must contain at least one rule")
        return self


class ParseSpec(_Model):
    """How to turn a matched line into a flat field dict."""

    envelope: _ENVELOPES = "none"
    engine: _ENGINES
    options: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _engine_needs_pattern(self) -> ParseSpec:
        """``grok``/``dissect`` are unusable without ``options.pattern``."""
        if self.engine in ("grok", "dissect"):
            pattern = self.options.get("pattern")
            if not isinstance(pattern, str) or not pattern.strip():
                raise ValueError(f"engine '{self.engine}' requires a non-empty options.pattern")
        return self


class FieldMapping(_Model):
    """One OCSF output field, built from one or more parsed source fields."""

    from_: str | list[str] = Field(alias="from")
    type: _FIELD_TYPES = "str"
    map: dict[str, Any] | None = None
    default: Any = None
    format: str | None = None
    tz: str | None = None
    required: bool = False

    @model_validator(mode="after")
    def _shape(self) -> FieldMapping:
        """Validate ``from`` is non-empty and ``format``/``tz`` fit the type."""
        if isinstance(self.from_, list):
            if not self.from_ or any(not item.strip() for item in self.from_):
                raise ValueError("'from' list must be non-empty with non-blank entries")
        elif not self.from_.strip():
            raise ValueError("'from' must be a non-empty string")
        if self.type != "timestamp" and (self.format is not None or self.tz is not None):
            raise ValueError("'format' and 'tz' only apply to type: timestamp")
        return self


class ActivityFromSpec(_Model):
    """Derive ``activity_id`` from a parsed field via a lookup map."""

    from_: str = Field(alias="from", min_length=1)
    map: dict[str, int]
    default: int | None = None


class OcsfSpec(_Model):
    """The normalization target: an OCSF class plus how to fill it."""

    class_uid: int
    category_uid: int
    activity_id: int | ActivityFromSpec
    fields: dict[str, FieldMapping] = Field(default_factory=dict)
    constants: dict[str, Any] = Field(default_factory=dict)
    unmapped: Literal["keep_all", "drop"] | list[str] = "drop"


class ValidateSpec(_Model):
    """Post-normalization checks."""

    required: list[str] = Field(default_factory=list)
    on_failure: _ON_FAILURE = "dead_letter"


class SourceDefinition(_Model):
    """A complete perimeter-log source definition (one YAML file)."""

    name: str
    version: str = Field(min_length=1)
    vendor: str = Field(min_length=1)
    product: str = Field(min_length=1)
    product_version: str = Field(min_length=1)
    detect: DetectRule
    parse: ParseSpec
    normalize: OcsfSpec
    # YAML key is ``validate``; the attribute is ``validation`` to avoid shadowing
    # ``pydantic.BaseModel``'s legacy ``validate``.
    validation: ValidateSpec = Field(default_factory=ValidateSpec, alias="validate")
    enabled: bool = True
    priority: int = 100  # match order across sources; lower is tried first

    @field_validator("name")
    @classmethod
    def _name_is_slug(cls, value: str) -> str:
        """``name`` is used as a filename and as ``source_type`` — keep it a slug."""
        if not regex.match(r"^[a-z0-9][a-z0-9_-]*$", value):
            raise ValueError("source name must be a lowercase slug of [a-z0-9_-]")
        return value


# Resolve the self-reference in DetectRule.
DetectRule.model_rebuild()
SourceDefinition.model_rebuild()


def json_schema() -> dict[str, Any]:
    """Return the JSON Schema for a source-definition YAML file."""
    schema = SourceDefinition.model_json_schema()
    schema["title"] = "ULPF Source Definition"
    schema["$comment"] = f"ULPF source-definition DSL v{DSL_SCHEMA_VERSION}"
    return schema


def load_source_definition(data: dict[str, Any]) -> SourceDefinition:
    """Validate a parsed-YAML mapping into a :class:`SourceDefinition`.

    Raises ``pydantic.ValidationError`` whose messages name the offending path.
    """
    return SourceDefinition.model_validate(data)
