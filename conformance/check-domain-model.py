#!/usr/bin/env python3
"""Value-free executable evidence for the public record boundary."""

import re
from collections.abc import Mapping
from pathlib import Path

from strict_json import (
    DuplicateMemberError,
    InvalidJsonSyntaxError,
    InvalidUtf8Error,
    NonFiniteNumberError,
    decode_strict_json,
)

ROOT = Path(__file__).parents[1]
SUPPORTED_EXTENSION_VERSION = "1.0.0"
UNDERSTOOD_REQUIRED_EXTENSIONS: frozenset[str] = frozenset()


class InvalidSerializedEnvelope(ValueError):
    """The serialized input is ambiguous or is not strict JSON."""


class UnsupportedEnvelopeSchemaError(ValueError):
    """The checked-in envelope schema uses a construct this reader cannot enforce."""


def parse_serialized_envelope(serialized: bytes) -> object:
    """Parse one strict JSON value without collapsing duplicate members."""

    try:
        return decode_strict_json(serialized)
    except DuplicateMemberError as exc:
        raise InvalidSerializedEnvelope(f"duplicate JSON member: {exc.member}") from exc
    except NonFiniteNumberError as exc:
        label = (
            "non-JSON constant"
            if exc.value in {"NaN", "Infinity", "-Infinity"}
            else "non-finite JSON number"
        )
        raise InvalidSerializedEnvelope(f"{label}: {exc.value}") from exc
    except InvalidUtf8Error as exc:
        raise InvalidSerializedEnvelope("serialized envelope is not UTF-8") from exc
    except InvalidJsonSyntaxError as exc:
        raise InvalidSerializedEnvelope("serialized envelope is not JSON") from exc


ENVELOPE_SCHEMA = parse_serialized_envelope(
    (ROOT / "contracts/schemas/public-record-envelope-v1.schema.json").read_bytes()
)


_ENVELOPE_SCHEMA_KEYS = {
    "$defs",
    "$id",
    "$ref",
    "$schema",
    "additionalProperties",
    "const",
    "enum",
    "pattern",
    "properties",
    "propertyNames",
    "required",
    "title",
    "type",
}


def _require_supported_envelope_schema(schema: object, location: str = "$") -> None:
    """Audit the small schema subset used by the public envelope.

    This is deliberately not a general JSON Schema implementation. Any keyword
    or type outside the checked-in closed-object/string subset fails closed.
    """

    if not isinstance(schema, dict):
        raise UnsupportedEnvelopeSchemaError(f"{location} is not a schema object")
    unsupported = set(schema) - _ENVELOPE_SCHEMA_KEYS
    if unsupported:
        names = ", ".join(sorted(unsupported))
        raise UnsupportedEnvelopeSchemaError(
            f"unsupported schema keyword at {location}: {names}"
        )
    if "$schema" in schema and schema["$schema"] != (
        "https://json-schema.org/draft/2020-12/schema"
    ):
        raise UnsupportedEnvelopeSchemaError(
            f"unsupported JSON Schema dialect at {location}"
        )
    if "$ref" in schema:
        if set(schema) != {"$ref"} or not isinstance(schema["$ref"], str):
            raise UnsupportedEnvelopeSchemaError(
                f"unsupported reference form at {location}"
            )
        return
    if "type" in schema and schema["type"] not in {"object", "string"}:
        raise UnsupportedEnvelopeSchemaError(f"unsupported schema type at {location}")
    if "pattern" in schema:
        if not isinstance(schema["pattern"], str):
            raise UnsupportedEnvelopeSchemaError(f"non-string pattern at {location}")
        try:
            re.compile(schema["pattern"])
        except re.error as exc:
            raise UnsupportedEnvelopeSchemaError(
                f"invalid pattern at {location}"
            ) from exc
    if "enum" in schema and (
        not isinstance(schema["enum"], list) or not schema["enum"]
    ):
        raise UnsupportedEnvelopeSchemaError(f"invalid enum at {location}")
    if "required" in schema:
        required = schema["required"]
        if (
            not isinstance(required, list)
            or any(not isinstance(name, str) for name in required)
            or len(required) != len(set(required))
        ):
            raise UnsupportedEnvelopeSchemaError(
                f"invalid required members at {location}"
            )
    properties = schema.get("properties", {})
    if not isinstance(properties, dict) or any(
        not isinstance(name, str) for name in properties
    ):
        raise UnsupportedEnvelopeSchemaError(f"invalid properties at {location}")
    for name, child in properties.items():
        _require_supported_envelope_schema(child, f"{location}.properties.{name}")
    if "propertyNames" in schema:
        _require_supported_envelope_schema(
            schema["propertyNames"], f"{location}.propertyNames"
        )
    if "additionalProperties" in schema:
        additional = schema["additionalProperties"]
        if not isinstance(additional, (bool, dict)):
            raise UnsupportedEnvelopeSchemaError(
                f"invalid additionalProperties at {location}"
            )
        if isinstance(additional, dict):
            _require_supported_envelope_schema(
                additional, f"{location}.additionalProperties"
            )
    definitions = schema.get("$defs", {})
    if not isinstance(definitions, dict) or any(
        not isinstance(name, str) for name in definitions
    ):
        raise UnsupportedEnvelopeSchemaError(f"invalid definitions at {location}")
    for name, child in definitions.items():
        _require_supported_envelope_schema(child, f"{location}.$defs.{name}")


def _resolve_envelope_schema_reference(
    reference: str, root_schema: Mapping[str, object]
) -> object:
    prefix = "#/$defs/"
    if not reference.startswith(prefix) or "/" in reference[len(prefix) :]:
        raise UnsupportedEnvelopeSchemaError(
            f"unsupported schema reference: {reference}"
        )
    definitions = root_schema.get("$defs")
    if not isinstance(definitions, dict) or reference[len(prefix) :] not in definitions:
        raise UnsupportedEnvelopeSchemaError(
            f"unresolved schema reference: {reference}"
        )
    return definitions[reference[len(prefix) :]]


def _matches_envelope_schema(
    value: object, schema: Mapping[str, object], root_schema: Mapping[str, object]
) -> bool:
    if "$ref" in schema:
        referenced = _resolve_envelope_schema_reference(
            str(schema["$ref"]), root_schema
        )
        if not isinstance(referenced, dict):
            raise UnsupportedEnvelopeSchemaError("referenced schema is not an object")
        return _matches_envelope_schema(value, referenced, root_schema)
    if "const" in schema and value != schema["const"]:
        return False
    if "enum" in schema and value not in schema["enum"]:  # type: ignore[operator]
        return False
    expected_type = schema.get("type")
    if expected_type == "string" and not isinstance(value, str):
        return False
    if "pattern" in schema and (
        not isinstance(value, str) or re.search(str(schema["pattern"]), value) is None
    ):
        return False
    if expected_type != "object":
        return True
    if not isinstance(value, dict):
        return False
    required = schema.get("required", [])
    if not set(required) <= value.keys():  # type: ignore[arg-type]
        return False
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        raise UnsupportedEnvelopeSchemaError("schema properties are not an object")
    property_names = schema.get("propertyNames")
    if property_names is not None:
        if not isinstance(property_names, dict):
            raise UnsupportedEnvelopeSchemaError("propertyNames is not a schema object")
        if any(
            not _matches_envelope_schema(name, property_names, root_schema)
            for name in value
        ):
            return False
    additional = schema.get("additionalProperties", True)
    for name, child_value in value.items():
        child_schema = properties.get(name)
        if child_schema is None:
            if additional is False:
                return False
            if isinstance(additional, dict) and not _matches_envelope_schema(
                child_value, additional, root_schema
            ):
                return False
            continue
        if not isinstance(child_schema, dict):
            raise UnsupportedEnvelopeSchemaError(f"schema for {name} is not an object")
        if not _matches_envelope_schema(child_value, child_schema, root_schema):
            return False
    return True


def envelope_matches_schema(
    record: object, *, schema: object = ENVELOPE_SCHEMA
) -> bool:
    _require_supported_envelope_schema(schema)
    if not isinstance(schema, dict):
        raise UnsupportedEnvelopeSchemaError("root schema is not an object")
    return _matches_envelope_schema(record, schema, schema)


def extensions_admissible(record: object) -> bool:
    """Apply inert-extension admission rules outside the JSON shape."""

    if not isinstance(record, dict):
        return False
    extensions = record.get("extensions", {})
    if not isinstance(extensions, dict):
        return False
    for name, extension in extensions.items():
        if not isinstance(extension, dict):
            return False
        if extension.get("version") != SUPPORTED_EXTENSION_VERSION:
            return False
        if (
            extension.get("criticality") == "required"
            and name not in UNDERSTOOD_REQUIRED_EXTENSIONS
        ):
            return False
    return True


def envelope_admissible(record: object, *, schema: object = ENVELOPE_SCHEMA) -> bool:
    # No record-family body schemas are supplied. The checked-in schema enforces
    # only that body is an object; this checker does not consume that object.
    return envelope_matches_schema(record, schema=schema) and extensions_admissible(
        record
    )


def load_envelope_fixture(path: Path) -> object:
    try:
        return parse_serialized_envelope(path.read_bytes())
    except OSError as exc:
        raise SystemExit(f"fixture is not readable: {path.name}") from exc


def main() -> None:
    if ENVELOPE_SCHEMA.get("$id") != (
        "https://sacrysty.nisavid.io/schemas/public-record-envelope/v1"
    ):
        raise SystemExit("public-record envelope schema identity mismatch")

    canonical = sorted((ROOT / "fixtures").glob("public-record*.json"))
    if not canonical:
        raise SystemExit("no canonical public-record fixtures found")
    for path in canonical:
        try:
            record = load_envelope_fixture(path)
        except InvalidSerializedEnvelope as exc:
            raise SystemExit(
                f"canonical envelope fixture is not strict JSON: {path.name}"
            ) from exc
        if not envelope_admissible(record):
            raise SystemExit(f"canonical envelope fixture rejected: {path.name}")

    hostile = sorted((ROOT / "fixtures").glob("hostile-public-record-*.json"))
    if not hostile:
        raise SystemExit("no hostile public-record fixtures found")
    strict_parse_rejections = 0
    for path in hostile:
        try:
            record = load_envelope_fixture(path)
        except InvalidSerializedEnvelope:
            strict_parse_rejections += 1
            continue
        if envelope_admissible(record):
            raise SystemExit(
                f"hostile envelope fixture unexpectedly admitted: {path.name}"
            )
    print(
        "public record envelope conformance passed (family bodies not validated): "
        f"{len(canonical)} canonical accepted, {len(hostile)} hostile rejected "
        f"({strict_parse_rejections} at strict JSON parsing)"
    )


if __name__ == "__main__":
    main()
