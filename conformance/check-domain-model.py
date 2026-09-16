#!/usr/bin/env python3
"""Value-free executable evidence for the public record boundary."""

import json
import re
from collections.abc import Mapping
from pathlib import Path

ROOT = Path(__file__).parents[1]
SUPPORTED_EXTENSION_VERSION = "1.0.0"
UNDERSTOOD_REQUIRED_EXTENSIONS: frozenset[str] = frozenset()


class InvalidSerializedEnvelope(ValueError):
    """The serialized input is ambiguous or is not strict JSON."""


class UnsupportedSchemaError(ValueError):
    """The checked-in envelope schema uses a construct this reader cannot enforce."""


def _object_without_duplicate_members(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise InvalidSerializedEnvelope(f"duplicate JSON member: {name}")
        result[name] = value
    return result


def _reject_non_json_constant(value: str) -> object:
    raise InvalidSerializedEnvelope(f"non-JSON constant: {value}")


def parse_serialized_envelope(serialized: bytes) -> object:
    """Parse one strict JSON value without collapsing duplicate members."""

    try:
        text = serialized.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidSerializedEnvelope("serialized envelope is not UTF-8") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_members,
            parse_constant=_reject_non_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise InvalidSerializedEnvelope("serialized envelope is not JSON") from exc


SCHEMA = parse_serialized_envelope(
    (ROOT / "contracts/schemas/public-record-envelope-v1.schema.json").read_bytes()
)


_SCHEMA_KEYS = {
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


def _require_supported_schema(schema: object, location: str = "$") -> None:
    """Audit the small schema subset used by the public envelope.

    This is deliberately not a general JSON Schema implementation. Any keyword
    or type outside the checked-in closed-object/string subset fails closed.
    """

    if not isinstance(schema, dict):
        raise UnsupportedSchemaError(f"{location} is not a schema object")
    unsupported = set(schema) - _SCHEMA_KEYS
    if unsupported:
        names = ", ".join(sorted(unsupported))
        raise UnsupportedSchemaError(
            f"unsupported schema keyword at {location}: {names}"
        )
    if "$schema" in schema and schema["$schema"] != (
        "https://json-schema.org/draft/2020-12/schema"
    ):
        raise UnsupportedSchemaError(f"unsupported JSON Schema dialect at {location}")
    if "$ref" in schema:
        if set(schema) != {"$ref"} or not isinstance(schema["$ref"], str):
            raise UnsupportedSchemaError(f"unsupported reference form at {location}")
        return
    if "type" in schema and schema["type"] not in {"object", "string"}:
        raise UnsupportedSchemaError(f"unsupported schema type at {location}")
    if "pattern" in schema:
        if not isinstance(schema["pattern"], str):
            raise UnsupportedSchemaError(f"non-string pattern at {location}")
        try:
            re.compile(schema["pattern"])
        except re.error as exc:
            raise UnsupportedSchemaError(f"invalid pattern at {location}") from exc
    if "enum" in schema and (
        not isinstance(schema["enum"], list) or not schema["enum"]
    ):
        raise UnsupportedSchemaError(f"invalid enum at {location}")
    if "required" in schema:
        required = schema["required"]
        if (
            not isinstance(required, list)
            or any(not isinstance(name, str) for name in required)
            or len(required) != len(set(required))
        ):
            raise UnsupportedSchemaError(f"invalid required members at {location}")
    properties = schema.get("properties", {})
    if not isinstance(properties, dict) or any(
        not isinstance(name, str) for name in properties
    ):
        raise UnsupportedSchemaError(f"invalid properties at {location}")
    for name, child in properties.items():
        _require_supported_schema(child, f"{location}.properties.{name}")
    if "propertyNames" in schema:
        _require_supported_schema(schema["propertyNames"], f"{location}.propertyNames")
    if "additionalProperties" in schema:
        additional = schema["additionalProperties"]
        if not isinstance(additional, (bool, dict)):
            raise UnsupportedSchemaError(f"invalid additionalProperties at {location}")
        if isinstance(additional, dict):
            _require_supported_schema(additional, f"{location}.additionalProperties")
    definitions = schema.get("$defs", {})
    if not isinstance(definitions, dict) or any(
        not isinstance(name, str) for name in definitions
    ):
        raise UnsupportedSchemaError(f"invalid definitions at {location}")
    for name, child in definitions.items():
        _require_supported_schema(child, f"{location}.$defs.{name}")


def _resolve_reference(reference: str, root_schema: Mapping[str, object]) -> object:
    prefix = "#/$defs/"
    if not reference.startswith(prefix) or "/" in reference[len(prefix) :]:
        raise UnsupportedSchemaError(f"unsupported schema reference: {reference}")
    definitions = root_schema.get("$defs")
    if not isinstance(definitions, dict) or reference[len(prefix) :] not in definitions:
        raise UnsupportedSchemaError(f"unresolved schema reference: {reference}")
    return definitions[reference[len(prefix) :]]


def _matches_schema(
    value: object, schema: Mapping[str, object], root_schema: Mapping[str, object]
) -> bool:
    if "$ref" in schema:
        referenced = _resolve_reference(str(schema["$ref"]), root_schema)
        if not isinstance(referenced, dict):
            raise UnsupportedSchemaError("referenced schema is not an object")
        return _matches_schema(value, referenced, root_schema)
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
        raise UnsupportedSchemaError("schema properties are not an object")
    property_names = schema.get("propertyNames")
    if property_names is not None:
        if not isinstance(property_names, dict):
            raise UnsupportedSchemaError("propertyNames is not a schema object")
        if any(
            not _matches_schema(name, property_names, root_schema) for name in value
        ):
            return False
    additional = schema.get("additionalProperties", True)
    for name, child_value in value.items():
        child_schema = properties.get(name)
        if child_schema is None:
            if additional is False:
                return False
            if isinstance(additional, dict) and not _matches_schema(
                child_value, additional, root_schema
            ):
                return False
            continue
        if not isinstance(child_schema, dict):
            raise UnsupportedSchemaError(f"schema for {name} is not an object")
        if not _matches_schema(child_value, child_schema, root_schema):
            return False
    return True


def structurally_valid(record: object, *, schema: object = SCHEMA) -> bool:
    _require_supported_schema(schema)
    if not isinstance(schema, dict):
        raise UnsupportedSchemaError("root schema is not an object")
    return _matches_schema(record, schema, schema)


def semantically_admissible(record: object) -> bool:
    """Apply admission rules that are intentionally not JSON shape rules."""

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


def valid(record: object, *, schema: object = SCHEMA) -> bool:
    # No record-family body schemas are supplied. The checked-in schema enforces
    # only that body is an object; this checker does not consume that object.
    return structurally_valid(record, schema=schema) and semantically_admissible(record)


def load_fixture(path: Path) -> object:
    try:
        return parse_serialized_envelope(path.read_bytes())
    except OSError as exc:
        raise SystemExit(f"fixture is not readable: {path.name}") from exc


def main() -> None:
    if SCHEMA.get("$id") != (
        "https://sacrysty.nisavid.io/schemas/public-record-envelope/v1"
    ):
        raise SystemExit("public-record envelope schema identity mismatch")

    canonical = sorted((ROOT / "fixtures").glob("public-record*.json"))
    if not canonical:
        raise SystemExit("no canonical public-record fixtures found")
    for path in canonical:
        try:
            record = load_fixture(path)
        except InvalidSerializedEnvelope as exc:
            raise SystemExit(
                f"canonical fixture is not strict JSON: {path.name}"
            ) from exc
        if not valid(record):
            raise SystemExit(f"canonical fixture rejected: {path.name}")

    hostile = sorted((ROOT / "fixtures").glob("hostile-public-record-*.json"))
    if not hostile:
        raise SystemExit("no hostile public-record fixtures found")
    strict_parse_rejections = 0
    for path in hostile:
        try:
            record = load_fixture(path)
        except InvalidSerializedEnvelope:
            strict_parse_rejections += 1
            continue
        if valid(record):
            raise SystemExit(f"hostile fixture unexpectedly validates: {path.name}")
    print(
        "public record domain conformance passed: "
        f"{len(canonical)} canonical accepted, {len(hostile)} hostile rejected "
        f"({strict_parse_rejections} at strict JSON parsing)"
    )


if __name__ == "__main__":
    main()
