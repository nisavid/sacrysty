#!/usr/bin/env python3
"""Value-free executable evidence for the public record boundary."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCHEMA = json.loads((ROOT / "contracts/schemas/public-record-envelope-v1.schema.json").read_text())
EXTENSION_NAME = re.compile(r"^[a-z0-9]+(?:\.[a-z0-9-]+)+$")
RECORD_ID = re.compile(r"^[a-z0-9][a-z0-9.-]*:[a-z0-9][a-z0-9._/-]*$")
PUBLISHER = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
CONTENT_DIGEST = re.compile(r"^sha512-[0-9a-f]{128}$")
SUPPORTED_EXTENSION_VERSION = "1.0.0"
UNDERSTOOD_REQUIRED_EXTENSIONS: frozenset[str] = frozenset()


def valid(record: object) -> bool:
    if not isinstance(record, dict):
        return False
    allowed = {
        "record_type",
        "schema_version",
        "record_id",
        "publisher",
        "version",
        "content_digest",
        "body",
        "extensions",
    }
    required = {"record_type", "schema_version", "record_id", "publisher", "body"}
    if set(record) - allowed or not required <= record.keys():
        return False
    if not isinstance(record["record_type"], str) or record["record_type"] not in {
        "contract",
        "profile",
        "adapter",
        "qualification",
        "release",
    }:
        return False
    if (
        not isinstance(record["schema_version"], str)
        or record["schema_version"] != "io.nisavid.sacrysty.public-record/v1"
        or not isinstance(record["record_id"], str)
        or RECORD_ID.fullmatch(record["record_id"]) is None
        or not isinstance(record["publisher"], str)
        or PUBLISHER.fullmatch(record["publisher"]) is None
    ):
        return False
    if "version" in record and (
        not isinstance(record["version"], str)
        or VERSION.fullmatch(record["version"]) is None
    ):
        return False
    if "content_digest" in record and (
        not isinstance(record["content_digest"], str)
        or CONTENT_DIGEST.fullmatch(record["content_digest"]) is None
    ):
        return False
    extensions = record.get("extensions", {})
    if not isinstance(extensions, dict):
        return False
    for name, extension in extensions.items():
        if (
            not isinstance(name, str)
            or EXTENSION_NAME.fullmatch(name) is None
            or not isinstance(extension, dict)
        ):
            return False
        allowed_extension_fields = {"state", "version", "criticality", "metadata"}
        required_extension_fields = {"state", "version", "criticality"}
        if (
            set(extension) - allowed_extension_fields
            or not required_extension_fields <= extension.keys()
        ):
            return False
        if extension["state"] != "inert":
            return False
        if (
            not isinstance(extension["version"], str)
            or VERSION.fullmatch(extension["version"]) is None
            or extension["version"] != SUPPORTED_EXTENSION_VERSION
        ):
            return False
        if extension["criticality"] not in ("optional", "required"):
            return False
        if (
            extension["criticality"] == "required"
            and name not in UNDERSTOOD_REQUIRED_EXTENSIONS
        ):
            return False
        if "metadata" in extension and not isinstance(extension["metadata"], dict):
            return False
    # Record-family schemas are not part of this conformance increment. The
    # envelope checker therefore establishes only that body is an object.
    return isinstance(record["body"], dict)


def load_fixture(path: Path) -> object:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"fixture is not readable JSON: {path.name}") from exc


def main() -> None:
    if SCHEMA.get("$id") != (
        "https://sacrysty.nisavid.io/schemas/public-record-envelope/v1"
    ):
        raise SystemExit("public-record envelope schema identity mismatch")

    canonical = sorted((ROOT / "fixtures").glob("public-record*.json"))
    if not canonical:
        raise SystemExit("no canonical public-record fixtures found")
    for path in canonical:
        if not valid(load_fixture(path)):
            raise SystemExit(f"canonical fixture rejected: {path.name}")

    hostile = sorted((ROOT / "fixtures").glob("hostile-public-record-*.json"))
    if not hostile:
        raise SystemExit("no hostile public-record fixtures found")
    for path in hostile:
        if valid(load_fixture(path)):
            raise SystemExit(f"hostile fixture unexpectedly validates: {path.name}")
    print(
        "public record domain conformance passed: "
        f"{len(canonical)} canonical accepted, {len(hostile)} hostile rejected"
    )


if __name__ == "__main__":
    main()
