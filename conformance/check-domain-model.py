#!/usr/bin/env python3
"""Value-free executable evidence for the public record boundary."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCHEMA = json.loads((ROOT / "contracts/schemas/public-record-envelope-v1.schema.json").read_text())
NAME = re.compile(r"^[a-z0-9]+(?:\.[a-z0-9-]+)+$")


def valid(record: dict) -> bool:
    allowed = {"record_type", "schema_version", "record_id", "publisher", "version", "content_digest", "body", "extensions"}
    required = {"record_type", "schema_version", "record_id", "publisher", "body"}
    if set(record) - allowed or not required <= record.keys():
        return False
    if record["record_type"] not in {"contract", "profile", "adapter", "qualification", "release"}:
        return False
    if record["schema_version"] != "io.nisavid.sacrysty.public-record/v1" or not isinstance(record["body"], dict):
        return False
    for name, extension in record.get("extensions", {}).items():
        if not NAME.fullmatch(name) or not isinstance(extension, dict):
            return False
        if set(extension) - {"state", "version", "criticality", "metadata"}:
            return False
        if extension.get("state") != "inert" or extension.get("criticality") not in {"optional", "required"}:
            return False
        if extension["criticality"] == "required" and extension["version"] != "1.0.0":
            return False
    return True


def main() -> None:
    assert SCHEMA["$id"].endswith("public-record-envelope/v1")
    assert valid(json.loads((ROOT / "fixtures/public-record-canonical.json").read_text()))
    hostile = sorted((ROOT / "fixtures").glob("hostile-public-record-*.json"))
    assert len(hostile) == 4
    for path in hostile:
        assert not valid(json.loads(path.read_text())), f"hostile fixture unexpectedly validates: {path.name}"
    print("public record domain conformance passed: 1 canonical accepted, 4 hostile rejected")


if __name__ == "__main__":
    main()
