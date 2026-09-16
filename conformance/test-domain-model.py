#!/usr/bin/env python3
"""Focused regressions for the public-record conformance interface."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import unittest

from test_support import external_temporary_directory

CHECKER_PATH = pathlib.Path(__file__).with_name("check-domain-model.py")
STRICT_JSON_HELPER = pathlib.Path(__file__).with_name("strict_json.py")
SPEC = importlib.util.spec_from_file_location("check_domain_model", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load domain-model checker")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)
CANONICAL = json.loads(
    (CHECKER_PATH.parents[1] / "fixtures/public-record-canonical.json").read_text()
)


class PublicRecordEnvelopeAdmissionTests(unittest.TestCase):
    def test_non_object_is_rejected_cleanly(self) -> None:
        self.assertFalse(CHECKER.envelope_admissible([]))

    def test_body_check_is_explicitly_envelope_only(self) -> None:
        candidate = copy.deepcopy(CANONICAL)
        candidate["body"] = {"unknown_family_field": {"not": "consumed"}}
        self.assertTrue(CHECKER.envelope_admissible(candidate))

    def test_serialized_envelope_rejects_duplicate_members_at_any_depth(self) -> None:
        for label, serialized in (
            ("top level", b'{"body":{},"body":{}}'),
            ("body", b'{"body":{"claim":1,"claim":2}}'),
            (
                "extension metadata",
                b'{"extensions":{"example.invalid.audit":{"metadata":{"claim":1,"claim":2}}}}',
            ),
        ):
            with (
                self.subTest(label),
                self.assertRaises(CHECKER.InvalidSerializedEnvelope),
            ):
                CHECKER.parse_serialized_envelope(serialized)

    def test_serialized_envelope_rejects_non_json_constants(self) -> None:
        for constant in (b"NaN", b"Infinity", b"-Infinity"):
            with (
                self.subTest(constant),
                self.assertRaises(CHECKER.InvalidSerializedEnvelope),
            ):
                CHECKER.parse_serialized_envelope(
                    b'{"body":{"value":' + constant + b"}}"
                )

    def test_serialized_envelope_rejects_invalid_utf8_and_syntax(self) -> None:
        for serialized in (b'{"body":"\xff"}', b'{"body":'):
            with self.subTest(serialized), self.assertRaises(
                CHECKER.InvalidSerializedEnvelope
            ):
                CHECKER.parse_serialized_envelope(serialized)

    def test_envelope_structure_is_derived_from_the_checked_in_schema(self) -> None:
        schema = copy.deepcopy(CHECKER.ENVELOPE_SCHEMA)
        schema["properties"]["record_type"]["enum"].append("test-family")
        candidate = copy.deepcopy(CANONICAL)
        candidate["record_type"] = "test-family"

        self.assertTrue(CHECKER.envelope_admissible(candidate, schema=schema))

        schema["properties"]["body"]["minProperties"] = 1
        with self.assertRaises(CHECKER.UnsupportedEnvelopeSchemaError):
            CHECKER.envelope_admissible(candidate, schema=schema)

    def test_required_envelope_fields_cannot_be_omitted(self) -> None:
        for field in (
            "record_type",
            "schema_version",
            "record_id",
            "publisher",
            "body",
        ):
            with self.subTest(field):
                candidate = copy.deepcopy(CANONICAL)
                candidate.pop(field)
                self.assertFalse(CHECKER.envelope_admissible(candidate))

    def test_envelope_fields_follow_contract_types_and_patterns(self) -> None:
        without_optional_fields = copy.deepcopy(CANONICAL)
        without_optional_fields.pop("version")
        without_optional_fields.pop("content_digest")
        self.assertTrue(CHECKER.envelope_admissible(without_optional_fields))

        invalid_fields = {
            "record_type type": ("record_type", []),
            "record_type value": ("record_type", "unknown"),
            "schema_version type": ("schema_version", 1),
            "record_id type": ("record_id", 1),
            "record_id pattern": ("record_id", "not-qualified"),
            "publisher type": ("publisher", []),
            "publisher pattern": ("publisher", "Example Invalid"),
            "version type": ("version", 1),
            "version pattern": ("version", "v1"),
            "content_digest type": ("content_digest", None),
            "content_digest pattern": ("content_digest", "sha512-deadbeef"),
            "body type": ("body", []),
        }
        for label, (field, value) in invalid_fields.items():
            with self.subTest(label):
                candidate = copy.deepcopy(CANONICAL)
                candidate[field] = value
                self.assertFalse(CHECKER.envelope_admissible(candidate))

    def test_envelope_identifiers_and_versions_reject_terminal_newlines(self) -> None:
        top_level_values = {
            "record_id": CANONICAL["record_id"] + "\n",
            "publisher": CANONICAL["publisher"] + "\n",
            "version": CANONICAL["version"] + "\n",
            "content_digest": CANONICAL["content_digest"] + "\n",
        }
        for field, value in top_level_values.items():
            with self.subTest(field):
                candidate = copy.deepcopy(CANONICAL)
                candidate[field] = value
                self.assertFalse(CHECKER.envelope_admissible(candidate))

        extension_name = copy.deepcopy(CANONICAL)
        extension = extension_name["extensions"].pop("example.invalid.audit")
        extension_name["extensions"]["example.invalid.audit\n"] = extension
        self.assertFalse(CHECKER.envelope_admissible(extension_name))

        extension_version = copy.deepcopy(CANONICAL)
        extension_version["extensions"]["example.invalid.audit"]["version"] += "\n"
        self.assertFalse(CHECKER.envelope_admissible(extension_version))

        body_control = copy.deepcopy(CANONICAL)
        body_control["body"] = {"documentary_text": "line one\nline two\n"}
        self.assertTrue(CHECKER.envelope_admissible(body_control))

    def test_extensions_are_inert_supported_and_optional(self) -> None:
        supported_optional = {
            "example.invalid.unknown": {
                "state": "inert",
                "version": "1.0.0",
                "criticality": "optional",
                "metadata": {"preserve": True},
            }
        }
        control = copy.deepcopy(CANONICAL)
        control["extensions"] = copy.deepcopy(supported_optional)
        unchanged = copy.deepcopy(control)
        self.assertTrue(CHECKER.envelope_admissible(control))
        self.assertEqual(control, unchanged)

        invalid_extensions = {
            "extensions type": [],
            "unnamespaced": {
                "unknown": {
                    "state": "inert",
                    "version": "1.0.0",
                    "criticality": "optional",
                }
            },
            "extension type": {"example.invalid.unknown": []},
            "unknown field": {
                "example.invalid.unknown": {
                    "state": "inert",
                    "version": "1.0.0",
                    "criticality": "optional",
                    "execute": True,
                }
            },
            "missing state": {
                "example.invalid.unknown": {
                    "version": "1.0.0",
                    "criticality": "optional",
                }
            },
            "missing version": {
                "example.invalid.unknown": {
                    "state": "inert",
                    "criticality": "optional",
                }
            },
            "missing criticality": {
                "example.invalid.unknown": {
                    "state": "inert",
                    "version": "1.0.0",
                }
            },
            "active": {
                "example.invalid.unknown": {
                    "state": "active",
                    "version": "1.0.0",
                    "criticality": "optional",
                }
            },
            "state type": {
                "example.invalid.unknown": {
                    "state": [],
                    "version": "1.0.0",
                    "criticality": "optional",
                }
            },
            "version type": {
                "example.invalid.unknown": {
                    "state": "inert",
                    "version": 1,
                    "criticality": "optional",
                }
            },
            "unsupported optional version": {
                "example.invalid.unknown": {
                    "state": "inert",
                    "version": "2.0.0",
                    "criticality": "optional",
                }
            },
            "unknown required supported version": {
                "example.invalid.unknown": {
                    "state": "inert",
                    "version": "1.0.0",
                    "criticality": "required",
                }
            },
            "unknown required unsupported version": {
                "example.invalid.unknown": {
                    "state": "inert",
                    "version": "2.0.0",
                    "criticality": "required",
                }
            },
            "criticality type": {
                "example.invalid.unknown": {
                    "state": "inert",
                    "version": "1.0.0",
                    "criticality": [],
                }
            },
            "criticality value": {
                "example.invalid.unknown": {
                    "state": "inert",
                    "version": "1.0.0",
                    "criticality": "advisory",
                }
            },
            "metadata type": {
                "example.invalid.unknown": {
                    "state": "inert",
                    "version": "1.0.0",
                    "criticality": "optional",
                    "metadata": [],
                }
            },
        }
        for label, extensions in invalid_extensions.items():
            with self.subTest(label):
                candidate = copy.deepcopy(CANONICAL)
                candidate["extensions"] = extensions
                self.assertFalse(CHECKER.envelope_admissible(candidate))

    def test_success_diagnostic_states_the_envelope_only_boundary(self) -> None:
        result = subprocess.run(
            [sys.executable, "-B", str(CHECKER_PATH)],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("public record envelope conformance passed", result.stdout)
        self.assertIn("family bodies not validated", result.stdout)

    def test_optimized_checker_fails_when_a_control_fixture_is_invalid(self) -> None:
        repository = CHECKER_PATH.parents[1]
        with external_temporary_directory(
            repository, prefix="sacrysty-domain-model-test-"
        ) as directory:
            fixture_root = pathlib.Path(directory)
            (fixture_root / "conformance").mkdir()
            (fixture_root / "contracts/schemas").mkdir(parents=True)
            shutil.copy2(CHECKER_PATH, fixture_root / "conformance")
            shutil.copy2(STRICT_JSON_HELPER, fixture_root / "conformance")
            shutil.copytree(repository / "fixtures", fixture_root / "fixtures")
            shutil.copy2(
                repository / "contracts/schemas/public-record-envelope-v1.schema.json",
                fixture_root / "contracts/schemas",
            )
            (fixture_root / "fixtures/public-record-canonical.json").write_text("{}\n")

            result = subprocess.run(
                [
                    sys.executable,
                    "-O",
                    str(fixture_root / "conformance/check-domain-model.py"),
                ],
                check=False,
                capture_output=True,
                env={"PATH": os.environ["PATH"]},
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("conformance passed", result.stdout)
        self.assertIn("canonical envelope fixture", result.stderr)


if __name__ == "__main__":
    unittest.main()
