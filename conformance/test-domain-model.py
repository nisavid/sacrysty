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
import tempfile
import unittest


CHECKER_PATH = pathlib.Path(__file__).with_name("check-domain-model.py")
SPEC = importlib.util.spec_from_file_location("check_domain_model", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load domain-model checker")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)
CANONICAL = json.loads(
    (CHECKER_PATH.parents[1] / "fixtures/public-record-canonical.json").read_text()
)


class PublicRecordValidationTests(unittest.TestCase):
    def test_non_object_is_rejected_cleanly(self) -> None:
        self.assertFalse(CHECKER.valid([]))

    def test_body_check_is_explicitly_envelope_only(self) -> None:
        candidate = copy.deepcopy(CANONICAL)
        candidate["body"] = {"unknown_family_field": {"not": "consumed"}}
        self.assertTrue(CHECKER.valid(candidate))

    def test_required_envelope_fields_cannot_be_omitted(self) -> None:
        for field in ("record_type", "schema_version", "record_id", "publisher", "body"):
            with self.subTest(field):
                candidate = copy.deepcopy(CANONICAL)
                candidate.pop(field)
                self.assertFalse(CHECKER.valid(candidate))

    def test_envelope_fields_follow_contract_types_and_patterns(self) -> None:
        without_optional_fields = copy.deepcopy(CANONICAL)
        without_optional_fields.pop("version")
        without_optional_fields.pop("content_digest")
        self.assertTrue(CHECKER.valid(without_optional_fields))

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
                self.assertFalse(CHECKER.valid(candidate))

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
        self.assertTrue(CHECKER.valid(control))
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
                self.assertFalse(CHECKER.valid(candidate))

    def test_optimized_checker_fails_when_a_control_fixture_is_invalid(self) -> None:
        repository = CHECKER_PATH.parents[1]
        with tempfile.TemporaryDirectory(
            prefix=".domain-model-test-", dir=repository
        ) as directory:
            fixture_root = pathlib.Path(directory)
            (fixture_root / "conformance").mkdir()
            (fixture_root / "contracts/schemas").mkdir(parents=True)
            shutil.copy2(CHECKER_PATH, fixture_root / "conformance")
            shutil.copytree(repository / "fixtures", fixture_root / "fixtures")
            shutil.copy2(
                repository
                / "contracts/schemas/public-record-envelope-v1.schema.json",
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


if __name__ == "__main__":
    unittest.main()
