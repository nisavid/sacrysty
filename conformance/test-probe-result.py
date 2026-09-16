#!/usr/bin/env python3
"""Regressions for aggregate admission of crypto-probe evidence."""

from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import sys
import unittest

from test_support import external_temporary_directory

ROOT = pathlib.Path(__file__).parents[1]
CHECKER = ROOT / "conformance/check-probe-result.py"
REVISION = "a" * 40
SHA256 = "b" * 64
SHA512 = "c" * 128


def fixture() -> dict[str, object]:
    return {"bytes": 1, "sha256": SHA256, "sha512": SHA512}


def crypto_result() -> dict[str, object]:
    return {
        "schema": "io.nisavid.sacrysty.crypto-conformance-result/v1",
        "source_revision": REVISION,
        "reference_time": "20260910",
        "sq_version": "sq fixture",
        "sqv_version": "sqv fixture",
        "fixture_sha256": SHA256,
        "fixture_sha512": SHA512,
        "fixture_bytes": 1,
        "result": {
            "openpgp-rfc9580-classical-v1": "qualified-for-observed-runtime",
            "openpgp-rfc9980-pqc-v1": "unsupported",
        },
        "fixtures": {
            "message": fixture(),
            "signature": fixture(),
            "tampered_message": fixture(),
            "tampered_signature": fixture(),
        },
        "checks": {
            "sq_sign_verify": True,
            "sqv_detached_verify": True,
            "tampered_message_rejected": True,
            "tampered_signature_rejected": True,
            "wrong_certificate_rejected": True,
            "temporary_key_material_removed": True,
            "production_values": False,
        },
    }


def signing_result() -> dict[str, object]:
    return {
        "schema": "io.nisavid.sacrysty.signing-profile-result/v1",
        "source_revision": REVISION,
        "reference_time": "20260910",
        "sq_version": "sq fixture",
        "sqv_version": "sqv fixture",
        "profile": "openpgp-rfc9580-classical-v1",
        "fixtures": {"message": fixture(), "signature": fixture()},
        "checks": {
            "detached_sign_verify": True,
            "tampered_message_rejected": True,
            "tampered_signature_rejected": True,
            "wrong_certificate_rejected": True,
            "temporary_key_material_removed": True,
        },
        "diagnostics": {
            name: {"command": "sqv fixture", "exit_status": 7, "stderr": "rejected"}
            for name in (
                "tampered_message",
                "tampered_signature",
                "wrong_certificate",
            )
        },
        "production_values_policy": "forbidden",
        "rfc9980": "unsupported-capability-gated",
    }


class ProbeResultTests(unittest.TestCase):
    def check(self, kind: str, content: bytes) -> subprocess.CompletedProcess[str]:
        with external_temporary_directory(
            ROOT, prefix="sacrysty-probe-result-test-"
        ) as directory:
            result_path = pathlib.Path(directory) / "result.json"
            result_path.write_bytes(content)
            return subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(CHECKER),
                    kind,
                    str(result_path),
                    REVISION,
                ],
                check=False,
                capture_output=True,
                text=True,
            )

    def check_json(self, kind: str, value: object) -> subprocess.CompletedProcess[str]:
        return self.check(kind, json.dumps(value).encode("utf-8"))

    def test_each_probe_profile_accepts_its_complete_passing_result(self) -> None:
        for kind, value in (
            ("crypto-conformance", crypto_result()),
            ("signing-profile", signing_result()),
        ):
            with self.subTest(kind):
                result = self.check_json(kind, value)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_malformed_missing_wrong_schema_and_false_checks_are_rejected(self) -> None:
        cases: list[tuple[str, bytes]] = [
            ("malformed", b'{"schema":'),
            (
                "duplicate",
                b'{"schema":"first","schema":"io.nisavid.sacrysty.crypto-conformance-result/v1"}',
            ),
            (
                "non-json constant",
                b'{"schema":"io.nisavid.sacrysty.crypto-conformance-result/v1","value":NaN}',
            ),
            ("invalid UTF-8", b'{"schema":"\xff"}'),
        ]
        missing = crypto_result()
        missing.pop("checks")
        cases.append(("missing", json.dumps(missing).encode()))
        wrong_schema = crypto_result()
        wrong_schema["schema"] = "example.invalid/wrong"
        cases.append(("wrong schema", json.dumps(wrong_schema).encode()))
        false_check = crypto_result()
        false_check["checks"]["temporary_key_material_removed"] = False  # type: ignore[index]
        cases.append(("false check", json.dumps(false_check).encode()))

        for label, content in cases:
            with self.subTest(label):
                result = self.check("crypto-conformance", content)
                self.assertNotEqual(result.returncode, 0)

    def test_nonpositive_or_mismatched_results_cannot_pass_aggregate_admission(
        self,
    ) -> None:
        for pqc_result in ("probe-failed", "round-trip-failed", "qualified"):
            with self.subTest(pqc_result):
                value = crypto_result()
                value["result"]["openpgp-rfc9980-pqc-v1"] = pqc_result  # type: ignore[index]
                result = self.check_json("crypto-conformance", value)
                self.assertNotEqual(result.returncode, 0)

        source_mismatch = copy.deepcopy(signing_result())
        source_mismatch["source_revision"] = "d" * 40
        result = self.check_json("signing-profile", source_mismatch)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
