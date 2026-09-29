#!/usr/bin/env python3
"""Admit only complete passing evidence from the two disposable crypto probes."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))

from sacrysty_runtime.strict_json import (
    DuplicateMemberError,
    InvalidJsonSyntaxError,
    InvalidUtf8Error,
    NonFiniteNumberError,
    UnrepresentableNumberError,
    decode_strict_json,
)

SHA256 = re.compile(r"^[0-9a-f]{64}$")
SHA512 = re.compile(r"^[0-9a-f]{128}$")


class ResultError(ValueError):
    """A probe result cannot support a passing aggregate result."""


def _load_result(path: Path) -> dict[str, object]:
    try:
        result = decode_strict_json(path.read_bytes())
    except OSError as exc:
        raise ResultError("probe result is not readable strict JSON") from exc
    except DuplicateMemberError as exc:
        raise ResultError(f"duplicate result member: {exc.member}") from exc
    except NonFiniteNumberError as exc:
        label = (
            "non-JSON result constant"
            if exc.value in {"NaN", "Infinity", "-Infinity"}
            else "non-finite result number"
        )
        raise ResultError(f"{label}: {exc.value}") from exc
    except UnrepresentableNumberError as exc:
        raise ResultError(f"unrepresentable result number: {exc.value}") from exc
    except (InvalidUtf8Error, InvalidJsonSyntaxError) as exc:
        raise ResultError("probe result is not readable strict JSON") from exc
    if not isinstance(result, dict):
        raise ResultError("probe result is not an object")
    return result


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ResultError(message)


def _require_exact_members(
    value: object, expected: set[str], label: str
) -> dict[str, object]:
    _require(isinstance(value, dict), f"{label} is not an object")
    mapping = value
    _require(set(mapping) == expected, f"{label} members are incomplete or unknown")
    return mapping


def _validate_fixture(value: object, label: str) -> dict[str, object]:
    fixture = _require_exact_members(
        value, {"bytes", "sha256", "sha512"}, f"{label} fixture"
    )
    byte_length = fixture["bytes"]
    _require(
        isinstance(byte_length, int)
        and not isinstance(byte_length, bool)
        and byte_length > 0,
        f"{label} fixture byte length is invalid",
    )
    _require(
        isinstance(fixture["sha256"], str)
        and SHA256.fullmatch(fixture["sha256"]) is not None,
        f"{label} fixture SHA-256 is invalid",
    )
    _require(
        isinstance(fixture["sha512"], str)
        and SHA512.fullmatch(fixture["sha512"]) is not None,
        f"{label} fixture SHA-512 is invalid",
    )
    return fixture


def _validate_common(result: dict[str, object], revision: str) -> None:
    _require(result["source_revision"] == revision, "probe source revision mismatch")
    _require(result["reference_time"] == "20260910", "probe reference time mismatch")
    for field in ("sq_version", "sqv_version"):
        _require(
            isinstance(result[field], str) and bool(result[field]),
            f"{field} is missing",
        )


def _validate_crypto(result: dict[str, object], revision: str) -> None:
    expected = {
        "checks",
        "fixture_bytes",
        "fixture_sha256",
        "fixture_sha512",
        "fixtures",
        "reference_time",
        "result",
        "schema",
        "source_revision",
        "sq_version",
        "sqv_version",
    }
    _require(
        set(result) == expected, "crypto-conformance result members are incomplete"
    )
    _require(
        result["schema"] == "io.nisavid.sacrysty.crypto-conformance-result/v1",
        "crypto-conformance result schema mismatch",
    )
    _validate_common(result, revision)

    fixtures = _require_exact_members(
        result["fixtures"],
        {"message", "signature", "tampered_message", "tampered_signature"},
        "crypto-conformance fixtures",
    )
    checked_fixtures = {
        name: _validate_fixture(value, name) for name, value in fixtures.items()
    }
    message = checked_fixtures["message"]
    _require(
        result["fixture_bytes"] == message["bytes"], "fixture byte binding mismatch"
    )
    _require(
        result["fixture_sha256"] == message["sha256"],
        "fixture SHA-256 binding mismatch",
    )
    _require(
        result["fixture_sha512"] == message["sha512"],
        "fixture SHA-512 binding mismatch",
    )

    observations = _require_exact_members(
        result["result"],
        {"openpgp-rfc9580-classical-v1", "openpgp-rfc9980-pqc-v1"},
        "crypto-conformance observations",
    )
    _require(
        observations["openpgp-rfc9580-classical-v1"]
        == "qualified-for-observed-runtime",
        "classical profile did not complete its required round trip",
    )
    _require(
        observations["openpgp-rfc9980-pqc-v1"]
        in {"unsupported", "qualified-for-observed-runtime"},
        "PQC observation is failed, indeterminate, or unknown",
    )

    expected_true = {
        "sq_sign_verify",
        "sqv_detached_verify",
        "tampered_message_rejected",
        "tampered_signature_rejected",
        "wrong_certificate_rejected",
        "temporary_key_material_removed",
    }
    checks = _require_exact_members(
        result["checks"], expected_true | {"production_values"}, "crypto checks"
    )
    for name in expected_true:
        _require(checks[name] is True, f"mandatory crypto check is false: {name}")
    _require(
        checks["production_values"] is False,
        "crypto result indicates production values",
    )


def _validate_signing(result: dict[str, object], revision: str) -> None:
    expected = {
        "checks",
        "diagnostics",
        "fixtures",
        "production_values_policy",
        "profile",
        "reference_time",
        "rfc9980",
        "schema",
        "source_revision",
        "sq_version",
        "sqv_version",
    }
    _require(set(result) == expected, "signing-profile result members are incomplete")
    _require(
        result["schema"] == "io.nisavid.sacrysty.signing-profile-result/v1",
        "signing-profile result schema mismatch",
    )
    _validate_common(result, revision)
    _require(
        result["profile"] == "openpgp-rfc9580-classical-v1",
        "signing profile mismatch",
    )
    _require(
        result["production_values_policy"] == "forbidden",
        "signing result production-values policy mismatch",
    )
    _require(
        result["rfc9980"] == "unsupported-capability-gated",
        "signing result RFC 9980 boundary mismatch",
    )

    fixtures = _require_exact_members(
        result["fixtures"], {"message", "signature"}, "signing fixtures"
    )
    for name, value in fixtures.items():
        _validate_fixture(value, name)

    expected_true = {
        "detached_sign_verify",
        "tampered_message_rejected",
        "tampered_signature_rejected",
        "wrong_certificate_rejected",
        "temporary_key_material_removed",
    }
    checks = _require_exact_members(result["checks"], expected_true, "signing checks")
    for name in expected_true:
        _require(checks[name] is True, f"mandatory signing check is false: {name}")

    diagnostics = _require_exact_members(
        result["diagnostics"],
        {"tampered_message", "tampered_signature", "wrong_certificate"},
        "signing diagnostics",
    )
    for name, value in diagnostics.items():
        diagnostic = _require_exact_members(
            value, {"command", "exit_status", "stderr"}, f"{name} diagnostic"
        )
        _require(
            isinstance(diagnostic["command"], str) and bool(diagnostic["command"]),
            f"{name} diagnostic command is missing",
        )
        exit_status = diagnostic["exit_status"]
        _require(
            isinstance(exit_status, int)
            and not isinstance(exit_status, bool)
            and 1 <= exit_status <= 123,
            f"{name} diagnostic is not a rejection",
        )
        _require(
            isinstance(diagnostic["stderr"], str),
            f"{name} diagnostic stderr is not a string",
        )


def main() -> None:
    if len(sys.argv) != 4 or sys.argv[1] not in {
        "crypto-conformance",
        "signing-profile",
    }:
        raise SystemExit(
            f"usage: {sys.argv[0]} <crypto-conformance|signing-profile> <result.json> <source-revision>"
        )
    kind, path, revision = sys.argv[1:]
    try:
        result = _load_result(Path(path))
        if kind == "crypto-conformance":
            _validate_crypto(result, revision)
        else:
            _validate_signing(result, revision)
    except ResultError as exc:
        raise SystemExit(str(exc)) from exc
    print(f"{kind} probe result admitted")


if __name__ == "__main__":
    main()
