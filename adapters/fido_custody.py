"""Value-free one-shot custody adapter for the Sacrysty FIDO contract.

The adapter deliberately knows nothing about FIDO credentials or cryptography.
It supplies the process, pipe, timeout, environment, and evidence boundary
around a separately pinned age-plugin-fido2prf worker.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
from dataclasses import dataclass
from typing import Mapping, Sequence


class CustodyError(RuntimeError):
    """A fail-closed operation result with a value-free diagnostic."""


@dataclass(frozen=True)
class CustodyRequest:
    envelope: bytes
    profile_revision: str
    plugin_digest: str
    age_digest: str


@dataclass(frozen=True)
class CustodyEvidence:
    result: str
    uv_mode: str
    timing_class: str
    profile_revision: str
    plugin_digest: str
    age_digest: str
    plaintext_sha256: str


@dataclass(frozen=True)
class CustodyResult:
    plaintext: bytes
    evidence: CustodyEvidence


def _scrub_environment(source: Mapping[str, str] | None) -> dict[str, str]:
    """Keep only non-secret process settings needed to locate the worker."""

    source = os.environ if source is None else source
    if source.get("AGEDEBUG") or source.get("RUST_LOG"):
        raise CustodyError("debugging environment is forbidden")
    allowed = {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR"}
    # Synthetic conformance workers may receive namespaced controls. Real
    # integrations must leave these unset; they are not a production input.
    allowed.update(key for key in source if key.startswith("SACRYSTY_TEST_"))
    return {key: value for key, value in source.items() if key in allowed}


class OneShotCustodyAdapter:
    """Run one external unwrap operation and then discard its process."""

    def __init__(
        self,
        command: Sequence[str],
        *,
        timeout_seconds: float = 5.0,
        max_envelope_bytes: int = 1 << 20,
        max_output_bytes: int = 1 << 20,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        if not command or any(not part for part in command):
            raise ValueError("worker command must be non-empty")
        if timeout_seconds <= 0:
            raise ValueError("timeout must be positive")
        if max_envelope_bytes <= 0 or max_output_bytes <= 0:
            raise ValueError("I/O limits must be positive")
        self._command = tuple(command)
        self._timeout_seconds = timeout_seconds
        self._max_envelope_bytes = max_envelope_bytes
        self._max_output_bytes = max_output_bytes
        self._environment = _scrub_environment(environment)

    def unwrap(self, request: CustodyRequest) -> CustodyResult:
        if not request.envelope:
            raise CustodyError("empty envelope")
        if len(request.envelope) > self._max_envelope_bytes:
            raise CustodyError("envelope too large")
        try:
            process = subprocess.Popen(
                self._command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self._environment,
                close_fds=True,
                start_new_session=True,
            )
        except OSError as exc:
            raise CustodyError("worker unavailable") from exc
        try:
            stdout, _stderr = process.communicate(
                input=request.envelope, timeout=self._timeout_seconds
            )
        except subprocess.TimeoutExpired as exc:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise CustodyError("worker timeout") from exc
        except OSError as exc:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise CustodyError("worker I/O failure") from exc
        if len(stdout) > self._max_output_bytes:
            raise CustodyError("worker output too large")
        if process.returncode != 0:
            raise CustodyError("worker failure")
        try:
            message = json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CustodyError("malformed worker output") from exc
        if not isinstance(message, dict) or message.get("status") != "ok":
            raise CustodyError("worker rejected envelope")
        required = {
            "status",
            "plaintext",
            "plaintext_sha256",
            "profile_revision",
            "plugin_digest",
            "age_digest",
            "uv_mode",
            "timing_class",
        }
        if set(message) != required:
            raise CustodyError("incomplete worker output")
        try:
            plaintext = bytes.fromhex(message["plaintext"])
        except (TypeError, ValueError) as exc:
            raise CustodyError("malformed plaintext") from exc
        digest = hashlib.sha256(plaintext).hexdigest()
        if digest != message["plaintext_sha256"]:
            raise CustodyError("plaintext digest mismatch")
        for key, expected in (
            ("profile_revision", request.profile_revision),
            ("plugin_digest", request.plugin_digest),
            ("age_digest", request.age_digest),
        ):
            if message[key] != expected:
                raise CustodyError(f"{key} mismatch")
        if (
            not isinstance(message["uv_mode"], str)
            or message["uv_mode"] not in {"built-in", "pin"}
        ):
            raise CustodyError("unknown UV mode")
        if (
            not isinstance(message["timing_class"], str)
            or message["timing_class"] not in {"interactive", "bounded"}
        ):
            raise CustodyError("unknown timing class")
        return CustodyResult(
            plaintext=plaintext,
            evidence=CustodyEvidence(
                result="ok",
                uv_mode=message["uv_mode"],
                timing_class=message["timing_class"],
                profile_revision=message["profile_revision"],
                plugin_digest=message["plugin_digest"],
                age_digest=message["age_digest"],
                plaintext_sha256=digest,
            ),
        )
