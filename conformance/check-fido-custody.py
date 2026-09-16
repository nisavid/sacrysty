#!/usr/bin/env python3
"""Executable synthetic conformance for the one-shot FIDO adapter."""

from __future__ import annotations

import os
import pathlib
import stat
import sys
import time

ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))
from adapters.fido_custody import CustodyError, CustodyRequest, OneShotCustodyAdapter
from conformance.test_support import external_temporary_directory

WORKER = r"""#!/usr/bin/env python3
import hashlib, json, os, subprocess, sys, time
case = sys.stdin.buffer.readline().decode("ascii").rstrip("\n")
if any(name.startswith("SACRYSTY_TEST_") for name in os.environ):
    raise SystemExit(17)
if case == "duplex":
    sys.stdout.write(" " * 32768)
    sys.stdout.flush()
sys.stdin.buffer.read()
if case == "oversized-stdout":
    sys.stdout.write("x" * 4096)
    sys.stdout.flush()
    time.sleep(2)
    raise SystemExit(0)
if case == "oversized-stderr":
    sys.stderr.write("x" * 4096)
    sys.stderr.flush()
    time.sleep(2)
    raise SystemExit(0)
if case == "timeout":
    time.sleep(2)
    raise SystemExit(0)
if case in {"lingering-child", "redirected-child"}:
    marker = os.path.join(os.path.dirname(__file__), f"{case}-survived")
    child = (
        "import pathlib,time; time.sleep(0.4); "
        f"pathlib.Path({marker!r}).write_text('alive')"
    )
    if case == "redirected-child":
        subprocess.Popen(
            [sys.executable, "-c", child],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        subprocess.Popen([sys.executable, "-c", child])
if case == "crash":
    raise SystemExit(9)
if case == "partial":
    print('{"status":"ok"}', end="")
    raise SystemExit(0)
if case == "mismatch":
    plaintext = b"wrong"
else:
    plaintext = b"synthetic plaintext canary"
message = {
    "status": "ok",
    "plaintext": plaintext.hex(),
    "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
    "profile_revision": "profile-v1",
    "plugin_digest": "sha256:plugin",
    "age_digest": "sha256:age",
    "uv_mode": "pin" if case == "pin" else "built-in",
    "timing_class": "bounded",
}
if case == "mismatch":
    message["plugin_digest"] = "sha256:wrong"
if case == "bad-uv":
    message["uv_mode"] = []
if case == "duplicate":
    encoded = json.dumps(message, separators=(",", ":"))
    print('{"status":"rejected",' + encoded[1:], end="")
    raise SystemExit(0)
print(json.dumps(message), end="")
"""


def expect_failure(
    adapter: OneShotCustodyAdapter,
    request: CustodyRequest,
    expected_diagnostic: str | None = None,
) -> None:
    try:
        adapter.unwrap(request)
    except CustodyError as exc:
        if expected_diagnostic is not None and str(exc) != expected_diagnostic:
            raise AssertionError(
                f"expected {expected_diagnostic!r}, received {str(exc)!r}"
            ) from exc
        return
    raise AssertionError("expected fail-closed result")


def request_for(case: str = "success") -> CustodyRequest:
    return CustodyRequest(
        f"{case}\n".encode("ascii"), "profile-v1", "sha256:plugin", "sha256:age"
    )


def require(condition: bool, diagnostic: str) -> None:
    if not condition:
        raise AssertionError(diagnostic)


def main() -> None:
    request = request_for()
    with external_temporary_directory(ROOT, prefix="sacrysty-fido-test-") as directory:
        worker = pathlib.Path(directory) / "worker.py"
        worker.write_text(WORKER)
        worker.chmod(worker.stat().st_mode | stat.S_IXUSR)
        command = [sys.executable, str(worker)]
        environment = {
            "PATH": os.environ["PATH"],
            "SACRYSTY_TEST_LEAK": "must-not-reach-worker",
        }
        adapter = OneShotCustodyAdapter(command, environment=environment)
        result = adapter.unwrap(request)
        require(
            result.plaintext == b"synthetic plaintext canary",
            "normal worker plaintext was not returned",
        )
        require(
            result.evidence.uv_mode == "built-in", "normal UV mode was not recorded"
        )

        pin_adapter = OneShotCustodyAdapter(command, environment=environment)
        require(
            pin_adapter.unwrap(request_for("pin")).evidence.uv_mode == "pin",
            "PIN UV mode was not recorded",
        )

        duplex_envelope = b"duplex\n" + (b"x" * (1 << 18))
        duplex_request = CustodyRequest(
            duplex_envelope, "profile-v1", "sha256:plugin", "sha256:age"
        )
        duplex_adapter = OneShotCustodyAdapter(
            command,
            timeout_seconds=1.0,
            max_envelope_bytes=len(duplex_envelope),
            max_output_bytes=1 << 16,
            environment=environment,
        )
        require(
            duplex_adapter.unwrap(duplex_request).plaintext
            == b"synthetic plaintext canary",
            "bounded full-duplex worker exchange did not complete",
        )

        for case, diagnostic in (
            ("crash", "worker failure"),
            ("partial", "incomplete worker output"),
            ("mismatch", "plugin_digest mismatch"),
            ("timeout", "worker timeout"),
            ("bad-uv", "unknown UV mode"),
            ("duplicate", "malformed worker output"),
        ):
            expect_failure(
                OneShotCustodyAdapter(
                    command,
                    timeout_seconds=0.1,
                    environment=environment,
                ),
                request_for(case),
                diagnostic,
            )
        for case, diagnostic in (
            ("oversized-stdout", "worker output too large"),
            ("oversized-stderr", "worker stderr too large"),
        ):
            started = time.monotonic()
            expect_failure(
                OneShotCustodyAdapter(
                    command,
                    timeout_seconds=1.0,
                    max_output_bytes=128,
                    environment=environment,
                ),
                request_for(case),
                diagnostic,
            )
            if time.monotonic() - started >= 0.8:
                raise AssertionError(f"{case} was not rejected at the byte limit")
        started = time.monotonic()
        expect_failure(
            OneShotCustodyAdapter(
                command,
                timeout_seconds=0.1,
                environment=environment,
            ),
            request_for("lingering-child"),
            "worker timeout",
        )
        if time.monotonic() - started >= 1.0:
            raise AssertionError(
                "worker child retaining pipes was not boundedly terminated"
            )
        time.sleep(0.5)
        if (pathlib.Path(directory) / "lingering-child-survived").exists():
            raise AssertionError(
                "worker child retaining pipes survived process-group cleanup"
            )
        redirected = OneShotCustodyAdapter(command, environment=environment).unwrap(
            request_for("redirected-child")
        )
        require(
            redirected.plaintext == b"synthetic plaintext canary",
            "worker response preceding redirected child was not accepted",
        )
        time.sleep(0.5)
        if (pathlib.Path(directory) / "redirected-child-survived").exists():
            raise AssertionError(
                "worker child with redirected streams survived successful completion"
            )
        expect_failure(
            OneShotCustodyAdapter(
                command, max_envelope_bytes=4, environment=environment
            ),
            request,
        )
        try:
            OneShotCustodyAdapter(command, environment={"AGEDEBUG": "plugin"})
        except CustodyError:
            pass
        else:
            raise AssertionError("debug environment must be rejected")
    print("fido custody synthetic conformance passed")


if __name__ == "__main__":
    main()
