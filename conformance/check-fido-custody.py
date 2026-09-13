#!/usr/bin/env python3
"""Executable synthetic conformance for the one-shot FIDO adapter."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))
from adapters.fido_custody import CustodyError, CustodyRequest, OneShotCustodyAdapter


WORKER = r'''#!/usr/bin/env python3
import hashlib, json, os, sys, time
payload = sys.stdin.buffer.read()
if os.environ.get("SACRYSTY_TEST_ENV") != "scrubbed":
    print(json.dumps({"status": "bad-env"}))
    raise SystemExit(3)
case = os.environ.get("SACRYSTY_TEST_CASE", "success")
if case == "timeout":
    time.sleep(2)
    raise SystemExit(0)
if case == "crash":
    raise SystemExit(9)
if case == "partial":
    print('{"status":"ok"}', end="")
    raise SystemExit(0)
if case == "large":
    print("x" * 4096, end="")
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
    "uv_mode": os.environ.get("SACRYSTY_TEST_UV", "built-in"),
    "timing_class": "bounded",
}
if case == "mismatch":
    message["plugin_digest"] = "sha256:wrong"
if case == "bad-uv":
    message["uv_mode"] = []
print(json.dumps(message), end="")
'''


def expect_failure(adapter: OneShotCustodyAdapter, request: CustodyRequest) -> None:
    try:
        adapter.unwrap(request)
    except CustodyError:
        return
    raise AssertionError("expected fail-closed result")


def main() -> None:
    request = CustodyRequest(b"synthetic envelope", "profile-v1", "sha256:plugin", "sha256:age")
    with tempfile.TemporaryDirectory() as directory:
        worker = pathlib.Path(directory) / "worker.py"
        worker.write_text(WORKER)
        worker.chmod(worker.stat().st_mode | stat.S_IXUSR)
        command = [sys.executable, str(worker)]
        environment = {"PATH": os.environ["PATH"], "SACRYSTY_TEST_ENV": "scrubbed"}
        adapter = OneShotCustodyAdapter(command, environment=environment)
        result = adapter.unwrap(request)
        assert result.plaintext == b"synthetic plaintext canary"
        assert result.evidence.uv_mode == "built-in"

        pin_adapter = OneShotCustodyAdapter(
            command,
            environment={**environment, "SACRYSTY_TEST_UV": "pin"},
        )
        assert pin_adapter.unwrap(request).evidence.uv_mode == "pin"

        for case in ("crash", "partial", "mismatch", "timeout", "bad-uv"):
            expect_failure(
                OneShotCustodyAdapter(
                    command,
                    timeout_seconds=0.1,
                    environment={**environment, "SACRYSTY_TEST_CASE": case},
                ),
                request,
            )
        expect_failure(
            OneShotCustodyAdapter(
                command,
                max_output_bytes=128,
                environment={**environment, "SACRYSTY_TEST_CASE": "large"},
            ),
            request,
        )
        expect_failure(
            OneShotCustodyAdapter(command, max_envelope_bytes=4, environment=environment),
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
