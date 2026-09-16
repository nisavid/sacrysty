"""Value-free one-shot custody adapter for the Sacrysty FIDO contract.

The adapter deliberately knows nothing about FIDO credentials or cryptography.
It supplies the process, pipe, timeout, environment, and evidence boundary
around a separately pinned age-plugin-fido2prf worker.

Cleanup is bounded by the worker's new process group. A descendant that
deliberately creates a different session can escape that group; containing
such a worker requires an operating-system sandbox outside this reference
adapter.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import selectors
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import BinaryIO


class CustodyError(RuntimeError):
    """A fail-closed operation result with a value-free diagnostic."""


class _OutputLimitExceeded(Exception):
    def __init__(self, stream_name: str) -> None:
        self.stream_name = stream_name


class _WorkerTimedOut(Exception):
    pass


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
    return {key: value for key, value in source.items() if key in allowed}


def _object_without_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _close_pipe(pipe: BinaryIO) -> None:
    try:
        pipe.close()
    except OSError:
        pass


def _terminate_and_reap(process: subprocess.Popen[bytes]) -> None:
    """Request group termination, close pipes, and boundedly attempt leader reaping."""

    group_cleanup_error: OSError | None = None
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError as exc:
        if exc.errno != errno.ESRCH:
            group_cleanup_error = exc
            # A leader-only fallback cannot establish descendant cleanup. Try it
            # for bounded cleanup, but retain the group failure for the caller.
            try:
                process.kill()
            except OSError:
                pass

    for pipe in (process.stdin, process.stdout, process.stderr):
        if pipe is not None:
            _close_pipe(pipe)

    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            # An uninterruptible leader cannot be reaped synchronously. Returning
            # remains bounded and the public operation still fails closed.
            pass

    if group_cleanup_error is not None:
        raise CustodyError("worker cleanup failure") from group_cleanup_error


def _bounded_communicate(
    process: subprocess.Popen[bytes],
    input_bytes: bytes,
    timeout_seconds: float,
    max_output_bytes: int,
) -> tuple[bytes, bytes]:
    """Exchange bytes without buffering beyond either output limit."""

    if process.stdin is None or process.stdout is None or process.stderr is None:
        raise OSError("worker pipes unavailable")

    stdin = process.stdin
    stdout = process.stdout
    stderr = process.stderr
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    input_offset = 0
    deadline = time.monotonic() + timeout_seconds

    def unregister_and_close(pipe: BinaryIO) -> None:
        try:
            selector.unregister(pipe)
        except (KeyError, ValueError):
            pass
        _close_pipe(pipe)

    try:
        for pipe in (stdin, stdout, stderr):
            os.set_blocking(pipe.fileno(), False)
        selector.register(stdin, selectors.EVENT_WRITE, "stdin")
        selector.register(stdout, selectors.EVENT_READ, "stdout")
        selector.register(stderr, selectors.EVENT_READ, "stderr")

        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _WorkerTimedOut
            events = selector.select(remaining)
            if not events:
                raise _WorkerTimedOut

            for key, _mask in events:
                pipe = key.fileobj
                stream_name = key.data
                if stream_name == "stdin":
                    try:
                        written = os.write(
                            pipe.fileno(),
                            input_bytes[input_offset : input_offset + 65536],
                        )
                    except BlockingIOError:
                        continue
                    input_offset += written
                    if input_offset == len(input_bytes):
                        unregister_and_close(pipe)
                    continue

                output = buffers[stream_name]
                read_size = min(65536, max_output_bytes - len(output) + 1)
                try:
                    chunk = os.read(pipe.fileno(), read_size)
                except BlockingIOError:
                    continue
                if not chunk:
                    unregister_and_close(pipe)
                    continue
                output.extend(chunk)
                if len(output) > max_output_bytes:
                    raise _OutputLimitExceeded(stream_name)
    finally:
        selector.close()

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _WorkerTimedOut
    try:
        process.wait(timeout=remaining)
    except subprocess.TimeoutExpired as exc:
        raise _WorkerTimedOut from exc
    return bytes(buffers["stdout"]), bytes(buffers["stderr"])


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
        process: subprocess.Popen[bytes] | None = None
        try:
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
                stdout, _stderr = _bounded_communicate(
                    process,
                    request.envelope,
                    self._timeout_seconds,
                    self._max_output_bytes,
                )
            except _WorkerTimedOut as exc:
                raise CustodyError("worker timeout") from exc
            except _OutputLimitExceeded as exc:
                if exc.stream_name == "stderr":
                    raise CustodyError("worker stderr too large") from exc
                raise CustodyError("worker output too large") from exc
            except OSError as exc:
                raise CustodyError("worker I/O failure") from exc
        finally:
            if process is not None:
                # The leader may have exited while an ordinary same-group
                # descendant remains. Every completion path requests group
                # termination and bounded leader reaping.
                _terminate_and_reap(process)
        if process is None:
            raise CustodyError("worker unavailable")
        if process.returncode != 0:
            raise CustodyError("worker failure")
        try:
            message = json.loads(
                stdout.decode("utf-8"), object_pairs_hook=_object_without_duplicate_keys
            )
        except (UnicodeDecodeError, ValueError) as exc:
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
        if not isinstance(message["uv_mode"], str) or message["uv_mode"] not in {
            "built-in",
            "pin",
        }:
            raise CustodyError("unknown UV mode")
        if not isinstance(message["timing_class"], str) or message[
            "timing_class"
        ] not in {"interactive", "bounded"}:
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
