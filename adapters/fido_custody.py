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

import hashlib
import os
import selectors
import signal
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import FrameType
from typing import BinaryIO

from sacrysty_runtime.process_groups import (
    ProcessGroupError,
    ProcessGroupOwnershipLost,
    SignalStep,
    leader_exited_unreaped,
    terminate_and_reap,
)
from sacrysty_runtime.strict_json import StrictJsonError, decode_strict_json

_UNBLOCK_CANCELLATION_AND_EXEC = r"""
import os
import signal
import sys

try:
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT, signal.SIGTERM})
    os.execvpe(sys.argv[1], sys.argv[1:], os.environ)
except OSError:
    os.write(2, b"worker setup failed\n")
    os._exit(125)
"""


class CustodyError(RuntimeError):
    """A fail-closed operation result with a value-free diagnostic."""


class _OutputLimitExceeded(Exception):
    def __init__(self, stream_name: str) -> None:
        self.stream_name = stream_name


class _WorkerTimedOut(Exception):
    pass


class _CallerTerminated(BaseException):
    def __init__(self, signal_number: int, frame: FrameType | None) -> None:
        self.signal_number = signal_number
        self.frame = frame


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


def _close_pipe(pipe: BinaryIO) -> None:
    try:
        pipe.close()
    except OSError:
        pass


def _terminate_and_reap(process: subprocess.Popen[bytes]) -> None:
    """Request group termination, close pipes, and boundedly attempt leader reaping."""

    try:
        terminate_and_reap(
            process,
            (SignalStep(signal.SIGKILL),),
            leader_wait_seconds=0.5,
            absence_wait_seconds=0.5,
        )
    except ProcessGroupOwnershipLost as exc:
        raise CustodyError("worker ownership lost") from exc
    except ProcessGroupError as exc:
        raise CustodyError("worker cleanup failure") from exc
    finally:
        for pipe in (process.stdin, process.stdout, process.stderr):
            if pipe is not None:
                _close_pipe(pipe)


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

    while not leader_exited_unreaped(process):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _WorkerTimedOut
        time.sleep(min(0.01, remaining))
    return bytes(buffers["stdout"]), bytes(buffers["stderr"])


def _propagate_sigterm(
    previous_handler: object, cancellation: _CallerTerminated
) -> None:
    if previous_handler == signal.SIG_DFL:
        os.kill(os.getpid(), signal.SIGTERM)
        raise CustodyError("worker interruption propagation failed")
    if callable(previous_handler):
        previous_handler(cancellation.signal_number, cancellation.frame)
        raise CustodyError("worker interrupted")
    raise CustodyError("worker interrupted")


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
        process_owned = True
        cancellation: _CallerTerminated | None = None
        previous_signal_mask: set[signal.Signals] | None = None
        previous_sigterm_handler: object | None = None
        sigterm_handler_installed = False
        try:
            previous_signal_mask = signal.pthread_sigmask(
                signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM}
            )

            def terminate_caller(signal_number: int, frame: FrameType | None) -> None:
                raise _CallerTerminated(signal_number, frame)

            previous_sigterm_handler = signal.getsignal(signal.SIGTERM)
            if previous_sigterm_handler != signal.SIG_IGN:
                signal.signal(signal.SIGTERM, terminate_caller)
                sigterm_handler_installed = True
            try:
                command = self._command
                if not {signal.SIGINT, signal.SIGTERM} <= previous_signal_mask:
                    command = (
                        sys.executable,
                        "-B",
                        "-c",
                        _UNBLOCK_CANCELLATION_AND_EXEC,
                        *command,
                    )
                try:
                    process = subprocess.Popen(
                        command,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        env=self._environment,
                        close_fds=True,
                        start_new_session=True,
                    )
                except OSError as exc:
                    raise CustodyError("worker unavailable") from exc
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_signal_mask)
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
            except ProcessGroupOwnershipLost as exc:
                process_owned = False
                raise CustodyError("worker ownership lost") from exc
        except _CallerTerminated as exc:
            cancellation = exc
        finally:
            if previous_signal_mask is not None:
                signal.pthread_sigmask(
                    signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM}
                )
            try:
                if process is not None and process_owned:
                    # The leader may have exited while an ordinary same-group
                    # descendant remains. Every completion path requests group
                    # termination and bounded leader reaping.
                    _terminate_and_reap(process)
            finally:
                if sigterm_handler_installed and previous_sigterm_handler is not None:
                    signal.signal(signal.SIGTERM, previous_sigterm_handler)
                if previous_signal_mask is not None:
                    signal.pthread_sigmask(signal.SIG_SETMASK, previous_signal_mask)
        if cancellation is not None:
            if previous_sigterm_handler is None:
                raise CustodyError("worker interrupted")
            _propagate_sigterm(previous_sigterm_handler, cancellation)
        if process is None:
            raise CustodyError("worker unavailable")
        if process.returncode != 0:
            raise CustodyError("worker failure")
        try:
            message = decode_strict_json(stdout)
        except StrictJsonError as exc:
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
