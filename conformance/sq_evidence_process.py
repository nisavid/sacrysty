#!/usr/bin/env python3
"""Bound the selected sq/sqv processes used by disposable evidence probes."""

from __future__ import annotations

import errno
import os
import pathlib
import selectors
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Sequence
from typing import BinaryIO

TOOL_TIMEOUT_SECONDS = 120.0
PROBE_TIMEOUT_SECONDS = 900.0
STREAM_LIMIT_BYTES = 1024 * 1024
FILE_LIMIT_BYTES = 16 * 1024 * 1024
TERMINATE_GRACE_SECONDS = 0.25
KILL_GRACE_SECONDS = 1.0
# A probe runner can be waiting on one tool helper whose selected process is in
# a separate session. Let that helper use both of its cleanup windows and exit
# before escalating against the runner group.
PROBE_TERMINATE_GRACE_SECONDS = (
    TERMINATE_GRACE_SECONDS + 2 * KILL_GRACE_SECONDS
)
_LIMIT_AND_EXEC = r"""
import os
import resource
import signal
import sys

try:
    limit = int(sys.argv[1])
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT, signal.SIGTERM})
    os.execvpe(sys.argv[2], sys.argv[2:], os.environ)
except Exception as error:
    os.write(2, f"selected process setup failed: {error}\n".encode("utf-8", "replace"))
    os._exit(125)
"""


class ProcessBoundaryError(RuntimeError):
    """A selected process crossed an evidence-runner resource boundary."""


class ProcessInterrupted(ProcessBoundaryError):
    """The helper was asked to stop while its selected process was active."""


def _errno_name(error: OSError) -> str:
    if error.errno is None:
        return "unknown errno"
    return errno.errorcode.get(error.errno, f"errno {error.errno}")


def _group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except OSError as exc:
        raise ProcessBoundaryError(
            f"process-group cleanup check failed ({_errno_name(exc)})"
        ) from exc
    return True


def _signal_group(process_group: int, selected_signal: signal.Signals) -> bool:
    try:
        os.killpg(process_group, selected_signal)
    except ProcessLookupError:
        return False
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return False
        raise ProcessBoundaryError(
            f"process-group cleanup signal failed ({_errno_name(exc)})"
        ) from exc
    return True


def _wait_for_group_exit(process: subprocess.Popen[bytes], seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        process.poll()
        if not _group_exists(process.pid):
            return True
        time.sleep(0.01)
    process.poll()
    return not _group_exists(process.pid)


def _reap_leader_after_group_failure(
    process: subprocess.Popen[bytes], group_cleanup_error: ProcessBoundaryError
) -> None:
    leader_signal_error: OSError | None = None
    try:
        process.kill()
    except OSError as exc:
        if exc.errno != errno.ESRCH:
            leader_signal_error = exc
    try:
        process.wait(timeout=KILL_GRACE_SECONDS)
    except subprocess.TimeoutExpired as exc:
        if leader_signal_error is not None:
            raise ProcessBoundaryError(
                "process leader cleanup signal failed "
                f"({_errno_name(leader_signal_error)}) after group cleanup failure"
            ) from group_cleanup_error
        raise ProcessBoundaryError(
            "process leader cleanup timed out after group cleanup failure"
        ) from exc
    raise group_cleanup_error


def _signal_group_or_reap_leader(
    process: subprocess.Popen[bytes], selected_signal: signal.Signals
) -> None:
    try:
        _signal_group(process.pid, selected_signal)
    except ProcessBoundaryError as group_cleanup_error:
        _reap_leader_after_group_failure(process, group_cleanup_error)


def _terminate_and_reap(process: subprocess.Popen[bytes], mode: str) -> None:
    terminate_grace_seconds = (
        PROBE_TERMINATE_GRACE_SECONDS
        if mode == "probe"
        else TERMINATE_GRACE_SECONDS
    )
    _signal_group_or_reap_leader(process, signal.SIGTERM)
    try:
        if _wait_for_group_exit(process, terminate_grace_seconds):
            return
    except ProcessBoundaryError as group_cleanup_error:
        _reap_leader_after_group_failure(process, group_cleanup_error)

    _signal_group_or_reap_leader(process, signal.SIGKILL)
    try:
        if not _wait_for_group_exit(process, KILL_GRACE_SECONDS):
            if process.poll() is None:
                raise ProcessBoundaryError("process leader cleanup timed out")
            raise ProcessBoundaryError("process-group cleanup timed out")
    except ProcessBoundaryError as group_cleanup_error:
        _reap_leader_after_group_failure(process, group_cleanup_error)


def _normalized_status(returncode: int) -> int:
    return returncode if returncode >= 0 else 128 - returncode


def _regular_file_limit_reached(directory: pathlib.Path) -> bool:
    try:
        for current_root, _, files in os.walk(directory, followlinks=False):
            for name in files:
                metadata = os.stat(
                    pathlib.Path(current_root, name), follow_symlinks=False
                )
                if (
                    stat.S_ISREG(metadata.st_mode)
                    and metadata.st_size >= FILE_LIMIT_BYTES
                ):
                    return True
    except OSError as exc:
        raise ProcessBoundaryError("regular-file bound check failed") from exc
    return False


def _timeout_for(mode: str) -> float:
    if mode == "tool":
        return TOOL_TIMEOUT_SECONDS
    if mode == "probe":
        return PROBE_TIMEOUT_SECONDS
    raise ProcessBoundaryError(f"unknown sq evidence process mode: {mode}")


def _capture_ready_streams(
    mode: str,
    selector: selectors.BaseSelector,
    streams: dict[BinaryIO, tuple[str, BinaryIO]],
    counts: dict[str, int],
    wait_seconds: float,
) -> bool:
    events = selector.select(wait_seconds)
    for key, _ in events:
        stream = key.fileobj
        if not hasattr(stream, "fileno"):
            raise ProcessBoundaryError("selected process stream is invalid")
        try:
            chunk = os.read(stream.fileno(), 64 * 1024)
        except BlockingIOError:
            continue
        if not chunk:
            selector.unregister(stream)
            stream.close()
            continue
        label, destination = streams[stream]
        available = STREAM_LIMIT_BYTES - counts[label]
        if available > 0:
            destination.write(chunk[:available])
            counts[label] += min(len(chunk), available)
        if len(chunk) > available:
            destination.flush()
            raise ProcessBoundaryError(f"{mode} process exceeded {label} limit")
    return bool(events)


def run_process(
    mode: str,
    status_path: pathlib.Path,
    stdout_path: pathlib.Path,
    stderr_path: pathlib.Path,
    command: Sequence[str],
) -> int:
    """Run one selected process and write its bounded streams and exit status."""

    timeout_seconds = _timeout_for(mode)
    if not command:
        raise ProcessBoundaryError("selected process command is empty")
    paths = (status_path, stdout_path, stderr_path)
    if len({path.resolve() for path in paths}) != len(paths):
        raise ProcessBoundaryError("selected process output paths must be distinct")
    output_parents = {path.parent.resolve() for path in paths}
    if len(output_parents) != 1:
        raise ProcessBoundaryError("selected process outputs must share a directory")
    output_directory = output_parents.pop()
    if any(path.exists() for path in paths):
        raise ProcessBoundaryError("selected process output path already exists")

    try:
        stdout_file = stdout_path.open("xb")
    except OSError as exc:
        raise ProcessBoundaryError("selected process output cannot be created") from exc
    try:
        stderr_file = stderr_path.open("xb")
    except OSError as exc:
        stdout_file.close()
        raise ProcessBoundaryError("selected process output cannot be created") from exc

    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    cleanup_complete = False
    previous_sigterm_handler: object | None = None
    previous_startup_signal_mask: set[signal.Signals] | None = None
    startup_signal_mask_restored = False
    interruption_requested = False
    streams: dict[BinaryIO, tuple[str, BinaryIO]] = {}
    counts = {"stdout": 0, "stderr": 0}
    try:
        previous_startup_signal_mask = signal.pthread_sigmask(
            signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM}
        )

        def interrupt_selected_process(_signal_number: int, _frame: object) -> None:
            nonlocal interruption_requested
            if interruption_requested:
                return
            interruption_requested = True
            raise ProcessInterrupted(f"{mode} process interrupted")

        previous_sigterm_handler = signal.signal(
            signal.SIGTERM, interrupt_selected_process
        )
        try:
            try:
                process = subprocess.Popen(
                    [
                        sys.executable,
                        "-B",
                        "-c",
                        _LIMIT_AND_EXEC,
                        str(FILE_LIMIT_BYTES),
                        *command,
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise ProcessBoundaryError("selected process could not start") from exc
        finally:
            startup_signal_mask_restored = True
            signal.pthread_sigmask(
                signal.SIG_SETMASK, previous_startup_signal_mask
            )
        if process.stdout is None or process.stderr is None:
            raise ProcessBoundaryError("selected process pipes are unavailable")

        streams = {
            process.stdout: ("stdout", stdout_file),
            process.stderr: ("stderr", stderr_file),
        }
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)

        deadline = time.monotonic() + timeout_seconds
        while selector.get_map() or process.poll() is None:
            if process.poll() is not None and not cleanup_complete:
                _terminate_and_reap(process, mode)
                cleanup_complete = True

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProcessBoundaryError(f"{mode} process timed out")
            if not selector.get_map():
                time.sleep(min(0.01, remaining))
                continue

            _capture_ready_streams(
                mode, selector, streams, counts, min(0.05, remaining)
            )

        if not cleanup_complete:
            _terminate_and_reap(process, mode)
            cleanup_complete = True
        if process.returncode is None:
            raise ProcessBoundaryError("selected process has no exit status")
        if _regular_file_limit_reached(output_directory):
            raise ProcessBoundaryError(f"{mode} process reached regular-file limit")
        child_status = _normalized_status(process.returncode)
        if child_status == 125:
            raise ProcessBoundaryError(f"{mode} process setup or execution failed")
        try:
            with status_path.open("x", encoding="ascii") as status_file:
                status_file.write(f"{child_status}\n")
        except OSError as exc:
            raise ProcessBoundaryError(
                "selected process status cannot be written"
            ) from exc
        return child_status
    except BaseException as original_error:
        if process is not None and not cleanup_complete:
            try:
                _terminate_and_reap(process, mode)
            except ProcessBoundaryError as cleanup_error:
                raise cleanup_error from original_error
        drain_deadline = time.monotonic() + KILL_GRACE_SECONDS
        while selector.get_map():
            remaining = drain_deadline - time.monotonic()
            if remaining <= 0 or not _capture_ready_streams(
                mode, selector, streams, counts, min(0.05, remaining)
            ):
                break
        raise
    finally:
        if (
            previous_startup_signal_mask is not None
            and not startup_signal_mask_restored
        ):
            signal.pthread_sigmask(
                signal.SIG_SETMASK, previous_startup_signal_mask
            )
        if previous_sigterm_handler is not None:
            signal.signal(signal.SIGTERM, previous_sigterm_handler)
        selector.close()
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
        stdout_file.close()
        stderr_file.close()


def main(arguments: Sequence[str]) -> int:
    if len(arguments) < 6 or arguments[4] != "--":
        print(
            "usage: sq_evidence_process.py <tool|probe> <status> <stdout> <stderr> -- <command> [args...]",
            file=sys.stderr,
        )
        return 64
    mode, status, stdout, stderr = arguments[:4]
    try:
        run_process(
            mode,
            pathlib.Path(status),
            pathlib.Path(stdout),
            pathlib.Path(stderr),
            arguments[5:],
        )
    except ProcessBoundaryError as exc:
        print(f"sq evidence {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
