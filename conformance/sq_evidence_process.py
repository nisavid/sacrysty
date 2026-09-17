#!/usr/bin/env python3
"""Bound the selected sq/sqv processes used by disposable evidence probes."""

from __future__ import annotations

import json
import os
import pathlib
import selectors
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import BinaryIO

ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))

from sacrysty_runtime.process_groups import (
    ProcessGroupError,
    ProcessGroupOwnershipLost,
    SignalStep,
    leader_exited_unreaped,
    terminate_and_reap,
)

STREAM_LIMIT_BYTES = 1024 * 1024
FILE_LIMIT_BYTES = 16 * 1024 * 1024
KILL_GRACE_SECONDS = 1.0
INNER_CLEANUP_SECONDS = 0.25 + 2 * KILL_GRACE_SECONDS
OUTER_COOPERATIVE_MARGIN_SECONDS = 1.0
PROCESS_CLEANUP_RECEIPT = b"io.nisavid.sacrysty.process-cleanup/v1\n"
RUNNER_CLEANUP_RECEIPT = b"io.nisavid.sacrysty.runner-cleanup/v1\n"


@dataclass(frozen=True)
class ProcessLimits:
    timeout_seconds: float
    terminate_grace_seconds: float


@dataclass(frozen=True)
class ProcessOutputPaths:
    status: pathlib.Path
    stdout: pathlib.Path
    stderr: pathlib.Path

    def all(self) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        return self.status, self.stdout, self.stderr


@dataclass(frozen=True)
class CleanupReceipt:
    """Private same-run proof that an owned selected group is absent."""

    path: pathlib.Path

    @classmethod
    def for_status(cls, status_path: pathlib.Path) -> CleanupReceipt:
        return cls(pathlib.Path(f"{status_path}.cleanup"))

    def write(self) -> None:
        try:
            with self.path.open("xb") as stream:
                stream.write(PROCESS_CLEANUP_RECEIPT)
        except OSError as exc:
            raise ProcessBoundaryError(
                "process cleanup receipt cannot be written"
            ) from exc

    def consume(self) -> None:
        try:
            content = self.path.read_bytes()
            if content != PROCESS_CLEANUP_RECEIPT:
                raise ProcessBoundaryError("process cleanup receipt is invalid")
            self.path.unlink()
        except ProcessBoundaryError:
            raise
        except OSError as exc:
            raise ProcessBoundaryError(
                "process cleanup receipt is unavailable"
            ) from exc


def _runner_receipt_path(status_path: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(f"{status_path}.runner-cleanup")


def _cancellation_marker_path(status_path: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(f"{status_path}.cancel")


PROCESS_LIMITS = {
    "tool": ProcessLimits(timeout_seconds=120.0, terminate_grace_seconds=0.25),
    # A probe runner can be waiting on one tool helper whose selected process
    # is in a separate session. Let that helper use both of its cleanup windows
    # and exit before escalating against the runner group.
    "probe": ProcessLimits(
        timeout_seconds=900.0,
        terminate_grace_seconds=(
            INNER_CLEANUP_SECONDS + OUTER_COOPERATIVE_MARGIN_SECONDS
        ),
    ),
}
_LIMIT_AND_EXEC = r"""
import json
import os
import resource
import signal
import sys

try:
    limit = int(sys.argv[1])
    selected_environment = json.loads(sys.argv[2])
    if not isinstance(selected_environment, dict) or any(
        not isinstance(name, str) or not isinstance(value, str)
        for name, value in selected_environment.items()
    ):
        raise ValueError("selected process environment is invalid")
    command = sys.argv[3:]
    if not command:
        raise ValueError("selected process command is empty")
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT, signal.SIGTERM})
    os.execvpe(command[0], command, selected_environment)
except Exception as error:
    os.write(2, f"selected process setup failed: {error}\n".encode("utf-8", "replace"))
    os._exit(125)
"""


class ProcessBoundaryError(RuntimeError):
    """A selected process crossed an evidence-runner resource boundary."""


class ProcessInterrupted(ProcessBoundaryError):
    """The helper was asked to stop while its selected process was active."""


class _ProcessOwnershipLost(ProcessBoundaryError):
    """The selected leader was reaped outside this process boundary."""


def _leader_exited_unreaped(process: subprocess.Popen[bytes]) -> bool:
    try:
        return leader_exited_unreaped(process)
    except ProcessGroupOwnershipLost as exc:
        raise _ProcessOwnershipLost("process leader ownership was lost") from exc
    except ProcessGroupError as exc:
        raise ProcessBoundaryError(str(exc)) from exc


def _terminate_and_reap(
    process: subprocess.Popen[bytes], limits: ProcessLimits
) -> None:
    try:
        terminate_and_reap(
            process,
            (
                SignalStep(signal.SIGTERM, limits.terminate_grace_seconds),
                SignalStep(signal.SIGKILL),
            ),
            leader_wait_seconds=KILL_GRACE_SECONDS,
            absence_wait_seconds=KILL_GRACE_SECONDS,
        )
    except ProcessGroupOwnershipLost as exc:
        raise _ProcessOwnershipLost("process leader ownership was lost") from exc
    except ProcessGroupError as exc:
        raise ProcessBoundaryError(str(exc)) from exc


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


def _limits_for(mode: str) -> ProcessLimits:
    try:
        return PROCESS_LIMITS[mode]
    except KeyError as exc:
        raise ProcessBoundaryError(f"unknown sq evidence process mode: {mode}") from exc


def _make_private_directory(path: pathlib.Path) -> None:
    try:
        path.mkdir(mode=0o700)
    except OSError as exc:
        raise ProcessBoundaryError(
            "selected process environment cannot be created"
        ) from exc


def _selected_environment(
    mode: str, output_paths: ProcessOutputPaths
) -> dict[str, str]:
    """Build the value-free environment for one runner or selected tool."""

    path = os.environ.get("PATH")
    if not path:
        raise ProcessBoundaryError("selected process PATH is unavailable")
    environment_root = output_paths.status.parent / (
        f".{output_paths.status.name}.environment"
    )
    _make_private_directory(environment_root)
    directories = {
        "HOME": environment_root / "home",
        "TMPDIR": environment_root / "tmp",
        "XDG_CACHE_HOME": environment_root / "xdg-cache",
        "XDG_CONFIG_HOME": environment_root / "xdg-config",
        "XDG_DATA_HOME": environment_root / "xdg-data",
        "GNUPGHOME": environment_root / "gnupg",
    }
    for directory in directories.values():
        _make_private_directory(directory)
    environment = {name: str(directory) for name, directory in directories.items()}
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": str(environment_root / "missing-global-gitconfig"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": path,
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    if sys.platform == "darwin":
        # macOS process startup can add this key while the Python exec wrapper
        # runs. Supply a value-free runtime-derived value so the final selected
        # environment remains explicit rather than forwarding an ambient value
        # or admitting a startup-added key after the fact.
        environment["__CF_USER_TEXT_ENCODING"] = f"0x{os.getuid():X}:0:0"
    if mode == "probe":
        for name in ("SQ", "SQV"):
            selected = os.environ.get(name)
            if selected:
                environment[name] = selected
        environment["SACRYSTY_RUNNER_CLEANUP_RECEIPT"] = str(
            _runner_receipt_path(output_paths.status)
        )
    return environment


def _consume_runner_receipt(path: pathlib.Path) -> None:
    try:
        content = path.read_bytes()
        if content != RUNNER_CLEANUP_RECEIPT:
            raise ProcessBoundaryError("runner cleanup receipt is invalid")
        path.unlink()
    except ProcessBoundaryError:
        raise
    except OSError as exc:
        raise ProcessBoundaryError("runner cleanup receipt is unavailable") from exc


def _cancellation_requested(mode: str, output_paths: ProcessOutputPaths) -> bool:
    return mode == "probe" and _cancellation_marker_path(output_paths.status).exists()


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
    output_paths: ProcessOutputPaths,
    command: Sequence[str],
) -> int:
    """Run one selected process and write its bounded streams and exit status."""

    limits = _limits_for(mode)
    if not command:
        raise ProcessBoundaryError("selected process command is empty")
    paths = output_paths.all()
    cleanup_receipt = CleanupReceipt.for_status(output_paths.status)
    runner_receipt = _runner_receipt_path(output_paths.status)
    if len({path.resolve() for path in paths}) != len(paths):
        raise ProcessBoundaryError("selected process output paths must be distinct")
    output_parents = {path.parent.resolve() for path in paths}
    if len(output_parents) != 1:
        raise ProcessBoundaryError("selected process outputs must share a directory")
    output_directory = output_parents.pop()
    reserved_paths = (*paths, cleanup_receipt.path, runner_receipt)
    if any(path.exists() for path in reserved_paths):
        raise ProcessBoundaryError("selected process output path already exists")
    selected_environment = _selected_environment(mode, output_paths)
    serialized_environment = json.dumps(
        selected_environment,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )

    try:
        stdout_file = output_paths.stdout.open("xb")
    except OSError as exc:
        raise ProcessBoundaryError("selected process output cannot be created") from exc
    try:
        stderr_file = output_paths.stderr.open("xb")
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

    def record_completed_cleanup() -> None:
        if process is not None and not cleanup_complete:
            raise ProcessBoundaryError("process cleanup was not confirmed")
        if mode == "probe" and process is not None and process.returncode != 125:
            _consume_runner_receipt(runner_receipt)
        cleanup_receipt.write()

    try:
        if _cancellation_requested(mode, output_paths):
            raise ProcessInterrupted(f"{mode} process interrupted")
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
                        serialized_environment,
                        *command,
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=selected_environment,
                    start_new_session=True,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise ProcessBoundaryError("selected process could not start") from exc
        finally:
            startup_signal_mask_restored = True
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_startup_signal_mask)
        if process.stdout is None or process.stderr is None:
            raise ProcessBoundaryError("selected process pipes are unavailable")

        streams = {
            process.stdout: ("stdout", stdout_file),
            process.stderr: ("stderr", stderr_file),
        }
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)

        deadline = time.monotonic() + limits.timeout_seconds
        while selector.get_map() or not cleanup_complete:
            if _cancellation_requested(mode, output_paths):
                raise ProcessInterrupted(f"{mode} process interrupted")
            if not cleanup_complete and _leader_exited_unreaped(process):
                _terminate_and_reap(process, limits)
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

        if process.returncode is None:
            raise ProcessBoundaryError("selected process has no exit status")
        if _regular_file_limit_reached(output_directory):
            raise ProcessBoundaryError(f"{mode} process reached regular-file limit")
        child_status = _normalized_status(process.returncode)
        if child_status == 125:
            raise ProcessBoundaryError(f"{mode} process setup or execution failed")
        record_completed_cleanup()
        try:
            with output_paths.status.open("x", encoding="ascii") as status_file:
                status_file.write(f"{child_status}\n")
        except OSError as exc:
            raise ProcessBoundaryError(
                "selected process status cannot be written"
            ) from exc
        return child_status
    except BaseException as original_error:
        if (
            process is not None
            and not cleanup_complete
            and process.returncode is None
            and not isinstance(original_error, _ProcessOwnershipLost)
        ):
            try:
                _terminate_and_reap(process, limits)
                cleanup_complete = True
            except ProcessBoundaryError as cleanup_error:
                raise cleanup_error from original_error
        if process is not None and not cleanup_complete:
            raise
        drain_deadline = time.monotonic() + KILL_GRACE_SECONDS
        while selector.get_map():
            remaining = drain_deadline - time.monotonic()
            if remaining <= 0 or not _capture_ready_streams(
                mode, selector, streams, counts, min(0.05, remaining)
            ):
                break
        try:
            record_completed_cleanup()
        except ProcessBoundaryError as cleanup_error:
            raise cleanup_error from original_error
        raise
    finally:
        if (
            previous_startup_signal_mask is not None
            and not startup_signal_mask_restored
        ):
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_startup_signal_mask)
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
            ProcessOutputPaths(
                status=pathlib.Path(status),
                stdout=pathlib.Path(stdout),
                stderr=pathlib.Path(stderr),
            ),
            arguments[5:],
        )
    except ProcessBoundaryError as exc:
        print(f"sq evidence {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
