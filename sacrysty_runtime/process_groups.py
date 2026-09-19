"""Owned POSIX process-group cleanup for internal Sacrysty runtimes."""

from __future__ import annotations

import errno
import os
import signal
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass


class ProcessGroupError(RuntimeError):
    """An owned process group could not be cleaned up definitively."""


class ProcessGroupOwnershipLost(ProcessGroupError):
    """The process leader was reaped outside the owning handle."""


@dataclass(frozen=True)
class SignalStep:
    """One group signal followed by a cooperative grace period."""

    selected_signal: signal.Signals
    grace_seconds: float = 0.0

    def __post_init__(self) -> None:
        if self.selected_signal == 0 or self.grace_seconds < 0:
            raise ValueError("invalid process-group cleanup step")


def _errno_name(error: OSError) -> str:
    if error.errno is None:
        return "unknown errno"
    return errno.errorcode.get(error.errno, f"errno {error.errno}")


def leader_exited_unreaped(process: subprocess.Popen[bytes]) -> bool:
    """Report leader exit without ending the caller's numeric ownership."""

    if process.returncode is not None:
        raise ProcessGroupOwnershipLost("process leader ownership was lost")
    try:
        status = os.waitid(
            os.P_PID,
            process.pid,
            os.WEXITED | os.WNOHANG | os.WNOWAIT,
        )
    except ChildProcessError as exc:
        raise ProcessGroupOwnershipLost("process leader ownership was lost") from exc
    except OSError as exc:
        raise ProcessGroupError(
            f"process leader status check failed ({_errno_name(exc)})"
        ) from exc
    return status is not None


def _signal_group(process_group: int, selected_signal: signal.Signals) -> bool:
    try:
        os.killpg(process_group, selected_signal)
    except ProcessLookupError:
        return False
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return False
        raise ProcessGroupError(
            f"process-group cleanup signal failed ({_errno_name(exc)})"
        ) from exc
    return True


def _group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return False
        raise ProcessGroupError(
            f"process-group cleanup check failed ({_errno_name(exc)})"
        ) from exc
    return True


def _wait_for_group_absence(process_group: int, seconds: float) -> None:
    deadline = time.monotonic() + seconds
    last_permission_denial: ProcessGroupError | None = None
    while True:
        try:
            exists = _group_exists(process_group)
        except ProcessGroupError as exc:
            cause = exc.__cause__
            if not isinstance(cause, OSError) or cause.errno != errno.EPERM:
                raise
            # Denial is never absence. XNU can transiently deny a signal-zero
            # probe for a group containing only zombies, so require a later
            # definitive ESRCH within the same bounded window.
            last_permission_denial = exc
        else:
            if not exists:
                return
            last_permission_denial = None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            if last_permission_denial is not None:
                raise last_permission_denial
            raise ProcessGroupError("process-group cleanup timed out")
        time.sleep(min(0.01, remaining))


def _reap_leader(process: subprocess.Popen[bytes], seconds: float) -> None:
    try:
        process.wait(timeout=seconds)
    except subprocess.TimeoutExpired as exc:
        raise ProcessGroupError("process leader cleanup timed out") from exc
    except ChildProcessError as exc:
        raise ProcessGroupOwnershipLost("process leader ownership was lost") from exc


def _fail_after_group_signal_error(
    process: subprocess.Popen[bytes],
    group_error: ProcessGroupError,
    leader_wait_seconds: float,
) -> None:
    """Bound the owned leader without pretending that descendants were cleaned."""

    signal_error: OSError | None = None
    try:
        process.kill()
    except OSError as exc:
        if exc.errno != errno.ESRCH:
            signal_error = exc
    try:
        _reap_leader(process, leader_wait_seconds)
    except ProcessGroupError as exc:
        if signal_error is not None:
            raise ProcessGroupError(
                "process leader cleanup signal failed "
                f"({_errno_name(signal_error)}) after group cleanup failure"
            ) from group_error
        raise exc from group_error
    raise group_error


def _signal_owned_group(
    process: subprocess.Popen[bytes],
    selected_signal: signal.Signals,
    leader_wait_seconds: float,
    absence_wait_seconds: float,
) -> bool:
    """Signal while leader ownership exists, or finish an exited-denial case."""

    try:
        signalled = _signal_group(process.pid, selected_signal)
    except ProcessGroupError as group_error:
        cause = group_error.__cause__
        permission_denied = isinstance(cause, OSError) and cause.errno == errno.EPERM
        if permission_denied and leader_exited_unreaped(process):
            # Reaping ends numeric group ownership. Only signal-zero checks are
            # allowed after this point, and only definitive absence succeeds.
            _reap_leader(process, leader_wait_seconds)
            _wait_for_group_absence(process.pid, absence_wait_seconds)
            return False
        _fail_after_group_signal_error(process, group_error, leader_wait_seconds)
    if not signalled:
        if leader_exited_unreaped(process):
            # ESRCH is definitive for the group, but the caller still owns the
            # exited leader handle and must reap it before ownership can end.
            _reap_leader(process, leader_wait_seconds)
            _wait_for_group_absence(process.pid, absence_wait_seconds)
            return False
        # A live session leader must name an extant process group. Bound the
        # owned leader, but do not turn this inconsistent observation into a
        # claim that any descendants were cleaned.
        _fail_after_group_signal_error(
            process,
            ProcessGroupError(
                "process group was absent while its owned leader was running"
            ),
            leader_wait_seconds,
        )
    return True


def terminate_and_reap(
    process: subprocess.Popen[bytes],
    signal_steps: Sequence[SignalStep],
    *,
    leader_wait_seconds: float,
    absence_wait_seconds: float,
) -> None:
    """Clean one owned session leader and its ordinary same-group descendants.

    The caller owns the ``Popen`` leader until this function reaps it. Nonzero
    signals are sent only before that reap. Success requires a later definitive
    signal-zero absence observation for the complete group.
    """

    if not signal_steps:
        raise ValueError("at least one process-group cleanup signal is required")
    if leader_wait_seconds <= 0 or absence_wait_seconds <= 0:
        raise ValueError("process-group cleanup windows must be positive")

    leader_already_exited = leader_exited_unreaped(process)
    for step in signal_steps:
        if not _signal_owned_group(
            process,
            step.selected_signal,
            leader_wait_seconds,
            absence_wait_seconds,
        ):
            return
        if step.grace_seconds > 0 and not leader_already_exited:
            deadline = time.monotonic() + step.grace_seconds
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(remaining)

    try:
        _reap_leader(process, leader_wait_seconds)
    except ProcessGroupError as wait_error:
        try:
            process.kill()
        except OSError as signal_error:
            if signal_error.errno != errno.ESRCH:
                raise ProcessGroupError(
                    "process leader cleanup signal failed "
                    f"({_errno_name(signal_error)})"
                ) from wait_error
        try:
            _reap_leader(process, leader_wait_seconds)
        except ProcessGroupError as final_error:
            raise final_error from wait_error
    _wait_for_group_absence(process.pid, absence_wait_seconds)
