#!/usr/bin/env python3
"""Executable synthetic conformance for the one-shot FIDO adapter."""

from __future__ import annotations

import errno
import fcntl
import os
import pathlib
import select
import signal
import stat
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))
from adapters import fido_custody
from adapters.fido_custody import CustodyError, CustodyRequest, OneShotCustodyAdapter
from conformance.test_support import external_temporary_directory
from sacrysty_runtime import process_groups

WORKER = r"""#!/usr/bin/env python3
import hashlib, json, os, subprocess, sys, time
case_line = sys.stdin.buffer.readline().decode("ascii").rstrip("\n")
case, separator, argument = case_line.partition(":")
if any(name.startswith("SACRYSTY_TEST_") for name in os.environ):
    raise SystemExit(17)
if case == "duplex":
    sys.stdout.write(" " * 32768)
    sys.stdout.flush()
if case == "early-close":
    sys.stdin.buffer.close()
    envelope_body = b""
else:
    envelope_body = sys.stdin.buffer.read()
if case == "complete-input":
    if not separator or not argument.isdecimal():
        raise SystemExit(18)
    expected_body_size = int(argument)
    if (
        len(envelope_body) != expected_body_size
        or envelope_body != b"x" * expected_body_size
    ):
        raise SystemExit(19)
if case == "interrupt":
    directory = os.path.dirname(__file__)
    with open(os.path.join(directory, "interrupt-worker-pid"), "w") as marker:
        marker.write(f"{os.getpid()}\n")
    child_marker = os.path.join(directory, "interrupt-child-pid")
    child = (
        "import os,pathlib,time; "
        f"pathlib.Path({child_marker!r}).write_text("
        "str(os.getpid()) + '\\n', encoding='ascii'); "
        "time.sleep(10)"
    )
    subprocess.Popen([sys.executable, "-c", child])
    time.sleep(5)
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
if case == "cleanup-denied":
    marker = os.path.join(os.path.dirname(__file__), "cleanup-denied-child-pid")
    child = (
        "import os,pathlib,time; "
        f"pathlib.Path({marker!r}).write_text(str(os.getpid()), encoding='ascii'); "
        "time.sleep(2)"
    )
    subprocess.Popen(
        [sys.executable, "-c", child],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 1.0
    while not os.path.exists(marker):
        if time.monotonic() >= deadline:
            raise SystemExit(20)
        time.sleep(0.01)
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
    # Exercise semantic rejection after controlled latency. This does not model
    # a hosted scheduler.
    time.sleep(0.2)
    message["uv_mode"] = []
if case == "non-finite":
    message["timing_class"] = float("nan")
if case == "duplicate":
    encoded = json.dumps(message, separators=(",", ":"))
    print('{"status":"rejected",' + encoded[1:], end="")
    raise SystemExit(0)
print(json.dumps(message), end="")
"""


INTERRUPTED_CALLER = r"""#!/usr/bin/env python3
import os, pathlib, sys

root = pathlib.Path(sys.argv[1])
worker = pathlib.Path(sys.argv[2])
sys.path.insert(0, str(root))

from adapters.fido_custody import CustodyRequest, OneShotCustodyAdapter

request = CustodyRequest(
    b"interrupt\n", "profile-v1", "sha256:plugin", "sha256:age"
)
try:
    OneShotCustodyAdapter(
        [sys.executable, str(worker)],
        timeout_seconds=10.0,
        environment={"PATH": os.environ["PATH"]},
    ).unwrap(request)
except KeyboardInterrupt:
    (worker.parent / "interrupt-propagated").write_text("yes", encoding="ascii")
    worker_pid = int(
        (worker.parent / "interrupt-worker-pid").read_text(encoding="ascii")
    )
    try:
        waited_pid, _status = os.waitpid(worker_pid, os.WNOHANG)
    except ChildProcessError:
        pass
    else:
        if waited_pid == 0:
            raise AssertionError("worker leader remained live after interruption")
        raise AssertionError("worker leader was not reaped by the adapter")
    (worker.parent / "interrupt-leader-reaped").write_text("yes", encoding="ascii")
    raise
else:
    raise AssertionError("interruption was converted into success")
"""


SIGTERM_CALLER = r"""#!/usr/bin/env python3
import os, pathlib, signal, sys

root = pathlib.Path(sys.argv[1])
worker = pathlib.Path(sys.argv[2])
directory = pathlib.Path(sys.argv[3])
phase = sys.argv[4]
disposition = sys.argv[5]
sys.path.insert(0, str(root))

from adapters import fido_custody
from adapters.fido_custody import CustodyRequest, OneShotCustodyAdapter

marker = directory / f"{phase}-{disposition}-worker-pid"
custom_marker = directory / f"{phase}-{disposition}-custom-handler"

class ExpectedTermination(BaseException):
    pass

if disposition == "ignored":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
elif disposition == "custom":
    def custom_handler(_signal_number, _frame):
        worker_pid = int(marker.read_text(encoding="ascii"))
        try:
            os.killpg(worker_pid, 0)
        except ProcessLookupError:
            state = "absent"
        else:
            state = "present"
        custom_marker.write_text(state, encoding="ascii")
        raise ExpectedTermination
    signal.signal(signal.SIGTERM, custom_handler)

real_popen = fido_custody.subprocess.Popen
def cancellation_popen(*arguments, **keywords):
    if phase == "before-creation":
        os.kill(os.getpid(), signal.SIGTERM)
    process = real_popen(*arguments, **keywords)
    marker.write_text(f"{process.pid}\n", encoding="ascii")
    if phase == "before-assignment":
        os.kill(os.getpid(), signal.SIGTERM)
    return process

fido_custody.subprocess.Popen = cancellation_popen
request_case = "success" if disposition == "ignored" else (
    "interrupt" if phase == "operation" else "timeout"
)
request = CustodyRequest(
    f"{request_case}\n".encode("ascii"),
    "profile-v1", "sha256:plugin", "sha256:age"
)
try:
    OneShotCustodyAdapter(
        [sys.executable, str(worker)],
        timeout_seconds=4.0,
        environment={"PATH": os.environ["PATH"]},
    ).unwrap(request)
except ExpectedTermination:
    raise SystemExit(42)
finally:
    fido_custody.subprocess.Popen = real_popen
if disposition != "ignored":
    raise AssertionError("SIGTERM did not preserve its caller disposition")
"""


PID_MARKER_PRODUCER = r"""#!/usr/bin/env python3
import os, pathlib, sys

marker = pathlib.Path(sys.argv[1])
records = (
    ("empty", b""),
    ("malformed", b"not-a-pid\n"),
    ("partial", str(os.getpid()).encode("ascii")),
    ("complete", f"{os.getpid()}\n".encode("ascii")),
)
with marker.open("wb", buffering=0) as stream:
    for label, record in records:
        stream.seek(0)
        stream.truncate()
        stream.write(record)
        sys.stdout.write(label + "\n")
        sys.stdout.flush()
        if sys.stdin.buffer.read(1) != b"+":
            raise SystemExit(21)
"""


def expect_failure(
    adapter: OneShotCustodyAdapter,
    request: CustodyRequest,
    expected_diagnostic: str | tuple[str, ...] | None = None,
) -> None:
    try:
        adapter.unwrap(request)
    except CustodyError as exc:
        if isinstance(expected_diagnostic, tuple):
            if str(exc) not in expected_diagnostic:
                raise AssertionError(
                    f"expected one of {expected_diagnostic!r}, received {str(exc)!r}"
                ) from exc
        elif expected_diagnostic is not None and str(exc) != expected_diagnostic:
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


def read_complete_pid_marker(marker: pathlib.Path) -> int | None:
    try:
        record = marker.read_bytes()
    except OSError:
        return None
    if not record.endswith(b"\n"):
        return None
    encoded_pid = record[:-1]
    if not encoded_pid.isdigit():
        return None
    try:
        pid = int(encoded_pid)
    except ValueError:
        return None
    if pid <= 0 or str(pid).encode("ascii") != encoded_pid:
        return None
    return pid


def wait_for_markers(
    markers: tuple[pathlib.Path, ...],
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: float,
) -> tuple[int, ...]:
    deadline = time.monotonic() + timeout_seconds
    while True:
        pids: list[int] = []
        for marker in markers:
            pid = read_complete_pid_marker(marker)
            if pid is None:
                break
            pids.append(pid)
        else:
            return tuple(pids)
        if process.poll() is not None:
            _stdout, stderr = process.communicate()
            raise AssertionError(
                "interruption caller exited before its worker group was ready: "
                + stderr.decode("utf-8", errors="replace")
            )
        if time.monotonic() >= deadline:
            raise AssertionError("interruption worker group did not become ready")
        time.sleep(0.01)


def require_pid_marker_producer_state(
    producer: subprocess.Popen[bytes], state: str
) -> None:
    require(producer.stdout is not None, "PID marker producer stdout was not piped")
    readable, _writable, _exceptional = select.select((producer.stdout,), (), (), 2.0)
    require(bool(readable), f"PID marker producer did not reach its {state} barrier")
    observed_state = producer.stdout.readline()
    require(
        observed_state == f"{state}\n".encode("ascii"),
        f"PID marker producer did not publish its {state} barrier",
    )


class ReadinessMarkerProbe:
    def __init__(
        self,
        marker: pathlib.Path,
        producer: subprocess.Popen[bytes],
    ) -> None:
        self.marker = marker
        self.producer = producer
        self.records_read = 0
        self.complete_record_read = False
        self.transitions = (
            ("empty", b"", "malformed"),
            ("malformed", b"not-a-pid\n", "partial"),
            ("partial", str(producer.pid).encode("ascii"), "complete"),
        )

    def is_file(self) -> bool:
        # Keep the regression red against an existence-only readiness predicate.
        return self.marker.is_file()

    def read_bytes(self) -> bytes:
        record = self.marker.read_bytes()
        self.records_read += 1
        if self.records_read <= len(self.transitions):
            state, expected_record, next_state = self.transitions[self.records_read - 1]
            require(record == expected_record, f"producer left its {state} barrier")
            require(self.producer.stdin is not None, "PID marker producer stdin closed")
            self.producer.stdin.write(b"+")
            self.producer.stdin.flush()
            require_pid_marker_producer_state(self.producer, next_state)
        else:
            self.complete_record_read = True
        return record


def check_pid_marker_readiness(directory: pathlib.Path) -> None:
    marker = directory / "readiness-producer-pid"
    producer = subprocess.Popen(
        [sys.executable, "-B", "-c", PID_MARKER_PRODUCER, str(marker)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1"},
        close_fds=True,
    )
    try:
        require(producer.stdin is not None, "PID marker producer stdin was not piped")
        require_pid_marker_producer_state(producer, "empty")
        marker_probe = ReadinessMarkerProbe(marker, producer)
        pids = wait_for_markers((marker_probe,), producer, timeout_seconds=3.0)
        require(marker_probe.records_read > 0, "empty PID marker was accepted as ready")
        require(
            marker_probe.complete_record_read,
            "readiness returned before the complete PID marker was read",
        )
        require(
            pids == (producer.pid,),
            "complete PID marker was not returned from readiness",
        )
        producer.stdin.write(b"+")
        producer.stdin.flush()
        _stdout, stderr = producer.communicate(timeout=2.0)
        require(producer.returncode == 0, "PID marker producer failed")
        require(stderr == b"", "PID marker producer wrote unexpected stderr")
    finally:
        if producer.poll() is None:
            producer.kill()
        producer.communicate(timeout=2.0)


def process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def check_permission_denied_group_probe_is_not_absence() -> None:
    real_killpg = os.killpg
    calls: list[tuple[int, int]] = []

    def deny_group_probe(process_group: int, requested_signal: int) -> None:
        calls.append((process_group, requested_signal))
        raise PermissionError(errno.EPERM, "constructed process-group probe denial")

    try:
        # Construct only the hosted syscall result at the checker boundary.
        # This Linux test does not reproduce the observed Darwin condition.
        os.killpg = deny_group_probe
        group_exists = process_group_exists(os.getpgrp())
    finally:
        os.killpg = real_killpg
    require(group_exists, "process-group probe inferred absence from EPERM")
    require(
        calls == [(os.getpgrp(), 0)],
        "process-group denial control did not exercise one existence probe",
    )


def wait_for_process_group_exit(process_group: int, *, timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    while process_group_exists(process_group):
        if time.monotonic() >= deadline:
            raise AssertionError("worker process group survived cleanup")
        time.sleep(0.01)


def check_startup_interruption_owns_worker(
    command: list[str], environment: dict[str, str]
) -> None:
    spawned_processes: list[subprocess.Popen[bytes]] = []
    real_popen = fido_custody.subprocess.Popen

    def interrupt_after_spawn(
        *arguments: object, **keywords: object
    ) -> subprocess.Popen[bytes]:
        process = real_popen(*arguments, **keywords)
        spawned_processes.append(process)
        os.kill(os.getpid(), signal.SIGINT)
        return process

    worker_was_reaped = False
    try:
        fido_custody.subprocess.Popen = interrupt_after_spawn
        try:
            OneShotCustodyAdapter(
                command,
                timeout_seconds=1.0,
                environment=environment,
            ).unwrap(request_for("timeout"))
        except KeyboardInterrupt:
            pass
        else:
            raise AssertionError("startup interruption was converted into success")
        require(len(spawned_processes) == 1, "startup did not create one worker")
        try:
            os.waitid(
                os.P_PID,
                spawned_processes[0].pid,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        except ChildProcessError:
            worker_was_reaped = True
    finally:
        fido_custody.subprocess.Popen = real_popen
        for process in spawned_processes:
            if not worker_was_reaped:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=2.0)
    require(worker_was_reaped, "startup interruption left the worker unowned")


def check_cleanup_signals_only_owned_process_group(
    command: list[str], environment: dict[str, str]
) -> None:
    signal_observations: list[tuple[int, bool]] = []
    real_killpg = process_groups.os.killpg

    def observe_group_signal(process_group: int, requested_signal: int) -> None:
        if requested_signal == 0:
            raise ProcessLookupError(errno.ESRCH, "constructed absent process group")
        try:
            os.waitid(
                os.P_PID,
                process_group,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        except ChildProcessError:
            leader_is_owned = False
        else:
            leader_is_owned = True
        signal_observations.append((requested_signal, leader_is_owned))

    try:
        # Constructed evidence: observe the cleanup syscall boundary without
        # sending a signal or attempting to force numeric PID reuse.
        process_groups.os.killpg = observe_group_signal
        result = OneShotCustodyAdapter(command, environment=environment).unwrap(
            request_for()
        )
    finally:
        process_groups.os.killpg = real_killpg
    require(
        result.plaintext == b"synthetic plaintext canary",
        "cleanup ownership control did not retain the worker result",
    )
    require(
        signal_observations == [(signal.SIGKILL, True)],
        "cleanup reached a process group after its leader was reaped",
    )


def check_nonzero_group_signal_denial_requires_definitive_absence(
    command: list[str], environment: dict[str, str]
) -> None:
    call_observations: list[tuple[int, bool]] = []
    definitive_absence_observed = False
    real_killpg = process_groups.os.killpg

    def deny_owned_group_signal(process_group: int, requested_signal: int) -> None:
        nonlocal definitive_absence_observed
        try:
            os.waitid(
                os.P_PID,
                process_group,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        except ChildProcessError:
            leader_is_owned = False
        else:
            leader_is_owned = True
        call_observations.append((requested_signal, leader_is_owned))
        if requested_signal != 0:
            raise PermissionError(
                errno.EPERM, "constructed nonzero process-group signal denial"
            )
        try:
            real_killpg(process_group, requested_signal)
        except ProcessLookupError:
            definitive_absence_observed = True
            raise

    try:
        # Construct only the observed nonzero-signal denial at the cleanup
        # syscall seam. The real child wait and signal-zero probe independently
        # establish whether the disposable process group is then absent.
        process_groups.os.killpg = deny_owned_group_signal
        result = OneShotCustodyAdapter(command, environment=environment).unwrap(
            request_for()
        )
    finally:
        process_groups.os.killpg = real_killpg
    require(
        result.plaintext == b"synthetic plaintext canary",
        "nonzero group-signal denial discarded an ordinarily completed worker result",
    )
    require(
        call_observations[0] == (signal.SIGKILL, True)
        and len(call_observations) > 1
        and all(
            requested_signal == 0 and not leader_is_owned
            for requested_signal, leader_is_owned in call_observations[1:]
        )
        and definitive_absence_observed,
        "adapter did not require definitive absence without signalling after reaping",
    )


def check_adapter_group_probe_denial_requires_absence(
    command: list[str], environment: dict[str, str]
) -> None:
    remaining_denials = 2
    group_probes = 0
    real_killpg = process_groups.os.killpg

    def construct_denial_then_absence(
        _process_group: int, requested_signal: int
    ) -> None:
        nonlocal group_probes, remaining_denials
        if requested_signal != 0:
            return
        group_probes += 1
        if remaining_denials:
            remaining_denials -= 1
            raise PermissionError(
                errno.EPERM, "constructed transient process-group denial"
            )
        raise ProcessLookupError(errno.ESRCH, "constructed absent process group")

    try:
        # Construct only the observed OS return sequence. No numeric process
        # group is signalled by this regression.
        process_groups.os.killpg = construct_denial_then_absence
        result = OneShotCustodyAdapter(command, environment=environment).unwrap(
            request_for()
        )
    finally:
        process_groups.os.killpg = real_killpg
    require(
        result.plaintext == b"synthetic plaintext canary",
        "transient group-probe denial discarded a completed worker result",
    )
    require(
        group_probes == 3 and remaining_denials == 0,
        "adapter cleanup did not require definitive process-group absence",
    )


def default_pipe_capacity() -> int | None:
    get_pipe_size = getattr(fcntl, "F_GETPIPE_SZ", None)
    if get_pipe_size is None:
        return None
    read_fd, write_fd = os.pipe()
    try:
        return int(fcntl.fcntl(write_fd, get_pipe_size))
    finally:
        os.close(read_fd)
        os.close(write_fd)


def check_sigterm_cancellation(directory: pathlib.Path, worker_source: str) -> None:
    caller_source = directory / "sigterm-caller.py"
    caller_source.write_text(SIGTERM_CALLER, encoding="utf-8")
    cases = (
        ("before-creation", "default", -signal.SIGTERM),
        ("before-assignment", "default", -signal.SIGTERM),
        ("operation", "default", -signal.SIGTERM),
        ("before-assignment", "custom", 42),
        ("before-creation", "ignored", 0),
    )
    for phase, disposition, expected_status in cases:
        case_directory = directory / f"sigterm-{phase}-{disposition}"
        case_directory.mkdir()
        worker = case_directory / "worker.py"
        worker.write_text(worker_source, encoding="utf-8")
        worker.chmod(worker.stat().st_mode | stat.S_IXUSR)
        marker = case_directory / f"{phase}-{disposition}-worker-pid"
        child_marker = case_directory / "interrupt-child-pid"
        caller = subprocess.Popen(
            [
                sys.executable,
                "-B",
                str(caller_source),
                str(ROOT),
                str(worker),
                str(case_directory),
                phase,
                disposition,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1"},
            close_fds=True,
        )
        worker_pid: int | None = None
        try:
            required_markers = (
                (marker, child_marker) if phase == "operation" else (marker,)
            )
            try:
                observed = wait_for_markers(
                    required_markers, caller, timeout_seconds=3.0
                )
            except AssertionError as exc:
                raise AssertionError(
                    f"{phase} {disposition} SIGTERM fixture was not ready"
                ) from exc
            worker_pid = observed[0]
            if phase == "operation":
                require(
                    os.getpgid(worker_pid) == worker_pid,
                    "operational SIGTERM worker did not lead its process group",
                )
                caller.terminate()
            _stdout, stderr = caller.communicate(timeout=5.0)
            require(
                caller.returncode == expected_status,
                f"{phase} {disposition} SIGTERM returned {caller.returncode}: "
                + stderr.decode("utf-8", errors="replace"),
            )
            wait_for_process_group_exit(worker_pid, timeout_seconds=3.0)
            if disposition == "custom":
                custom_state = case_directory.joinpath(
                    f"{phase}-{disposition}-custom-handler"
                ).read_text(encoding="ascii")
                require(
                    custom_state == "absent",
                    "custom SIGTERM handler ran before worker cleanup",
                )
        finally:
            if caller.poll() is None:
                caller.terminate()
                try:
                    caller.communicate(timeout=2.0)
                except subprocess.TimeoutExpired:
                    caller.kill()
                    caller.communicate(timeout=2.0)
            if worker_pid is None:
                worker_pid = read_complete_pid_marker(marker)
            if worker_pid is not None:
                wait_for_process_group_exit(worker_pid, timeout_seconds=6.0)


def main() -> None:
    request = request_for()
    with external_temporary_directory(ROOT, prefix="sacrysty-fido-test-") as directory:
        directory_path = pathlib.Path(directory)
        check_pid_marker_readiness(directory_path)
        check_permission_denied_group_probe_is_not_absence()
        check_sigterm_cancellation(directory_path, WORKER)
        worker = directory_path / "worker.py"
        worker.write_text(WORKER)
        worker.chmod(worker.stat().st_mode | stat.S_IXUSR)
        command = [sys.executable, str(worker)]
        environment = {
            "PATH": os.environ["PATH"],
            "SACRYSTY_TEST_LEAK": "must-not-reach-worker",
        }
        adapter = OneShotCustodyAdapter(command, environment=environment)
        check_startup_interruption_owns_worker(command, environment)
        check_cleanup_signals_only_owned_process_group(command, environment)
        check_nonzero_group_signal_denial_requires_definitive_absence(
            command, environment
        )
        check_adapter_group_probe_denial_requires_absence(command, environment)
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

        pipe_capacity_exceeding_size = 4 << 20
        observed_pipe_capacity = default_pipe_capacity()
        if observed_pipe_capacity is not None:
            require(
                pipe_capacity_exceeding_size > observed_pipe_capacity,
                "bounded large-input fixture does not exceed pipe capacity",
            )
        complete_envelope = f"complete-input:{pipe_capacity_exceeding_size}\n".encode(
            "ascii"
        ) + (b"x" * pipe_capacity_exceeding_size)
        large_input_adapter = OneShotCustodyAdapter(
            command,
            timeout_seconds=2.0,
            max_envelope_bytes=len(complete_envelope),
            environment=environment,
        )
        require(
            large_input_adapter.unwrap(
                CustodyRequest(
                    complete_envelope,
                    "profile-v1",
                    "sha256:plugin",
                    "sha256:age",
                )
            ).plaintext
            == b"synthetic plaintext canary",
            "worker consuming complete pipe-capacity-exceeding input did not succeed",
        )

        early_close_envelope = b"early-close\n" + (b"x" * pipe_capacity_exceeding_size)
        expect_failure(
            OneShotCustodyAdapter(
                command,
                timeout_seconds=2.0,
                max_envelope_bytes=len(early_close_envelope),
                environment=environment,
            ),
            CustodyRequest(
                early_close_envelope,
                "profile-v1",
                "sha256:plugin",
                "sha256:age",
            ),
            # A later non-ESRCH group-cleanup failure must remain visible over
            # the initial broken pipe. Either result rejects incomplete input.
            ("worker I/O failure", "worker cleanup failure"),
        )

        expect_failure(
            OneShotCustodyAdapter(
                command,
                timeout_seconds=1.0,
                environment=environment,
            ),
            request_for("crash"),
            "worker failure",
        )
        expect_failure(
            OneShotCustodyAdapter(
                command,
                timeout_seconds=0.1,
                environment=environment,
            ),
            request_for("timeout"),
            "worker timeout",
        )
        for case, diagnostic in (
            ("partial", "incomplete worker output"),
            ("mismatch", "plugin_digest mismatch"),
            ("bad-uv", "unknown UV mode"),
            ("duplicate", "malformed worker output"),
            ("non-finite", "malformed worker output"),
        ):
            expect_failure(
                OneShotCustodyAdapter(
                    command,
                    timeout_seconds=1.0,
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

        cleanup_denied_marker = pathlib.Path(directory) / "cleanup-denied-child-pid"
        denied_process_group: int | None = None
        cleanup_denial_calls: list[tuple[int, int, bool]] = []
        real_killpg = os.killpg

        def constructed_group_cleanup_denial(
            process_group: int, requested_signal: int
        ) -> None:
            nonlocal denied_process_group
            denied_process_group = process_group
            try:
                os.waitid(
                    os.P_PID,
                    process_group,
                    os.WEXITED | os.WNOHANG | os.WNOWAIT,
                )
            except ChildProcessError:
                leader_is_owned = False
            else:
                leader_is_owned = True
            cleanup_denial_calls.append(
                (process_group, requested_signal, leader_is_owned)
            )
            raise PermissionError(
                errno.EPERM, "constructed process-group cleanup denial"
            )

        cleanup_denied_child: int | None = None
        cleanup_denied_child_group: int | None = None
        cleanup_denial_elapsed: float | None = None
        cleanup_denial_started = time.monotonic()
        try:
            # Constructed evidence: inject EPERM only at the adapter's killpg
            # boundary. The value-free descendant self-expires on every
            # assertion path; no saved numeric identifier is signalled.
            process_groups.os.killpg = constructed_group_cleanup_denial
            expect_failure(
                OneShotCustodyAdapter(command, environment=environment),
                request_for("cleanup-denied"),
                "worker cleanup failure",
            )
            cleanup_denial_elapsed = time.monotonic() - cleanup_denial_started
        finally:
            process_groups.os.killpg = real_killpg
            if cleanup_denied_marker.is_file():
                cleanup_denied_child = int(
                    cleanup_denied_marker.read_text(encoding="ascii")
                )
                try:
                    cleanup_denied_child_group = os.getpgid(cleanup_denied_child)
                except ProcessLookupError:
                    pass
            if denied_process_group is None and cleanup_denied_child is not None:
                denied_process_group = cleanup_denied_child_group
            if denied_process_group is not None:
                wait_for_process_group_exit(denied_process_group, timeout_seconds=4.0)
        require(
            cleanup_denial_calls[0] == (denied_process_group, signal.SIGKILL, True)
            and len(cleanup_denial_calls) > 1
            and all(
                process_group == denied_process_group
                and requested_signal == 0
                and not leader_is_owned
                for process_group, requested_signal, leader_is_owned in cleanup_denial_calls[
                    1:
                ]
            ),
            "persistent cleanup denial escaped its ownership-safe failure boundary",
        )
        require(
            cleanup_denial_elapsed is not None and cleanup_denial_elapsed < 1.5,
            "persistent cleanup denial was not bounded",
        )
        require(
            cleanup_denied_child_group == denied_process_group,
            "constructed cleanup denial did not leave a same-group descendant",
        )

        caller = pathlib.Path(directory) / "interrupted-caller.py"
        caller.write_text(INTERRUPTED_CALLER, encoding="utf-8")
        worker_pid_marker = pathlib.Path(directory) / "interrupt-worker-pid"
        child_pid_marker = pathlib.Path(directory) / "interrupt-child-pid"
        interrupted_process: subprocess.Popen[bytes] | None = None
        worker_pid: int | None = None
        child_pid: int | None = None
        try:
            interrupted_process = subprocess.Popen(
                [sys.executable, "-B", str(caller), str(ROOT), str(worker)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"PATH": os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1"},
                close_fds=True,
            )
            worker_pid, child_pid = wait_for_markers(
                (worker_pid_marker, child_pid_marker),
                interrupted_process,
                timeout_seconds=3.0,
            )
            require(
                os.getpgid(worker_pid) == worker_pid,
                "interruption worker did not lead its fresh process group",
            )
            require(
                os.getpgid(child_pid) == worker_pid,
                "interruption descendant was not in the worker process group",
            )
            interrupted_process.send_signal(signal.SIGINT)
            _stdout, _stderr = interrupted_process.communicate(timeout=3.0)
            require(
                interrupted_process.returncode != 0,
                "caller interruption was converted into success",
            )
            require(
                (pathlib.Path(directory) / "interrupt-propagated").is_file(),
                "caller interruption did not propagate as KeyboardInterrupt",
            )
            require(
                (pathlib.Path(directory) / "interrupt-leader-reaped").is_file(),
                "interrupted worker leader was not reaped",
            )
            wait_for_process_group_exit(worker_pid, timeout_seconds=2.0)
        finally:
            if interrupted_process is not None and interrupted_process.poll() is None:
                try:
                    interrupted_process.send_signal(signal.SIGINT)
                except ProcessLookupError:
                    pass
                try:
                    interrupted_process.communicate(timeout=2.0)
                except subprocess.TimeoutExpired:
                    interrupted_process.kill()
                    interrupted_process.communicate(timeout=2.0)
            if worker_pid is None:
                worker_pid = read_complete_pid_marker(worker_pid_marker)
            if child_pid is None:
                child_pid = read_complete_pid_marker(child_pid_marker)
            if worker_pid is not None:
                wait_for_process_group_exit(worker_pid, timeout_seconds=6.0)

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
