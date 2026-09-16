#!/usr/bin/env python3
"""Executable synthetic conformance for the one-shot FIDO adapter."""

from __future__ import annotations

import errno
import fcntl
import os
import pathlib
import signal
import stat
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))
import adapters.fido_custody as fido_custody
from adapters.fido_custody import CustodyError, CustodyRequest, OneShotCustodyAdapter
from conformance.test_support import external_temporary_directory

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
        marker.write(str(os.getpid()))
    child_marker = os.path.join(directory, "interrupt-child-pid")
    child = (
        "import os,pathlib,time; "
        f"pathlib.Path({child_marker!r}).write_text(str(os.getpid()), encoding='ascii'); "
        "time.sleep(10)"
    )
    subprocess.Popen([sys.executable, "-c", child])
    time.sleep(10)
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
        "time.sleep(10)"
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
    message["uv_mode"] = []
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


def wait_for_markers(
    markers: tuple[pathlib.Path, ...],
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: float,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while not all(marker.is_file() for marker in markers):
        if process.poll() is not None:
            _stdout, stderr = process.communicate()
            raise AssertionError(
                "interruption caller exited before its worker group was ready: "
                + stderr.decode("utf-8", errors="replace")
            )
        if time.monotonic() >= deadline:
            raise AssertionError("interruption worker group did not become ready")
        time.sleep(0.01)


def process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    return True


def wait_for_process_group_exit(
    process_group: int, *, timeout_seconds: float
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while process_group_exists(process_group):
        if time.monotonic() >= deadline:
            raise AssertionError("worker process group survived cleanup")
        time.sleep(0.01)


def kill_process_group(process_group: int) -> None:
    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        pass


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

        pipe_capacity_exceeding_size = 4 << 20
        observed_pipe_capacity = default_pipe_capacity()
        if observed_pipe_capacity is not None:
            require(
                pipe_capacity_exceeding_size > observed_pipe_capacity,
                "bounded large-input fixture does not exceed pipe capacity",
            )
        complete_envelope = (
            f"complete-input:{pipe_capacity_exceeding_size}\n".encode("ascii")
            + (b"x" * pipe_capacity_exceeding_size)
        )
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

        early_close_envelope = b"early-close\n" + (
            b"x" * pipe_capacity_exceeding_size
        )
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

        cleanup_denied_marker = (
            pathlib.Path(directory) / "cleanup-denied-child-pid"
        )
        denied_process_group: int | None = None
        cleanup_denial_calls: list[tuple[int, int]] = []
        real_killpg = os.killpg

        def constructed_group_cleanup_denial(
            process_group: int, requested_signal: int
        ) -> None:
            nonlocal denied_process_group
            denied_process_group = process_group
            cleanup_denial_calls.append((process_group, requested_signal))
            raise PermissionError(
                errno.EPERM, "constructed process-group cleanup denial"
            )

        cleanup_denied_child: int | None = None
        cleanup_denied_child_group: int | None = None
        try:
            # Constructed evidence: inject EPERM only at the adapter's killpg
            # boundary. The saved syscall and PID marker provide an independent
            # fallback for the disposable descendant on every assertion path.
            fido_custody.os.killpg = constructed_group_cleanup_denial
            expect_failure(
                OneShotCustodyAdapter(command, environment=environment),
                request_for("cleanup-denied"),
                "worker cleanup failure",
            )
        finally:
            fido_custody.os.killpg = real_killpg
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
                try:
                    real_killpg(denied_process_group, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if cleanup_denied_child is not None:
                try:
                    os.kill(cleanup_denied_child, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if denied_process_group is not None:
                wait_for_process_group_exit(
                    denied_process_group, timeout_seconds=2.0
                )
        require(
            cleanup_denial_calls == [(denied_process_group, signal.SIGKILL)],
            "constructed cleanup denial did not replace one group-kill attempt",
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
            wait_for_markers(
                (worker_pid_marker, child_pid_marker),
                interrupted_process,
                timeout_seconds=3.0,
            )
            worker_pid = int(worker_pid_marker.read_text(encoding="ascii"))
            child_pid = int(child_pid_marker.read_text(encoding="ascii"))
            require(
                os.getpgid(worker_pid) == worker_pid,
                "interruption worker did not lead its fresh process group",
            )
            require(
                os.getpgid(child_pid) == worker_pid,
                "interruption descendant was not in the worker process group",
            )
            os.kill(interrupted_process.pid, signal.SIGINT)
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
                    os.kill(interrupted_process.pid, signal.SIGINT)
                except ProcessLookupError:
                    pass
                try:
                    interrupted_process.communicate(timeout=2.0)
                except subprocess.TimeoutExpired:
                    interrupted_process.kill()
                    interrupted_process.communicate(timeout=2.0)
            if worker_pid is None and worker_pid_marker.is_file():
                worker_pid = int(worker_pid_marker.read_text(encoding="ascii"))
            if child_pid is None and child_pid_marker.is_file():
                child_pid = int(child_pid_marker.read_text(encoding="ascii"))
            if worker_pid is not None:
                kill_process_group(worker_pid)
            if child_pid is not None:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

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
