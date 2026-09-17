#!/usr/bin/env python3
"""Regressions for the sq/sqv evidence process boundary."""

from __future__ import annotations

import errno
import json
import os
import pathlib
import signal
import subprocess
import sys
import time
import unittest
from unittest import mock

import sq_evidence_process as process_boundary
from test_support import external_temporary_directory

ROOT = pathlib.Path(__file__).parents[1]


def _close_owned_process(
    helper: subprocess.Popen[str], pid_paths: tuple[pathlib.Path, ...]
) -> None:
    if helper.poll() is None:
        helper.terminate()
    try:
        helper.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        helper.kill()
        helper.communicate(timeout=2)
    for pid_path in pid_paths:
        if not pid_path.is_file():
            continue
        pid = int(pid_path.read_text())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.01)


class SqEvidenceProcessTests(unittest.TestCase):
    def assert_process_gone(self, pid: int) -> None:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.01)
        self.fail(f"bounded process survived: {pid}")

    def make_paths(self, directory: str) -> process_boundary.ProcessOutputPaths:
        root = pathlib.Path(directory)
        return process_boundary.ProcessOutputPaths(
            status=root / "status",
            stdout=root / "stdout",
            stderr=root / "stderr",
        )

    def test_tool_and_aggregate_probe_timeouts_fail_and_reap(self) -> None:
        for mode in ("tool", "probe"):
            with self.subTest(mode), external_temporary_directory(
                ROOT, prefix=f"sacrysty-{mode}-timeout-test-"
            ) as directory:
                root = pathlib.Path(directory)
                pid_path = root / "pid"
                script = root / "hang.py"
                script.write_text(
                    "import atexit, os, pathlib, signal, time\n"
                    f"pathlib.Path({str(pid_path)!r}).write_text(str(os.getpid()))\n"
                    "def receipt():\n"
                    "    path = os.environ.get('SACRYSTY_RUNNER_CLEANUP_RECEIPT')\n"
                    "    if path and not pathlib.Path(path).exists():\n"
                    "        pathlib.Path(path).write_bytes(\n"
                    "            b'io.nisavid.sacrysty.runner-cleanup/v1\\n'\n"
                    "        )\n"
                    "def stop(_number, _frame):\n"
                    "    receipt()\n"
                    "    raise SystemExit(0)\n"
                    "atexit.register(receipt)\n"
                    "signal.signal(signal.SIGTERM, stop)\n"
                    "deadline = time.monotonic() + 5\n"
                    "while time.monotonic() < deadline:\n"
                    "    time.sleep(0.1)\n"
                )
                outputs = self.make_paths(directory)
                limits = process_boundary.PROCESS_LIMITS[mode]
                pid: int | None = None
                try:
                    with (
                        mock.patch.dict(
                            process_boundary.PROCESS_LIMITS,
                            {
                                mode: process_boundary.ProcessLimits(
                                    timeout_seconds=0.1,
                                    terminate_grace_seconds=(
                                        limits.terminate_grace_seconds
                                    ),
                                )
                            },
                        ),
                        self.assertRaisesRegex(
                            process_boundary.ProcessBoundaryError, "timed out"
                        ),
                    ):
                        process_boundary.run_process(
                            mode,
                            outputs,
                            [sys.executable, str(script)],
                        )
                finally:
                    if pid_path.is_file():
                        pid = int(pid_path.read_text())
                self.assertIsNotNone(pid)
                self.assert_process_gone(int(pid))
                self.assertFalse(outputs.status.exists())

    def test_stdout_and_stderr_floods_stop_at_the_stream_limit(self) -> None:
        for stream in ("stdout", "stderr"):
            with self.subTest(stream), external_temporary_directory(
                ROOT, prefix=f"sacrysty-{stream}-limit-test-"
            ) as directory:
                root = pathlib.Path(directory)
                script = root / "flood.py"
                descriptor = "sys.stdout" if stream == "stdout" else "sys.stderr"
                script.write_text(
                    "import sys\n"
                    f"{descriptor}.buffer.write(b'x' * 4096)\n"
                    f"{descriptor}.buffer.flush()\n"
                )
                outputs = self.make_paths(directory)
                with (
                    mock.patch.object(process_boundary, "STREAM_LIMIT_BYTES", 128),
                    self.assertRaisesRegex(
                        process_boundary.ProcessBoundaryError,
                        f"{stream} limit",
                    ),
                ):
                    process_boundary.run_process(
                        "tool", outputs, [sys.executable, str(script)]
                    )
                captured = outputs.stdout if stream == "stdout" else outputs.stderr
                self.assertLessEqual(captured.stat().st_size, 128)
                self.assertFalse(outputs.status.exists())

    def test_child_regular_file_growth_is_bounded(self) -> None:
        with external_temporary_directory(
            ROOT, prefix="sacrysty-file-limit-test-"
        ) as directory:
            root = pathlib.Path(directory)
            artifact = root / "artifact"
            script = root / "write-file.py"
            script.write_text(
                "import pathlib, sys\n"
                "pathlib.Path(sys.argv[1]).write_bytes(b'x' * 4096)\n"
            )
            outputs = self.make_paths(directory)
            with (
                mock.patch.object(process_boundary, "FILE_LIMIT_BYTES", 128),
                self.assertRaisesRegex(
                    process_boundary.ProcessBoundaryError,
                    "regular-file limit",
                ),
            ):
                process_boundary.run_process(
                    "tool",
                    outputs,
                    [sys.executable, str(script), str(artifact)],
                )
            self.assertFalse(outputs.status.exists())
            self.assertLessEqual(artifact.stat().st_size, 128)

    def test_non_esrch_cleanup_error_is_visible_and_never_admitted(self) -> None:
        with external_temporary_directory(
            ROOT, prefix="sacrysty-process-cleanup-denial-test-"
        ) as directory:
            root = pathlib.Path(directory)
            selected_pid_path = root / "selected-pid"
            descendant_pid_path = root / "descendant-pid"
            descendant_program = (
                "import os, pathlib, signal, time\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                f"pathlib.Path({str(descendant_pid_path)!r})"
                ".write_text(str(os.getpid()))\n"
                "deadline = time.monotonic() + 1.5\n"
                "while time.monotonic() < deadline:\n"
                "    time.sleep(0.1)\n"
            )
            script = root / "hang.py"
            script.write_text(
                "import os, pathlib, signal, subprocess, sys, time\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                f"pathlib.Path({str(selected_pid_path)!r})"
                ".write_text(str(os.getpid()))\n"
                "child = subprocess.Popen("
                f"[sys.executable, '-c', {descendant_program!r}])\n"
                f"marker = pathlib.Path({str(descendant_pid_path)!r})\n"
                "deadline = time.monotonic() + 2\n"
                "while not marker.is_file() and time.monotonic() < deadline:\n"
                "    if child.poll() is not None:\n"
                "        break\n"
                "    time.sleep(0.01)\n"
                "if not marker.is_file():\n"
                "    child.kill()\n"
                "    child.wait()\n"
                "    raise SystemExit(20)\n"
                "deadline = time.monotonic() + 4\n"
                "while time.monotonic() < deadline:\n"
                "    time.sleep(0.1)\n"
            )
            outputs = self.make_paths(directory)
            cleanup_calls: list[tuple[int, int]] = []
            real_killpg = os.killpg

            def deny_group_cleanup(process_group: int, requested_signal: int) -> None:
                if requested_signal != 0:
                    cleanup_calls.append((process_group, requested_signal))
                if requested_signal == signal.SIGKILL:
                    raise PermissionError(
                        errno.EPERM, "constructed process-group cleanup denial"
                    )
                real_killpg(process_group, requested_signal)

            selected_pid: int | None = None
            descendant_pid: int | None = None
            descendant_group: int | None = None
            try:
                with (
                    mock.patch.dict(
                        process_boundary.PROCESS_LIMITS,
                        {
                            "tool": process_boundary.ProcessLimits(
                                timeout_seconds=0.2,
                                terminate_grace_seconds=0.25,
                            )
                        },
                    ),
                    mock.patch.object(
                        process_boundary.os, "killpg", deny_group_cleanup
                    ),
                    self.assertRaisesRegex(
                        process_boundary.ProcessBoundaryError,
                        r"process-group cleanup signal failed \(EPERM\)",
                    ),
                ):
                    process_boundary.run_process(
                        "tool",
                        outputs,
                        [sys.executable, str(script)],
                    )
            finally:
                if selected_pid_path.is_file():
                    selected_pid = int(selected_pid_path.read_text())
                if descendant_pid_path.is_file():
                    descendant_pid = int(descendant_pid_path.read_text())
                    try:
                        descendant_group = os.getpgid(descendant_pid)
                    except ProcessLookupError:
                        pass
            self.assertIsNotNone(selected_pid)
            self.assertIsNotNone(descendant_pid)
            self.assertEqual(descendant_group, selected_pid)
            self.assertEqual(
                cleanup_calls,
                [
                    (selected_pid, signal.SIGTERM),
                    (selected_pid, signal.SIGKILL),
                ],
            )
            self.assert_process_gone(int(descendant_pid))
            self.assertFalse(outputs.status.exists())

    def test_success_reaps_an_ordinary_same_group_descendant(self) -> None:
        with external_temporary_directory(
            ROOT, prefix="sacrysty-process-group-test-"
        ) as directory:
            root = pathlib.Path(directory)
            child_pid_path = root / "child-pid"
            child_program = (
                "import os, pathlib, time\n"
                f"pid_path = pathlib.Path({str(child_pid_path)!r})\n"
                "pid_path.write_text(f'{os.getpid()}:{os.getpgrp()}')\n"
                "deadline = time.monotonic() + 5\n"
                "while time.monotonic() < deadline:\n"
                "    time.sleep(0.1)\n"
            )
            script = root / "spawn-child.py"
            script.write_text(
                "import os, pathlib, subprocess, sys, time\n"
                "child = subprocess.Popen(\n"
                f"    [sys.executable, '-c', {child_program!r}],\n"
                "    stdin=subprocess.DEVNULL,\n"
                "    stdout=subprocess.DEVNULL,\n"
                "    stderr=subprocess.DEVNULL,\n"
                ")\n"
                f"marker = pathlib.Path({str(child_pid_path)!r})\n"
                "deadline = time.monotonic() + 2\n"
                "while not marker.is_file() and time.monotonic() < deadline:\n"
                "    if child.poll() is not None:\n"
                "        break\n"
                "    time.sleep(0.01)\n"
                "if not marker.is_file() or os.getpgid(child.pid) != os.getpgrp():\n"
                "    child.kill()\n"
                "    child.wait()\n"
                "    raise SystemExit(20)\n"
            )
            outputs = self.make_paths(directory)
            child_pid: int | None = None
            child_group: int | None = None
            try:
                child_status = process_boundary.run_process(
                    "tool", outputs, [sys.executable, str(script)]
                )
            finally:
                if child_pid_path.is_file():
                    child_pid, child_group = map(
                        int, child_pid_path.read_text().split(":")
                    )
            self.assertEqual(child_status, 0)
            self.assertIsNotNone(child_pid)
            self.assertIsNotNone(child_group)
            self.assertNotEqual(child_pid, child_group)
            self.assertNotEqual(child_group, os.getpgrp())
            self.assert_process_gone(int(child_pid))

    def test_group_cleanup_signals_only_while_leader_is_owned(self) -> None:
        with external_temporary_directory(
            ROOT, prefix="sacrysty-process-leader-ownership-test-"
        ) as directory:
            root = pathlib.Path(directory)
            script = root / "exit.py"
            script.write_text("raise SystemExit(0)\n")
            outputs = self.make_paths(directory)
            signal_observations: list[tuple[int, bool]] = []

            def observe_group_signal(process_group: int, requested_signal: int) -> None:
                if requested_signal == 0:
                    raise ProcessLookupError(
                        errno.ESRCH, "constructed absent process group"
                    )
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

            # Construct the signal return sequence without signalling a numeric
            # process group or attempting to force PID reuse.
            with mock.patch.object(process_boundary.os, "killpg", observe_group_signal):
                child_status = process_boundary.run_process(
                    "tool", outputs, [sys.executable, str(script)]
                )

            self.assertEqual(child_status, 0)
            self.assertEqual(outputs.status.read_text(), "0\n")
            self.assertTrue(signal_observations)
            self.assertTrue(
                all(
                    leader_is_owned for _signal, leader_is_owned in signal_observations
                ),
                "cleanup reached a process group after its leader was reaped",
            )

    def test_nonzero_group_signal_denial_requires_definitive_absence(self) -> None:
        with external_temporary_directory(
            ROOT, prefix="sacrysty-process-nonzero-eperm-test-"
        ) as directory:
            root = pathlib.Path(directory)
            script = root / "exit.py"
            script.write_text("raise SystemExit(0)\n")
            outputs = self.make_paths(directory)
            call_observations: list[tuple[int, bool]] = []
            definitive_absence_observed = False
            real_killpg = os.killpg

            def deny_owned_group_signal(
                process_group: int, requested_signal: int
            ) -> None:
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
                        errno.EPERM,
                        "constructed nonzero process-group signal denial",
                    )
                try:
                    real_killpg(process_group, requested_signal)
                except ProcessLookupError:
                    definitive_absence_observed = True
                    raise

            # Construct only the observed nonzero-signal denial at the helper's
            # cleanup syscall seam. The real wait and signal-zero probe determine
            # whether the disposable process group is then absent.
            with mock.patch.object(
                process_boundary.os, "killpg", deny_owned_group_signal
            ):
                child_status = process_boundary.run_process(
                    "tool", outputs, [sys.executable, str(script)]
                )

            self.assertEqual(child_status, 0)
            self.assertEqual(outputs.status.read_text(), "0\n")
            self.assertEqual(call_observations[0], (signal.SIGTERM, True))
            self.assertGreater(len(call_observations), 1)
            self.assertTrue(
                all(
                    requested_signal == 0 and not leader_is_owned
                    for requested_signal, leader_is_owned in call_observations[1:]
                ),
                "helper signalled after reaping the owned leader",
            )
            self.assertTrue(definitive_absence_observed)

    def test_nonzero_group_signal_persistent_denial_fails_boundedly(self) -> None:
        with external_temporary_directory(
            ROOT, prefix="sacrysty-process-nonzero-eperm-persistent-test-"
        ) as directory:
            root = pathlib.Path(directory)
            child_pid_path = root / "child-pid"
            child_program = (
                "import os, pathlib, time\n"
                f"pathlib.Path({str(child_pid_path)!r})"
                ".write_text(f'{os.getpid()}:{os.getpgrp()}')\n"
                "deadline = time.monotonic() + 1.5\n"
                "while time.monotonic() < deadline:\n"
                "    time.sleep(0.1)\n"
            )
            script = root / "spawn-child.py"
            script.write_text(
                "import os, pathlib, subprocess, sys, time\n"
                "child = subprocess.Popen(\n"
                f"    [sys.executable, '-c', {child_program!r}],\n"
                "    stdin=subprocess.DEVNULL,\n"
                "    stdout=subprocess.DEVNULL,\n"
                "    stderr=subprocess.DEVNULL,\n"
                ")\n"
                f"marker = pathlib.Path({str(child_pid_path)!r})\n"
                "deadline = time.monotonic() + 2\n"
                "while not marker.is_file() and time.monotonic() < deadline:\n"
                "    if child.poll() is not None:\n"
                "        break\n"
                "    time.sleep(0.01)\n"
                "if not marker.is_file() or os.getpgid(child.pid) != os.getpgrp():\n"
                "    child.kill()\n"
                "    child.wait()\n"
                "    raise SystemExit(20)\n"
            )
            outputs = self.make_paths(directory)
            call_observations: list[tuple[int, bool]] = []
            real_killpg = os.killpg

            def deny_signals_and_checks(
                process_group: int, requested_signal: int
            ) -> None:
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
                if requested_signal == 0:
                    real_killpg(process_group, 0)
                    raise PermissionError(
                        errno.EPERM,
                        "constructed persistent process-group denial",
                    )
                raise PermissionError(
                    errno.EPERM,
                    "constructed nonzero process-group signal denial",
                )

            child_pid: int | None = None
            child_group: int | None = None
            started = time.monotonic()
            try:
                with (
                    mock.patch.object(process_boundary, "KILL_GRACE_SECONDS", 0.05),
                    mock.patch.object(
                        process_boundary.os, "killpg", deny_signals_and_checks
                    ),
                    self.assertRaisesRegex(
                        process_boundary.ProcessBoundaryError,
                        r"process-group cleanup check failed \(EPERM\)",
                    ),
                ):
                    process_boundary.run_process(
                        "tool", outputs, [sys.executable, str(script)]
                    )
            finally:
                elapsed = time.monotonic() - started
                if child_pid_path.is_file():
                    child_pid, child_group = map(
                        int, child_pid_path.read_text().split(":")
                    )
            self.assertLess(elapsed, 1.0)
            self.assertIsNotNone(child_pid)
            self.assertIsNotNone(child_group)
            self.assertNotEqual(child_group, os.getpgrp())
            self.assertEqual(call_observations[0], (signal.SIGTERM, True))
            self.assertGreater(len(call_observations), 1)
            self.assertTrue(
                all(
                    requested_signal == 0 and not leader_is_owned
                    for requested_signal, leader_is_owned in call_observations[1:]
                ),
                "helper signalled after reaping under persistent denial",
            )
            self.assert_process_gone(int(child_pid))
            self.assertFalse(outputs.status.exists())

    def test_transient_eperm_check_requires_eventual_group_absence(self) -> None:
        with external_temporary_directory(
            ROOT, prefix="sacrysty-process-group-eperm-test-"
        ) as directory:
            root = pathlib.Path(directory)
            child_pid_path = root / "child-pid"
            term_observed_path = root / "term-observed"
            child_program = (
                "import os, pathlib, signal, time\n"
                "def exit_on_term(_number, _frame):\n"
                f"    pathlib.Path({str(term_observed_path)!r})"
                ".write_text(str(os.getpid()))\n"
                "    os._exit(0)\n"
                "signal.signal(signal.SIGTERM, exit_on_term)\n"
                f"pathlib.Path({str(child_pid_path)!r})"
                ".write_text(f'{os.getpid()}:{os.getpgrp()}')\n"
                "deadline = time.monotonic() + 5\n"
                "while time.monotonic() < deadline:\n"
                "    time.sleep(0.1)\n"
            )
            script = root / "spawn-child.py"
            script.write_text(
                "import os, pathlib, subprocess, sys, time\n"
                "child = subprocess.Popen(\n"
                f"    [sys.executable, '-c', {child_program!r}],\n"
                "    stdin=subprocess.DEVNULL,\n"
                "    stdout=subprocess.DEVNULL,\n"
                "    stderr=subprocess.DEVNULL,\n"
                ")\n"
                f"marker = pathlib.Path({str(child_pid_path)!r})\n"
                "deadline = time.monotonic() + 2\n"
                "while not marker.is_file() and time.monotonic() < deadline:\n"
                "    if child.poll() is not None:\n"
                "        break\n"
                "    time.sleep(0.01)\n"
                "if not marker.is_file() or os.getpgid(child.pid) != os.getpgrp():\n"
                "    child.kill()\n"
                "    child.wait()\n"
                "    raise SystemExit(20)\n"
            )
            outputs = self.make_paths(directory)
            real_killpg = os.killpg
            remaining_transient_check_denials = 2
            cleanup_signal_attempts: list[int] = []
            returned_group_signal_calls: list[int] = []
            denied_group_signal_calls: list[int] = []
            call_observations: list[tuple[int, bool]] = []
            definitive_absence_observed = False

            def construct_denied_kill_then_transient_checks(
                process_group: int, requested_signal: int
            ) -> None:
                nonlocal definitive_absence_observed
                nonlocal remaining_transient_check_denials
                try:
                    leader_status = os.waitid(
                        os.P_PID,
                        process_group,
                        os.WEXITED | os.WNOHANG | os.WNOWAIT,
                    )
                except ChildProcessError:
                    leader_is_owned = False
                else:
                    leader_is_owned = leader_status is not None
                call_observations.append((requested_signal, leader_is_owned))

                if requested_signal != 0:
                    if not leader_is_owned:
                        raise AssertionError(
                            "refusing a cleanup signal without leader ownership"
                        )
                    cleanup_signal_attempts.append(requested_signal)
                    if requested_signal == signal.SIGKILL:
                        denied_group_signal_calls.append(requested_signal)
                        raise PermissionError(errno.EPERM, "constructed SIGKILL denial")
                    real_killpg(process_group, requested_signal)
                    returned_group_signal_calls.append(requested_signal)
                    deadline = time.monotonic() + 2
                    while (
                        not term_observed_path.is_file() and time.monotonic() < deadline
                    ):
                        time.sleep(0.01)
                    if not term_observed_path.is_file():
                        raise AssertionError("child did not observe SIGTERM")
                    return
                if leader_is_owned:
                    raise AssertionError("group check preceded leader reaping")
                # This constructs only a userspace return sequence. Linux is not
                # reproducing the hosted macOS kernel or scheduler cause.
                if remaining_transient_check_denials:
                    remaining_transient_check_denials -= 1
                    raise PermissionError(
                        errno.EPERM, "constructed transient group-check denial"
                    )
                try:
                    real_killpg(process_group, requested_signal)
                except ProcessLookupError:
                    definitive_absence_observed = True
                    raise

            child_pid: int | None = None
            child_group: int | None = None
            try:
                with mock.patch.object(
                    process_boundary.os,
                    "killpg",
                    construct_denied_kill_then_transient_checks,
                ):
                    child_status = process_boundary.run_process(
                        "tool", outputs, [sys.executable, str(script)]
                    )
            finally:
                if child_pid_path.is_file():
                    child_pid, child_group = map(
                        int, child_pid_path.read_text().split(":")
                    )
            self.assertEqual(child_status, 0)
            self.assertEqual(cleanup_signal_attempts, [signal.SIGTERM, signal.SIGKILL])
            self.assertEqual(denied_group_signal_calls, [signal.SIGKILL])
            self.assertEqual(remaining_transient_check_denials, 0)
            self.assertTrue(definitive_absence_observed)
            self.assertEqual(
                call_observations[:2],
                [(signal.SIGTERM, True), (signal.SIGKILL, True)],
            )
            self.assertTrue(
                all(
                    requested_signal == 0 and not leader_is_owned
                    for requested_signal, leader_is_owned in call_observations[2:]
                ),
                "helper signalled after reaping the owned leader",
            )
            self.assertIsNotNone(child_pid)
            self.assertIsNotNone(child_group)
            self.assertEqual(term_observed_path.read_text(), str(child_pid))
            self.assertNotEqual(child_pid, child_group)
            self.assertNotEqual(child_group, os.getpgrp())
            self.assert_process_gone(int(child_pid))
            self.assertEqual(
                returned_group_signal_calls,
                [signal.SIGTERM],
            )

    def test_persistent_eperm_check_is_bounded_and_never_admitted(self) -> None:
        with external_temporary_directory(
            ROOT, prefix="sacrysty-process-group-persistent-eperm-test-"
        ) as directory:
            root = pathlib.Path(directory)
            selected_pid_path = root / "selected-pid"
            script = root / "hang.py"
            script.write_text(
                "import os, pathlib, signal, time\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                f"pathlib.Path({str(selected_pid_path)!r})"
                ".write_text(str(os.getpid()))\n"
                "deadline = time.monotonic() + 5\n"
                "while time.monotonic() < deadline:\n"
                "    time.sleep(0.1)\n"
            )
            outputs = self.make_paths(directory)
            real_killpg = os.killpg
            cleanup_signals: list[int] = []
            denied_checks = 0

            def deny_checks_while_group_exists(
                process_group: int, requested_signal: int
            ) -> None:
                nonlocal denied_checks
                if requested_signal == 0:
                    denied_checks += 1
                    raise PermissionError(
                        errno.EPERM, "constructed persistent process-group denial"
                    )
                real_killpg(process_group, requested_signal)
                cleanup_signals.append(requested_signal)

            selected_pid: int | None = None
            started = time.monotonic()
            try:
                with (
                    mock.patch.dict(
                        process_boundary.PROCESS_LIMITS,
                        {
                            "tool": process_boundary.ProcessLimits(
                                timeout_seconds=0.2,
                                terminate_grace_seconds=0.03,
                            )
                        },
                    ),
                    mock.patch.object(
                        process_boundary.os,
                        "killpg",
                        deny_checks_while_group_exists,
                    ),
                    self.assertRaisesRegex(
                        process_boundary.ProcessBoundaryError,
                        r"process-group cleanup check failed \(EPERM\)",
                    ),
                ):
                    process_boundary.run_process(
                        "tool", outputs, [sys.executable, str(script)]
                    )
            finally:
                elapsed = time.monotonic() - started
                if selected_pid_path.is_file():
                    selected_pid = int(selected_pid_path.read_text())
            self.assertEqual(cleanup_signals, [signal.SIGTERM, signal.SIGKILL])
            self.assertGreater(denied_checks, 1)
            self.assertLess(elapsed, 2.0)
            self.assertIsNotNone(selected_pid)
            self.assert_process_gone(int(selected_pid))
            self.assertFalse(outputs.status.exists())

    def test_cli_preserves_a_bounded_child_exit_status(self) -> None:
        with external_temporary_directory(
            ROOT, prefix="sacrysty-process-cli-test-"
        ) as directory:
            outputs = self.make_paths(directory)
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(pathlib.Path(process_boundary.__file__)),
                    "tool",
                    str(outputs.status),
                    str(outputs.stdout),
                    str(outputs.stderr),
                    "--",
                    sys.executable,
                    "-c",
                    "import sys; print('rejected', file=sys.stderr); raise SystemExit(7)",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(outputs.status.read_text(), "7\n")
            self.assertEqual(outputs.stderr.read_text(), "rejected\n")

    def test_named_output_paths_keep_status_and_streams_distinct(self) -> None:
        with external_temporary_directory(
            ROOT, prefix="sacrysty-process-output-paths-test-"
        ) as directory:
            paths = self.make_paths(directory)
            outputs = process_boundary.ProcessOutputPaths(
                stderr=paths.stderr,
                status=paths.status,
                stdout=paths.stdout,
            )
            child_status = process_boundary.run_process(
                "tool",
                outputs,
                [
                    sys.executable,
                    "-c",
                    (
                        "import sys; print('out'); print('err', file=sys.stderr); "
                        "raise SystemExit(7)"
                    ),
                ],
            )

            self.assertEqual(child_status, 7)
            self.assertEqual(outputs.status.read_text(), "7\n")
            self.assertEqual(outputs.stdout.read_text(), "out\n")
            self.assertEqual(outputs.stderr.read_text(), "err\n")

    def test_probe_requires_a_same_run_runner_cleanup_receipt(self) -> None:
        with external_temporary_directory(
            ROOT, prefix="sacrysty-runner-receipt-test-"
        ) as directory:
            root = pathlib.Path(directory)
            missing_outputs = process_boundary.ProcessOutputPaths(
                status=root / "missing.status",
                stdout=root / "missing.stdout",
                stderr=root / "missing.stderr",
            )
            with self.assertRaisesRegex(
                process_boundary.ProcessBoundaryError,
                "runner cleanup receipt is unavailable",
            ):
                process_boundary.run_process(
                    "probe", missing_outputs, [sys.executable, "-c", "pass"]
                )
            self.assertFalse(missing_outputs.status.exists())
            self.assertFalse(
                process_boundary.CleanupReceipt.for_status(
                    missing_outputs.status
                ).path.exists()
            )

            receipt_outputs = process_boundary.ProcessOutputPaths(
                status=root / "present.status",
                stdout=root / "present.stdout",
                stderr=root / "present.stderr",
            )
            script = (
                "import os, pathlib\n"
                "pathlib.Path(os.environ['SACRYSTY_RUNNER_CLEANUP_RECEIPT'])"
                ".write_bytes(b'io.nisavid.sacrysty.runner-cleanup/v1\\n')\n"
                "raise SystemExit(7)\n"
            )
            self.assertEqual(
                process_boundary.run_process(
                    "probe", receipt_outputs, [sys.executable, "-c", script]
                ),
                7,
            )
            self.assertEqual(receipt_outputs.status.read_text(), "7\n")
            self.assertFalse(
                pathlib.Path(f"{receipt_outputs.status}.runner-cleanup").exists()
            )
            self.assertEqual(
                process_boundary.CleanupReceipt.for_status(
                    receipt_outputs.status
                ).path.read_bytes(),
                process_boundary.PROCESS_CLEANUP_RECEIPT,
            )

    def test_selected_process_environment_is_explicit_and_value_free(self) -> None:
        allowed_common = {
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_TERMINAL_PROMPT",
            "GNUPGHOME",
            "HOME",
            "LANG",
            "LC_ALL",
            "PATH",
            "PYTHONDONTWRITEBYTECODE",
            "TMPDIR",
            "XDG_CACHE_HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
        }
        selected = {
            "PATH": os.defpath,
            "SACRYSTY_SYNTHETIC_SENTINEL": "must-not-cross-boundary",
            "SQ": "/value-free/sq",
            "SQV": "/value-free/sqv",
        }
        for mode in ("tool", "probe"):
            with self.subTest(mode), external_temporary_directory(
                ROOT, prefix=f"sacrysty-{mode}-environment-test-"
            ) as directory, mock.patch.dict(os.environ, selected, clear=True):
                outputs = self.make_paths(directory)
                script = (
                    "import json, os, pathlib\n"
                    "receipt = os.environ.get('SACRYSTY_RUNNER_CLEANUP_RECEIPT')\n"
                    "if receipt:\n"
                    "    pathlib.Path(receipt).write_bytes(\n"
                    "        b'io.nisavid.sacrysty.runner-cleanup/v1\\n'\n"
                    "    )\n"
                    "print(json.dumps(dict(os.environ), sort_keys=True))\n"
                )
                self.assertEqual(
                    process_boundary.run_process(
                        mode, outputs, [sys.executable, "-c", script]
                    ),
                    0,
                )
                observed = json.loads(outputs.stdout.read_text())
                expected_keys = set(allowed_common)
                if mode == "probe":
                    expected_keys.update(
                        {"SACRYSTY_RUNNER_CLEANUP_RECEIPT", "SQ", "SQV"}
                    )
                self.assertEqual(set(observed), expected_keys)
                self.assertNotIn("SACRYSTY_SYNTHETIC_SENTINEL", observed)
                self.assertEqual(observed["PATH"], os.defpath)
                for name in (
                    "GNUPGHOME",
                    "HOME",
                    "TMPDIR",
                    "XDG_CACHE_HOME",
                    "XDG_CONFIG_HOME",
                    "XDG_DATA_HOME",
                ):
                    path = pathlib.Path(observed[name])
                    self.assertTrue(path.is_dir())
                    self.assertEqual(path.stat().st_mode & 0o777, 0o700)
                if mode == "tool":
                    self.assertNotIn("SQ", observed)
                    self.assertNotIn("SQV", observed)
                else:
                    self.assertEqual(observed["SQ"], selected["SQ"])
                    self.assertEqual(observed["SQV"], selected["SQV"])

    def test_terminating_the_helper_reaps_its_selected_process_group(self) -> None:
        with external_temporary_directory(
            ROOT, prefix="sacrysty-process-interruption-test-"
        ) as directory:
            root = pathlib.Path(directory)
            selected_pid_path = root / "selected-pid"
            script = root / "hang.py"
            script.write_text(
                "import os, pathlib, time\n"
                f"pathlib.Path({str(selected_pid_path)!r})"
                ".write_text(str(os.getpid()))\n"
                "deadline = time.monotonic() + 5\n"
                "while time.monotonic() < deadline:\n"
                "    time.sleep(0.1)\n"
            )
            outputs = self.make_paths(directory)
            helper = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    str(pathlib.Path(process_boundary.__file__)),
                    "tool",
                    str(outputs.status),
                    str(outputs.stdout),
                    str(outputs.stderr),
                    "--",
                    sys.executable,
                    str(script),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.addCleanup(_close_owned_process, helper, (selected_pid_path,))
            deadline = time.monotonic() + 2
            while not selected_pid_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(
                selected_pid_path.exists(), "selected process did not start"
            )
            selected_pid = int(selected_pid_path.read_text())

            helper.terminate()
            helper.communicate(timeout=3)

            self.assert_process_gone(selected_pid)
            self.assertFalse(outputs.status.exists())

    def test_termination_during_process_startup_reaps_the_selected_group(self) -> None:
        with external_temporary_directory(
            ROOT, prefix="sacrysty-process-startup-interruption-test-"
        ) as directory:
            root = pathlib.Path(directory)
            selected_pid_path = root / "selected-pid"
            tool = root / "tool.py"
            tool.write_text(
                "import os, pathlib, time\n"
                f"pathlib.Path({str(selected_pid_path)!r})"
                ".write_text(str(os.getpid()))\n"
                "deadline = time.monotonic() + 5\n"
                "while time.monotonic() < deadline:\n"
                "    time.sleep(0.1)\n"
            )
            outputs = self.make_paths(directory)
            caller = root / "caller.py"
            caller.write_text(
                "import os, pathlib, signal, sys, time\n"
                f"sys.path.insert(0, {str(ROOT / 'conformance')!r})\n"
                "import sq_evidence_process as process_boundary\n"
                "real_popen = process_boundary.subprocess.Popen\n"
                "def cancel_after_selected_process_starts(*args, **kwargs):\n"
                "    process = real_popen(*args, **kwargs)\n"
                f"    marker = pathlib.Path({str(selected_pid_path)!r})\n"
                "    deadline = time.monotonic() + 2\n"
                "    while not marker.is_file() and time.monotonic() < deadline:\n"
                "        if process.poll() is not None:\n"
                "            break\n"
                "        time.sleep(0.01)\n"
                "    if not marker.is_file():\n"
                "        raise RuntimeError('selected process did not start')\n"
                "    os.kill(os.getpid(), signal.SIGTERM)\n"
                "    return process\n"
                "process_boundary.subprocess.Popen = "
                "cancel_after_selected_process_starts\n"
                "raise SystemExit(process_boundary.main([\n"
                "    'tool',\n"
                f"    {str(outputs.status)!r},\n"
                f"    {str(outputs.stdout)!r},\n"
                f"    {str(outputs.stderr)!r},\n"
                "    '--',\n"
                "    sys.executable,\n"
                f"    {str(tool)!r},\n"
                "]))\n"
            )
            caller_process = subprocess.Popen(
                [sys.executable, "-B", str(caller)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.addCleanup(_close_owned_process, caller_process, (selected_pid_path,))

            _caller_stdout, caller_stderr = caller_process.communicate(timeout=5)

            self.assertTrue(
                selected_pid_path.is_file(), "selected process did not start"
            )
            selected_pid = int(selected_pid_path.read_text())
            self.assertNotEqual(caller_process.returncode, 0)
            self.assert_process_gone(selected_pid)
            self.assertFalse(outputs.status.exists(), caller_stderr)


if __name__ == "__main__":
    unittest.main()
