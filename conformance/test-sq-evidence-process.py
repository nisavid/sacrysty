#!/usr/bin/env python3
"""Regressions for the sq/sqv evidence process boundary."""

from __future__ import annotations

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


def _terminate_if_alive(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


class SqEvidenceProcessTests(unittest.TestCase):
    def assert_process_gone(self, pid: int) -> None:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.01)
        self.fail(f"bounded process survived: {pid}")

    def make_paths(
        self, directory: str
    ) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        root = pathlib.Path(directory)
        return root / "status", root / "stdout", root / "stderr"

    def test_tool_and_aggregate_probe_timeouts_fail_and_reap(self) -> None:
        for mode, timeout_name in (
            ("tool", "TOOL_TIMEOUT_SECONDS"),
            ("probe", "PROBE_TIMEOUT_SECONDS"),
        ):
            with self.subTest(mode), external_temporary_directory(
                ROOT, prefix=f"sacrysty-{mode}-timeout-test-"
            ) as directory:
                root = pathlib.Path(directory)
                pid_path = root / "pid"
                script = root / "hang.py"
                script.write_text(
                    "import os, pathlib, time\n"
                    f"pathlib.Path({str(pid_path)!r}).write_text(str(os.getpid()))\n"
                    "while True:\n"
                    "    time.sleep(1)\n"
                )
                status, stdout, stderr = self.make_paths(directory)
                with (
                    mock.patch.object(process_boundary, timeout_name, 0.1),
                    self.assertRaisesRegex(
                        process_boundary.ProcessBoundaryError, "timed out"
                    ),
                ):
                    process_boundary.run_process(
                        mode, status, stdout, stderr, [sys.executable, str(script)]
                    )
                pid = int(pid_path.read_text())
                self.addCleanup(_terminate_if_alive, pid)
                self.assert_process_gone(pid)
                self.assertFalse(status.exists())

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
                status, stdout, stderr = self.make_paths(directory)
                with (
                    mock.patch.object(process_boundary, "STREAM_LIMIT_BYTES", 128),
                    self.assertRaisesRegex(
                        process_boundary.ProcessBoundaryError,
                        f"{stream} limit",
                    ),
                ):
                    process_boundary.run_process(
                        "tool", status, stdout, stderr, [sys.executable, str(script)]
                    )
                captured = stdout if stream == "stdout" else stderr
                self.assertLessEqual(captured.stat().st_size, 128)
                self.assertFalse(status.exists())

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
            status, stdout, stderr = self.make_paths(directory)
            with (
                mock.patch.object(process_boundary, "FILE_LIMIT_BYTES", 128),
                self.assertRaisesRegex(
                    process_boundary.ProcessBoundaryError,
                    "regular-file limit",
                ),
            ):
                process_boundary.run_process(
                    "tool",
                    status,
                    stdout,
                    stderr,
                    [sys.executable, str(script), str(artifact)],
                )
            self.assertFalse(status.exists())
            self.assertLessEqual(artifact.stat().st_size, 128)

    def test_success_reaps_an_ordinary_same_group_descendant(self) -> None:
        with external_temporary_directory(
            ROOT, prefix="sacrysty-process-group-test-"
        ) as directory:
            root = pathlib.Path(directory)
            child_pid_path = root / "child-pid"
            script = root / "spawn-child.py"
            script.write_text(
                "import pathlib, subprocess, sys\n"
                "child = subprocess.Popen(\n"
                "    [sys.executable, '-c', 'import time; time.sleep(30)'],\n"
                "    stdin=subprocess.DEVNULL,\n"
                "    stdout=subprocess.DEVNULL,\n"
                "    stderr=subprocess.DEVNULL,\n"
                ")\n"
                f"pathlib.Path({str(child_pid_path)!r}).write_text(str(child.pid))\n"
            )
            status, stdout, stderr = self.make_paths(directory)
            child_status = process_boundary.run_process(
                "tool", status, stdout, stderr, [sys.executable, str(script)]
            )
            child_pid = int(child_pid_path.read_text())
            self.addCleanup(_terminate_if_alive, child_pid)
            self.assertEqual(child_status, 0)
            self.assert_process_gone(child_pid)

    def test_cli_preserves_a_bounded_child_exit_status(self) -> None:
        with external_temporary_directory(
            ROOT, prefix="sacrysty-process-cli-test-"
        ) as directory:
            status, stdout, stderr = self.make_paths(directory)
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(pathlib.Path(process_boundary.__file__)),
                    "tool",
                    str(status),
                    str(stdout),
                    str(stderr),
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
            self.assertEqual(status.read_text(), "7\n")
            self.assertEqual(stderr.read_text(), "rejected\n")

    def test_terminating_the_helper_reaps_its_selected_process_group(self) -> None:
        with external_temporary_directory(
            ROOT, prefix="sacrysty-process-interruption-test-"
        ) as directory:
            root = pathlib.Path(directory)
            selected_pid_path = root / "selected-pid"
            script = root / "hang.py"
            script.write_text(
                "import os, pathlib, time\n"
                f"pathlib.Path({str(selected_pid_path)!r}).write_text(str(os.getpid()))\n"
                "while True:\n"
                "    time.sleep(1)\n"
            )
            status, stdout, stderr = self.make_paths(directory)
            helper = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    str(pathlib.Path(process_boundary.__file__)),
                    "tool",
                    str(status),
                    str(stdout),
                    str(stderr),
                    "--",
                    sys.executable,
                    str(script),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.addCleanup(helper.kill)
            deadline = time.monotonic() + 2
            while not selected_pid_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(
                selected_pid_path.exists(), "selected process did not start"
            )
            selected_pid = int(selected_pid_path.read_text())
            self.addCleanup(_terminate_if_alive, selected_pid)

            helper.terminate()
            helper.communicate(timeout=3)

            self.assert_process_gone(selected_pid)
            self.assertFalse(status.exists())


if __name__ == "__main__":
    unittest.main()
