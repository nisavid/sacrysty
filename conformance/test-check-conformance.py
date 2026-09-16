#!/usr/bin/env python3
"""Regressions for the aggregate conformance procedure."""

from __future__ import annotations

import os
import pathlib
import shutil
import signal
import stat
import subprocess
import time
import unittest

from test_support import external_temporary_directory

ROOT = pathlib.Path(__file__).parents[1]
AGGREGATE = ROOT / "scripts/check-conformance.sh"
RESULT_CHECKER = ROOT / "conformance/check-probe-result.py"
SHARED_HELPER = ROOT / "conformance/sq-evidence-lib.sh"
STRICT_JSON_HELPER = ROOT / "conformance/strict_json.py"
PROCESS_HELPER = ROOT / "conformance/sq_evidence_process.py"


PYTHON_STUB = r"""#!/usr/bin/env python3
import os
import pathlib
import sys

with open(os.environ["SYNTHETIC_LOG"], "a", encoding="utf-8") as log:
    log.write(f"{pathlib.Path(sys.argv[0]).name}:{sys.flags.optimize}\n")
"""

TEST_SYNTHETIC_CHECKS = ("fixture-check.py", "fixture-test.py")


PROBE_STUB = r"""#!/usr/bin/env python3
import json
import os
import pathlib
import subprocess
import time

revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
sha256 = "b" * 64
sha512 = "c" * 128
fixture = {"bytes": 1, "sha256": sha256, "sha512": sha512}
name = pathlib.Path(__file__).name
with open(os.environ["AGGREGATE_PROBE_LOG"], "a", encoding="utf-8") as log:
    log.write(name + "\n")
if (
    os.environ.get("FAKE_AGGREGATE_RESULT") == "startup-cancel-hang"
    and name == "run-sq.sh"
):
    pathlib.Path(os.environ["AGGREGATE_SUPERVISOR_PID"]).write_text(
        str(os.getppid())
    )
    pathlib.Path(os.environ["AGGREGATE_RUNNER_PID"]).write_text(str(os.getpid()))
    while True:
        time.sleep(1)
if (
    os.environ.get("FAKE_AGGREGATE_RESULT") == "same-group-descendant"
    and name == "run-sq.sh"
):
    descendant_pid_path = os.environ["AGGREGATE_DESCENDANT_PID"]
    child_program = (
        "import os,pathlib,time\n"
        f"pid_path=pathlib.Path({descendant_pid_path!r})\n"
        "pid_path.write_text(f'{os.getpid()}:{os.getpgrp()}')\n"
        "while True: time.sleep(1)\n"
    )
    child = subprocess.Popen(
        [__import__("sys").executable, "-c", child_program],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    marker = pathlib.Path(os.environ["AGGREGATE_DESCENDANT_PID"])
    deadline = time.monotonic() + 2
    while not marker.is_file() and time.monotonic() < deadline:
        if child.poll() is not None:
            break
        time.sleep(0.01)
    if not marker.is_file() or os.getpgid(child.pid) != os.getpgrp():
        child.kill()
        child.wait()
        raise SystemExit(20)
if (
    os.environ.get("FAKE_AGGREGATE_RESULT") == "nested-tool-hang"
    and name == "run-sq.sh"
):
    runtime = pathlib.Path(os.environ["TEST_RUNTIME"])
    tool_pid_path = os.environ["AGGREGATE_TOOL_PID"]
    pathlib.Path(os.environ["AGGREGATE_RUNNER_PID"]).write_text(str(os.getpid()))
    tool_program = (
        "import os,pathlib,signal,time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"pathlib.Path({tool_pid_path!r}).write_text(str(os.getpid())); "
        "time.sleep(30)"
    )
    raise SystemExit(
        subprocess.run(
            [
                __import__("sys").executable,
                "-B",
                str(pathlib.Path(__file__).with_name("sq_evidence_process.py")),
                "tool",
                str(runtime / "nested-tool.status"),
                str(runtime / "nested-tool.stdout"),
                str(runtime / "nested-tool.stderr"),
                "--",
                __import__("sys").executable,
                "-c",
                tool_program,
            ],
            check=False,
        ).returncode
    )
if os.environ.get("FAKE_AGGREGATE_RESULT") == "stdout-flood":
    __import__("sys").stdout.buffer.write(b"x" * (2 * 1024 * 1024))
    raise SystemExit(0)
if os.environ.get("FAKE_AGGREGATE_RESULT") == "malformed":
    print("not-json")
    raise SystemExit(0)
if name == "run-sq.sh":
    result = {
        "schema": "io.nisavid.sacrysty.crypto-conformance-result/v1",
        "source_revision": revision,
        "reference_time": "20260910",
        "sq_version": "sq fixture",
        "sqv_version": "sqv fixture",
        "fixture_sha256": sha256,
        "fixture_sha512": sha512,
        "fixture_bytes": 1,
        "result": {
            "openpgp-rfc9580-classical-v1": "qualified-for-observed-runtime",
            "openpgp-rfc9980-pqc-v1": "unsupported",
        },
        "fixtures": {
            "message": fixture,
            "signature": fixture,
            "tampered_message": fixture,
            "tampered_signature": fixture,
        },
        "checks": {
            "sq_sign_verify": True,
            "sqv_detached_verify": True,
            "tampered_message_rejected": True,
            "tampered_signature_rejected": True,
            "wrong_certificate_rejected": True,
            "temporary_key_material_removed": True,
            "production_values": False,
        },
    }
else:
    result = {
        "schema": "io.nisavid.sacrysty.signing-profile-result/v1",
        "source_revision": revision,
        "reference_time": "20260910",
        "sq_version": "sq fixture",
        "sqv_version": "sqv fixture",
        "profile": "openpgp-rfc9580-classical-v1",
        "fixtures": {"message": fixture, "signature": fixture},
        "checks": {
            "detached_sign_verify": True,
            "tampered_message_rejected": True,
            "tampered_signature_rejected": True,
            "wrong_certificate_rejected": True,
            "temporary_key_material_removed": True,
        },
        "diagnostics": {
            key: {"command": "sqv fixture", "exit_status": 7, "stderr": "rejected"}
            for key in (
                "tampered_message",
                "tampered_signature",
                "wrong_certificate",
            )
        },
        "production_values_policy": "forbidden",
        "rfc9980": "unsupported-capability-gated",
    }
if os.environ.get("FAKE_AGGREGATE_RESULT") == "false-check":
    result["checks"]["temporary_key_material_removed"] = False
json.dump(result, __import__("sys").stdout)
print()
if os.environ.get("FAKE_AGGREGATE_RESULT") == "nonzero":
    raise SystemExit(7)
"""


def write_executable(path: pathlib.Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def terminate_group_if_alive(process_group: int) -> None:
    if process_group == os.getpgrp():
        raise AssertionError("refusing to signal the test process group")
    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        pass


def terminate_if_alive(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def clean_aggregate_process(
    aggregate: subprocess.Popen[str], pid_paths: tuple[pathlib.Path, ...]
) -> None:
    terminate_group_if_alive(aggregate.pid)
    for pid_path in pid_paths:
        if not pid_path.is_file():
            continue
        pid = int(pid_path.read_text())
        try:
            process_group = os.getpgid(pid)
        except ProcessLookupError:
            continue
        terminate_group_if_alive(process_group)
    aggregate.communicate(timeout=2)


class AggregateConformanceTests(unittest.TestCase):
    def assert_process_gone(self, pid: int) -> None:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.01)
        self.fail(f"aggregate process survived: {pid}")

    def make_repository(self) -> tuple[pathlib.Path, dict[str, str]]:
        temporary_directory = external_temporary_directory(
            ROOT, prefix="sacrysty-aggregate-test-"
        )
        self.addCleanup(temporary_directory.cleanup)
        test_root = pathlib.Path(temporary_directory.name)
        repository = test_root / "repository"
        runtime = test_root / "runtime"
        (repository / "scripts").mkdir(parents=True)
        (repository / "conformance").mkdir()
        (runtime / "tmp").mkdir(parents=True)
        (runtime / "home").mkdir()
        shutil.copy2(AGGREGATE, repository / "scripts")
        shutil.copy2(RESULT_CHECKER, repository / "conformance")
        shutil.copy2(SHARED_HELPER, repository / "conformance")
        shutil.copy2(STRICT_JSON_HELPER, repository / "conformance")
        shutil.copy2(PROCESS_HELPER, repository / "conformance")
        write_executable(
            repository / "scripts/check-repository.sh", "#!/bin/sh\nexit 0\n"
        )
        for name in TEST_SYNTHETIC_CHECKS:
            write_executable(repository / "conformance" / name, PYTHON_STUB)
        (repository / "conformance/synthetic-checks.txt").write_text(
            "".join(f"conformance/{name}\n" for name in TEST_SYNTHETIC_CHECKS)
        )
        for name in ("run-sq.sh", "run-signing-profile.sh"):
            write_executable(repository / "conformance" / name, PROBE_STUB)

        environment = {
            "AGGREGATE_PROBE_LOG": str(runtime / "probe.log"),
            "GIT_CONFIG_GLOBAL": str(runtime / "missing-global-gitconfig"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": str(runtime / "home"),
            "LC_ALL": "C",
            "PATH": os.environ["PATH"],
            "SYNTHETIC_LOG": str(runtime / "synthetic.log"),
            "TEST_RUNTIME": str(runtime),
            "TMPDIR": str(runtime / "tmp"),
        }
        subprocess.run(
            ["git", "init", "-q", str(repository)], check=True, env=environment
        )
        subprocess.run(
            ["git", "-C", str(repository), "config", "user.name", "Fixture"],
            check=True,
            env=environment,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "config",
                "user.email",
                "fixture@example.invalid",
            ],
            check=True,
            env=environment,
        )
        subprocess.run(
            ["git", "-C", str(repository), "add", "."], check=True, env=environment
        )
        subprocess.run(
            ["git", "-C", str(repository), "commit", "-q", "-m", "fixture"],
            check=True,
            env=environment,
        )
        return repository, environment

    def run_aggregate(
        self,
        repository: pathlib.Path,
        environment: dict[str, str],
        *arguments: str,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(repository / "scripts/check-conformance.sh"), *arguments],
            cwd=repository,
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

    def test_malformed_or_false_probe_result_cannot_pass_the_aggregate(self) -> None:
        for mode in ("malformed", "false-check"):
            with self.subTest(mode):
                repository, environment = self.make_repository()
                environment["FAKE_AGGREGATE_RESULT"] = mode

                result = self.run_aggregate(repository, environment)

                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("complete conformance checks passed", result.stdout)

    def test_source_inspection_failure_stops_before_the_first_check(self) -> None:
        repository, environment = self.make_repository()
        real_git = shutil.which("git")
        self.assertIsNotNone(real_git)
        failure_bin = pathlib.Path(environment["TEST_RUNTIME"]) / "git-failure-bin"
        write_executable(
            failure_bin / "git",
            r"""#!/bin/sh
for argument in "$@"; do
    if [ "$argument" = status ]; then
        exit 71
    fi
done
exec "$REAL_GIT" "$@"
""",
        )
        environment.update(
            {
                "PATH": f"{failure_bin}{os.pathsep}{environment['PATH']}",
                "REAL_GIT": str(real_git),
            }
        )

        result = self.run_aggregate(repository, environment)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not inspect source worktree", result.stderr)
        self.assertFalse(pathlib.Path(environment["SYNTHETIC_LOG"]).exists())
        self.assertFalse(pathlib.Path(environment["AGGREGATE_PROBE_LOG"]).exists())

    def test_valid_json_from_nonzero_runner_is_never_announced_as_admitted(
        self,
    ) -> None:
        repository, environment = self.make_repository()
        environment["FAKE_AGGREGATE_RESULT"] = "nonzero"

        result = self.run_aggregate(repository, environment)

        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("probe result admitted", result.stdout)
        self.assertIn("crypto-conformance probe exited with status 7", result.stderr)

    def test_oversized_probe_result_fails_at_the_aggregate_bound(self) -> None:
        repository, environment = self.make_repository()
        environment["FAKE_AGGREGATE_RESULT"] = "stdout-flood"

        result = self.run_aggregate(repository, environment)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("probe process exceeded stdout limit", result.stderr)
        self.assertNotIn("probe result admitted", result.stdout)

    def test_aggregate_reaps_an_ordinary_same_group_runner_descendant(self) -> None:
        repository, environment = self.make_repository()
        pid_path = pathlib.Path(environment["TEST_RUNTIME"]) / "descendant.pid"
        environment.update(
            {
                "AGGREGATE_DESCENDANT_PID": str(pid_path),
                "FAKE_AGGREGATE_RESULT": "same-group-descendant",
            }
        )

        descendant: int | None = None
        descendant_group: int | None = None
        try:
            result = self.run_aggregate(repository, environment)
        finally:
            if pid_path.is_file():
                descendant, descendant_group = map(
                    int, pid_path.read_text().split(":")
                )
                self.addCleanup(terminate_if_alive, descendant)
        self.assertIsNotNone(descendant)
        self.assertIsNotNone(descendant_group)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(descendant, descendant_group)
        self.assertNotEqual(descendant_group, os.getpgrp())
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.kill(int(descendant), 0)
            except ProcessLookupError:
                break
            time.sleep(0.01)
        else:
            self.fail(f"aggregate runner descendant survived: {descendant}")

    def assert_aggregate_interruption_reaps_nested_selected_session(
        self, requested_signal: signal.Signals, *, signal_group: bool
    ) -> None:
        repository, environment = self.make_repository()
        runtime = pathlib.Path(environment["TEST_RUNTIME"])
        runner_pid_path = runtime / "cancel-runner.pid"
        tool_pid_path = runtime / "cancel-tool.pid"
        environment.update(
            {
                "AGGREGATE_RUNNER_PID": str(runner_pid_path),
                "AGGREGATE_TOOL_PID": str(tool_pid_path),
                "FAKE_AGGREGATE_RESULT": "nested-tool-hang",
            }
        )
        aggregate = subprocess.Popen(
            ["bash", str(repository / "scripts/check-conformance.sh")],
            cwd=repository,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
            start_new_session=True,
        )
        self.addCleanup(
            clean_aggregate_process,
            aggregate,
            (runner_pid_path, tool_pid_path),
        )
        deadline = time.monotonic() + 5
        while not tool_pid_path.is_file() and time.monotonic() < deadline:
            if aggregate.poll() is not None:
                break
            time.sleep(0.01)
        self.assertTrue(tool_pid_path.is_file(), "nested tool did not start")
        runner_pid = int(runner_pid_path.read_text())
        tool_pid = int(tool_pid_path.read_text())
        self.assertEqual(os.getpgid(aggregate.pid), aggregate.pid)
        self.assertEqual(os.getpgid(runner_pid), runner_pid)
        self.assertEqual(os.getpgid(tool_pid), tool_pid)

        if signal_group:
            os.killpg(aggregate.pid, requested_signal)
        else:
            os.kill(aggregate.pid, requested_signal)
        aggregate_stdout, aggregate_stderr = aggregate.communicate(timeout=5)

        self.assertNotEqual(aggregate.returncode, 0)
        self.assertNotIn("complete conformance checks passed", aggregate_stdout)
        self.assertIn("sq evidence tool process interrupted", aggregate_stderr)
        self.assertIn("sq evidence probe process interrupted", aggregate_stderr)
        self.assert_process_gone(runner_pid)
        self.assert_process_gone(tool_pid)
        temporary_results = list(
            pathlib.Path(environment["TMPDIR"]).glob("sacrysty-conformance-results.*")
        )
        self.assertEqual(temporary_results, [])

    def test_interrupting_aggregate_reaps_nested_selected_session(self) -> None:
        for requested_signal, signal_group in (
            (signal.SIGINT, False),
            (signal.SIGTERM, True),
        ):
            with self.subTest(requested_signal):
                self.assert_aggregate_interruption_reaps_nested_selected_session(
                    requested_signal, signal_group=signal_group
                )

    def assert_startup_interruption_reaps_registered_probe(
        self, requested_signal: signal.Signals
    ) -> None:
        repository, environment = self.make_repository()
        runtime = pathlib.Path(environment["TEST_RUNTIME"])
        barrier_once = runtime / "startup-barrier.once"
        barrier_ready = runtime / "startup-barrier.ready"
        barrier_release = runtime / "startup-barrier.release"
        supervisor_pid_path = runtime / "startup-supervisor.pid"
        runner_pid_path = runtime / "startup-runner.pid"
        bash_environment = runtime / "startup-barrier.bash"
        bash_environment.write_text(
            r"""set -T
aggregate_startup_barrier() {
  if [[ $BASH_COMMAND == 'active_probe_supervisor=$!' \
    && ! -e $AGGREGATE_STARTUP_BARRIER_ONCE ]]; then
    : >"$AGGREGATE_STARTUP_BARRIER_ONCE"
    : >"$AGGREGATE_STARTUP_BARRIER_READY"
    while [[ ! -e $AGGREGATE_STARTUP_BARRIER_RELEASE ]]; do
      sleep 0.01
    done
  fi
}
trap aggregate_startup_barrier DEBUG
"""
        )
        environment.update(
            {
                "AGGREGATE_RUNNER_PID": str(runner_pid_path),
                "AGGREGATE_STARTUP_BARRIER_ONCE": str(barrier_once),
                "AGGREGATE_STARTUP_BARRIER_READY": str(barrier_ready),
                "AGGREGATE_STARTUP_BARRIER_RELEASE": str(barrier_release),
                "AGGREGATE_SUPERVISOR_PID": str(supervisor_pid_path),
                "BASH_ENV": str(bash_environment),
                "FAKE_AGGREGATE_RESULT": "startup-cancel-hang",
            }
        )
        aggregate = subprocess.Popen(
            ["bash", str(repository / "scripts/check-conformance.sh")],
            cwd=repository,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
            start_new_session=True,
        )
        self.addCleanup(
            clean_aggregate_process,
            aggregate,
            (supervisor_pid_path, runner_pid_path),
        )
        deadline = time.monotonic() + 5
        while (
            not barrier_ready.is_file() or not runner_pid_path.is_file()
        ) and time.monotonic() < deadline:
            if aggregate.poll() is not None:
                break
            time.sleep(0.01)
        self.assertTrue(barrier_ready.is_file(), "startup barrier was not reached")
        self.assertTrue(runner_pid_path.is_file(), "probe runner did not start")
        supervisor_pid = int(supervisor_pid_path.read_text())
        runner_pid = int(runner_pid_path.read_text())
        self.assertEqual(os.getpgid(aggregate.pid), aggregate.pid)
        self.assertEqual(os.getpgid(supervisor_pid), aggregate.pid)
        self.assertEqual(os.getpgid(runner_pid), runner_pid)

        os.kill(aggregate.pid, requested_signal)
        barrier_release.touch()
        aggregate.wait(timeout=5)

        self.assertEqual(aggregate.returncode, 128 + requested_signal)
        self.assert_process_gone(supervisor_pid)
        self.assert_process_gone(runner_pid)
        aggregate_stdout, aggregate_stderr = aggregate.communicate(timeout=2)
        self.assertNotIn("complete conformance checks passed", aggregate_stdout)
        self.assertIn("sq evidence probe process interrupted", aggregate_stderr)

    def test_startup_interruption_reaps_the_registered_probe(self) -> None:
        for requested_signal in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(requested_signal):
                self.assert_startup_interruption_reaps_registered_probe(
                    requested_signal
                )

    def test_complete_aggregate_runs_synthetic_checks_in_both_modes(self) -> None:
        repository, environment = self.make_repository()

        result = self.run_aggregate(repository, environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        observations: dict[str, set[int]] = {}
        for line in pathlib.Path(environment["SYNTHETIC_LOG"]).read_text().splitlines():
            name, optimized = line.split(":")
            observations.setdefault(name, set()).add(int(optimized))
        for name in TEST_SYNTHETIC_CHECKS:
            self.assertEqual(observations.get(name), {0, 1}, name)
        self.assertEqual(
            pathlib.Path(environment["AGGREGATE_PROBE_LOG"]).read_text().splitlines(),
            ["run-sq.sh", "run-signing-profile.sh"],
        )
        temporary_results = list(
            pathlib.Path(environment["TMPDIR"]).glob("sacrysty-conformance-results.*")
        )
        self.assertEqual(temporary_results, [])

    def test_synthetic_only_runs_manifest_checks_without_probe_invocation(self) -> None:
        repository, environment = self.make_repository()

        result = self.run_aggregate(repository, environment, "--synthetic-only")

        self.assertEqual(result.returncode, 0, result.stderr)
        observations: dict[str, set[int]] = {}
        for line in pathlib.Path(environment["SYNTHETIC_LOG"]).read_text().splitlines():
            name, optimized = line.split(":")
            observations.setdefault(name, set()).add(int(optimized))
        self.assertEqual(observations, {name: {0, 1} for name in TEST_SYNTHETIC_CHECKS})
        self.assertFalse(pathlib.Path(environment["AGGREGATE_PROBE_LOG"]).exists())
        self.assertIn("crypto-tool probes not run: synthetic-only mode", result.stdout)
        self.assertIn("synthetic conformance checks passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
