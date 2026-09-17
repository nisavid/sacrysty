#!/usr/bin/env python3
"""Regressions for the aggregate conformance procedure."""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import signal
import stat
import subprocess
import time
import unittest

from test_support import ConstructedRepository

ROOT = pathlib.Path(__file__).parents[1]
AGGREGATE = ROOT / "scripts/check-conformance.sh"
RESULT_CHECKER = ROOT / "conformance/check-probe-result.py"
SHARED_HELPER = ROOT / "conformance/sq-evidence-lib.sh"
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
import atexit
import json
import os
import pathlib
import signal
import subprocess
import time

runtime = pathlib.Path(__RUNTIME__)
probe_log = pathlib.Path(__PROBE_LOG__)
mode_path = runtime / "aggregate-mode"
mode = mode_path.read_text(encoding="ascii") if mode_path.is_file() else "normal"
interrupted = False
def request_interruption(_signal_number, _frame):
    global interrupted
    interrupted = True
signal.signal(signal.SIGTERM, request_interruption)
def write_runner_receipt():
    receipt = os.environ.get("SACRYSTY_RUNNER_CLEANUP_RECEIPT")
    if receipt and mode != "missing-runner-receipt":
        pathlib.Path(receipt).write_bytes(
            b"io.nisavid.sacrysty.runner-cleanup/v1\n"
        )
atexit.register(write_runner_receipt)
revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
sha256 = "b" * 64
sha512 = "c" * 128
fixture = {"bytes": 1, "sha256": sha256, "sha512": sha512}
name = pathlib.Path(__file__).name
with probe_log.open("a", encoding="utf-8") as log:
    log.write(name + "\n")
if mode == "startup-cancel-hang" and name == "run-sq.sh":
    runtime.joinpath("startup-supervisor.pid").write_text(str(os.getppid()))
    runtime.joinpath("startup-runner.pid").write_text(str(os.getpid()))
    deadline = time.monotonic() + 5
    while not interrupted and time.monotonic() < deadline:
        time.sleep(0.1)
    raise SystemExit(143)
if mode == "same-group-descendant" and name == "run-sq.sh":
    descendant_pid_path = str(runtime / "descendant.pid")
    child_program = (
        "import os,pathlib,time\n"
        f"pid_path=pathlib.Path({descendant_pid_path!r})\n"
        "pid_path.write_text(f'{os.getpid()}:{os.getpgrp()}')\n"
        "deadline=time.monotonic()+5\n"
        "while time.monotonic()<deadline: time.sleep(0.1)\n"
    )
    child = subprocess.Popen(
        [__import__("sys").executable, "-c", child_program],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    marker = runtime / "descendant.pid"
    deadline = time.monotonic() + 2
    while not marker.is_file() and time.monotonic() < deadline:
        if child.poll() is not None:
            break
        time.sleep(0.01)
    if not marker.is_file() or os.getpgid(child.pid) != os.getpgrp():
        child.kill()
        child.wait()
        raise SystemExit(20)
if mode == "nested-tool-hang" and name == "run-sq.sh":
    tool_pid_path = str(runtime / "cancel-tool.pid")
    runtime.joinpath("cancel-runner.pid").write_text(str(os.getpid()))
    tool_program = (
        "import os,pathlib,signal,time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"pathlib.Path({tool_pid_path!r}).write_text(str(os.getpid())); "
        "time.sleep(5)"
    )
    nested_status = runtime / "nested-tool.status"
    completed = subprocess.run(
        [
            __import__("sys").executable,
            "-B",
            str(pathlib.Path(__file__).with_name("sq_evidence_process.py")),
            "tool",
            str(nested_status),
            str(runtime / "nested-tool.stdout"),
            str(runtime / "nested-tool.stderr"),
            "--",
            __import__("sys").executable,
            "-c",
            tool_program,
        ],
        check=False,
    )
    cleanup_receipt = pathlib.Path(f"{nested_status}.cleanup")
    if cleanup_receipt.read_bytes() != b"io.nisavid.sacrysty.process-cleanup/v1\n":
        raise SystemExit(21)
    cleanup_receipt.unlink()
    raise SystemExit(completed.returncode)
if mode == "stdout-flood":
    __import__("sys").stdout.buffer.write(b"x" * (2 * 1024 * 1024))
    raise SystemExit(0)
if mode == "malformed":
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
if mode == "false-check":
    result["checks"]["temporary_key_material_removed"] = False
json.dump(result, __import__("sys").stdout)
print()
if mode == "nonzero":
    raise SystemExit(7)
"""


ACTUAL_FAKE_TOOL = r"""#!/usr/bin/env python3
import json
import os
import pathlib
import signal
import sys
import time

runtime = pathlib.Path(__RUNTIME__)
controls = runtime / "actual-controls"
controls.mkdir(exist_ok=True)
name = pathlib.Path(sys.argv[0]).name
arguments = sys.argv[1:]
def control(label, default):
    path = controls / label
    return path.read_text(encoding="ascii") if path.is_file() else default
def runner_name():
    joined = " ".join(arguments)
    if "sacrysty-signing-profile." in joined:
        return "run-signing-profile"
    if "sacrysty-conformance." in joined:
        return "run-sq"
    return "version"
runner = runner_name()
with (runtime / "actual-tool.log").open("a", encoding="utf-8") as log:
    log.write(json.dumps({"name": name, "runner": runner, "arguments": arguments}) + "\n")

if name == "sq" and arguments == ["version"]:
    print("sq value-free fixture 1")
    raise SystemExit(0)
if name == "sqv" and arguments == ["--version"]:
    print("sqv value-free fixture 1")
    raise SystemExit(0)

joined = " " + " ".join(arguments) + " "
target = control("target", "none")
mode = control("mode", "normal")
classical_generation = (
    name == "sq"
    and " key generate " in joined
    and " mldsa65-ed25519 " not in joined
)
if runner == target and classical_generation:
    if mode == "failure":
        print("constructed ordinary tool failure", file=sys.stderr)
        raise SystemExit(70)
    if mode in {"hang-ignore", "hang-delay"}:
        marker = runtime / f"{target}-{mode}.selected"
        work = next(
            (
                pathlib.Path(arguments[index + 1]).parent
                for index, value in enumerate(arguments[:-1])
                if value in {"--output", "--rev-cert", "--signature-file"}
            ),
            pathlib.Path("."),
        )
        marker.write_text(
            f"{os.getpid()}:{os.getpgrp()}:{work}", encoding="utf-8"
        )
        if mode == "hang-ignore":
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        else:
            def delayed_stop(_number, _frame):
                pathlib.Path(f"{marker}.term").write_text("observed\n")
                time.sleep(0.15)
                raise SystemExit(143)
            signal.signal(signal.SIGTERM, delayed_stop)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            time.sleep(0.1)
        raise SystemExit(75)

if name == "sq" and " mldsa65-ed25519 " in joined:
    print(
        "Error: Unsupported public key algorithm: ML-DSA-65+Ed25519",
        file=sys.stderr,
    )
    raise SystemExit(1)
if name == "sq":
    for index, value in enumerate(arguments[:-1]):
        if value in {"--output", "--rev-cert", "--signature-file"}:
            pathlib.Path(arguments[index + 1]).write_bytes(
                b"disposable value-free fake artifact\n"
            )
    raise SystemExit(0)

negative = (
    arguments[-1].endswith("tampered-message.bin")
    or any(value.endswith("tampered-signature.sig") for value in arguments)
    or any(value.endswith("other-cert.pgp") for value in arguments)
)
if negative:
    print("constructed verification rejection", file=sys.stderr)
    raise SystemExit(7)
raise SystemExit(0)
"""


def write_executable(path: pathlib.Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def clean_aggregate_process(
    aggregate: subprocess.Popen[str], pid_paths: tuple[pathlib.Path, ...]
) -> None:
    if aggregate.poll() is None:
        aggregate.terminate()
    try:
        aggregate.communicate(timeout=4)
    except subprocess.TimeoutExpired:
        aggregate.kill()
        aggregate.communicate(timeout=2)
    for pid_path in pid_paths:
        if not pid_path.is_file():
            continue
        pid = int(pid_path.read_text().split(":", 1)[0])
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.01)


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
        fixture = ConstructedRepository(ROOT, prefix="sacrysty-aggregate-test-")
        self.addCleanup(fixture.cleanup)
        self.constructed_repository = fixture
        repository = fixture.repository
        runtime = fixture.runtime
        fixture.copy(AGGREGATE, "scripts/check-conformance.sh")
        fixture.copy(RESULT_CHECKER, "conformance/check-probe-result.py")
        fixture.copy(SHARED_HELPER, "conformance/sq-evidence-lib.sh")
        fixture.copy(PROCESS_HELPER, "conformance/sq_evidence_process.py")
        fixture.copy_tree(ROOT / "sacrysty_runtime", "sacrysty_runtime")
        write_executable(
            repository / "scripts/check-repository.sh", "#!/bin/sh\nexit 0\n"
        )
        for name in TEST_SYNTHETIC_CHECKS:
            write_executable(repository / "conformance" / name, PYTHON_STUB)
        (repository / "conformance/synthetic-checks.txt").write_text(
            "".join(f"conformance/{name}\n" for name in TEST_SYNTHETIC_CHECKS)
        )
        probe_stub = PROBE_STUB.replace("__RUNTIME__", repr(str(runtime))).replace(
            "__PROBE_LOG__", repr(str(runtime / "probe.log"))
        )
        for name in ("run-sq.sh", "run-signing-profile.sh"):
            write_executable(repository / "conformance" / name, probe_stub)

        environment = fixture.environment
        environment.update(
            {
                "AGGREGATE_PROBE_LOG": str(runtime / "probe.log"),
                "SYNTHETIC_LOG": str(runtime / "synthetic.log"),
            }
        )
        fixture.commit()
        return repository, environment

    def make_actual_runner_repository(
        self,
    ) -> tuple[pathlib.Path, dict[str, str]]:
        fixture = ConstructedRepository(
            ROOT, prefix="sacrysty-actual-runner-aggregate-test-"
        )
        self.addCleanup(fixture.cleanup)
        self.constructed_repository = fixture
        repository = fixture.repository
        runtime = fixture.runtime
        for source, destination in (
            (AGGREGATE, "scripts/check-conformance.sh"),
            (RESULT_CHECKER, "conformance/check-probe-result.py"),
            (SHARED_HELPER, "conformance/sq-evidence-lib.sh"),
            (PROCESS_HELPER, "conformance/sq_evidence_process.py"),
            (ROOT / "conformance/run-sq.sh", "conformance/run-sq.sh"),
            (
                ROOT / "conformance/run-signing-profile.sh",
                "conformance/run-signing-profile.sh",
            ),
        ):
            fixture.copy(source, destination)
        fixture.copy_tree(ROOT / "sacrysty_runtime", "sacrysty_runtime")
        fixture.write(
            "fixtures/rfc9580/message.txt",
            "Sacrysty value-free aggregate fixture.\n",
        )
        fixture.write(
            "fixtures/signing/message.bin",
            b"Sacrysty value-free signing fixture.\n",
        )
        write_executable(
            repository / "scripts/check-repository.sh", "#!/bin/sh\nexit 0\n"
        )
        for name in TEST_SYNTHETIC_CHECKS:
            write_executable(repository / "conformance" / name, PYTHON_STUB)
        (repository / "conformance/synthetic-checks.txt").write_text(
            "".join(f"conformance/{name}\n" for name in TEST_SYNTHETIC_CHECKS)
        )
        fake_tool = ACTUAL_FAKE_TOOL.replace("__RUNTIME__", repr(str(runtime)))
        for name in ("sq", "sqv"):
            write_executable(repository / "fake-bin" / name, fake_tool)
        fixture.commit()
        environment = fixture.environment
        environment.update(
            {
                "SQ": str(repository / "fake-bin/sq"),
                "SQV": str(repository / "fake-bin/sqv"),
                "SYNTHETIC_LOG": str(runtime / "synthetic.log"),
            }
        )
        return repository, environment

    def set_actual_control(
        self, environment: dict[str, str], name: str, value: str
    ) -> None:
        control = pathlib.Path(environment["TEST_RUNTIME"]) / "actual-controls" / name
        control.parent.mkdir(exist_ok=True)
        control.write_text(value, encoding="ascii")

    def start_aggregate(
        self, repository: pathlib.Path, environment: dict[str, str]
    ) -> subprocess.Popen[str]:
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
        self.addCleanup(clean_aggregate_process, aggregate, ())
        return aggregate

    def assert_no_disposable_runner_paths(self, environment: dict[str, str]) -> None:
        temporary_root = pathlib.Path(environment["TMPDIR"])
        for pattern in (
            "sacrysty-conformance.*",
            "sacrysty-signing-profile.*",
            "sacrysty-conformance-results.*",
        ):
            self.assertEqual(list(temporary_root.glob(pattern)), [], pattern)

    def read_selected_marker(
        self, marker: pathlib.Path
    ) -> tuple[int, int, pathlib.Path]:
        pid, process_group, work = marker.read_text().split(":", 2)
        return int(pid), int(process_group), pathlib.Path(work)

    def set_mode(self, environment: dict[str, str], mode: str) -> None:
        pathlib.Path(environment["TEST_RUNTIME"], "aggregate-mode").write_text(
            mode, encoding="ascii"
        )

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
                self.set_mode(environment, mode)

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
        self.set_mode(environment, "nonzero")

        result = self.run_aggregate(repository, environment)

        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("probe result admitted", result.stdout)
        self.assertIn("crypto-conformance probe exited with status 7", result.stderr)

    def test_oversized_probe_result_fails_at_the_aggregate_bound(self) -> None:
        repository, environment = self.make_repository()
        self.set_mode(environment, "stdout-flood")

        result = self.run_aggregate(repository, environment)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("probe process exceeded stdout limit", result.stderr)
        self.assertNotIn("probe result admitted", result.stdout)

    def test_aggregate_reaps_an_ordinary_same_group_runner_descendant(self) -> None:
        repository, environment = self.make_repository()
        pid_path = pathlib.Path(environment["TEST_RUNTIME"]) / "descendant.pid"
        self.set_mode(environment, "same-group-descendant")

        descendant: int | None = None
        descendant_group: int | None = None
        try:
            result = self.run_aggregate(repository, environment)
        finally:
            if pid_path.is_file():
                descendant, descendant_group = map(int, pid_path.read_text().split(":"))
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
        self.set_mode(environment, "nested-tool-hang")
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
            self.assertIsNone(aggregate.poll())
            os.killpg(aggregate.pid, requested_signal)
        else:
            aggregate.send_signal(requested_signal)
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
        bash_environment.write_text(r"""set -T
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
""")
        environment.update(
            {
                "AGGREGATE_STARTUP_BARRIER_ONCE": str(barrier_once),
                "AGGREGATE_STARTUP_BARRIER_READY": str(barrier_ready),
                "AGGREGATE_STARTUP_BARRIER_RELEASE": str(barrier_release),
                "BASH_ENV": str(bash_environment),
            }
        )
        self.set_mode(environment, "startup-cancel-hang")
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

        aggregate.send_signal(requested_signal)
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

    def test_actual_runners_complete_and_remove_disposable_material(self) -> None:
        repository, environment = self.make_actual_runner_repository()

        result = self.run_aggregate(repository, environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        observations = {
            json.loads(line)["runner"]
            for line in pathlib.Path(environment["TEST_RUNTIME"], "actual-tool.log")
            .read_text()
            .splitlines()
        }
        self.assertIn("run-sq", observations)
        self.assertIn("run-signing-profile", observations)
        self.assertIn("complete conformance checks passed", result.stdout)
        self.assert_no_disposable_runner_paths(environment)

    def test_actual_runner_failures_still_remove_disposable_material(self) -> None:
        for target in ("run-sq", "run-signing-profile"):
            with self.subTest(target):
                repository, environment = self.make_actual_runner_repository()
                self.set_actual_control(environment, "target", target)
                self.set_actual_control(environment, "mode", "failure")

                result = self.run_aggregate(repository, environment)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "classical key generation exited with status 70", result.stderr
                )
                self.assertNotIn("complete conformance checks passed", result.stdout)
                self.assert_no_disposable_runner_paths(environment)

    def assert_actual_runner_cancellation(
        self,
        target: str,
        mode: str,
        *,
        startup_occurrence: int | None = None,
    ) -> None:
        repository, environment = self.make_actual_runner_repository()
        runtime = pathlib.Path(environment["TEST_RUNTIME"])
        marker = runtime / f"{target}-{mode}.selected"
        self.set_actual_control(environment, "target", target)
        self.set_actual_control(environment, "mode", mode)
        release: pathlib.Path | None = None
        if startup_occurrence is not None:
            ready = runtime / "actual-startup.ready"
            release = runtime / "actual-startup.release"
            bash_environment = runtime / "actual-startup-barrier.bash"
            bash_environment.write_text(
                r"""set -T
actual_probe_spawn_count=0
actual_probe_startup_barrier() {
  if [[ $BASH_COMMAND == 'active_probe_supervisor=$!' ]]; then
    actual_probe_spawn_count=$((actual_probe_spawn_count + 1))
    if (( actual_probe_spawn_count == AGGREGATE_STARTUP_OCCURRENCE )); then
      : >"$AGGREGATE_STARTUP_READY"
      while [[ ! -e $AGGREGATE_STARTUP_RELEASE ]]; do
        sleep 0.01
      done
    fi
  fi
}
trap actual_probe_startup_barrier DEBUG
""",
                encoding="utf-8",
            )
            environment.update(
                {
                    "AGGREGATE_STARTUP_OCCURRENCE": str(startup_occurrence),
                    "AGGREGATE_STARTUP_READY": str(ready),
                    "AGGREGATE_STARTUP_RELEASE": str(release),
                    "BASH_ENV": str(bash_environment),
                }
            )
        aggregate = self.start_aggregate(repository, environment)
        deadline = time.monotonic() + 10
        while not marker.is_file() and time.monotonic() < deadline:
            if aggregate.poll() is not None:
                break
            time.sleep(0.01)
        self.assertTrue(marker.is_file(), f"{target} selected tool did not start")
        if startup_occurrence is not None:
            ready = runtime / "actual-startup.ready"
            self.assertTrue(
                ready.is_file(), "aggregate startup barrier was not reached"
            )
        selected_pid, selected_group, work = self.read_selected_marker(marker)
        self.assertEqual(selected_pid, selected_group)
        self.assertTrue(work.is_dir())

        aggregate.send_signal(signal.SIGTERM)
        if release is not None:
            release.touch()
        aggregate_stdout, aggregate_stderr = aggregate.communicate(timeout=10)

        self.assertEqual(aggregate.returncode, 143, aggregate_stderr)
        self.assertNotIn("complete conformance checks passed", aggregate_stdout)
        self.assert_process_gone(selected_pid)
        self.assertFalse(work.exists())
        if mode == "hang-delay":
            self.assertTrue(pathlib.Path(f"{marker}.term").is_file())
        self.assert_no_disposable_runner_paths(environment)

    def test_actual_runner_startup_registration_cancellation_is_owned(self) -> None:
        for target, occurrence in (
            ("run-sq", 1),
            ("run-signing-profile", 2),
        ):
            with self.subTest(target):
                self.assert_actual_runner_cancellation(
                    target, "hang-ignore", startup_occurrence=occurrence
                )

    def test_actual_runner_operational_cancellation_allows_nested_cleanup(
        self,
    ) -> None:
        for target in ("run-sq", "run-signing-profile"):
            for mode in ("hang-delay", "hang-ignore"):
                with self.subTest(target=target, mode=mode):
                    self.assert_actual_runner_cancellation(target, mode)

    def test_missing_runner_receipt_fails_and_retains_result_storage(self) -> None:
        repository, environment = self.make_repository()
        self.set_mode(environment, "missing-runner-receipt")

        result = self.run_aggregate(repository, environment)

        self.assertNotEqual(result.returncode, 0)
        retained = list(
            pathlib.Path(environment["TMPDIR"]).glob("sacrysty-conformance-results.*")
        )
        self.assertEqual(len(retained), 1)
        self.assertIn("cleanup receipt is unavailable", result.stderr)
        self.assertIn("result directory retained", result.stderr)

    def test_interruption_after_probe_reap_never_signals_the_saved_pid(self) -> None:
        repository, environment = self.make_repository()
        runtime = pathlib.Path(environment["TEST_RUNTIME"])
        once = runtime / "post-wait.once"
        signal_log = runtime / "post-wait-signals.log"
        bash_environment = runtime / "post-wait-barrier.bash"
        bash_environment.write_text(
            r"""set -T
aggregate_post_wait_barrier() {
  if [[ $BASH_COMMAND == 'active_probe_supervisor=' \
    && -n ${active_probe_supervisor:-} \
    && ! -e $AGGREGATE_POST_WAIT_ONCE ]]; then
    : >"$AGGREGATE_POST_WAIT_ONCE"
    builtin kill -s TERM "$$"
  fi
}
kill() {
  printf '%s\n' "$*" >>"$AGGREGATE_POST_WAIT_SIGNAL_LOG"
  return 0
}
trap aggregate_post_wait_barrier DEBUG
""",
            encoding="utf-8",
        )
        environment.update(
            {
                "AGGREGATE_POST_WAIT_ONCE": str(once),
                "AGGREGATE_POST_WAIT_SIGNAL_LOG": str(signal_log),
                "BASH_ENV": str(bash_environment),
            }
        )

        result = self.run_aggregate(repository, environment)

        attempts = signal_log.read_text().splitlines() if signal_log.exists() else []
        self.assertTrue(once.is_file(), "aggregate did not reach post-wait barrier")
        self.assertEqual(attempts, [])
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("complete conformance checks passed", result.stdout)

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
