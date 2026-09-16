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


PROBE_STUB = r"""#!/usr/bin/env python3
import json
import os
import pathlib
import subprocess

revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
sha256 = "b" * 64
sha512 = "c" * 128
fixture = {"bytes": 1, "sha256": sha256, "sha512": sha512}
name = pathlib.Path(__file__).name
if (
    os.environ.get("FAKE_AGGREGATE_RESULT") == "same-group-descendant"
    and name == "run-sq.sh"
):
    child = subprocess.Popen(
        [__import__("sys").executable, "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    pathlib.Path(os.environ["AGGREGATE_DESCENDANT_PID"]).write_text(str(child.pid))
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


def terminate_if_alive(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


class AggregateConformanceTests(unittest.TestCase):
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
        for name in (
            "check-domain-model.py",
            "test-domain-model.py",
            "check-fido-custody.py",
            "test-run-sq.py",
            "test-run-signing-profile.py",
            "test-sq-evidence-process.py",
            "check-source-inventory.py",
            "test-source-inventory.py",
            "test-probe-result.py",
            "test-strict-json.py",
            "test-check-conformance.py",
        ):
            write_executable(repository / "conformance" / name, PYTHON_STUB)
        for name in ("run-sq.sh", "run-signing-profile.sh"):
            write_executable(repository / "conformance" / name, PROBE_STUB)

        environment = {
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
        self, repository: pathlib.Path, environment: dict[str, str]
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(repository / "scripts/check-conformance.sh")],
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

        result = self.run_aggregate(repository, environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        descendant = int(pid_path.read_text())
        self.addCleanup(terminate_if_alive, descendant)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.kill(descendant, 0)
            except ProcessLookupError:
                break
            time.sleep(0.01)
        else:
            self.fail(f"aggregate runner descendant survived: {descendant}")

    def test_complete_aggregate_runs_synthetic_checks_in_both_modes(self) -> None:
        repository, environment = self.make_repository()

        result = self.run_aggregate(repository, environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        observations: dict[str, set[int]] = {}
        for line in pathlib.Path(environment["SYNTHETIC_LOG"]).read_text().splitlines():
            name, optimized = line.split(":")
            observations.setdefault(name, set()).add(int(optimized))
        for name in (
            "check-domain-model.py",
            "test-domain-model.py",
            "check-fido-custody.py",
            "test-run-sq.py",
            "test-run-signing-profile.py",
            "test-sq-evidence-process.py",
            "check-source-inventory.py",
            "test-source-inventory.py",
            "test-probe-result.py",
            "test-strict-json.py",
            "test-check-conformance.py",
        ):
            self.assertEqual(observations.get(name), {0, 1}, name)
        temporary_results = list(
            pathlib.Path(environment["TMPDIR"]).glob("sacrysty-conformance-results.*")
        )
        self.assertEqual(temporary_results, [])


if __name__ == "__main__":
    unittest.main()
