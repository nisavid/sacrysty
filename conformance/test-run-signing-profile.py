#!/usr/bin/env python3
"""Focused regressions for the retained signing-profile evidence runner."""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import stat
import subprocess
import unittest
from itertools import pairwise

from test_support import external_temporary_directory

ROOT = pathlib.Path(__file__).parents[1]
RUNNER = ROOT / "conformance/run-signing-profile.sh"
SHARED_HELPER = ROOT / "conformance/sq-evidence-lib.sh"
PROCESS_HELPER = ROOT / "conformance/sq_evidence_process.py"


FAKE_TOOL = r"""#!/usr/bin/env python3
import json
import os
import pathlib
import sys

name = pathlib.Path(sys.argv[0]).name
arguments = sys.argv[1:]
with open(os.environ["FAKE_TOOL_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps({"name": name, "arguments": arguments}) + "\n")

controls = bytes(range(32))
if name == "sq" and arguments == ["version"]:
    sys.stdout.buffer.write(b"sq-version:" + controls + b":end")
    raise SystemExit(0)
if name == "sqv" and arguments == ["--version"]:
    if os.environ.get("FAKE_TOOL_FAULT") == "stderr-flood":
        sys.stderr.buffer.write(b"x" * (2 * 1024 * 1024))
        raise SystemExit(0)
    sys.stdout.buffer.write(b"sqv-version:" + controls + b":end")
    raise SystemExit(0)

if name == "sq":
    for flag in ("--output", "--rev-cert", "--signature-file"):
        if flag in arguments:
            path = pathlib.Path(arguments[arguments.index(flag) + 1])
            path.write_bytes(b"disposable fake artifact\n")
    raise SystemExit(0)

mode = os.environ.get("FAKE_SQV_MODE", "reject-negatives")
is_tampered_message = arguments[-1].endswith("tampered.bin")
is_tampered_signature = any(value.endswith("tampered.sig") for value in arguments)
is_wrong_certificate = any(value.endswith("wrong-cert.pgp") for value in arguments)
negative = is_tampered_message or is_tampered_signature or is_wrong_certificate
if not negative:
    if mode == "positive-fail":
        sys.stderr.buffer.write(b"positive verification failure:" + controls + b":end")
        raise SystemExit(9)
    raise SystemExit(0)

label = (
    "tampered-message"
    if is_tampered_message
    else "tampered-signature"
    if is_tampered_signature
    else "wrong-certificate"
)
if mode == label + "-accept":
    raise SystemExit(0)
sys.stderr.buffer.write(label.encode("ascii") + b":" + controls + b":end")
raise SystemExit(7)
"""


def write_executable(path: pathlib.Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def is_positive_independent_verification(call: dict[str, object]) -> bool:
    if call.get("name") != "sqv":
        return False
    arguments = call.get("arguments")
    if not isinstance(arguments, list) or len(arguments) != 7:
        return False
    if arguments[:3] != ["--time", "20260910", "--keyring"]:
        return False
    if arguments[4] != "--signature-file":
        return False
    certificate = pathlib.Path(arguments[3])
    signature = pathlib.Path(arguments[5])
    message = pathlib.Path(arguments[6])
    return (
        certificate.name == "signer-cert.pgp"
        and signature.name == "message.sig"
        and message.name == "message.bin"
        and certificate.parent == signature.parent == message.parent
    )


class SigningProfileRunnerTests(unittest.TestCase):
    def make_repository(self) -> tuple[pathlib.Path, dict[str, str]]:
        temporary_directory = external_temporary_directory(
            ROOT, prefix="sacrysty-signing-runner-test-"
        )
        self.addCleanup(temporary_directory.cleanup)
        test_root = pathlib.Path(temporary_directory.name)
        repository = test_root / "repository"
        runtime = test_root / "runtime"
        (repository / "conformance").mkdir(parents=True)
        (repository / "fixtures/signing").mkdir(parents=True)
        (repository / "hooks").mkdir()
        (runtime / "tmp").mkdir(parents=True)
        (runtime / "home").mkdir()
        shutil.copy2(RUNNER, repository / "conformance")
        if SHARED_HELPER.exists():
            shutil.copy2(SHARED_HELPER, repository / "conformance")
        shutil.copy2(PROCESS_HELPER, repository / "conformance")
        (repository / "fixtures/signing/message.bin").write_bytes(
            b"Sacrysty disposable signing fixture.\n"
        )
        for name in ("sq", "sqv"):
            write_executable(repository / "fake-bin" / name, FAKE_TOOL)

        environment = {
            "FAKE_TOOL_LOG": str(runtime / "tool.log"),
            "GIT_CONFIG_GLOBAL": str(runtime / "missing-global-gitconfig"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": str(runtime / "home"),
            "LC_ALL": "C",
            "PATH": os.environ["PATH"],
            "SQ": str(repository / "fake-bin/sq"),
            "SQV": str(repository / "fake-bin/sqv"),
            "TEST_RUNTIME": str(runtime),
            "TMPDIR": str(runtime / "tmp"),
            "XDG_CONFIG_HOME": str(runtime / "home/config"),
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
            [
                "git",
                "-C",
                str(repository),
                "config",
                "core.hooksPath",
                str(repository / "hooks"),
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

    def run_runner(
        self, repository: pathlib.Path, environment: dict[str, str]
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(repository / "conformance/run-signing-profile.sh")],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

    def test_every_json_control_byte_is_encoded_without_loss(self) -> None:
        repository, environment = self.make_repository()

        result = self.run_runner(repository, environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        controls = "".join(chr(value) for value in range(32))
        self.assertIn(controls, evidence["sq_version"])
        self.assertIn(controls, evidence["sqv_version"])
        for diagnostic in evidence["diagnostics"].values():
            self.assertIn(controls, diagnostic["stderr"])

    def test_success_requires_independent_verification_negative_cases_and_no_stores(
        self,
    ) -> None:
        repository, environment = self.make_repository()

        result = self.run_runner(repository, environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertEqual(
            evidence["schema"], "io.nisavid.sacrysty.signing-profile-result/v1"
        )
        self.assertTrue(all(evidence["checks"].values()))
        self.assertTrue(
            all(
                diagnostic["exit_status"] != 0
                for diagnostic in evidence["diagnostics"].values()
            )
        )
        calls = [
            json.loads(line)
            for line in pathlib.Path(environment["FAKE_TOOL_LOG"])
            .read_text()
            .splitlines()
        ]
        operational_sq = [
            call
            for call in calls
            if call["name"] == "sq" and call["arguments"] != ["version"]
        ]
        self.assertTrue(operational_sq)
        for call in operational_sq:
            arguments = call["arguments"]
            pairs = list(pairwise(arguments))
            self.assertIn(("--home", "none"), pairs)
            self.assertIn(("--key-store", "none"), pairs)
            self.assertIn(("--cert-store", "none"), pairs)
        self.assertEqual(
            sum(is_positive_independent_verification(call) for call in calls),
            1,
            "independent positive verification did not run",
        )
        temporary_prefix = pathlib.Path(environment["TMPDIR"]) / (
            "sacrysty-signing-profile."
        )
        temporary_paths = {
            pathlib.Path(value)
            for call in calls
            for value in call["arguments"]
            if value.startswith(str(temporary_prefix))
        }
        self.assertTrue(temporary_paths)
        self.assertTrue(all(not path.exists() for path in temporary_paths))

    def test_dirty_source_is_rejected_before_tool_execution(self) -> None:
        repository, environment = self.make_repository()
        (repository / "untracked").write_text("dirty\n")

        result = self.run_runner(repository, environment)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("clean worktree", result.stderr)
        self.assertFalse(pathlib.Path(environment["FAKE_TOOL_LOG"]).exists())

    def test_source_inspection_failure_is_rejected_before_tool_execution(self) -> None:
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

        result = self.run_runner(repository, environment)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not inspect source worktree", result.stderr)
        self.assertFalse(pathlib.Path(environment["FAKE_TOOL_LOG"]).exists())

    def test_stderr_flood_fails_instead_of_becoming_probe_evidence(self) -> None:
        repository, environment = self.make_repository()
        environment["FAKE_TOOL_FAULT"] = "stderr-flood"

        result = self.run_runner(repository, environment)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exceeded stderr limit", result.stderr)
        self.assertNotIn('"detached_sign_verify": true', result.stdout)

    def test_verification_and_each_negative_case_fail_closed(self) -> None:
        for mode in (
            "positive-fail",
            "tampered-message-accept",
            "tampered-signature-accept",
            "wrong-certificate-accept",
        ):
            with self.subTest(mode):
                repository, environment = self.make_repository()
                environment["FAKE_SQV_MODE"] = mode

                result = self.run_runner(repository, environment)

                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('"detached_sign_verify": true', result.stdout)

    def test_cleanup_failure_or_lie_cannot_report_success(self) -> None:
        for label, rm_body in (
            ("failure", "#!/bin/sh\nexit 1\n"),
            ("lie", "#!/bin/sh\nexit 0\n"),
        ):
            with self.subTest(label):
                repository, environment = self.make_repository()
                failure_bin = pathlib.Path(environment["TEST_RUNTIME"]) / "failure-bin"
                write_executable(failure_bin / "rm", rm_body)
                environment["PATH"] = f"{failure_bin}{os.pathsep}{environment['PATH']}"

                result = self.run_runner(repository, environment)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("cleanup failed", result.stderr)
                self.assertNotIn(
                    '"temporary_key_material_removed": true', result.stdout
                )


if __name__ == "__main__":
    unittest.main()
