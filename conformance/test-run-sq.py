#!/usr/bin/env python3
"""Focused regressions for the isolated sq/sqv evidence runner."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shlex
import shutil
import stat
import subprocess
import sys
import unittest

from test_support import ConstructedRepository

ROOT = pathlib.Path(__file__).parents[1]
RUNNER = ROOT / "conformance/run-sq.sh"
SHARED_HELPER = ROOT / "conformance/sq-evidence-lib.sh"
PROCESS_HELPER = ROOT / "conformance/sq_evidence_process.py"


def write_executable(path: pathlib.Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class RunSqTests(unittest.TestCase):
    def make_repository(self) -> tuple[pathlib.Path, dict[str, str]]:
        fixture = ConstructedRepository(ROOT, prefix="sacrysty-run-sq-test-")
        self.addCleanup(fixture.cleanup)
        self.constructed_repository = fixture
        repository = fixture.repository
        fixture.copy(RUNNER, "conformance/run-sq.sh")
        fixture.copy(SHARED_HELPER, "conformance/sq-evidence-lib.sh")
        fixture.copy(PROCESS_HELPER, "conformance/sq_evidence_process.py")
        fixture.copy_tree(ROOT / "sacrysty_runtime", "sacrysty_runtime")
        fixture.write(
            "fixtures/rfc9580/message.txt",
            "Sacrysty disposable conformance fixture.\n",
        )
        fixture.commit("conformance", "fixtures", "sacrysty_runtime")
        return repository, fixture.environment

    def commit_paths(
        self,
        repository: pathlib.Path,
        environment: dict[str, str],
        *paths: str,
    ) -> None:
        del repository, environment
        self.constructed_repository.commit(*paths, message="test input")

    def install_successful_fake_tools(
        self, repository: pathlib.Path, environment: dict[str, str]
    ) -> pathlib.Path:
        tool_log = pathlib.Path(environment["TEST_RUNTIME"]) / "tool.log"
        control_directory = pathlib.Path(environment["TEST_RUNTIME"]) / "controls"
        control_directory.mkdir(exist_ok=True)
        tool_log_shell = shlex.quote(str(tool_log))
        control_directory_shell = shlex.quote(str(control_directory))
        write_executable(
            repository / "fake-bin/sq",
            rf"""#!/bin/sh
tool_log={tool_log_shell}
control_directory={control_directory_shell}
control() {{
    if [ -f "$control_directory/$1" ]; then
        cat "$control_directory/$1"
    else
        printf '%s' "$2"
    fi
}}
printf 'sq:%s\n' "$*" >>"$tool_log"
if [ "${{1-}}" = version ]; then
    if [ "$(control fault none)" = stdout-flood ]; then
        python3 -c 'import sys; sys.stdout.buffer.write(b"x" * (2 * 1024 * 1024))'
        exit 0
    fi
    printf 'sq "quoted" \\ path\nsecond\tline\n'
    printf 'diagnostic: "quoted" \\ value\rcontrol\n' >&2
    exit 0
fi
case " $* " in
    *' mldsa65-ed25519 '*)
        case "$(control pqc-generation unsupported)" in
            unsupported)
                printf 'Error: Unsupported public key algorithm: ML-DSA-65+Ed25519\n' >&2
                exit 1
                ;;
            indeterminate)
                printf 'Error: Unsupported public key algorithm: ML-DSA-65+Ed25519\n' >&2
                printf 'Error: unable to write output: resource unavailable\n' >&2
                exit 74
                ;;
            abnormal)
                # Model the helper's normalized abnormal status without signalling.
                printf 'Error: Unsupported public key algorithm: ML-DSA-65+Ed25519\n' >&2
                exit 137
                ;;
            success) ;;
        esac
        ;;
esac
case " $* " in
    *' sign '*'pqc-key.pgp '*)
        if [ "$(control pqc-round-trip success)" = fail ]; then
            printf 'Error: synthetic signing failure\n' >&2
            exit 70
        fi
        ;;
esac
while [ "$#" -gt 0 ]; do
    case "$1" in
        --output|--rev-cert|--signature-file)
            shift
            printf 'disposable fake artifact\n' >"$1"
            ;;
    esac
    shift
done
""",
        )
        write_executable(
            repository / "fake-bin/sqv",
            rf"""#!/bin/sh
tool_log={tool_log_shell}
printf 'sqv:%s\n' "$*" >>"$tool_log"
if [ "${{1-}}" = --version ]; then
    printf 'sqv "quoted" \\ path\nsecond\tline\n'
    printf 'diagnostic: "quoted" \\ value\rcontrol\n' >&2
    exit 0
fi
case " $* " in
    *'/tampered-message.bin '*|*'/tampered-signature.sig '*|*'/other-cert.pgp '*) exit 1 ;;
esac
exit 0
""",
        )
        self.commit_paths(repository, environment, "fake-bin")
        environment.update(
            {
                "SQ": str(repository / "fake-bin/sq"),
                "SQV": str(repository / "fake-bin/sqv"),
            }
        )
        return tool_log

    def set_control(self, environment: dict[str, str], name: str, value: str) -> None:
        control = pathlib.Path(environment["TEST_RUNTIME"]) / "controls" / name
        control.parent.mkdir(exist_ok=True)
        control.write_text(value, encoding="ascii")

    def test_untracked_dirt_is_rejected_before_tool_work(self) -> None:
        repository, environment = self.make_repository()
        tool_log = pathlib.Path(environment["TEST_RUNTIME"]) / "tool.log"
        fake_tool = """#!/bin/sh
printf 'invoked\\n' >>"$FAKE_TOOL_LOG"
exit 97
"""
        for name in ("sq", "sqv"):
            write_executable(repository / "fake-bin" / name, fake_tool)
        self.commit_paths(repository, environment, "fake-bin")
        environment.update(
            {
                "FAKE_TOOL_LOG": str(tool_log),
                "SQ": str(repository / "fake-bin/sq"),
                "SQV": str(repository / "fake-bin/sqv"),
            }
        )
        (repository / "untracked").write_text("dirty\n")

        result = subprocess.run(
            ["bash", str(repository / "conformance/run-sq.sh")],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("clean worktree", result.stderr)
        self.assertFalse(
            tool_log.exists(), "sq/sqv ran before untracked dirt rejection"
        )

    def test_tracked_dirt_is_rejected_before_tool_work(self) -> None:
        repository, environment = self.make_repository()
        tool_log = self.install_successful_fake_tools(repository, environment)
        (repository / "fixtures/rfc9580/message.txt").write_text("tracked dirt\n")

        result = subprocess.run(
            ["bash", str(repository / "conformance/run-sq.sh")],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("clean worktree", result.stderr)
        self.assertFalse(tool_log.exists(), "sq/sqv ran before tracked dirt rejection")

    def test_source_inspection_failure_is_rejected_before_tool_work(self) -> None:
        repository, environment = self.make_repository()
        tool_log = self.install_successful_fake_tools(repository, environment)
        real_git = shutil.which("git")
        self.assertIsNotNone(real_git)
        failure_bin = pathlib.Path(environment["TEST_RUNTIME"]) / "git-failure-bin"
        failure_bin.mkdir()
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

        result = subprocess.run(
            ["bash", str(repository / "conformance/run-sq.sh")],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not inspect source worktree", result.stderr)
        self.assertFalse(tool_log.exists(), "sq/sqv ran after source inspection failed")

    def test_hostile_tool_versions_are_json_strings(self) -> None:
        repository, environment = self.make_repository()
        self.install_successful_fake_tools(repository, environment)

        result = subprocess.run(
            ["bash", str(repository / "conformance/run-sq.sh")],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertIn('sq "quoted" \\ path', evidence["sq_version"])
        self.assertIn('sqv "quoted" \\ path', evidence["sqv_version"])
        self.assertIn("\n", evidence["sq_version"])
        self.assertIn("\t", evidence["sqv_version"])
        self.assertIn("\r", evidence["sq_version"])

    def test_stdout_flood_fails_instead_of_becoming_probe_evidence(self) -> None:
        repository, environment = self.make_repository()
        self.install_successful_fake_tools(repository, environment)
        self.set_control(environment, "fault", "stdout-flood")

        result = subprocess.run(
            ["bash", str(repository / "conformance/run-sq.sh")],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exceeded stdout limit", result.stderr)
        self.assertNotIn('"sq_sign_verify": true', result.stdout)

    def test_shasum_is_used_when_gnu_hash_tools_are_unavailable(self) -> None:
        repository, environment = self.make_repository()
        self.install_successful_fake_tools(repository, environment)
        portable_bin = repository / "portable-bin"
        portable_bin.mkdir()
        for name in (
            "awk",
            "cat",
            "cp",
            "dirname",
            "git",
            "mktemp",
            "rm",
            "tr",
            "wc",
        ):
            executable = shutil.which(name)
            if executable is None:
                self.fail(f"required test executable is unavailable: {name}")
            (portable_bin / name).symlink_to(executable)
        (portable_bin / "python3").symlink_to(sys.executable)
        hash_log = pathlib.Path(environment["TEST_RUNTIME"]) / "hash.log"
        write_executable(
            portable_bin / "shasum",
            r"""#!/bin/sh
printf '%s:%s\n' "$2" "$3" >>"$HASH_TOOL_LOG"
"$HASH_PYTHON" -c '
import hashlib, pathlib, sys
algorithm, path = sys.argv[1:]
print(hashlib.new("sha" + algorithm, pathlib.Path(path).read_bytes()).hexdigest(), path)
' "$2" "$3"
""",
        )
        self.commit_paths(repository, environment, "portable-bin")
        environment.update(
            {
                "HASH_PYTHON": sys.executable,
                "HASH_TOOL_LOG": str(hash_log),
                "PATH": str(portable_bin),
            }
        )

        bash = shutil.which("bash")
        if bash is None:
            self.fail("bash is unavailable")
        result = subprocess.run(
            [bash, str(repository / "conformance/run-sq.sh")],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        message = (repository / "fixtures/rfc9580/message.txt").read_bytes()
        self.assertEqual(
            evidence["fixtures"]["message"]["sha256"],
            hashlib.sha256(message).hexdigest(),
        )
        self.assertEqual(
            evidence["fixtures"]["message"]["sha512"],
            hashlib.sha512(message).hexdigest(),
        )
        hash_calls = hash_log.read_text().splitlines()
        self.assertTrue(any(call.startswith("256:") for call in hash_calls))
        self.assertTrue(any(call.startswith("512:") for call in hash_calls))

    def test_evidence_bindings_follow_profile_and_cleanup_is_verified(self) -> None:
        repository, environment = self.make_repository()
        tool_log = self.install_successful_fake_tools(repository, environment)

        result = subprocess.run(
            ["bash", str(repository / "conformance/run-sq.sh")],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertTrue(
            {
                "source_revision",
                "reference_time",
                "sq_version",
                "sqv_version",
                "fixture_sha256",
                "fixture_sha512",
                "fixture_bytes",
                "result",
            }
            <= evidence.keys()
        )
        message = (repository / "fixtures/rfc9580/message.txt").read_bytes()
        self.assertEqual(evidence["fixture_bytes"], len(message))
        self.assertEqual(
            evidence["fixture_sha256"], hashlib.sha256(message).hexdigest()
        )
        self.assertEqual(
            evidence["fixture_sha512"], hashlib.sha512(message).hexdigest()
        )
        self.assertEqual(
            evidence["result"],
            {
                "openpgp-rfc9580-classical-v1": "qualified-for-observed-runtime",
                "openpgp-rfc9980-pqc-v1": "unsupported",
            },
        )
        self.assertIs(evidence["checks"]["temporary_key_material_removed"], True)

        temporary_paths = []
        prefix = str(pathlib.Path(environment["TMPDIR"]) / "sacrysty-conformance.")
        for token in tool_log.read_text().split():
            if token.startswith(prefix):
                temporary_paths.append(pathlib.Path(token))
        self.assertTrue(temporary_paths, "fake tools did not receive isolated paths")
        for path in temporary_paths:
            self.assertFalse(path.exists(), f"temporary artifact was retained: {path}")

    def test_indeterminate_pqc_generation_failure_is_not_unsupported(self) -> None:
        repository, environment = self.make_repository()
        self.install_successful_fake_tools(repository, environment)
        self.set_control(environment, "pqc-generation", "indeterminate")

        result = subprocess.run(
            ["bash", str(repository / "conformance/run-sq.sh")],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

        evidence = json.loads(result.stdout)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(evidence["result"]["openpgp-rfc9980-pqc-v1"], "probe-failed")

    def test_abnormal_pqc_generation_exit_is_not_unsupported(self) -> None:
        repository, environment = self.make_repository()
        self.install_successful_fake_tools(repository, environment)
        self.set_control(environment, "pqc-generation", "abnormal")

        result = subprocess.run(
            ["bash", str(repository / "conformance/run-sq.sh")],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

        evidence = json.loads(result.stdout)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(evidence["result"]["openpgp-rfc9980-pqc-v1"], "probe-failed")

    def test_failed_pqc_round_trip_is_nonpositive_and_fails_the_probe(self) -> None:
        repository, environment = self.make_repository()
        self.install_successful_fake_tools(repository, environment)
        self.set_control(environment, "pqc-generation", "success")
        self.set_control(environment, "pqc-round-trip", "fail")

        result = subprocess.run(
            ["bash", str(repository / "conformance/run-sq.sh")],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

        evidence = json.loads(result.stdout)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            evidence["result"]["openpgp-rfc9980-pqc-v1"], "round-trip-failed"
        )

    def test_positive_pqc_round_trip_uses_observed_runtime_result(self) -> None:
        repository, environment = self.make_repository()
        self.install_successful_fake_tools(repository, environment)
        self.set_control(environment, "pqc-generation", "success")

        result = subprocess.run(
            ["bash", str(repository / "conformance/run-sq.sh")],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertEqual(
            evidence["result"]["openpgp-rfc9980-pqc-v1"],
            "qualified-for-observed-runtime",
        )

    def test_cleanup_failure_cannot_emit_cleanup_success(self) -> None:
        repository, environment = self.make_repository()
        self.install_successful_fake_tools(repository, environment)
        failure_bin = repository / "failure-bin"
        failure_bin.mkdir()
        write_executable(
            failure_bin / "rm",
            "#!/bin/sh\nexit 1\n",
        )
        self.commit_paths(repository, environment, "failure-bin")
        environment["PATH"] = f"{failure_bin}{os.pathsep}{environment['PATH']}"

        result = subprocess.run(
            ["bash", str(repository / "conformance/run-sq.sh")],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cleanup failed", result.stderr)
        self.assertNotIn('"temporary_key_material_removed": true', result.stdout)


if __name__ == "__main__":
    unittest.main()
