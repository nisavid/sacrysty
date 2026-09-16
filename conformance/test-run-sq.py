#!/usr/bin/env python3
"""Focused regressions for the isolated sq/sqv evidence runner."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).parents[1]
RUNNER = ROOT / "conformance/run-sq.sh"


def write_executable(path: pathlib.Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class RunSqTests(unittest.TestCase):
    def make_repository(self) -> tuple[pathlib.Path, dict[str, str]]:
        self.temporary_directory = tempfile.TemporaryDirectory(
            prefix=".run-sq-test-", dir=ROOT
        )
        self.addCleanup(self.temporary_directory.cleanup)
        repository = pathlib.Path(self.temporary_directory.name) / "repository"
        (repository / "conformance").mkdir(parents=True)
        (repository / "fixtures/rfc9580").mkdir(parents=True)
        (repository / "fake-bin").mkdir()
        (repository / "tmp").mkdir()
        (repository / "home").mkdir()
        (repository / "hooks").mkdir()
        shutil.copy2(RUNNER, repository / "conformance/run-sq.sh")
        (repository / "fixtures/rfc9580/message.txt").write_text(
            "Sacrysty disposable conformance fixture.\n"
        )

        environment = {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(repository / "missing-global-gitconfig"),
            "HOME": str(repository / "home"),
            "LC_ALL": "C",
            "PATH": os.environ["PATH"],
            "XDG_CONFIG_HOME": str(repository / "home/config"),
            "TMPDIR": str(repository / "tmp"),
        }
        subprocess.run(["git", "init", "-q", str(repository)], check=True, env=environment)
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
            ["git", "-C", str(repository), "add", "conformance", "fixtures"],
            check=True,
            env=environment,
        )
        subprocess.run(
            ["git", "-C", str(repository), "commit", "-q", "-m", "fixture"],
            check=True,
            env=environment,
        )
        return repository, environment

    def commit_paths(
        self,
        repository: pathlib.Path,
        environment: dict[str, str],
        *paths: str,
    ) -> None:
        subprocess.run(
            ["git", "-C", str(repository), "add", "--", *paths],
            check=True,
            env=environment,
        )
        subprocess.run(
            ["git", "-C", str(repository), "commit", "-q", "-m", "test input"],
            check=True,
            env=environment,
        )

    def install_successful_fake_tools(
        self, repository: pathlib.Path, environment: dict[str, str]
    ) -> pathlib.Path:
        tool_log = repository / "tool.log"
        write_executable(
            repository / "fake-bin/sq",
            r'''#!/bin/sh
printf 'sq:%s\n' "$*" >>"$FAKE_TOOL_LOG"
if [ "${1-}" = version ]; then
    printf 'sq "quoted" \\ path\nsecond\tline\n'
    printf 'diagnostic: "quoted" \\ value\rcontrol\n' >&2
    exit 0
fi
case " $* " in
    *' mldsa65-ed25519 '*) exit 1 ;;
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
''',
        )
        write_executable(
            repository / "fake-bin/sqv",
            r'''#!/bin/sh
printf 'sqv:%s\n' "$*" >>"$FAKE_TOOL_LOG"
if [ "${1-}" = --version ]; then
    printf 'sqv "quoted" \\ path\nsecond\tline\n'
    printf 'diagnostic: "quoted" \\ value\rcontrol\n' >&2
    exit 0
fi
case " $* " in
    *'/tampered.txt '*|*'/tampered.sig '*|*'/other-cert.pgp '*) exit 1 ;;
esac
exit 0
''',
        )
        self.commit_paths(repository, environment, "fake-bin")
        environment.update(
            {
                "FAKE_TOOL_LOG": str(tool_log),
                "SQ": str(repository / "fake-bin/sq"),
                "SQV": str(repository / "fake-bin/sqv"),
            }
        )
        return tool_log

    def test_untracked_dirt_is_rejected_before_tool_work(self) -> None:
        repository, environment = self.make_repository()
        tool_log = repository / "tool.log"
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
        self.assertFalse(tool_log.exists(), "sq/sqv ran before untracked dirt rejection")

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

    def test_shasum_is_used_when_gnu_hash_tools_are_unavailable(self) -> None:
        repository, environment = self.make_repository()
        self.install_successful_fake_tools(repository, environment)
        portable_bin = repository / "portable-bin"
        portable_bin.mkdir()
        for name in ("awk", "cat", "cp", "dirname", "git", "mktemp", "rm", "tr", "wc"):
            executable = shutil.which(name)
            if executable is None:
                self.fail(f"required test executable is unavailable: {name}")
            (portable_bin / name).symlink_to(executable)
        (portable_bin / "python3").symlink_to(sys.executable)
        hash_log = repository / "hash.log"
        write_executable(
            portable_bin / "shasum",
            r'''#!/bin/sh
printf '%s:%s\n' "$2" "$3" >>"$HASH_TOOL_LOG"
"$HASH_PYTHON" -c '
import hashlib, pathlib, sys
algorithm, path = sys.argv[1:]
print(hashlib.new("sha" + algorithm, pathlib.Path(path).read_bytes()).hexdigest(), path)
' "$2" "$3"
''',
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
        self.assertEqual(evidence["fixture_sha256"], hashlib.sha256(message).hexdigest())
        self.assertEqual(evidence["fixture_sha512"], hashlib.sha512(message).hexdigest())
        self.assertEqual(
            evidence["result"],
            {
                "openpgp-rfc9580-classical-v1": "qualified-for-observed-runtime",
                "openpgp-rfc9980-pqc-v1": "unsupported",
            },
        )
        self.assertIs(evidence["checks"]["temporary_key_material_removed"], True)

        temporary_paths = []
        prefix = str(repository / "tmp/sacrysty-conformance.")
        for token in tool_log.read_text().split():
            if token.startswith(prefix):
                temporary_paths.append(pathlib.Path(token))
        self.assertTrue(temporary_paths, "fake tools did not receive isolated paths")
        for path in temporary_paths:
            self.assertFalse(path.exists(), f"temporary artifact was retained: {path}")

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
