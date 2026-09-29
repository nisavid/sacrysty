#!/usr/bin/env python3
"""Exercise the documented Bash procedure with constructed command processes."""

from __future__ import annotations

import json
import pathlib
import shlex
import subprocess
import sys
import unittest

from test_support import ConstructedRepository

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROCEDURE = ROOT / "docs/agents/genesis-validation.md"

# These process-boundary substitutes exercise checkout changes and receipts.
# They do not run conformance or Cargo; reentering conformance would recurse.
STEP_STUB = r"""import json
import pathlib
import subprocess
import sys

runtime = pathlib.Path(__file__).resolve().parent
label = "conformance" if sys.argv[1] == "conformance" else "cargo-" + sys.argv[5]
plan = json.loads((runtime / "plan.json").read_text())
action = plan.get(label, {})
if "checkout" in action:
    subprocess.run(["git", "checkout", "--quiet", "--detach", action["checkout"]],
                   check=True)
head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
status = subprocess.check_output(["git", "status", "--porcelain=v1"], text=True)
with (runtime / "steps.jsonl").open("a") as log:
    log.write(json.dumps({"step": label, "head": head, "status": status}) + "\n")
print("constructed command: " + label)
print("constructed diagnostic: " + label, file=sys.stderr)
raise SystemExit(action.get("exit", 0))
"""


class GenesisValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = ConstructedRepository(ROOT, prefix="sacrysty-genesis-test-")
        self.addCleanup(self.fixture.cleanup)
        self.repository = self.fixture.repository
        self.runtime = self.fixture.runtime
        self.evidence_parent = self.runtime / "evidence"
        self.evidence_parent.mkdir()
        self.rustup_home = self.runtime / "rustup-home"
        self.rustup_home.mkdir()
        step = self.runtime / "step.py"
        step.write_text(STEP_STUB, encoding="utf-8")
        command = f"exec {shlex.quote(sys.executable)} -B {shlex.quote(str(step))}"
        self.fixture.write(
            "scripts/check-conformance.sh",
            f'#!/usr/bin/env bash\n{command} conformance "$@"\n',
            executable=True,
        )
        self.rustup = self.runtime / "rustup"
        self.rustup.write_text(
            f'#!/usr/bin/env bash\n{command} rustup "$@"\n', encoding="utf-8"
        )
        self.rustup.chmod(0o700)
        self.tool = self.runtime / "unused-tool"
        self.tool.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        self.tool.chmod(0o700)
        self.fixture.write(".gitignore", "target/\n")
        self.fixture.write("candidate.txt", "candidate A\n")
        self.fixture.commit(message="fixture A")
        self.revision_a = self.git("rev-parse", "HEAD")
        self.tree_a = self.git("rev-parse", "HEAD^{tree}")
        self.fixture.write("candidate.txt", "candidate B\n")
        self.fixture.commit(message="fixture B")
        self.revision_b = self.git("rev-parse", "HEAD")
        self.git("checkout", "--quiet", "--detach", self.revision_a)

    def git(self, *args: str) -> str:
        return subprocess.check_output(
            ["git", "-C", str(self.repository), *args],
            env=self.fixture.environment,
            text=True,
        ).strip()

    def run_procedure(
        self, plan: dict[str, dict[str, str | int]] | None = None
    ) -> subprocess.CompletedProcess[str]:
        (self.runtime / "plan.json").write_text(
            json.dumps(plan or {}), encoding="utf-8"
        )
        document = PROCEDURE.read_text(encoding="utf-8")
        self.assertEqual(document.count("```bash\n"), 1)
        block = document.split("```bash\n", 1)[1].split("\n```", 1)[0]
        replacements = {
            "/absolute/path/to/external-storage": self.evidence_parent,
            "/absolute/path/to/rustup-home": self.rustup_home,
            "/absolute/path/to/rustup": self.rustup,
            "/absolute/path/to/selected/sqv": self.tool,
            "/absolute/path/to/selected/sq": self.tool,
        }
        for placeholder, path in replacements.items():
            # A whole placeholder line avoids matching rustup inside rustup-home.
            self.assertEqual(block.count(placeholder + "\n"), 1)
            block = block.replace(placeholder + "\n", shlex.quote(str(path)) + "\n")
        return subprocess.run(
            ["bash"],
            input=block,
            cwd=self.repository,
            env=self.fixture.environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def receipt(self) -> tuple[pathlib.Path, str]:
        roots = list(self.evidence_parent.glob("sacrysty-genesis-validation.*"))
        self.assertEqual(len(roots), 1)
        return roots[0], (roots[0] / "receipt.txt").read_text(encoding="utf-8")

    def test_unchanged_clean_candidate_retains_external_success_evidence(self) -> None:
        completed = self.run_procedure()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        root, receipt = self.receipt()
        self.assertEqual(root.parent, self.evidence_parent)
        self.assertIn(f"before_head={self.revision_a}\n", receipt)
        self.assertIn(f"after_head={self.revision_a}\n", receipt)
        self.assertIn(f"before_tree={self.tree_a}\n", receipt)
        self.assertIn(f"after_tree={self.tree_a}\n", receipt)
        self.assertIn("result=passed\n", receipt)
        for label in (
            "conformance",
            "cargo-fmt",
            "cargo-clippy",
            "cargo-build",
            "cargo-test",
            "cargo-doc",
        ):
            self.assertIn(f"step_{label}_status=0\n", receipt)
            self.assertIn(
                "constructed command:", (root / f"{label}.stdout").read_text()
            )
            self.assertIn(
                "constructed diagnostic:", (root / f"{label}.stderr").read_text()
            )
        self.assertEqual(self.git("status", "--porcelain=v1"), "")
        self.assertFalse((self.repository / "target").exists())

    def test_clean_checkout_move_fails_before_positive_receipt(self) -> None:
        completed = self.run_procedure({"conformance": {"checkout": self.revision_b}})
        _, receipt = self.receipt()
        self.assertNotEqual(completed.returncode, 0, receipt)
        self.assertNotIn("result=passed\n", receipt)
        self.assertIn("result=failed phase=", receipt)
        self.assertEqual(self.git("status", "--porcelain=v1"), "")

    def test_observed_move_fails_before_a_later_step_can_return_to_start(self) -> None:
        completed = self.run_procedure(
            {
                "conformance": {"checkout": self.revision_b},
                "cargo-fmt": {"checkout": self.revision_a},
            }
        )
        root, receipt = self.receipt()
        self.assertNotEqual(completed.returncode, 0, receipt)
        self.assertNotIn("result=passed\n", receipt)
        self.assertIn(
            "result=failed phase=conformance-after-source-revision\n", receipt
        )
        self.assertFalse((root / "cargo-fmt.stdout").exists())
        self.assertEqual(self.git("rev-parse", "HEAD"), self.revision_b)

    def test_same_tree_at_a_different_commit_fails(self) -> None:
        self.git("commit", "--quiet", "--allow-empty", "-m", "fixture same tree")
        same_tree_revision = self.git("rev-parse", "HEAD")
        self.assertNotEqual(same_tree_revision, self.revision_a)
        self.assertEqual(self.git("rev-parse", "HEAD^{tree}"), self.tree_a)
        self.git("checkout", "--quiet", "--detach", self.revision_a)
        completed = self.run_procedure(
            {"cargo-clippy": {"checkout": same_tree_revision}}
        )
        _, receipt = self.receipt()
        self.assertNotEqual(completed.returncode, 0, receipt)
        self.assertIn(f"cargo-clippy-after_head={same_tree_revision}\n", receipt)
        self.assertIn(f"cargo-clippy-after_tree={self.tree_a}\n", receipt)
        self.assertIn(
            "result=failed phase=cargo-clippy-after-source-revision\n", receipt
        )
        self.assertNotIn("result=passed\n", receipt)

    def test_last_command_revision_change_fails(self) -> None:
        completed = self.run_procedure({"cargo-doc": {"checkout": self.revision_b}})
        _, receipt = self.receipt()
        self.assertNotEqual(completed.returncode, 0, receipt)
        self.assertIn("step_cargo-doc_status=0\n", receipt)
        self.assertIn("result=failed phase=cargo-doc-after-source-revision\n", receipt)
        self.assertNotIn("result=passed\n", receipt)

    def test_command_failure_retains_its_status_and_streams(self) -> None:
        completed = self.run_procedure({"cargo-build": {"exit": 23}})
        root, receipt = self.receipt()
        self.assertEqual(completed.returncode, 23, completed.stderr)
        self.assertIn("step_cargo-build_status=23\n", receipt)
        self.assertIn("result=failed phase=cargo-build\n", receipt)
        self.assertNotIn("result=passed\n", receipt)
        self.assertTrue((root / "cargo-build.stdout").is_file())
        self.assertIn(
            "constructed diagnostic: cargo-build",
            (root / "cargo-build.stderr").read_text(),
        )
        self.assertFalse((root / "cargo-test.stdout").exists())

    def test_storage_inside_source_checkout_is_rejected(self) -> None:
        self.evidence_parent = self.repository
        completed = self.run_procedure()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "validation storage must be outside the source checkout", completed.stderr
        )
        self.assertFalse(list(self.repository.glob("sacrysty-genesis-validation.*")))
        self.assertEqual(self.git("status", "--porcelain=v1"), "")

    def test_dirty_checkout_fails_before_commands(self) -> None:
        self.fixture.write("candidate.txt", "uncommitted fixture\n")
        completed = self.run_procedure()
        _, receipt = self.receipt()
        self.assertNotEqual(completed.returncode, 0, receipt)
        self.assertIn("result=failed phase=before-source-state\n", receipt)
        self.assertNotIn("result=passed\n", receipt)
        self.assertFalse((self.runtime / "steps.jsonl").exists())

    def test_ignored_checkout_target_fails_before_commands(self) -> None:
        (self.repository / "target").mkdir()
        self.assertEqual(self.git("status", "--porcelain=v1"), "")
        completed = self.run_procedure()
        _, receipt = self.receipt()
        self.assertNotEqual(completed.returncode, 0, receipt)
        self.assertIn("result=failed phase=before-source-state\n", receipt)
        self.assertNotIn("result=passed\n", receipt)
        self.assertFalse((self.runtime / "steps.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
