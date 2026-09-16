#!/usr/bin/env python3
"""Regressions for immutable producer-source inventory verification."""

from __future__ import annotations

import copy
import json
import os
import pathlib
import shutil
import subprocess
import sys
import unittest

from test_support import external_temporary_directory

ROOT = pathlib.Path(__file__).parents[1]
CHECKER = ROOT / "conformance/check-source-inventory.py"
STRICT_JSON_HELPER = ROOT / "conformance/strict_json.py"
INVENTORY = ROOT / "docs/provenance/genesis-source-inventory.json"


class SourceInventoryTests(unittest.TestCase):
    def run_checker(self, repository: pathlib.Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", "conformance/check-source-inventory.py"],
            cwd=repository,
            check=False,
            capture_output=True,
            text=True,
            env={
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "HOME": os.devnull,
                "LC_ALL": "C",
                "PATH": os.environ["PATH"],
            },
        )

    def clone_with_checker(
        self, destination: pathlib.Path, *, shallow: bool = False
    ) -> pathlib.Path:
        command = ["git", "clone", "-q", "--no-hardlinks"]
        if shallow:
            command.extend(["--depth=1", "--no-local"])
        command.extend([str(ROOT), str(destination)])
        subprocess.run(command, check=True)
        shutil.copy2(CHECKER, destination / "conformance")
        shutil.copy2(STRICT_JSON_HELPER, destination / "conformance")
        return destination

    def test_checked_in_inventory_matches_full_git_object_history(self) -> None:
        result = self.run_checker(ROOT)

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_tampered_identity_fields_and_path_sets_are_rejected(self) -> None:
        with external_temporary_directory(
            ROOT, prefix="sacrysty-source-inventory-test-"
        ) as directory:
            repository = self.clone_with_checker(pathlib.Path(directory) / "repository")
            inventory_path = repository / INVENTORY.relative_to(ROOT)
            original = json.loads(inventory_path.read_text())

            mutations = {}
            for field, value in (
                ("blob_oid", "0" * 40),
                ("byte_length", original["entries"][0]["byte_length"] + 1),
                ("git_file_mode", "100755"),
                ("parent_sha", "0" * 40),
                ("sha256", "0" * 64),
                ("tree_sha", "0" * 40),
            ):
                candidate = copy.deepcopy(original)
                candidate["entries"][0][field] = value
                mutations[field] = candidate

            missing = copy.deepcopy(original)
            missing["entries"].pop()
            missing["item_count"] -= 1
            mutations["missing path"] = missing

            duplicate = copy.deepcopy(original)
            duplicate["entries"].append(copy.deepcopy(duplicate["entries"][0]))
            duplicate["item_count"] += 1
            mutations["duplicate path"] = duplicate

            for label, candidate in mutations.items():
                with self.subTest(label):
                    inventory_path.write_text(json.dumps(candidate) + "\n")
                    result = self.run_checker(repository)
                    self.assertNotEqual(result.returncode, 0)

    def test_shallow_history_is_rejected_instead_of_skipping_provenance(self) -> None:
        with external_temporary_directory(
            ROOT, prefix="sacrysty-source-inventory-shallow-test-"
        ) as directory:
            repository = self.clone_with_checker(
                pathlib.Path(directory) / "repository", shallow=True
            )

            result = self.run_checker(repository)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("complete Git history", result.stderr)


if __name__ == "__main__":
    unittest.main()
