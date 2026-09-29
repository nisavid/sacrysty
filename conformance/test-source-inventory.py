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

from test_support import ConstructedRepository, external_temporary_directory

ROOT = pathlib.Path(__file__).parents[1]
CHECKER = ROOT / "conformance/check-source-inventory.py"
RUNTIME_SUPPORT = ROOT / "sacrysty_runtime"
INVENTORY = ROOT / "docs/provenance/genesis-source-inventory.json"
BUNDLE = ROOT / "docs/provenance/genesis-sources.bundle"


class SourceInventoryTests(unittest.TestCase):
    def test_squashed_shallow_checkout_verifies_without_producer_history(self) -> None:
        fixture = ConstructedRepository(ROOT, prefix="sacrysty-source-squash-test-")
        self.addCleanup(fixture.cleanup)
        fixture.write("README", "Value-free base.\n")
        fixture.commit()
        fixture.copy(CHECKER, "conformance/check-source-inventory.py")
        fixture.copy(ROOT / "conformance/test_support.py", "conformance/test_support.py")
        fixture.copy_tree(RUNTIME_SUPPORT, "sacrysty_runtime")
        fixture.copy(INVENTORY, str(INVENTORY.relative_to(ROOT)))
        fixture.copy(BUNDLE, str(BUNDLE.relative_to(ROOT)))
        fixture.commit(message="squashed source candidate")
        checkout = fixture.runtime / "shallow"
        subprocess.run(
            [
                "git", "clone", "-q", "--depth=1", "--no-local",
                str(fixture.repository), str(checkout),
            ],
            check=True,
            env=fixture.environment,
        )
        missing = subprocess.run(
            [
                "git", "-C", str(checkout), "cat-file", "-e",
                "cad9c98aa2a122368e31f4ab14aeff4e6c95a6cf",
            ],
            capture_output=True,
            check=False,
            env=fixture.environment,
        )
        self.assertNotEqual(missing.returncode, 0)

        result = self.run_checker(checkout)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("35 path entries across 4 producers", result.stdout)

    def run_checker(self, repository: pathlib.Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, *(["-O"] if sys.flags.optimize else []),
             "-B", "conformance/check-source-inventory.py"],
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

    def clone_with_checker(self, destination: pathlib.Path) -> pathlib.Path:
        command = ["git", "clone", "-q", "--no-hardlinks"]
        command.extend([str(ROOT), str(destination)])
        subprocess.run(command, check=True)
        shutil.copy2(CHECKER, destination / "conformance")
        shutil.copy2(ROOT / "conformance/test_support.py", destination / "conformance")
        shutil.copy2(BUNDLE, destination / BUNDLE.relative_to(ROOT))
        shutil.copytree(
            RUNTIME_SUPPORT, destination / "sacrysty_runtime", dirs_exist_ok=True
        )
        return destination

    def test_checked_in_inventory_matches_retained_producer_objects(self) -> None:
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

    def test_missing_or_damaged_bundle_fails_despite_available_git_history(self) -> None:
        with external_temporary_directory(
            ROOT, prefix="sacrysty-source-inventory-bundle-test-"
        ) as directory:
            repository = self.clone_with_checker(pathlib.Path(directory) / "repository")
            bundle = repository / BUNDLE.relative_to(ROOT)
            original = bundle.read_bytes()
            for label, value in (
                ("missing", None),
                ("truncated", original[:-1]),
                ("changed", original[:-1] + bytes([original[-1] ^ 1])),
                ("extended", original + b"x"),
            ):
                with self.subTest(label):
                    if value is None:
                        bundle.unlink()
                    else:
                        bundle.write_bytes(value)
                    result = self.run_checker(repository)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("source bundle", result.stderr)


if __name__ == "__main__":
    unittest.main()
