#!/usr/bin/env python3
"""Verify genesis producer provenance directly from complete Git object history."""

from __future__ import annotations

import hashlib
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))

from sacrysty_runtime.strict_json import (
    DuplicateMemberError,
    InvalidJsonSyntaxError,
    InvalidUtf8Error,
    NonFiniteNumberError,
    UnrepresentableNumberError,
    decode_strict_json,
)

INVENTORY = ROOT / "docs/provenance/genesis-source-inventory.json"
PRODUCERS = {
    "cad9c98aa2a122368e31f4ab14aeff4e6c95a6cf": 12,
    "5a4332f7c2801df808fee58e7997cdb3ed9c855d": 13,
    "b7b23d92fa9d1535683f7417051ebb2c886c1d28": 14,
    "2579e8011e298a8863ae4a6ee439d5faf2e037b7": 15,
}
ENTRY_FIELDS = {
    "blob_oid",
    "byte_length",
    "git_file_mode",
    "issue",
    "parent_sha",
    "path",
    "sha256",
    "source_commit",
    "tree_sha",
}


class InventoryError(ValueError):
    """The source receipt cannot be proven from the local Git objects."""


def _git(*arguments: str) -> bytes:
    try:
        return subprocess.run(
            ["git", "-C", str(ROOT), *arguments],
            check=True,
            capture_output=True,
        ).stdout
    except subprocess.CalledProcessError as exc:
        command = " ".join(arguments[:2])
        raise InventoryError(f"Git object check failed: {command}") from exc


def _load_inventory() -> dict[str, object]:
    try:
        value = decode_strict_json(INVENTORY.read_bytes())
    except OSError as exc:
        raise InventoryError("source inventory is not readable strict JSON") from exc
    except DuplicateMemberError as exc:
        raise InventoryError(f"duplicate inventory member: {exc.member}") from exc
    except NonFiniteNumberError as exc:
        label = (
            "non-JSON inventory constant"
            if exc.value in {"NaN", "Infinity", "-Infinity"}
            else "non-finite inventory number"
        )
        raise InventoryError(f"{label}: {exc.value}") from exc
    except UnrepresentableNumberError as exc:
        raise InventoryError(f"unrepresentable inventory number: {exc.value}") from exc
    except (InvalidUtf8Error, InvalidJsonSyntaxError) as exc:
        raise InventoryError("source inventory is not readable strict JSON") from exc
    if not isinstance(value, dict):
        raise InventoryError("source inventory is not an object")
    if set(value) != {"entries", "format", "item_count", "lookup_failures"}:
        raise InventoryError("source inventory top-level members are incomplete")
    if value["format"] != "sacrysty-source-inventory/v1":
        raise InventoryError("source inventory format mismatch")
    if value["lookup_failures"] != []:
        raise InventoryError("source inventory retains lookup failures")
    if not isinstance(value["entries"], list):
        raise InventoryError("source inventory entries are not an array")
    item_count = value["item_count"]
    if (
        not isinstance(item_count, int)
        or isinstance(item_count, bool)
        or item_count != len(value["entries"])
    ):
        raise InventoryError("source inventory item count mismatch")
    return value


def _require_complete_history() -> None:
    if _git("rev-parse", "--is-shallow-repository").strip() != b"false":
        raise InventoryError("complete Git history is required for source provenance")
    object_listing = _git("rev-list", "--objects", "--all", "--missing=print")
    if any(line.startswith(b"?") for line in object_listing.splitlines()):
        raise InventoryError("complete Git objects are required for source provenance")
    _git("fsck", "--full", "--no-dangling", "--no-reflogs")


def _commit_identity(commit: str) -> tuple[str, str]:
    _git("cat-file", "-e", f"{commit}^{{commit}}")
    commit_line = _git("rev-list", "--parents", "-n", "1", commit).decode().split()
    if len(commit_line) != 2 or commit_line[0] != commit:
        raise InventoryError(f"producer does not have one exact parent: {commit}")
    tree = _git("rev-parse", f"{commit}^{{tree}}").decode().strip()
    return commit_line[1], tree


def _changed_paths(parent: str, commit: str) -> set[str]:
    fields = _git(
        "diff-tree",
        "--no-commit-id",
        "--name-status",
        "-r",
        "-z",
        "--no-renames",
        parent,
        commit,
    ).split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    if len(fields) % 2:
        raise InventoryError(f"unparseable producer path list: {commit}")
    paths: set[str] = set()
    for offset in range(0, len(fields), 2):
        status = fields[offset]
        try:
            path = fields[offset + 1].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InventoryError(f"non-UTF-8 producer path: {commit}") from exc
        if status == b"D":
            raise InventoryError(f"deleted producer path cannot have a blob: {path}")
        if status not in {b"A", b"M", b"T"} or path in paths:
            raise InventoryError(f"unsupported or duplicate producer path: {path}")
        paths.add(path)
    return paths


def _tree_entry(commit: str, path: str) -> tuple[str, str, bytes]:
    output = _git("ls-tree", "-z", commit, "--", path)
    records = [record for record in output.split(b"\0") if record]
    if len(records) != 1 or b"\t" not in records[0]:
        raise InventoryError(f"producer path has no unique tree entry: {path}")
    metadata, encoded_path = records[0].split(b"\t", 1)
    try:
        actual_path = encoded_path.decode("utf-8")
        mode, object_type, oid = metadata.decode("ascii").split()
    except (UnicodeDecodeError, ValueError) as exc:
        raise InventoryError(f"unparseable producer tree entry: {path}") from exc
    if actual_path != path or object_type != "blob":
        raise InventoryError(f"producer tree entry is not the expected blob: {path}")
    return mode, oid, _git("cat-file", "blob", oid)


def _entry_string(entry: dict[str, object], field: str) -> str:
    value = entry[field]
    if not isinstance(value, str):
        raise InventoryError(f"inventory {field} is not a string")
    return value


def check_inventory() -> tuple[int, int]:
    inventory = _load_inventory()
    _require_complete_history()
    entries = inventory["entries"]
    if not isinstance(entries, list):
        raise InventoryError("source inventory entries are not an array")

    grouped: dict[str, list[dict[str, object]]] = {commit: [] for commit in PRODUCERS}
    identities: set[tuple[str, str]] = set()
    for raw_entry in entries:
        if not isinstance(raw_entry, dict) or set(raw_entry) != ENTRY_FIELDS:
            raise InventoryError("source inventory entry members are incomplete")
        entry = raw_entry
        commit = _entry_string(entry, "source_commit")
        path = _entry_string(entry, "path")
        if commit not in PRODUCERS:
            raise InventoryError(f"unknown producer commit: {commit}")
        if entry["issue"] != PRODUCERS[commit]:
            raise InventoryError(f"producer issue mismatch: {commit}")
        if (
            not path
            or pathlib.PurePosixPath(path).is_absolute()
            or ".." in pathlib.PurePosixPath(path).parts
        ):
            raise InventoryError(f"invalid producer path: {path}")
        identity = (commit, path)
        if identity in identities:
            raise InventoryError(f"duplicate producer path identity: {commit}:{path}")
        identities.add(identity)
        grouped[commit].append(entry)

    head = _git("rev-parse", "HEAD").decode().strip()
    exact_total = 0
    for commit, producer_entries in grouped.items():
        parent, tree = _commit_identity(commit)
        try:
            subprocess.run(
                ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", commit, head],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as exc:
            raise InventoryError(
                f"producer is not an ancestor of the candidate: {commit}"
            ) from exc
        changed_paths = _changed_paths(parent, commit)
        manifest_paths = {_entry_string(entry, "path") for entry in producer_entries}
        if manifest_paths != changed_paths or len(producer_entries) != len(
            changed_paths
        ):
            raise InventoryError(f"producer path inventory mismatch: {commit}")
        exact_total += len(changed_paths)

        for entry in producer_entries:
            path = _entry_string(entry, "path")
            if _entry_string(entry, "parent_sha") != parent:
                raise InventoryError(f"producer parent mismatch: {commit}:{path}")
            if _entry_string(entry, "tree_sha") != tree:
                raise InventoryError(f"producer tree mismatch: {commit}:{path}")
            mode, oid, blob = _tree_entry(commit, path)
            if _entry_string(entry, "git_file_mode") != mode:
                raise InventoryError(f"producer file mode mismatch: {commit}:{path}")
            if _entry_string(entry, "blob_oid") != oid:
                raise InventoryError(f"producer blob mismatch: {commit}:{path}")
            byte_length = entry["byte_length"]
            if (
                not isinstance(byte_length, int)
                or isinstance(byte_length, bool)
                or byte_length != len(blob)
            ):
                raise InventoryError(f"producer byte length mismatch: {commit}:{path}")
            if _entry_string(entry, "sha256") != hashlib.sha256(blob).hexdigest():
                raise InventoryError(f"producer SHA-256 mismatch: {commit}:{path}")

    if exact_total != inventory["item_count"]:
        raise InventoryError("exact producer path count mismatch")
    return exact_total, len(grouped)


def main() -> None:
    try:
        item_count, producer_count = check_inventory()
    except InventoryError as exc:
        raise SystemExit(str(exc)) from exc
    print(
        "source inventory conformance passed: "
        f"{item_count} path entries across {producer_count} producers"
    )


if __name__ == "__main__":
    main()
