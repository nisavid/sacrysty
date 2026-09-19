"""Shared external-temporary-directory guard for synthetic conformance tests."""

from __future__ import annotations

import os
import pathlib
import shutil
import stat
import subprocess
import tempfile


def external_temporary_directory(
    source_root: pathlib.Path, *, prefix: str
) -> tempfile.TemporaryDirectory[str]:
    configured = os.environ.get("TMPDIR")
    temporary_root = pathlib.Path(
        configured if configured is not None else tempfile.gettempdir()
    ).resolve()
    resolved_source = source_root.resolve()
    if not temporary_root.is_dir():
        raise RuntimeError("TMPDIR is unavailable")
    if temporary_root == resolved_source or resolved_source in temporary_root.parents:
        raise RuntimeError("TMPDIR must be outside the source checkout")
    return tempfile.TemporaryDirectory(prefix=prefix, dir=temporary_root)


class ConstructedRepository:
    """One value-free external Git repository for runner-facing tests."""

    def __init__(self, source_root: pathlib.Path, *, prefix: str) -> None:
        self._temporary_directory = external_temporary_directory(
            source_root, prefix=prefix
        )
        root = pathlib.Path(self._temporary_directory.name)
        self.repository = root / "repository"
        self.runtime = root / "runtime"
        self.repository.mkdir()
        (self.runtime / "tmp").mkdir(parents=True)
        (self.runtime / "home").mkdir()
        (self.repository / "hooks").mkdir()
        self.environment = {
            "GIT_CONFIG_GLOBAL": str(self.runtime / "missing-global-gitconfig"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": str(self.runtime / "home"),
            "LC_ALL": "C",
            "PATH": os.environ["PATH"],
            "PYTHONDONTWRITEBYTECODE": "1",
            "TEST_RUNTIME": str(self.runtime),
            "TMPDIR": str(self.runtime / "tmp"),
            "XDG_CONFIG_HOME": str(self.runtime / "home/config"),
        }
        subprocess.run(
            ["git", "init", "-q", str(self.repository)],
            check=True,
            env=self.environment,
        )
        for name, value in (
            ("user.name", "Fixture"),
            ("user.email", "fixture@example.invalid"),
            ("core.hooksPath", str(self.repository / "hooks")),
        ):
            subprocess.run(
                ["git", "-C", str(self.repository), "config", name, value],
                check=True,
                env=self.environment,
            )

    def cleanup(self) -> None:
        self._temporary_directory.cleanup()

    def copy(
        self, source: pathlib.Path, destination: str | None = None
    ) -> pathlib.Path:
        target = self.repository / (destination or source.name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        return target

    def copy_tree(self, source: pathlib.Path, destination: str) -> pathlib.Path:
        target = self.repository / destination
        shutil.copytree(source, target)
        return target

    def write(
        self,
        path: str,
        content: str | bytes,
        *,
        executable: bool = False,
    ) -> pathlib.Path:
        target = self.repository / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")
        if executable:
            target.chmod(target.stat().st_mode | stat.S_IXUSR)
        return target

    def commit(self, *paths: str, message: str = "fixture") -> None:
        selected = paths or (".",)
        subprocess.run(
            ["git", "-C", str(self.repository), "add", "--", *selected],
            check=True,
            env=self.environment,
        )
        subprocess.run(
            ["git", "-C", str(self.repository), "commit", "-q", "-m", message],
            check=True,
            env=self.environment,
        )
