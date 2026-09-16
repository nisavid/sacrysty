"""Shared external-temporary-directory guard for synthetic conformance tests."""

from __future__ import annotations

import os
import pathlib
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
