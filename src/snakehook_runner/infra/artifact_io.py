from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import BinaryIO, TextIO


def is_regular_file(path: str | Path) -> bool:
    try:
        metadata = Path(path).lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISREG(metadata.st_mode)


def open_regular_binary(path: str | Path) -> BinaryIO:
    fd = _open_regular_fd(path)
    return os.fdopen(fd, "rb")


def open_regular_text(
    path: str | Path,
    *,
    encoding: str = "utf-8",
    errors: str = "strict",
) -> TextIO:
    fd = _open_regular_fd(path)
    return os.fdopen(fd, "r", encoding=encoding, errors=errors)


def _open_regular_fd(path: str | Path) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError(f"artifact is not a regular file: {path}")
    except BaseException:
        os.close(fd)
        raise
    return fd
