from __future__ import annotations

import gzip
import os
import shutil
import tempfile
from pathlib import Path

from snakehook_runner.infra.artifact_io import open_regular_binary


def gzip_file(path: str) -> str:
    source = Path(path)
    with open_regular_binary(source) as fin:
        fd, dest = tempfile.mkstemp(
            prefix=f"{source.name}-",
            suffix=".gz",
            dir="/tmp",
        )
        try:
            with os.fdopen(fd, "wb") as raw_dest:
                with gzip.GzipFile(
                    filename=source.name,
                    mode="wb",
                    fileobj=raw_dest,
                ) as fout:
                    shutil.copyfileobj(fin, fout)
        except BaseException:
            Path(dest).unlink(missing_ok=True)
            raise
    source.unlink(missing_ok=True)
    return dest
