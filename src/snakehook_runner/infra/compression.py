from __future__ import annotations

import gzip
import shutil
from pathlib import Path


def gzip_file(path: str) -> str:
    source = Path(path)
    dest = source.with_suffix(source.suffix + ".gz")
    with source.open("rb") as fin, gzip.open(dest, "wb") as fout:
        shutil.copyfileobj(fin, fout)
    source.unlink(missing_ok=True)
    return str(dest)
