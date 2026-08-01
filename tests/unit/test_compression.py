from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from snakehook_runner.infra.compression import gzip_file


def test_gzip_file_uses_trusted_temporary_destination(tmp_path: Path) -> None:
    source = tmp_path / "audit.jsonl"
    source.write_bytes(b"event\n")

    output = Path(gzip_file(str(source)))

    try:
        assert output.parent == Path("/tmp")
        assert output.stat().st_mode & 0o777 == 0o600
        assert gzip.open(output, "rb").read() == b"event\n"
        assert source.exists() is False
    finally:
        output.unlink(missing_ok=True)


def test_gzip_file_rejects_symlink_source(tmp_path: Path) -> None:
    target = tmp_path / "host-data"
    target.write_bytes(b"sensitive")
    source = tmp_path / "audit.jsonl"
    source.symlink_to(target)

    with pytest.raises(OSError):
        gzip_file(str(source))

    assert target.read_bytes() == b"sensitive"
    assert source.is_symlink()


def test_gzip_file_does_not_follow_attacker_destination(tmp_path: Path) -> None:
    source = tmp_path / "audit.jsonl"
    source.write_bytes(b"event\n")
    victim = tmp_path / "victim"
    victim.write_bytes(b"unchanged")
    attacker_destination = tmp_path / "audit.jsonl.gz"
    attacker_destination.symlink_to(victim)

    output = Path(gzip_file(str(source)))

    try:
        assert output != attacker_destination
        assert victim.read_bytes() == b"unchanged"
        assert attacker_destination.is_symlink()
    finally:
        output.unlink(missing_ok=True)
