from __future__ import annotations

from pathlib import Path

import pytest

from snakehook_runner.infra.runtime_paths import (
    cleanup_job_dir,
    code_dir,
    job_dir,
    prepare_code_dir,
    prepare_job_dir,
)


def _set_roots(monkeypatch, tmp_path: Path) -> tuple[Path, Path]:
    work_root = tmp_path / "work"
    code_root = tmp_path / "code"
    work_root.mkdir()
    code_root.mkdir()
    monkeypatch.setenv("SNAKEHOOK_WORK_ROOT", str(work_root))
    monkeypatch.setenv("SNAKEHOOK_CODE_ROOT", str(code_root))
    return work_root, code_root


def test_job_directories_are_scoped_by_run_id(monkeypatch, tmp_path: Path) -> None:
    work_root, _ = _set_roots(monkeypatch, tmp_path)
    monkeypatch.setattr("snakehook_runner.infra.runtime_paths.os.chown", lambda *args: None)

    first = prepare_job_dir("run-1")
    second = prepare_job_dir("run-2")

    assert first == work_root / "run-1"
    assert second == work_root / "run-2"
    assert first != second


def test_job_directory_collision_fails(monkeypatch, tmp_path: Path) -> None:
    _set_roots(monkeypatch, tmp_path)
    monkeypatch.setattr("snakehook_runner.infra.runtime_paths.os.chown", lambda *args: None)
    prepare_job_dir("same-run")

    with pytest.raises(FileExistsError):
        prepare_job_dir("same-run")


def test_cleanup_removes_only_selected_job(monkeypatch, tmp_path: Path) -> None:
    _set_roots(monkeypatch, tmp_path)
    monkeypatch.setattr("snakehook_runner.infra.runtime_paths.os.chown", lambda *args: None)
    prepare_job_dir("remove")
    prepare_code_dir("remove")
    prepare_job_dir("keep")
    prepare_code_dir("keep")

    cleanup_job_dir("remove")

    assert not job_dir("remove").exists()
    assert not code_dir("remove").exists()
    assert job_dir("keep").exists()
    assert code_dir("keep").exists()


def test_job_dir_rejects_path_traversal(monkeypatch, tmp_path: Path) -> None:
    _set_roots(monkeypatch, tmp_path)

    with pytest.raises(ValueError, match="single path component"):
        job_dir("../outside")

    with pytest.raises(ValueError, match="single path component"):
        code_dir("../outside")


def test_prepare_job_dir_assigns_jailed_owner_when_root(monkeypatch, tmp_path: Path) -> None:
    calls: list[tuple[Path, int, int]] = []
    _set_roots(monkeypatch, tmp_path)
    monkeypatch.setattr("snakehook_runner.infra.runtime_paths.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "snakehook_runner.infra.runtime_paths.os.chown",
        lambda path, uid, gid: calls.append((path, uid, gid)),
    )

    root = prepare_job_dir("owned")

    assert calls == [(root, 65534, 65534)]


def test_code_directories_are_separate_from_mutable_work(
    monkeypatch, tmp_path: Path
) -> None:
    work_root, code_root = _set_roots(monkeypatch, tmp_path)
    monkeypatch.setattr("snakehook_runner.infra.runtime_paths.os.chown", lambda *args: None)

    work = prepare_job_dir("split")
    code = prepare_code_dir("split")

    assert work == work_root / "split"
    assert code == code_root / "split"
    assert work != code
