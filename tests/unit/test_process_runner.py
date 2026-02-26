from __future__ import annotations

from snakehook_runner.infra.process_runner import MAX_CAPTURE_BYTES, AsyncProcessRunner


async def test_process_runner_success() -> None:
    runner = AsyncProcessRunner()
    result = await runner.run(["python", "-c", "print('ok')"], timeout_sec=2)

    assert result.returncode == 0
    assert result.stdout.strip() == "ok"
    assert result.stderr == ""
    assert result.timed_out is False


async def test_process_runner_timeout() -> None:
    runner = AsyncProcessRunner()
    result = await runner.run(
        ["python", "-c", "import time; print('late', flush=True); time.sleep(10)"],
        timeout_sec=1,
    )

    assert result.returncode == 124
    assert result.timed_out is True
    assert "late" in result.stdout


async def test_process_runner_truncates_large_output() -> None:
    runner = AsyncProcessRunner()
    result = await runner.run(
        ["python", "-c", f"print('x' * ({MAX_CAPTURE_BYTES} + 1024))"],
        timeout_sec=2,
    )

    assert result.returncode == 0
    assert "[output truncated]" in result.stdout
