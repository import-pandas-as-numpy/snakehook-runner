from __future__ import annotations

import logging
import warnings
from pathlib import Path

from snakehook_runner.core.interfaces import (
    PipInstallResult,
    RunJob,
    RunMode,
    SandboxResult,
    WebhookSummary,
)
from snakehook_runner.core.orchestrator import (
    AuditHighlights,
    ExecutionSummary,
    TriageOrchestrator,
    WorkerHandler,
    _build_html_report,
    _parse_literal_args,
)


class FakePipInstaller:
    def __init__(self, result: PipInstallResult) -> None:
        self._result = result

    async def install(self, package_name: str, version: str) -> PipInstallResult:
        return self._result


class FakeSandboxExecutor:
    def __init__(self, result: SandboxResult) -> None:
        self._result = result

    async def run(self, job: RunJob) -> SandboxResult:
        return self._result


class FakeWebhookClient:
    def __init__(self) -> None:
        self.calls: list[tuple[WebhookSummary, tuple[str, ...]]] = []

    async def send_summary(
        self,
        summary: WebhookSummary,
        attachment_paths: tuple[str, ...] = (),
    ) -> None:
        self.calls.append((summary, attachment_paths))


async def test_orchestrator_reports_pip_failure() -> None:
    webhook = FakeWebhookClient()
    orch = TriageOrchestrator(
        pip_installer=FakePipInstaller(PipInstallResult(ok=False, stdout="", stderr="boom")),
        sandbox_executor=FakeSandboxExecutor(
            SandboxResult(ok=True, stdout="", stderr="", timed_out=False, audit_jsonl_path=None),
        ),
        webhook_client=webhook,
    )

    result = await orch.execute(RunJob(run_id="r1", package_name="x", version="1"))

    assert result.ok is False
    assert "pip install failed" in result.message
    assert webhook.calls[0][0].run_id == "r1"


async def test_orchestrator_attaches_install_audit_on_pip_failure(tmp_path: Path) -> None:
    install_audit = tmp_path / "pip-audit.jsonl"
    install_audit.write_text("compile\n", encoding="utf-8")
    webhook = FakeWebhookClient()
    orch = TriageOrchestrator(
        pip_installer=FakePipInstaller(
            PipInstallResult(
                ok=False,
                stdout="",
                stderr="boom",
                audit_jsonl_path=str(install_audit),
            ),
        ),
        sandbox_executor=FakeSandboxExecutor(
            SandboxResult(ok=True, stdout="", stderr="", timed_out=False, audit_jsonl_path=None),
        ),
        webhook_client=webhook,
    )

    result = await orch.execute(RunJob(run_id="r1a", package_name="x", version="1"))

    assert result.ok is False
    assert result.attachment_path is not None
    assert result.attachment_path.endswith(".gz")
    assert Path(result.attachment_path).exists() is False
    assert result.attachment_path in webhook.calls[0][1]


async def test_orchestrator_reports_tail_of_pip_failure() -> None:
    stderr = (
        "[I] Mode: STANDALONE_ONCE\n"
        "[I] Jail parameters: ...\n"
        "[I] init clone...\n"
        "[I] mount setup...\n"
        "[I] seccomp setup...\n"
        "[I] sandbox startup...\n"
        "[E] connect() failed: Network is unreachable\n"
        "[E] pip exited non-zero\n"
    )
    webhook = FakeWebhookClient()
    orch = TriageOrchestrator(
        pip_installer=FakePipInstaller(PipInstallResult(ok=False, stdout="", stderr=stderr)),
        sandbox_executor=FakeSandboxExecutor(
            SandboxResult(ok=True, stdout="", stderr="", timed_out=False, audit_jsonl_path=None),
        ),
        webhook_client=webhook,
    )

    result = await orch.execute(RunJob(run_id="r1", package_name="x", version="1"))

    assert "[E] connect() failed: Network is unreachable" in result.message
    assert "[I] Mode: STANDALONE_ONCE" not in result.message


async def test_orchestrator_adds_hint_for_nsjail_clone_permission_failure() -> None:
    stderr = (
        "[W] Process will be UID/EUID=0 in the global user namespace\n"
        "[W] clone(flags=CLONE_NEWNS|CLONE_NEWUSER|CLONE_NEWNET) failed: Operation not permitted\n"
        "[E] standaloneMode(): Couldn't launch the child process\n"
    )
    webhook = FakeWebhookClient()
    orch = TriageOrchestrator(
        pip_installer=FakePipInstaller(PipInstallResult(ok=False, stdout="", stderr=stderr)),
        sandbox_executor=FakeSandboxExecutor(
            SandboxResult(ok=True, stdout="", stderr="", timed_out=False, audit_jsonl_path=None),
        ),
        webhook_client=webhook,
    )

    result = await orch.execute(RunJob(run_id="r1", package_name="x", version="1"))

    assert "Operation not permitted" in result.message
    assert "hint: nsjail namespace clone blocked by container runtime" in result.message


async def test_orchestrator_adds_hint_for_nsjail_cgroup_namespace_failure() -> None:
    stderr = (
        "[W][2026-02-26T03:34:50+0000][9] logParams():313 Process will be UID/EUID=0\n"
        "[I][2026-02-26T03:34:50+0000][9] initParent():452 "
        "Couldn't initialize cgroup user namespace for pid=10\n"
        "[F][2026-02-26T03:34:50+0000][1] runChild():506 Launching child process failed\n"
    )
    webhook = FakeWebhookClient()
    orch = TriageOrchestrator(
        pip_installer=FakePipInstaller(PipInstallResult(ok=False, stdout="", stderr=stderr)),
        sandbox_executor=FakeSandboxExecutor(
            SandboxResult(ok=True, stdout="", stderr="", timed_out=False, audit_jsonl_path=None),
        ),
        webhook_client=webhook,
    )

    result = await orch.execute(RunJob(run_id="r1", package_name="x", version="1"))

    assert "Couldn't initialize cgroup user namespace" in result.message
    assert "hint: nsjail cgroup namespace init failed" in result.message


async def test_orchestrator_adds_hint_for_nsjail_execve_failure() -> None:
    stderr = (
        "[I][2026-02-26T03:58:25+0000] Executing '/usr/bin/env'\n"
        "[E][2026-02-26T03:58:25+0000][1] newProc():232 "
        "execve('/usr/bin/env') failed: No such file or directory\n"
        "[F][2026-02-26T03:58:25+0000][9] standaloneMode():274 "
        "Couldn't launch the child process\n"
    )
    webhook = FakeWebhookClient()
    orch = TriageOrchestrator(
        pip_installer=FakePipInstaller(PipInstallResult(ok=False, stdout="", stderr=stderr)),
        sandbox_executor=FakeSandboxExecutor(
            SandboxResult(ok=True, stdout="", stderr="", timed_out=False, audit_jsonl_path=None),
        ),
        webhook_client=webhook,
    )

    result = await orch.execute(RunJob(run_id="r1", package_name="x", version="1"))

    assert "execve('/usr/bin/env')" in result.message
    assert "hint: nsjail could not exec the requested binary" in result.message
    assert "chroot/mounts include /usr, /bin, /lib, /lib64" in result.message


async def test_orchestrator_compresses_audit_and_reports_success(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    audit.write_text("event.one\n", encoding="utf-8")
    webhook = FakeWebhookClient()
    orch = TriageOrchestrator(
        pip_installer=FakePipInstaller(PipInstallResult(ok=True, stdout="", stderr="")),
        sandbox_executor=FakeSandboxExecutor(
            SandboxResult(
                ok=True,
                stdout="x",
                stderr="",
                timed_out=False,
                audit_jsonl_path=str(audit),
            ),
        ),
        webhook_client=webhook,
    )

    result = await orch.execute(
        RunJob(run_id="r2", package_name="x", version="1", mode=RunMode.EXECUTE),
    )

    assert result.ok is True
    assert result.attachment_path is not None
    assert result.attachment_path.endswith(".gz")
    assert Path(result.attachment_path).exists() is False
    assert result.attachment_path in webhook.calls[0][1]


async def test_orchestrator_merges_install_and_sandbox_audit(tmp_path: Path) -> None:
    install_audit = tmp_path / "install-audit.jsonl"
    install_audit.write_text("event.install\n", encoding="utf-8")
    run_audit = tmp_path / "run-audit.jsonl"
    run_audit.write_text("event.run\n", encoding="utf-8")
    webhook = FakeWebhookClient()
    orch = TriageOrchestrator(
        pip_installer=FakePipInstaller(
            PipInstallResult(ok=True, stdout="", stderr="", audit_jsonl_path=str(install_audit)),
        ),
        sandbox_executor=FakeSandboxExecutor(
            SandboxResult(
                ok=True,
                stdout="x",
                stderr="",
                timed_out=False,
                audit_jsonl_path=str(run_audit),
            ),
        ),
        webhook_client=webhook,
    )

    result = await orch.execute(
        RunJob(run_id="r2m", package_name="x", version="1", mode=RunMode.EXECUTE),
    )

    assert result.ok is True
    assert result.attachment_path is not None
    assert Path(result.attachment_path).exists() is False
    assert result.attachment_path in webhook.calls[0][1]
    assert install_audit.exists() is False
    assert run_audit.exists() is False


async def test_orchestrator_skips_missing_audit_file() -> None:
    webhook = FakeWebhookClient()
    orch = TriageOrchestrator(
        pip_installer=FakePipInstaller(PipInstallResult(ok=True, stdout="", stderr="")),
        sandbox_executor=FakeSandboxExecutor(
            SandboxResult(
                ok=True,
                stdout="x",
                stderr="",
                timed_out=False,
                audit_jsonl_path="/tmp/missing-audit.jsonl",
            ),
        ),
        webhook_client=webhook,
    )

    result = await orch.execute(
        RunJob(run_id="r2b", package_name="x", version="1", mode=RunMode.EXECUTE),
    )

    assert result.ok is True
    assert result.attachment_path is None
    assert webhook.calls[0][0].run_id == "r2b"
    assert webhook.calls[0][0].summary == "run ok; stdout=1B stderr=0B"
    assert webhook.calls[0][1] == ()


async def test_worker_handler_logs_exceptions(caplog) -> None:
    class BoomOrchestrator:
        async def execute(self, job: RunJob):
            raise RuntimeError("explode")

    handler = WorkerHandler(orchestrator=BoomOrchestrator())

    caplog.set_level(logging.ERROR)
    await handler(RunJob(run_id="r3", package_name="x", version="1"))

    assert "triage run failed run_id=r3" in caplog.text


async def test_orchestrator_install_mode_skips_sandbox_execution() -> None:
    webhook = FakeWebhookClient()

    class NeverRunSandbox:
        async def run(self, job: RunJob) -> SandboxResult:
            raise AssertionError("sandbox should not run in install mode")

    orch = TriageOrchestrator(
        pip_installer=FakePipInstaller(PipInstallResult(ok=True, stdout="", stderr="")),
        sandbox_executor=NeverRunSandbox(),
        webhook_client=webhook,
    )

    result = await orch.execute(RunJob(run_id="r4", package_name="x", version="1"))

    assert result.ok is True
    expected_message = "install ok"
    assert result.message == expected_message
    assert webhook.calls[0][0].run_id == "r4"
    assert webhook.calls[0][0].summary == expected_message
    assert webhook.calls[0][1] == ()


async def test_orchestrator_extracts_files_and_network_from_audit(tmp_path: Path) -> None:
    install_audit = tmp_path / "install-audit.jsonl"
    install_audit.write_text(
        "\n".join(
            [
                (
                    '{"timestamp":"2026-02-27T00:00:00+00:00","event":"open",'
                    '"args":"(\'/tmp/install.log\', \'w\', 524865)","caller":{}}'
                ),
                (
                    '{"timestamp":"2026-02-27T00:00:01+00:00","event":"socket.connect",'
                    '"args":"(<socket.socket fd=3>, (\'pypi.org\', 443))","caller":{}}'
                ),
                (
                    '{"timestamp":"2026-02-27T00:00:01+00:00","event":"socket.getaddrinfo",'
                    '"args":"(\'files.pythonhosted.org\', 443, 0, 1, 6)","caller":{}}'
                ),
            ],
        )
        + "\n",
        encoding="utf-8",
    )
    run_audit = tmp_path / "run-audit.jsonl"
    run_audit.write_text(
        "\n".join(
            [
                (
                    '{"timestamp":"2026-02-27T00:00:02+00:00","event":"os.open",'
                    '"args":"(\'/tmp/output.txt\', 577, 420)","caller":{}}'
                ),
                (
                    '{"timestamp":"2026-02-27T00:00:03+00:00","event":"open",'
                    '"args":"(\'/etc/hosts\', \'r\', 524288)","caller":{}}'
                ),
                (
                    '{"timestamp":"2026-02-27T00:00:04+00:00","event":"subprocess.Popen",'
                    '"args":"([\'python\', \'-c\', \'print(1)\'],)","caller":{}}'
                ),
                (
                    '{"timestamp":"2026-02-27T00:00:05+00:00","event":"socket.sendto",'
                    '"args":"(b\'x\', (\'1.1.1.1\', 53))","caller":{}}'
                ),
                (
                    '{"timestamp":"2026-02-27T00:00:06+00:00","event":"socket.bind",'
                    '"args":"(<socket.socket fd=4>, (\'0.0.0.0\', 8080))","caller":{}}'
                ),
            ],
        )
        + "\n",
        encoding="utf-8",
    )
    webhook = FakeWebhookClient()
    orch = TriageOrchestrator(
        pip_installer=FakePipInstaller(
            PipInstallResult(ok=True, stdout="", stderr="", audit_jsonl_path=str(install_audit)),
        ),
        sandbox_executor=FakeSandboxExecutor(
            SandboxResult(
                ok=True,
                stdout="x",
                stderr="",
                timed_out=False,
                audit_jsonl_path=str(run_audit),
            ),
        ),
        webhook_client=webhook,
    )

    await orch.execute(RunJob(run_id="r5", package_name="x", version="1", mode=RunMode.EXECUTE))

    sent = webhook.calls[0][0]
    assert "install: /tmp/install.log" in sent.files_written
    assert "sandbox: /tmp/output.txt" in sent.files_written
    assert "install: connect pypi.org:443" in sent.network_connections
    assert "install: dns files.pythonhosted.org" in sent.network_connections
    assert "sandbox: sendto 1.1.1.1:53" in sent.network_connections
    assert "sandbox: bind 0.0.0.0:8080" in sent.network_connections
    assert any(name.endswith(".html") for name in webhook.calls[0][1])


def test_parse_literal_args_suppresses_invalid_escape_warnings() -> None:
    args_text = "('\\\\.',)"
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        parsed = _parse_literal_args(args_text)
    assert parsed == ("\\.",)
    syntax_warnings = [w for w in caught if issubclass(w.category, SyntaxWarning)]
    assert syntax_warnings == []


def test_build_html_report_collapses_large_lists() -> None:
    job = RunJob(run_id="r-html", package_name="x", version="1", mode=RunMode.EXECUTE)
    summary = ExecutionSummary(run_id="r-html", ok=True, message="ok", attachment_path=None)
    highlights = AuditHighlights(
        files_written=tuple(f"item-{i}" for i in range(20)),
        files_read=(),
        network_connections=(),
        subprocesses=(),
        top_events=("open: 20",),
    )

    report = _build_html_report(job=job, summary=summary, highlights=highlights)

    assert "Show 4 more" in report
    assert "data-toggle='rows'" in report
    assert "row--hidden" in report
