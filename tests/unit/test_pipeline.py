"""Tests for PipelineOrchestrator.

Unit tests for pentestgpt.core.pipeline module.
"""

from pathlib import Path

import pytest

from pentestgpt.core.backend import AgentMessage, MessageType
from pentestgpt.core.config import PentestGPTConfig
from pentestgpt.core.events import EventBus
from pentestgpt.core.pipeline import (
    PipelineMode,
    PipelineOrchestrator,
    PipelineResult,
    StageDefinition,
    StageResult,
)
from pentestgpt.core.session import SessionStore
from tests.conftest import MockBackend

# =============================================================================
# Data structure tests
# =============================================================================


@pytest.mark.unit
class TestStageResult:
    """Tests for StageResult dataclass."""

    def test_defaults(self):
        """Test default values."""
        r = StageResult(stage_name="recon", display_name="Recon")
        assert r.status == "completed"
        assert r.output == ""
        assert r.flags_found == []
        assert r.cost_usd == 0.0
        assert r.error is None
        assert r.session_id == ""

    def test_with_values(self):
        """Test with explicit values."""
        r = StageResult(
            stage_name="exploit",
            display_name="Exploitation",
            status="completed",
            output="Got shell",
            flags_found=["flag{test}"],
            cost_usd=1.23,
            session_id="sess-123",
        )
        assert r.flags_found == ["flag{test}"]
        assert r.cost_usd == 1.23


@pytest.mark.unit
class TestPipelineResult:
    """Tests for PipelineResult dataclass."""

    def test_empty_result(self):
        """Test empty result."""
        r = PipelineResult(mode=PipelineMode.CTF)
        assert r.success is True  # vacuously true
        assert r.all_flags == []
        assert r.total_cost == 0.0
        assert r.combined_output == ""

    def test_success_with_stages(self):
        """Test success computation with completed stages."""
        r = PipelineResult(
            mode=PipelineMode.CTF,
            stage_results=[
                StageResult(stage_name="s1", display_name="S1", status="completed"),
                StageResult(stage_name="s2", display_name="S2", status="completed"),
            ],
        )
        assert r.success is True

    def test_failure_with_error_stage(self):
        """Test success is False when a stage has error."""
        r = PipelineResult(
            mode=PipelineMode.CTF,
            stage_results=[
                StageResult(stage_name="s1", display_name="S1", status="completed"),
                StageResult(stage_name="s2", display_name="S2", status="error"),
            ],
        )
        assert r.success is False

    def test_all_flags_deduplication(self):
        """Test that all_flags deduplicates across stages."""
        r = PipelineResult(
            mode=PipelineMode.CTF,
            stage_results=[
                StageResult(
                    stage_name="s1",
                    display_name="S1",
                    flags_found=["flag{a}", "flag{b}"],
                ),
                StageResult(
                    stage_name="s2",
                    display_name="S2",
                    flags_found=["flag{b}", "flag{c}"],
                ),
            ],
        )
        assert r.all_flags == ["flag{a}", "flag{b}", "flag{c}"]

    def test_total_cost(self):
        """Test total cost aggregation."""
        r = PipelineResult(
            mode=PipelineMode.PENTEST,
            stage_results=[
                StageResult(stage_name="s1", display_name="S1", cost_usd=1.5),
                StageResult(stage_name="s2", display_name="S2", cost_usd=2.3),
                StageResult(stage_name="s3", display_name="S3", cost_usd=0.7),
            ],
        )
        assert abs(r.total_cost - 4.5) < 0.01

    def test_combined_output(self):
        """Test combined output formatting."""
        r = PipelineResult(
            mode=PipelineMode.CTF,
            stage_results=[
                StageResult(stage_name="s1", display_name="Recon", output="Found port 80"),
                StageResult(stage_name="s2", display_name="Exploit", output="Got root"),
            ],
        )
        combined = r.combined_output
        assert "=== Recon ===" in combined
        assert "Found port 80" in combined
        assert "=== Exploit ===" in combined
        assert "Got root" in combined


# =============================================================================
# PipelineOrchestrator tests (using mock backend)
# =============================================================================


def _make_stage_def(
    name: str, display_name: str, sys_prompt: str = "test", task_prompt: str = "test task"
) -> StageDefinition:
    """Helper to create a simple StageDefinition."""
    return StageDefinition(
        name=name,
        display_name=display_name,
        get_system_prompt=lambda config, _sp=sys_prompt: _sp,
        get_task_prompt=lambda config, prior, _tp=task_prompt: _tp,
    )


@pytest.mark.unit
class TestPipelineOrchestrator:
    """Tests for PipelineOrchestrator."""

    @pytest.fixture
    def config(self, temp_working_dir: Path) -> PentestGPTConfig:
        """Create test config. Tests monkeypatch ``create_backend`` to return a
        MockBackend, so no real network call is made."""
        return PentestGPTConfig(
            target="test.example.com",
            working_directory=temp_working_dir,
        )

    @pytest.fixture
    def events(self) -> EventBus:
        """Get event bus."""
        return EventBus.get()

    @pytest.fixture
    def session_store(self, temp_sessions_dir: Path) -> SessionStore:
        """Create session store with temp dir."""
        return SessionStore(sessions_dir=temp_sessions_dir)

    @pytest.mark.asyncio
    async def test_run_single_stage(
        self,
        config: PentestGPTConfig,
        session_store: SessionStore,
        events: EventBus,
        monkeypatch,
    ):
        """Test running a single-stage pipeline with mock backend."""
        mock_backend = MockBackend()
        mock_backend.set_messages(
            [
                AgentMessage(type=MessageType.TEXT, content="Scanning target..."),
                AgentMessage(type=MessageType.RESULT, content=None, metadata={"cost_usd": 0.1}),
            ]
        )

        stages = [_make_stage_def("recon", "Recon")]

        # Monkeypatch create_backend to return our mock
        monkeypatch.setattr(
            "pentestgpt.core.backend.create_backend",
            lambda config, system_prompt: mock_backend,
        )

        orchestrator = PipelineOrchestrator(
            config=config,
            stages=stages,
            mode=PipelineMode.CTF,
            session_store=session_store,
            events=events,
        )

        result = await orchestrator.run()

        assert len(result.stage_results) == 1
        assert result.stage_results[0].stage_name == "recon"
        assert result.stage_results[0].status == "completed"

    @pytest.mark.asyncio
    async def test_run_multi_stage(
        self,
        config: PentestGPTConfig,
        session_store: SessionStore,
        events: EventBus,
        monkeypatch,
    ):
        """Test running a multi-stage pipeline."""
        mock_backend = MockBackend()
        mock_backend.set_messages(
            [
                AgentMessage(type=MessageType.TEXT, content="Stage output"),
                AgentMessage(type=MessageType.RESULT, content=None, metadata={}),
            ]
        )

        stages = [
            _make_stage_def("s1", "Stage 1"),
            _make_stage_def("s2", "Stage 2"),
            _make_stage_def("s3", "Stage 3"),
        ]

        monkeypatch.setattr(
            "pentestgpt.core.backend.create_backend",
            lambda config, system_prompt: mock_backend,
        )

        orchestrator = PipelineOrchestrator(
            config=config,
            stages=stages,
            mode=PipelineMode.CTF,
            session_store=session_store,
            events=events,
        )

        result = await orchestrator.run()

        assert len(result.stage_results) == 3
        assert all(r.status == "completed" for r in result.stage_results)

    @pytest.mark.asyncio
    async def test_flags_accumulated_across_stages(
        self,
        config: PentestGPTConfig,
        session_store: SessionStore,
        events: EventBus,
        monkeypatch,
    ):
        """Test that flags are detected and accumulated across stages."""
        mock_backend = MockBackend()
        mock_backend.set_messages(
            [
                AgentMessage(type=MessageType.TEXT, content="Found flag{stage_flag}!"),
                AgentMessage(type=MessageType.RESULT, content=None, metadata={}),
            ]
        )

        stages = [
            _make_stage_def("s1", "Stage 1"),
            _make_stage_def("s2", "Stage 2"),
        ]

        monkeypatch.setattr(
            "pentestgpt.core.backend.create_backend",
            lambda config, system_prompt: mock_backend,
        )

        orchestrator = PipelineOrchestrator(
            config=config,
            stages=stages,
            mode=PipelineMode.CTF,
            session_store=session_store,
            events=events,
        )

        result = await orchestrator.run()
        # flag{stage_flag} should be detected in both stages but deduplicated
        assert "flag{stage_flag}" in result.all_flags

    @pytest.mark.asyncio
    async def test_stop_halts_pipeline(
        self,
        config: PentestGPTConfig,
        session_store: SessionStore,
        events: EventBus,
        monkeypatch,
    ):
        """Test that stop() prevents remaining stages from running."""
        stage_count = 0

        class StopAfterFirstBackend(MockBackend):
            """Backend that triggers orchestrator stop after first stage."""

            def __init__(self, orchestrator_ref):
                super().__init__()
                self._orchestrator_ref = orchestrator_ref

            async def connect(self):
                nonlocal stage_count
                stage_count += 1
                if stage_count == 1:
                    # After first stage connects, request stop so stage 2+ won't run
                    self._orchestrator_ref._stop_requested = True
                self._connected = True

        stages_defs = [
            _make_stage_def("s1", "Stage 1"),
            _make_stage_def("s2", "Stage 2"),
            _make_stage_def("s3", "Stage 3"),
        ]

        orchestrator = PipelineOrchestrator(
            config=config,
            stages=stages_defs,
            mode=PipelineMode.CTF,
            session_store=session_store,
            events=events,
        )

        stop_backend = StopAfterFirstBackend(orchestrator)
        stop_backend.set_messages(
            [
                AgentMessage(type=MessageType.TEXT, content="Output"),
                AgentMessage(type=MessageType.RESULT, content=None, metadata={}),
            ]
        )

        monkeypatch.setattr(
            "pentestgpt.core.backend.create_backend",
            lambda config, system_prompt: stop_backend,
        )

        result = await orchestrator.run()
        # Only stage 1 ran; stop was requested before stage 2
        assert len(result.stage_results) == 1
        assert result.stage_results[0].stage_name == "s1"

    @pytest.mark.asyncio
    async def test_stage_error_continues_pipeline(
        self,
        config: PentestGPTConfig,
        session_store: SessionStore,
        events: EventBus,
        monkeypatch,
    ):
        """Test that a stage error doesn't abort the entire pipeline."""
        call_count = 0

        class FailFirstBackend(MockBackend):
            """Backend that fails on the first call."""

            async def connect(self):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    raise Exception("Connection failed")
                self._connected = True

        fail_backend = FailFirstBackend()
        fail_backend.set_messages(
            [
                AgentMessage(type=MessageType.TEXT, content="Success"),
                AgentMessage(type=MessageType.RESULT, content=None, metadata={}),
            ]
        )

        stages = [
            _make_stage_def("s1", "Stage 1"),
            _make_stage_def("s2", "Stage 2"),
        ]

        monkeypatch.setattr(
            "pentestgpt.core.backend.create_backend",
            lambda config, system_prompt: fail_backend,
        )

        orchestrator = PipelineOrchestrator(
            config=config,
            stages=stages,
            mode=PipelineMode.CTF,
            session_store=session_store,
            events=events,
        )

        result = await orchestrator.run()

        assert len(result.stage_results) == 2
        assert result.stage_results[0].status == "error"
        assert result.stage_results[1].status == "completed"

    def test_pause_without_active_controller(
        self,
        config: PentestGPTConfig,
        session_store: SessionStore,
        events: EventBus,
    ):
        """Test pause when no stage is active."""
        orchestrator = PipelineOrchestrator(
            config=config,
            stages=[],
            mode=PipelineMode.CTF,
            session_store=session_store,
            events=events,
        )
        assert orchestrator.pause() is False

    def test_resume_without_active_controller(
        self,
        config: PentestGPTConfig,
        session_store: SessionStore,
        events: EventBus,
    ):
        """Test resume when no stage is active."""
        orchestrator = PipelineOrchestrator(
            config=config,
            stages=[],
            mode=PipelineMode.CTF,
            session_store=session_store,
            events=events,
        )
        assert orchestrator.resume() is False

    def test_stop_without_active_controller(
        self,
        config: PentestGPTConfig,
        session_store: SessionStore,
        events: EventBus,
    ):
        """Test stop when no stage is active."""
        orchestrator = PipelineOrchestrator(
            config=config,
            stages=[],
            mode=PipelineMode.CTF,
            session_store=session_store,
            events=events,
        )
        assert orchestrator.stop() is True
        assert orchestrator._stop_requested is True

    def test_inject_without_active_controller(
        self,
        config: PentestGPTConfig,
        session_store: SessionStore,
        events: EventBus,
    ):
        """Test inject when no stage is active."""
        orchestrator = PipelineOrchestrator(
            config=config,
            stages=[],
            mode=PipelineMode.CTF,
            session_store=session_store,
            events=events,
        )
        assert orchestrator.inject("test") is False


@pytest.mark.unit
class TestPipelineMode:
    """Tests for PipelineMode enum."""

    def test_ctf_value(self):
        assert PipelineMode.CTF.value == "ctf"

    def test_pentest_value(self):
        assert PipelineMode.PENTEST.value == "pentest"
