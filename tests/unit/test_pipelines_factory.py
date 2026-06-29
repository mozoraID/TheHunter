"""Tests for pipeline factory module.

Unit tests for pentestgpt.core.pipelines module.
"""

from pathlib import Path

import pytest

from pentestgpt.core.config import PentestGPTConfig
from pentestgpt.core.pipeline import PipelineMode, StageDefinition
from pentestgpt.core.pipelines import CTF_STAGES, PENTEST_STAGES, get_stages


@pytest.fixture
def config(temp_working_dir: Path) -> PentestGPTConfig:
    """Create test config for prompt generation."""
    return PentestGPTConfig(
        target="10.10.11.234",
        working_directory=temp_working_dir,
    )


@pytest.mark.unit
class TestCTFStages:
    """Tests for CTF stage definitions."""

    def test_ctf_stages_count(self):
        """Test that CTF pipeline has 3 stages."""
        assert len(CTF_STAGES) == 3

    def test_ctf_stage_names(self):
        """Test CTF stage names."""
        names = [s.name for s in CTF_STAGES]
        assert names == ["recon", "exploit", "walkthrough"]

    def test_ctf_stage_display_names(self):
        """Test CTF stage display names are human-readable."""
        for stage in CTF_STAGES:
            assert len(stage.display_name) > 0
            assert stage.display_name[0].isupper()

    def test_ctf_stages_are_stage_definitions(self):
        """Test that all stages are StageDefinition instances."""
        for stage in CTF_STAGES:
            assert isinstance(stage, StageDefinition)

    def test_ctf_stage_prompts_callable(self, config: PentestGPTConfig):
        """Test that all stage prompt builders are callable and return strings."""
        for stage in CTF_STAGES:
            sys_prompt = stage.get_system_prompt(config)
            assert isinstance(sys_prompt, str)
            assert len(sys_prompt) > 50  # Non-trivial content

            task_prompt = stage.get_task_prompt(config, [])
            assert isinstance(task_prompt, str)
            assert len(task_prompt) > 10


@pytest.mark.unit
class TestPentestStages:
    """Tests for Pentest stage definitions."""

    def test_pentest_stages_count(self):
        """Test that Pentest pipeline has 3 stages."""
        assert len(PENTEST_STAGES) == 3

    def test_pentest_stage_names(self):
        """Test Pentest stage names."""
        names = [s.name for s in PENTEST_STAGES]
        assert names == ["asset_identification", "vulnerability_identification", "report"]

    def test_pentest_stage_display_names(self):
        """Test Pentest stage display names are human-readable."""
        for stage in PENTEST_STAGES:
            assert len(stage.display_name) > 0
            assert stage.display_name[0].isupper()

    def test_pentest_stages_are_stage_definitions(self):
        """Test that all stages are StageDefinition instances."""
        for stage in PENTEST_STAGES:
            assert isinstance(stage, StageDefinition)

    def test_pentest_stage_prompts_callable(self, config: PentestGPTConfig):
        """Test that all stage prompt builders are callable and return strings."""
        for stage in PENTEST_STAGES:
            sys_prompt = stage.get_system_prompt(config)
            assert isinstance(sys_prompt, str)
            assert len(sys_prompt) > 50

            task_prompt = stage.get_task_prompt(config, [])
            assert isinstance(task_prompt, str)
            assert len(task_prompt) > 10


@pytest.mark.unit
class TestGetStages:
    """Tests for get_stages factory function."""

    def test_get_ctf_stages(self):
        """Test getting CTF stages."""
        stages = get_stages(PipelineMode.CTF)
        assert stages is CTF_STAGES

    def test_get_pentest_stages(self):
        """Test getting Pentest stages."""
        stages = get_stages(PipelineMode.PENTEST)
        assert stages is PENTEST_STAGES

    def test_invalid_mode_raises(self):
        """Test that invalid mode raises ValueError."""
        with pytest.raises(ValueError, match="Unknown pipeline mode"):
            get_stages("invalid")  # type: ignore[arg-type]
