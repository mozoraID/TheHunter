"""Tests for stage prompt builders.

Unit tests for pentestgpt.prompts.stages module.
"""

from pathlib import Path

import pytest

from pentestgpt.core.config import PentestGPTConfig
from pentestgpt.core.pipeline import StageResult
from pentestgpt.prompts import stages


@pytest.fixture
def config(temp_working_dir: Path) -> PentestGPTConfig:
    """Create a config for prompt testing."""
    return PentestGPTConfig(
        target="10.10.11.234",
        working_directory=temp_working_dir,
    )


@pytest.fixture
def config_with_instruction(temp_working_dir: Path) -> PentestGPTConfig:
    """Create a config with custom instruction."""
    return PentestGPTConfig(
        target="10.10.11.234",
        working_directory=temp_working_dir,
        custom_instruction="Focus on web vulnerabilities",
    )


@pytest.fixture
def sample_prior_results() -> list[StageResult]:
    """Create sample prior stage results for context testing."""
    return [
        StageResult(
            stage_name="recon",
            display_name="Reconnaissance",
            status="completed",
            output="Port 22 SSH, Port 80 HTTP Apache 2.4, Port 443 HTTPS",
            flags_found=[],
            cost_usd=0.5,
        ),
    ]


@pytest.mark.unit
class TestBuildPriorContextBlock:
    """Tests for _build_prior_context_block helper."""

    def test_empty_results(self):
        """Test with no prior results returns empty string."""
        assert stages._build_prior_context_block([]) == ""

    def test_single_result(self, sample_prior_results: list[StageResult]):
        """Test with a single prior result."""
        context = stages._build_prior_context_block(sample_prior_results)
        assert "CONTEXT FROM PRIOR STAGES:" in context
        assert "Reconnaissance" in context
        assert "Port 22 SSH" in context

    def test_multiple_results(self):
        """Test with multiple prior results."""
        results = [
            StageResult(
                stage_name="recon",
                display_name="Recon",
                status="completed",
                output="Found port 80",
            ),
            StageResult(
                stage_name="exploit",
                display_name="Exploit",
                status="completed",
                output="Got shell as www-data",
                flags_found=["flag{test123}"],
            ),
        ]
        context = stages._build_prior_context_block(results)
        assert "Recon" in context
        assert "Exploit" in context
        assert "Found port 80" in context
        assert "Got shell as www-data" in context
        assert "flag{test123}" in context

    def test_truncation(self):
        """Test that long output gets truncated."""
        results = [
            StageResult(
                stage_name="recon",
                display_name="Recon",
                status="completed",
                output="A" * 5000,
            ),
        ]
        context = stages._build_prior_context_block(results)
        assert "... [truncated]" in context
        assert len(context) < 5000 + 500  # output truncated + overhead

    def test_error_status_shown(self):
        """Test that error status is reflected."""
        results = [
            StageResult(
                stage_name="recon",
                display_name="Recon",
                status="error",
                output="Some output before failure",
                error="Connection lost",
            ),
        ]
        context = stages._build_prior_context_block(results)
        assert "status: error" in context


@pytest.mark.unit
class TestCTFPrompts:
    """Tests for CTF pipeline prompt builders."""

    def test_ctf_stage1_system_prompt(self, config: PentestGPTConfig):
        """Test CTF stage 1 system prompt content."""
        prompt = stages.ctf_stage1_system_prompt(config)
        assert "RECONNAISSANCE" in prompt
        assert "Do NOT exploit" in prompt
        assert "ENUMERATION SUMMARY" in prompt
        assert "PentestGPT" in prompt

    def test_ctf_stage1_system_prompt_with_instruction(
        self, config_with_instruction: PentestGPTConfig
    ):
        """Test that custom instruction is appended."""
        prompt = stages.ctf_stage1_system_prompt(config_with_instruction)
        assert "Focus on web vulnerabilities" in prompt

    def test_ctf_stage1_task_prompt(self, config: PentestGPTConfig):
        """Test CTF stage 1 task prompt."""
        task = stages.ctf_stage1_task_prompt(config, [])
        assert "10.10.11.234" in task

    def test_ctf_stage2_system_prompt(self, config: PentestGPTConfig):
        """Test CTF stage 2 system prompt content."""
        prompt = stages.ctf_stage2_system_prompt(config)
        assert "EXPLOITATION" in prompt
        assert "NEVER GIVE UP" in prompt
        assert "PRE-COMPLETION CHECKLIST" in prompt
        assert "FALLBACK STRATEGIES" in prompt

    def test_ctf_stage2_task_prompt_with_context(
        self,
        config: PentestGPTConfig,
        sample_prior_results: list[StageResult],
    ):
        """Test CTF stage 2 task prompt includes prior context."""
        task = stages.ctf_stage2_task_prompt(config, sample_prior_results)
        assert "10.10.11.234" in task
        assert "CONTEXT FROM PRIOR STAGES:" in task
        assert "Port 22 SSH" in task

    def test_ctf_stage2_task_prompt_without_context(self, config: PentestGPTConfig):
        """Test CTF stage 2 task prompt without prior results."""
        task = stages.ctf_stage2_task_prompt(config, [])
        assert "10.10.11.234" in task
        assert "CONTEXT FROM PRIOR STAGES:" not in task

    def test_ctf_stage3_system_prompt(self, config: PentestGPTConfig):
        """Test CTF stage 3 system prompt content."""
        prompt = stages.ctf_stage3_system_prompt(config)
        assert "WALKTHROUGH" in prompt
        assert "Do NOT run new exploits" in prompt

    def test_ctf_stage3_task_prompt(
        self,
        config: PentestGPTConfig,
        sample_prior_results: list[StageResult],
    ):
        """Test CTF stage 3 task prompt includes prior context."""
        task = stages.ctf_stage3_task_prompt(config, sample_prior_results)
        assert "walkthrough" in task.lower()
        assert "10.10.11.234" in task


@pytest.mark.unit
class TestPentestPrompts:
    """Tests for Pentest pipeline prompt builders."""

    def test_pentest_stage1_system_prompt(self, config: PentestGPTConfig):
        """Test Pentest stage 1 system prompt content."""
        prompt = stages.pentest_stage1_system_prompt(config)
        assert "ASSET IDENTIFICATION" in prompt
        assert "ASSET INVENTORY" in prompt
        assert "65535" in prompt  # full TCP scan

    def test_pentest_stage1_system_prompt_with_instruction(
        self, config_with_instruction: PentestGPTConfig
    ):
        """Test that custom instruction is appended."""
        prompt = stages.pentest_stage1_system_prompt(config_with_instruction)
        assert "Focus on web vulnerabilities" in prompt

    def test_pentest_stage1_task_prompt(self, config: PentestGPTConfig):
        """Test Pentest stage 1 task prompt."""
        task = stages.pentest_stage1_task_prompt(config, [])
        assert "10.10.11.234" in task

    def test_pentest_stage2_system_prompt(self, config: PentestGPTConfig):
        """Test Pentest stage 2 system prompt content."""
        prompt = stages.pentest_stage2_system_prompt(config)
        assert "VULNERABILITY IDENTIFICATION" in prompt
        assert "BFS" in prompt
        assert "Critical" in prompt
        assert "VULNERABILITY SUMMARY" in prompt

    def test_pentest_stage2_task_prompt_with_context(
        self,
        config: PentestGPTConfig,
        sample_prior_results: list[StageResult],
    ):
        """Test Pentest stage 2 task prompt includes prior context."""
        task = stages.pentest_stage2_task_prompt(config, sample_prior_results)
        assert "10.10.11.234" in task
        assert "CONTEXT FROM PRIOR STAGES:" in task

    def test_pentest_stage3_system_prompt(self, config: PentestGPTConfig):
        """Test Pentest stage 3 system prompt content."""
        prompt = stages.pentest_stage3_system_prompt(config)
        assert "PENETRATION TEST REPORT" in prompt
        assert "Executive Summary" in prompt
        assert "Remediation" in prompt

    def test_pentest_stage3_task_prompt(
        self,
        config: PentestGPTConfig,
        sample_prior_results: list[StageResult],
    ):
        """Test Pentest stage 3 task prompt includes prior context."""
        task = stages.pentest_stage3_task_prompt(config, sample_prior_results)
        assert "report" in task.lower()
        assert "10.10.11.234" in task
