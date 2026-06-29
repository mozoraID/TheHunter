"""Tests for the unified `reconx` recon engine and its agent integration.

These are offline: help/usage/error paths plus a localhost-only run (no external
network). The heavy phases degrade gracefully and are exercised via fallbacks.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RECONX = REPO_ROOT / "recon" / "reconx"

bash_available = shutil.which("bash") is not None
requires_bash = pytest.mark.skipif(not bash_available, reason="bash not available")


def run_reconx(*args: str, env: dict | None = None, timeout: int = 60):
    return subprocess.run(
        ["bash", str(RECONX), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )


@pytest.mark.unit
def test_reconx_exists():
    assert RECONX.is_file(), "recon/reconx engine is missing"


@pytest.mark.unit
@requires_bash
def test_reconx_syntax_ok():
    result = subprocess.run(["bash", "-n", str(RECONX)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.unit
@requires_bash
def test_reconx_help():
    result = run_reconx("--help")
    assert result.returncode == 0
    for mode in ("flyover", "recon", "full", "vuln"):
        assert mode in result.stderr


@pytest.mark.unit
@requires_bash
def test_reconx_missing_target_is_usage_error():
    result = run_reconx("--mode", "recon")
    assert result.returncode == 2


@pytest.mark.unit
@requires_bash
def test_reconx_invalid_mode_is_usage_error():
    result = run_reconx("--target", "example.com", "--mode", "bogus")
    assert result.returncode == 2


@pytest.mark.unit
@requires_bash
def test_reconx_localhost_run_produces_artifacts(tmp_path):
    # Disable every network tool so only local fallbacks run; IP target skips
    # subdomain enumeration entirely (no external calls).
    import os

    env = dict(os.environ)
    env["RECONX_DISABLE"] = (
        "subfinder httpx dnsx naabu nuclei ffuf gobuster assetfinder whatweb crt "
        "wafw00f subjack gau waybackurls katana gowitness"
    )
    result = run_reconx(
        "--target", "127.0.0.1", "--mode", "flyover", "--out", str(tmp_path), env=env, timeout=90
    )
    # Output dir + structured result must exist regardless of what was found.
    out_dirs = list(tmp_path.glob("recon-127.0.0.1-*"))
    assert out_dirs, "reconx did not create an output directory"
    result_json = out_dirs[0] / "result.json"
    assert result_json.is_file()
    data = json.loads(result_json.read_text())
    assert data["host"] == "127.0.0.1"
    assert data["mode"] == "flyover"
    assert "counts" in data
    # The harmonized engine must report all phase counters.
    for key in ("subdomains", "hosts", "ports", "web", "waf", "content",
                "takeover", "urls", "secrets", "screenshots", "vulns"):
        assert key in data["counts"], f"missing count: {key}"
    assert "RECONX SUMMARY" in result.stdout


@pytest.mark.unit
def test_agent_prompt_advertises_reconx():
    from pentestgpt.prompts import stages

    assert "reconx" in stages._TOOLS
    # The pentest recon stage should instruct the agent to run it.
    from pentestgpt.core.config import load_config

    cfg = load_config(target="10.0.0.1")
    assert "reconx" in stages.pentest_stage1_system_prompt(cfg)
    assert "reconx" in stages.ctf_stage1_system_prompt(cfg)
