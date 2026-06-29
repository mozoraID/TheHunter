"""Tests for the Cloudflare token/scan budget tracker."""

import json

import pytest

from pentestgpt.core.budget import BudgetExceeded, ScanBudget, estimate_tokens


@pytest.fixture(autouse=True)
def _reset_singleton():
    ScanBudget.reset()
    yield
    ScanBudget.reset()


@pytest.fixture
def usage_file(tmp_path):
    return tmp_path / "cf_usage.json"


@pytest.mark.unit
def test_estimate_tokens():
    assert estimate_tokens("") == 0
    assert estimate_tokens("abcd") == 1
    assert estimate_tokens("a" * 40) == 10


@pytest.mark.unit
def test_per_scan_budget(usage_file):
    b = ScanBudget(max_tokens_per_scan=100, usage_file=usage_file)
    assert b.remaining() == 100
    assert b.can_continue()
    b.charge(60)
    assert b.remaining() == 40
    b.charge(50)
    assert b.remaining() == 0
    assert not b.can_continue()


@pytest.mark.unit
def test_charge_text(usage_file):
    b = ScanBudget(max_tokens_per_scan=1000, usage_file=usage_file)
    charged = b.charge_text("a" * 40, "b" * 40)
    assert charged == 20
    assert b.consumed == 20


@pytest.mark.unit
def test_charge_usage_real_tokens(usage_file):
    b = ScanBudget(max_tokens_per_scan=10_000, usage_file=usage_file)
    b.charge_usage(1200, 300)
    b.charge_usage(800, 200)
    assert b.prompt_tokens == 2000
    assert b.completion_tokens == 500
    assert b.total_tokens == 2500
    # Per-scan cap tracks NEURONS (~total input + output tokens).
    assert b.consumed == 2500
    # Daily total tracks input + output.
    assert json.loads(usage_file.read_text())["tokens"] == 2500


@pytest.mark.unit
def test_register_scan_increments_daily(usage_file):
    b = ScanBudget(max_scans_per_day=4, usage_file=usage_file)
    b.register_scan()
    data = json.loads(usage_file.read_text())
    assert data["scans"] == 1
    # Idempotent within the same process/instance.
    b.register_scan()
    data = json.loads(usage_file.read_text())
    assert data["scans"] == 1


@pytest.mark.unit
def test_daily_scan_limit(usage_file):
    # Pre-seed today's usage at the cap.
    from datetime import date

    usage_file.write_text(json.dumps({"date": date.today().isoformat(), "tokens": 0, "scans": 4}))
    b = ScanBudget(max_scans_per_day=4, usage_file=usage_file, enforce_daily_limit=True)
    with pytest.raises(BudgetExceeded):
        b.register_scan()


@pytest.mark.unit
def test_daily_token_limit(usage_file):
    from datetime import date

    usage_file.write_text(
        json.dumps({"date": date.today().isoformat(), "tokens": 10_000, "scans": 1})
    )
    b = ScanBudget(daily_token_budget=10_000, usage_file=usage_file, enforce_daily_limit=True)
    with pytest.raises(BudgetExceeded):
        b.register_scan()


@pytest.mark.unit
def test_daily_reset_on_new_day(usage_file):
    usage_file.write_text(json.dumps({"date": "2000-01-01", "tokens": 9999, "scans": 4}))
    b = ScanBudget(max_scans_per_day=4, usage_file=usage_file)
    # Stale day -> counters reset, scan allowed.
    b.register_scan()
    data = json.loads(usage_file.read_text())
    assert data["scans"] == 1
    assert data["tokens"] == 0


@pytest.mark.unit
def test_configure_singleton(usage_file):
    class Cfg:
        cf_max_tokens_per_scan = 2500
        cf_max_scans_per_day = 4
        cf_daily_token_budget = 10_000
        cf_usage_file = str(usage_file)
        cf_enforce_daily_limit = False

    first = ScanBudget.configure(Cfg())
    second = ScanBudget.configure(Cfg())
    assert first is second
    assert ScanBudget.get() is first
    assert first.max_tokens_per_scan == 2500
