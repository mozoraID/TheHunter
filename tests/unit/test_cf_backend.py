"""Tests for the Cloudflare GLM backend (ReAct loop, parsing, factory)."""

import json

import pytest

from pentestgpt.core.backend import MessageType, create_backend
from pentestgpt.core.budget import ScanBudget
from pentestgpt.core.cf_backend import CloudflareGLMBackend


@pytest.fixture(autouse=True)
def _reset_singleton():
    ScanBudget.reset()
    yield
    ScanBudget.reset()


def make_backend(tmp_path, **kwargs):
    budget = ScanBudget(
        max_tokens_per_scan=kwargs.pop("max_tokens", 100_000),
        usage_file=tmp_path / "usage.json",
    )
    return CloudflareGLMBackend(
        working_directory=str(tmp_path),
        system_prompt="SYS",
        account_id="acct",
        api_token="token",
        budget=budget,
        **kwargs,
    )


async def collect(backend):
    out = []
    async for msg in backend.receive_messages():
        out.append(msg)
    return out


# === Action parsing ===


@pytest.mark.unit
def test_parse_plain_json():
    action = CloudflareGLMBackend._parse_action('{"action": "bash", "command": "ls"}')
    assert action == {"action": "bash", "command": "ls"}


@pytest.mark.unit
def test_parse_fenced_json():
    reply = 'here:\n```json\n{"action": "finish", "report": "done"}\n```'
    action = CloudflareGLMBackend._parse_action(reply)
    assert action["action"] == "finish"


@pytest.mark.unit
def test_parse_json_with_prose_around():
    reply = 'Sure! {"thought": "t", "action": "bash", "command": "id"} ok'
    action = CloudflareGLMBackend._parse_action(reply)
    assert action["command"] == "id"


@pytest.mark.unit
def test_parse_invalid_returns_none():
    assert CloudflareGLMBackend._parse_action("not json at all") is None
    assert CloudflareGLMBackend._parse_action('{"no": "action key"}') is None


# === Response extraction ===


@pytest.mark.unit
def test_extract_native_shape():
    raw = json.dumps({"result": {"response": "hello"}, "success": True})
    assert CloudflareGLMBackend._extract_text(raw) == "hello"


@pytest.mark.unit
def test_extract_openai_shape():
    raw = json.dumps({"result": {"choices": [{"message": {"content": "hi"}}]}})
    assert CloudflareGLMBackend._extract_text(raw) == "hi"


@pytest.mark.unit
def test_extract_reasoning_content_fallback():
    # GLM reasoning models put the answer in reasoning_content when content is null.
    raw = json.dumps(
        {"result": {"choices": [{"message": {"content": None, "reasoning_content": "thinking"}}]}}
    )
    assert CloudflareGLMBackend._extract_text(raw) == "thinking"


@pytest.mark.unit
def test_consume_charges_real_usage(tmp_path):
    backend = make_backend(tmp_path)
    raw = json.dumps({
        "result": {"response": "ok", "usage": {"prompt_tokens": 1500, "completion_tokens": 250}},
        "success": True,
    })
    text = backend._consume(raw)
    assert text == "ok"
    assert backend._budget.prompt_tokens == 1500
    assert backend._budget.completion_tokens == 250
    assert backend._budget.total_tokens == 1750


@pytest.mark.unit
def test_consume_detects_daily_quota(tmp_path):
    from pentestgpt.core.cf_backend import _QuotaExhaustedError

    backend = make_backend(tmp_path)
    raw = json.dumps({
        "success": False,
        "errors": [{"code": 999, "message": "You have exceeded your daily free tier limit"}],
    })
    with pytest.raises(_QuotaExhaustedError):
        backend._consume(raw)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_quota_exhausted_yields_wait_message(tmp_path, monkeypatch):
    from pentestgpt.core.cf_backend import _QuotaExhaustedError

    backend = make_backend(tmp_path)

    def raise_quota(body, model):
        raise _QuotaExhaustedError("daily free tier limit exceeded")

    monkeypatch.setattr(backend, "_post", raise_quota)
    await backend.query("go")
    msgs = await collect(backend)
    errs = [m.content for m in msgs if m.type == MessageType.ERROR]
    assert errs and "reset" in errs[0].lower()


@pytest.mark.unit
def test_extract_error_raises():
    raw = json.dumps({"success": False, "errors": [{"message": "bad token"}]})
    with pytest.raises(RuntimeError):
        CloudflareGLMBackend._extract_text(raw)


@pytest.mark.unit
def test_extract_capacity_error_is_transient():
    from pentestgpt.core.cf_backend import _TransientAPIError

    raw = json.dumps(
        {"success": False, "errors": [{"code": 3040, "message": "Capacity exceeded"}]}
    )
    with pytest.raises(_TransientAPIError):
        CloudflareGLMBackend._extract_text(raw)


@pytest.mark.unit
def test_salvage_command_from_fence():
    reply = "Sure, I'll start by scanning:\n```bash\nreconx --target x --mode flyover\n```"
    assert CloudflareGLMBackend._salvage_command(reply) == "reconx --target x --mode flyover"


@pytest.mark.unit
def test_salvage_command_from_tool_line():
    reply = "First I will run\n$ nmap -sV 10.0.0.1\nto enumerate services."
    assert CloudflareGLMBackend._salvage_command(reply) == "nmap -sV 10.0.0.1"


@pytest.mark.unit
def test_salvage_command_none_for_pure_prose():
    assert CloudflareGLMBackend._salvage_command("I think we should look at the login page.") is None


@pytest.mark.unit
@pytest.mark.asyncio
async def test_react_loop_salvages_command(tmp_path, monkeypatch):
    backend = make_backend(tmp_path)
    replies = [
        "I'll map the surface first:\n```bash\nreconx --target x --mode flyover\n```",
        json.dumps({"action": "finish", "report": "done"}),
    ]
    calls = iter(replies)
    monkeypatch.setattr(backend, "_post", lambda body, model: next(calls))

    async def fake_bash(command):
        return "scan output"

    monkeypatch.setattr(backend, "_run_bash", fake_bash)
    await backend.query("go")
    msgs = await collect(backend)
    tool_starts = [m for m in msgs if m.type == MessageType.TOOL_START]
    assert tool_starts and tool_starts[0].tool_args == {"command": "reconx --target x --mode flyover"}


@pytest.mark.unit
@pytest.mark.asyncio
async def test_react_loop_nudges_then_finishes(tmp_path, monkeypatch):
    backend = make_backend(tmp_path)
    replies = [
        "Let me think about how to approach this target carefully.",  # prose, no command
        json.dumps({"action": "finish", "report": "flag{ok}"}),
    ]
    calls = iter(replies)
    monkeypatch.setattr(backend, "_post", lambda body, model: next(calls))
    await backend.query("go")
    msgs = await collect(backend)
    texts = [m.content for m in msgs if m.type == MessageType.TEXT]
    # It nudged (didn't abort on the prose) and reached the finish report.
    assert any("flag{ok}" in t for t in texts)
    assert msgs[-1].type == MessageType.RESULT


@pytest.mark.unit
def test_http_429_is_transient(tmp_path, monkeypatch):
    import urllib.error

    from pentestgpt.core.cf_backend import _TransientAPIError

    backend = make_backend(tmp_path)

    def raise_429(req, timeout, context=None):
        raise urllib.error.HTTPError(req.full_url, 429, "Too Many Requests", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", raise_429)
    with pytest.raises(_TransientAPIError):
        backend._post(b"{}", backend._model)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_chat_falls_back_on_capacity(tmp_path, monkeypatch):
    backend = make_backend(tmp_path)
    backend._fallback_model = "@cf/zai-org/glm-4.7-flash"
    backend._retry_delay = 0  # no real sleeping
    seen_models = []

    def fake_post(body, model):
        seen_models.append(model)
        from pentestgpt.core.cf_backend import _TransientAPIError

        if model == backend._model:
            raise _TransientAPIError("capacity")
        return "fallback reply"

    monkeypatch.setattr(backend, "_post", fake_post)
    reply = await backend._chat()
    assert reply == "fallback reply"
    # Primary tried (with retries) then the fallback model.
    assert backend._model in seen_models
    assert backend._fallback_model in seen_models


# === ReAct loop ===


@pytest.mark.unit
@pytest.mark.asyncio
async def test_react_loop_bash_then_finish(tmp_path, monkeypatch):
    backend = make_backend(tmp_path)

    replies = [
        json.dumps({"thought": "scan it", "action": "bash", "command": "echo hi"}),
        json.dumps({"thought": "all done", "action": "finish", "report": "flag{abc}"}),
    ]
    calls = iter(replies)

    def fake_post(body, model):
        return next(calls)

    async def fake_bash(command):
        return "command output"

    monkeypatch.setattr(backend, "_post", fake_post)
    monkeypatch.setattr(backend, "_run_bash", fake_bash)

    await backend.query("pwn the target")
    msgs = await collect(backend)
    types = [m.type for m in msgs]

    assert MessageType.TOOL_START in types
    assert MessageType.TOOL_RESULT in types
    assert types[-1] == MessageType.RESULT
    # The finish report (with the flag) is surfaced as text.
    texts = [m.content for m in msgs if m.type == MessageType.TEXT]
    assert any("flag{abc}" in t for t in texts)
    # bash command was carried through to the tool event.
    tool_starts = [m for m in msgs if m.type == MessageType.TOOL_START]
    assert tool_starts[0].tool_args == {"command": "echo hi"}


@pytest.mark.unit
@pytest.mark.asyncio
async def test_react_loop_stops_when_budget_exhausted(tmp_path, monkeypatch):
    backend = make_backend(tmp_path, max_tokens=0)  # no budget at all

    def fake_post(body):  # pragma: no cover - should not be called
        raise AssertionError("model should not be called with no budget")

    monkeypatch.setattr(backend, "_post", fake_post)

    await backend.query("task")
    msgs = await collect(backend)
    texts = [m.content for m in msgs if m.type == MessageType.TEXT]
    assert any("budget" in t.lower() for t in texts)
    assert msgs[-1].type == MessageType.RESULT


@pytest.mark.unit
@pytest.mark.asyncio
async def test_daily_limit_yields_error_when_enforced(tmp_path):
    from datetime import date

    usage = tmp_path / "usage.json"
    usage.write_text(json.dumps({"date": date.today().isoformat(), "tokens": 0, "scans": 4}))
    # Only blocks when enforcement is explicitly enabled.
    budget = ScanBudget(max_scans_per_day=4, usage_file=usage, enforce_daily_limit=True)
    backend = CloudflareGLMBackend(
        working_directory=str(tmp_path),
        system_prompt="SYS",
        account_id="acct",
        api_token="token",
        budget=budget,
    )
    await backend.query("task")
    msgs = await collect(backend)
    assert msgs[0].type == MessageType.ERROR
    assert msgs[-1].type == MessageType.RESULT


@pytest.mark.unit
def test_daily_limit_soft_by_default(tmp_path):
    """By default the daily caps are advisory — register_scan never raises."""
    from datetime import date

    from pentestgpt.core.budget import ScanBudget as SB

    usage = tmp_path / "usage.json"
    usage.write_text(json.dumps({"date": date.today().isoformat(), "tokens": 99999, "scans": 99}))
    budget = SB(max_scans_per_day=4, daily_token_budget=10_000, usage_file=usage)
    budget.register_scan()  # must NOT raise
    assert budget.can_continue()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_run_bash_executes(tmp_path):
    backend = make_backend(tmp_path)
    out = await backend._run_bash("echo pentestgpt")
    assert "pentestgpt" in out


# === Factory ===


@pytest.mark.unit
def test_factory_selects_cloudflare(tmp_path):
    from pentestgpt.core.config import load_config

    config = load_config(
        target="10.0.0.1",
        cloudflare_account_id="acct",
        cloudflare_api_token="token",
        cf_usage_file=str(tmp_path / "u.json"),
    )
    backend = create_backend(config, "SYS")
    assert isinstance(backend, CloudflareGLMBackend)


@pytest.mark.unit
def test_factory_missing_creds_raises():
    from pentestgpt.core.config import load_config

    # Explicit None overrides any .env-provided credentials (init args win).
    config = load_config(
        target="10.0.0.1",
        cloudflare_account_id=None,
        cloudflare_api_token=None,
    )
    with pytest.raises(RuntimeError):
        create_backend(config, "SYS")
