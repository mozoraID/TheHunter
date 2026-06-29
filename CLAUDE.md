# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TheHunter is an AI-powered autonomous penetration testing agent. It uses an agentic pipeline to solve CTF challenges, Hack The Box machines, and authorized security assessments. Output is raw streaming to stdout.

**Published at USENIX Security 2024**: [Paper](https://www.usenix.org/conference/usenixsecurity24/presentation/deng)

**Stack:** Python 3.12+, uv, Agent SDK

## Common Commands

```bash
# Setup
uv sync                           # Install dependencies
uv run pentestgpt --target X      # Run locally

# Testing
make test                         # Run all tests
make test-cov                     # Run tests with coverage
uv run pytest tests/test_controller.py -v  # Run single test file

# Code Quality
make lint                         # Run ruff linter
make format                       # Format code with ruff
make typecheck                    # Run mypy type checking
make check                        # All checks (lint + typecheck)
```

## Architecture

### Entry Point
- `pentestgpt/interface/main.py` - CLI entry, argument parsing, raw streaming output
- Command: `pentestgpt --target <IP/URL> [--max-iterations N] [--instruction "hint"] [--debug]`

### Core Layer (`pentestgpt/core/`)
- **pipeline.py** - `PipelineOrchestrator`: Runs an iteration loop, each iteration with a fresh backend + controller. Data classes: `IterationResult`, `LoopResult`. The agent writes a context file (`pentestgpt_context.md`) as it works; the orchestrator reads it after each iteration and feeds it into the next. Loop terminates on flag capture, error, or max iterations.
- **backend.py** - `AgentBackend` interface + `create_backend(config, system_prompt)` factory. GLM 5.2 via Cloudflare (`CloudflareGLMBackend`) is the only brain — the Claude backend has been removed.
- **cf_backend.py** - `CloudflareGLMBackend`: the default brain. Calls `@cf/zai-org/glm-5.2` via Cloudflare Workers AI and runs the agent loop *itself* (Workers AI is a plain chat endpoint, not agentic). JSON ReAct protocol (`{"action":"bash"|"finish", ...}`), executes shell commands, feeds output back, yields the same `AgentMessage` stream the controller expects. Retries capacity errors (code 3040) and falls back to `glm-4.7-flash`. Handles native/OpenAI/reasoning response shapes.
- **budget.py** - `ScanBudget`: process-singleton per-scan token budget (default 2500, shared across pipeline stages) + daily limits (4 scans, 10k tokens) persisted to `~/.pentestgpt/cf_usage.json`. The Cloudflare free tier is ~10k neurons/day.
- **controller.py** - `AgentController`: 5-state lifecycle (IDLE->RUNNING->PAUSED->COMPLETED->ERROR), pause/resume at message boundaries. Handles `ERROR` messages (surfaced as error events). Used per-iteration by the pipeline orchestrator
- **events.py** - `EventBus`: Singleton pub/sub for agent-output decoupling (STATE_CHANGED, MESSAGE, TOOL, FLAG_FOUND events)
- **session.py** - `SessionStore`: File-based persistence in `~/.pentestgpt/sessions/`, supports session resumption
- **config.py** - Pydantic settings with `.env` file support. `cloudflare_*` + `cf_*` fields configure GLM/Workers AI and budgets (daily caps advisory unless `cf_enforce_daily_limit`). Also `max_iterations` and `context_file`.

### System Prompts (`pentestgpt/prompts/`)
- **system_prompt.py** - Unified prompt builders: `build_system_prompt`, `build_first_task_prompt`, `build_continuation_task_prompt`. Shared fragments (`_IDENTITY`, `_TOOLS`, `_FLAG_PATTERNS`, `_PERSISTENCE`, `_FALLBACK_STRATEGIES`, `_CTF_CATEGORIES`, `_METHODOLOGY`, `_CONTEXT_PERSISTENCE`)

## Key Patterns

- **Iteration Loop**: `PipelineOrchestrator` runs iterations in a loop. Each iteration gets a fresh `ClaudeCodeBackend` + `AgentController` (system prompt is set at connect time, so a new backend is needed per iteration). The agent maintains a context file; the orchestrator reads it after each iteration and injects it into the next iteration's task prompt. Falls back to truncated prior output if the context file is missing.
- **Event-Driven**: Raw mode subscribes to EventBus; agent emits events for state changes, messages, flags
- **Singletons**: `EventBus.get()` for global access
- **Abstract Backend**: `AgentBackend` interface allows swapping LLM backends
- **Flag Detection**: Regex patterns in controller.py match `flag{}`, `HTB{}`, `CTF{}`, 32-char hex

## Testing

Tests use pytest with pytest-asyncio. Mock backends for unit tests.

```bash
uv run pytest tests/ -v                           # All tests
uv run pytest tests/test_controller.py -v         # Single file
uv run pytest tests/test_controller.py::test_name # Single test
```

## Repository Structure

```
.
├── pentestgpt/           # Autonomous agent (Claude-only, claude CLI backend)
│   ├── core/             # Pipeline, controller, events, session, backend
│   ├── interface/        # CLI entry point (raw streaming)
│   └── prompts/          # System prompts (system_prompt.py)
├── pentestgpt_legacy/    # Modernized legacy: interactive 3-session + PTT, multi-LLM
│   ├── llm/              # Native per-provider LLM layer (registry, factory, client, providers)
│   ├── utils/            # Orchestrator (pentest_gpt.py) + REPL helpers
│   └── prompts/          # Classic PTT/session prompts
├── recon/                # `reconx` — unified recon engine (reconFTW+Sn1per+Osmedeus, harmonized)
├── scripts/              # entrypoint.sh, ccr template, install-recon-tools.sh
├── docs/                 # CLOUDFLARE_GLM.md, RECONX.md
├── tests/                # Test suite (tests/legacy/ covers pentestgpt_legacy)
└── Makefile              # Development commands

### Unified recon engine (`recon/reconx`)

A single bash engine that distills reconFTW + Sn1per + Osmedeus into one
pipeline: scan **modes** (flyover/recon/full/vuln), **graceful tool fallbacks**
(subfinder/httpx/dnsx/naabu/nuclei/ffuf when present; crt.sh/curl/dig/nmap
otherwise), and **structured artifacts** (per-phase `.txt`, `result.json`,
`summary.md`) plus a concise `RECONX SUMMARY` stdout block tuned for the GLM
token budget. Installed to `/usr/local/bin/reconx` by the Dockerfile;
`scripts/install-recon-tools.sh` adds the modern toolset (skip with
`RECONX_SKIP_TOOLS=1`). The GLM agent is told (in `prompts/stages.py`) to use it
as its primary recon primitive. `RECONX_DISABLE="httpx ..."` forces fallbacks.
```

### Modernized Legacy (`pentestgpt_legacy/`)

The classic USENIX-2024 human-in-the-loop tool, rebuilt on a native multi-provider LLM
layer. CLI: `pentestgpt-legacy` (`--list-models`, `--smoke-test`, `--reasoning-model`,
`--parsing-model`, `--base-url`).

- **llm/registry.py** — single source of truth for supported models (`ModelSpec`/`PROVIDERS`),
  web-verified IDs. `--list-models` and the README table render from it.
- **llm/factory.py** — `get_client(model_name)` -> `LLMClient`; resolves provider, builds it.
- **llm/client.py** — `LLMClient` bridges async providers to the core's synchronous
  `send_new_message`/`send_message` (drop-in for the old `LLMAPI`); holds per-conversation history.
- **llm/providers/** — `OpenAICompatibleProvider` (OpenAI + DeepSeek/Ollama/xAI/Qwen/Moonshot via
  base_url; Responses-API fallback for `*-pro`/`*-codex`), `AnthropicProvider`, `GeminiProvider`.
- **llm/config.py** — pydantic-settings credentials (per-provider keys + base-url overrides).
- **smoke_test.py** — `--smoke-test` makes a real round-trip per configured model (acceptance gate).

Note: `make typecheck` is scoped to `pentestgpt/`; the new package is covered by ruff
(`make lint`) and `tests/legacy/`. Run `uv run mypy pentestgpt_legacy/llm/` for its typed core.

## Modification Requirements

When modifying code, ensure:
- Adherence to existing architecture and patterns
- Comprehensive tests for new features
- Ensure to run tests after changes, and do further updates to ensure code quality. Always keep the documentation up to date with any architectural changes. Also ensure all tests pass after modifications.
