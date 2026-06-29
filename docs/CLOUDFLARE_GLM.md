# Cloudflare GLM 5.2 Brain

TheHunter's autonomous agent (the `pentestgpt` CLI) now runs on **GLM 5.2 via
Cloudflare Workers AI** by default instead of the `claude` CLI. The Claude login
path is still available — only the default *brain* changed.

- **Model:** `@cf/zai-org/glm-5.2` (fallback: `@cf/zai-org/glm-4.7-flash`)
- **Free tier:** ~10,000 neurons/day
- **Budget policy:** 4 scans/day × ~2,500 tokens/scan = ~10,000

The bug-bounty workflow is unchanged:

```bash
/workspace/bb --target https://TARGET \
    --instruction "$(/workspace/bb-triage/instruction.sh PLATFORM ijusthunter 'SCOPE')" \
    && /workspace/bb-triage/run_triage.sh $(ls -t /workspace/scan-*.log | head -1)
```

---

## How it works

The `claude` CLI is *agentic* — it runs tools by itself. Cloudflare Workers AI is
a plain chat endpoint that only returns text, so TheHunter now runs the agent
loop itself in [`pentestgpt/core/cf_backend.py`](../pentestgpt/core/cf_backend.py):

1. Send the conversation to GLM.
2. GLM replies with **one JSON action** (ReAct):
   - `{"thought": "...", "action": "bash", "command": "nmap -sV TARGET"}`
   - `{"thought": "...", "action": "finish", "report": "<markdown report>"}`
3. The runner executes the shell command, feeds the output back, and loops.
4. Stops on `finish`, the step cap (`CF_MAX_STEPS`), or when the per-scan token
   budget runs out.

Everything downstream (flag detection, events, sessions, the 3-stage
recon → exploit/vuln → report pipeline) is unchanged — only the backend swapped.

### Budget accounting ([`pentestgpt/core/budget.py`](../pentestgpt/core/budget.py))

- **Per-scan:** an approximate token budget (`len/4`) shared across all pipeline
  stages of one `pentestgpt` run. When exhausted, the loop wraps up.
- **Daily:** scans started and tokens spent today are persisted to
  `~/.pentestgpt/cf_usage.json`. Hitting `CF_MAX_SCANS_PER_DAY` or
  `CF_DAILY_TOKEN_BUDGET` makes the next scan exit early with a clear message.
  Counters reset automatically each day.

---

## Setup

### First run — the login wizard (recommended)

On the first `docker compose run --rm pentestgpt`, an interactive wizard asks for
your plan and credentials, verifies the token with a live call, and saves the
config so it's never asked again (persisted in the bind-mounted workspace at
`/workspace/.pentestgpt-setup.env`). Re-run **`pentestgpt-setup`** anytime to
switch plan or update the token.

```
╔════════════════════════════════════════════════╗
║   TheHunter — GLM 5.2 brain setup             ║
╚════════════════════════════════════════════════╝
Choose your plan:
  1) Free  — 10,000 neurons/day    -> 10k/scan, ~1 scan/day
  2) Paid  — 300,000 neurons/month -> 15k/scan, deeper, ~20 scans/month
Select plan [1=Free / 2=Paid] (default 1):
Cloudflare Account ID:
Cloudflare API Token:
```

| Plan | Neurons | Per-scan cap | Steps/stage | Rough cadence |
|------|---------|--------------|-------------|----------------|
| **Free** | 10,000 / day | 10,000 | 3 | ~1 scan/day |
| **Paid** | 300,000 / month | 15,000 | 6 (deeper) | ~20 scans/month |

The per-scan cap is in **neurons (~total input+output tokens)** — what Cloudflare
bills. When a scan reaches its cap it wraps up with a report; the `[TOKENS]` note
shows exactly what it used.

### Or configure non-interactively via `.env`

Credentials and budgets can also live in `.env` (gitignored). See `.env.example`:

```dotenv
LLM_BACKEND=cloudflare

CLOUDFLARE_ACCOUNT_ID=<your account id>
CLOUDFLARE_API_TOKEN=<your Workers AI token>
CLOUDFLARE_MODEL=@cf/zai-org/glm-5.2
CLOUDFLARE_FALLBACK_MODEL=@cf/zai-org/glm-4.7-flash

CF_MAX_TOKENS_PER_SCAN=6000   # OUTPUT-token cap/scan (bounds the agent loop)
CF_DAILY_TOKEN_BUDGET=10000   # advisory daily total (Cloudflare enforces the real quota)
CF_TOOL_TIMEOUT=300           # seconds per shell command (reconx needs room)
CF_MAX_STEPS=5                # max ReAct steps per stage (token frugality)
CF_MAX_RETRIES=3              # retries on 429 / capacity before fallback
CF_ENFORCE_DAILY_LIMIT=false  # true = hard-block past the daily cap
```

### Token cost — measured, be realistic

GLM 5.2 is a *reasoning* model and Cloudflare bills **input + output** tokens.
Measured on a real run:

- **~4,000–5,000 tokens per LLM call** — dominated by the `instruction.sh`
  methodology (~3,000 tokens) which is re-sent as input on **every** call.
- A full recon→report scan = **~15,000–40,000 tokens** (several calls + tool
  output fed back).

So the **10,000-token/day free tier ≈ one scan per day**, not 2–3. The end-of-
report `[TOKENS]` note shows exactly what each scan used. To fit more scans:

1. Use a **shorter `--instruction`** (the methodology is the biggest cost), or
2. Run **`--mode flyover`** style / fewer steps (lower `CF_MAX_STEPS`), or
3. Raise `CF_DAILY_TOKEN_BUDGET` on a **paid** Cloudflare Workers AI plan.

When the daily quota is hit, the agent **auto-detects** it and prints a
"wait for the 00:00 UTC reset" message — no config needed.

Get both values from the Cloudflare dashboard → **AI → Workers AI**. The endpoint
called is:

```
https://api.cloudflare.com/client/v4/accounts/<ID>/ai/run/@cf/zai-org/glm-5.2
```

`docker-compose.yml` passes all of these through to the container, so a host
`.env` is enough.

---

## Usage

```bash
# GLM 5.2 is the only brain — nothing extra to pass:
pentestgpt --target 10.10.11.42 --mode pentest

# Override the Workers AI model id for a run:
pentestgpt --target https://example.com --model @cf/zai-org/glm-4.7-flash
```

Daily caps are advisory by default (`CF_ENFORCE_DAILY_LIMIT=false`): a scan is
never blocked client-side — Cloudflare's own 429 enforces the real free-tier
quota, and the backend handles it via retry + fallback to `glm-4.7-flash`.

---

## Notes & limits

- **`glm-5.2` is occasionally at capacity** on the free tier (`code 3040`). The
  backend retries `CF_MAX_RETRIES` times, then falls back to
  `glm-4.7-flash` for that call. Set `CLOUDFLARE_FALLBACK_MODEL=` (empty) to
  disable the fallback.
- **GLM are reasoning models** — they spend tokens "thinking". The 2,500-token
  per-scan budget is intentionally tight; expect concise enumeration rather than
  exhaustive scans. Raise `CF_MAX_TOKENS_PER_SCAN` / `CF_DAILY_TOKEN_BUDGET` if
  you have a paid plan.
- The backend executes shell commands in the container with the same
  capabilities as before — run it only against authorized targets.

---

## Testing

```bash
uv run pytest tests/unit/test_cf_backend.py tests/unit/test_budget.py -v
```

These cover ReAct JSON parsing, response-shape extraction (native + OpenAI +
reasoning), tool execution, per-scan/daily budget enforcement, capacity retry +
fallback, and backend-factory selection — all without network access.
