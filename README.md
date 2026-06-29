<div align="center">

# 🏹 TheHunter

**AI-powered autonomous penetration-testing & bug-bounty agent**

Runs on **GLM 5.2** via **Cloudflare Workers AI** — bring your own free (or paid) Cloudflare key.
One unified recon engine (`reconx`, distilled from reconFTW + Sn1per + Osmedeus), a budget-aware
agent loop, and a triage pipeline that only surfaces verified, in-scope findings.

</div>

> ⚠️ **Authorized use only.** TheHunter performs active scanning and exploitation. Only run it
> against systems you own or are explicitly authorized to test (your own labs, HackTheBox, or
> bug-bounty programs that include the target in scope). You are responsible for staying in scope.

---

## ✨ What you get

- 🧠 **GLM 5.2 brain (Cloudflare Workers AI)** — free tier gives ~10,000 neurons/day. No GPU, no local model.
- 🔍 **`reconx` unified recon engine** — subdomains → DNS → ports → web → WAF → content → takeover →
  URLs → JS secrets → screenshots → vuln scan, in **one** command, with graceful fallbacks.
- 🤖 **Autonomous ReAct agent** — runs tools, reads results, writes a report, all by itself.
- 🎯 **Bug-bounty workflow** (`bb` + `bb-triage`) — auto-detects program & scope, verifies findings
  live, and shows only the actionable ones.
- 💸 **Budget-aware** — Free / Paid plans, a per-scan neuron cap, and a token-usage note at the end
  of every report.
- 🐳 **One-command Docker** — all tools pre-installed.

---

## 🚀 Quick start (3 steps)

### 1. Clone & build

```bash
git clone https://github.com/mozoraID/TheHunter.git
cd TheHunter
docker compose build      # first build pulls the recon toolset (~10 min)
```

### 2. Get a Cloudflare Workers AI key (free) — see the next section 👇

### 3. Run it — the setup wizard handles the rest

```bash
docker compose run --rm pentestgpt
```

On first run you'll be asked to choose a plan and paste your **Account ID** + **API Token**.
That's it — you're ready to scan.

---

## 🔑 Cloudflare Workers AI setup (the only thing you need)

TheHunter's brain is GLM 5.2, served by **Cloudflare Workers AI**. You need two values: an
**Account ID** and an **API Token** with the right permissions. It's free.

### Step 1 — Create / log into Cloudflare

Sign up at **[dash.cloudflare.com](https://dash.cloudflare.com)** (free, no card required).

### Step 2 — Find your **Account ID**

1. In the dashboard, open **AI → Workers AI** (left sidebar).
2. Your **Account ID** is shown on that page (and in the sample code). Copy it.
   - It's a 32-character hex string, e.g. `1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d`

### Step 3 — Create an **API Token** with Workers AI **Read + Edit**

1. Go to **My Profile → API Tokens** → **Create Token**
   (direct link: **[dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens)**).
2. Click **Create Custom Token** → **Get started**.
3. Under **Permissions**, add the **Workers AI** permission with **both** Read and Edit:

   | Group | Permission | Access |
   |-------|------------|--------|
   | **Account** | **Workers AI** | **Read** |
   | **Account** | **Workers AI** | **Edit** |

   > 💡 Click **+ Add more** to add the second row. **Edit** lets the agent *run* inference;
   > **Read** lets it list/inspect models. TheHunter uses both.
4. Under **Account Resources**, choose **Include → your account**.
5. (Optional) leave **TTL** as is, then **Continue to summary → Create Token**.
6. **Copy the token now** — Cloudflare shows it only once. It looks like a long random string.

### Step 4 — Paste them into the wizard

When `docker compose run --rm pentestgpt` asks, paste the Account ID and the token. TheHunter
verifies them with a live test call before saving. Done.

> 🔒 Your credentials are saved to `workspace/.pentestgpt-setup.env`, which is **gitignored** and
> never leaves your machine. They are **not** committed to GitHub.

---

## 🪪 The login wizard — Free vs Paid

The first run shows:

```
╔════════════════════════════════════════════════╗
║   TheHunter — GLM 5.2 brain setup              ║
╚════════════════════════════════════════════════╝
Choose your plan:
  1) Free  — 10,000 neurons/day    -> 10k/scan, ~1 scan/day
  2) Paid  — 300,000 neurons/month -> 15k/scan, deeper, ~20 scans/month
Select plan [1=Free / 2=Paid] (default 1):
Cloudflare Account ID:
Cloudflare API Token:
Verifying credentials... ✓ Credentials OK — GLM 5.2 reachable.
```

| Plan | Cloudflare quota | Per-scan cap | Depth | Roughly |
|------|------------------|--------------|-------|---------|
| **Free** | 10,000 neurons/day | **10,000 neurons** | concise | **~1 scan/day** |
| **Paid** | 300,000 neurons/month | **15,000 neurons** | deeper full scan | **~20 scans/month** |

- A **neuron ≈ total input + output tokens** (what Cloudflare bills).
- The setup is saved, so the wizard only runs once. **Switch plan / update your token anytime:**

  ```bash
  docker compose run --rm pentestgpt   # inside the container:
  pentestgpt-setup
  ```

When the daily/monthly quota is used up, TheHunter **auto-detects it** and tells you to wait for
Cloudflare's reset — no crash, no confusion.

---

## 🎯 Running a scan

Inside the container (`docker compose run --rm pentestgpt`):

### Simple scan

```bash
pentestgpt --target https://example.com --mode pentest
```

### Bug-bounty workflow (recommended)

```bash
/workspace/bb --target https://TARGET \
  --instruction "$(/workspace/bb-triage/instruction.sh hackerone YOURHANDLE 'TARGET_or_*.root')" \
  && /workspace/bb-triage/run_triage.sh $(ls -t /workspace/scan-*.log | head -1)
```

- `bb` runs the agent in pentest mode and saves a timestamped log to `/workspace`.
- `instruction.sh PLATFORM HANDLE SCOPE` builds the rules-of-engagement (auth-bypass, XSS, IDOR,
  scope discipline, …). Platforms: `hackerone`, `bugcrowd`, `intigriti`, `yeswehack`, …
- `run_triage.sh` auto-detects program + scope, verifies each finding live, and prints only the
  **actionable, in-scope** ones.

At the end of every report you'll see your usage:

```
[TOKENS] This scan: 8563 in + 3110 out = 11673 tokens (GLM 5.2). Today: 11673/10000 tokens used.
```

---

## 🔭 `reconx` — the unified recon engine

One command runs the whole recon methodology (distilled from **reconFTW + Sn1per + Osmedeus**):

```bash
reconx --target <domain|ip|url> --mode <flyover|recon|full|vuln>
```

| Mode | What it does |
|------|--------------|
| `flyover` | fast: subdomains + live web + tech + WAF |
| `recon` | + ports, content discovery, subdomain takeover, historical URLs |
| `full` | + JS secrets/endpoints, screenshots, nuclei vuln scan |
| `vuln` | targeted vulnerability pass |

It uses modern tools when present (subfinder, httpx, nuclei, naabu, ffuf, katana, gau, …) and
**falls back** to base tools (curl, dig, nmap) otherwise — so it always runs. Full details in
**[docs/RECONX.md](docs/RECONX.md)**.

---

## ⚙️ Configuration

The wizard is the easy path. For automation you can also use a `.env` file (copy `.env.example`):

```dotenv
CLOUDFLARE_ACCOUNT_ID=your_account_id
CLOUDFLARE_API_TOKEN=your_workers_ai_token
CLOUDFLARE_MODEL=@cf/zai-org/glm-5.2
CLOUDFLARE_FALLBACK_MODEL=@cf/zai-org/glm-4.7-flash

CF_MAX_TOKENS_PER_SCAN=10000   # neurons (~total tokens) per scan; Paid: 15000
CF_DAILY_TOKEN_BUDGET=10000    # advisory; Cloudflare enforces the real quota
CF_TOOL_TIMEOUT=300            # seconds per shell command
CF_MAX_STEPS=5                 # ReAct steps per stage
```

> `.env` and `workspace/.pentestgpt-setup.env` are gitignored — never commit your token.

Full brain/budget details: **[docs/CLOUDFLARE_GLM.md](docs/CLOUDFLARE_GLM.md)**.

---

## 🧪 Development

```bash
uv sync             # install deps
make test           # run the test suite
make check          # ruff lint + mypy typecheck
```

---

## 🙏 Credits

- Recon methodology distilled from **[reconFTW](https://github.com/six2dez/reconftw)**,
  **[Sn1per](https://github.com/1N3/Sn1per)**, and **[Osmedeus](https://github.com/j3ssie/osmedeus)**.
- Built on the agentic foundation of the original **PentestGPT**
  ([USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/deng)).
- Brain by **GLM 5.2** on **Cloudflare Workers AI**.

## 📄 License

MIT — see [LICENSE.md](LICENSE.md).
