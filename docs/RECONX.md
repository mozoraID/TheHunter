# reconx — Unified Recon & Attack-Surface Engine

`reconx` is TheHunter's single, in-house recon engine. Rather than bundling
three large, overlapping frameworks (with hundreds of conflicting dependencies),
it **distills the methodology of all three into one harmonized pipeline**:

| Upstream framework | What reconx takes from it (read from the actual repo) |
|--------------------|----------------------------|
| **[reconFTW](https://github.com/six2dez/reconftw)** (six2dez) | The deep phase set from its modules: passive + crt.sh + active-brute subdomains (`sub_passive`/`sub_crt`/`sub_brute`), `subtakeover`, `waf_checks`, `urlchecks` (wayback/gau/katana), `jschecks` (JS secrets/endpoints), `screenshot`, `nuclei_check` |
| **[Sn1per](https://github.com/1N3/Sn1per)** (1N3) | The scan-**mode** taxonomy (`flyover`/`recon`/`full`/`vuln`) and its nmap-centric port→service→web→screenshot flow |
| **[Osmedeus](https://github.com/j3ssie/osmedeus)** (j3ssie) | Its `full-scan` flow shape — dependency-gated stages (subdomain → port → http-probe → screenshot ∥ vuln), structured per-phase output dirs, and machine-readable JSON artifacts |

> These were extracted by cloning and reading each repo's orchestrator
> (`reconftw/modules/*.sh`, `Sn1per/sniper`, and Osmedeus'
> `workflows/flows/full-scan.yaml` + `modules/*.yaml`) — not from memory.

It is wired directly into the agent: the GLM 5.2 brain is told (via the stage
prompts) to run `reconx` as its first move on any host/domain/URL target. Your
`bb` bug-bounty workflow is unchanged — the agent simply has a far stronger,
budget-friendly recon primitive.

---

## Why one engine instead of three repos

- **Token budget.** The GLM free tier gives a small per-scan token budget. Piping
  raw output from three verbose frameworks would exhaust it instantly. `reconx`
  writes full results to disk and prints only a **concise summary** the agent
  reads back.
- **No dependency hell.** reconFTW + Sn1per + Osmedeus pull in ~hundreds of
  tools across bash/Go/Python/Perl. `reconx` needs none of them — it *uses* the
  best ones when present and **falls back** to base utilities otherwise.
- **Always runs.** With only `curl` + `dig`/`host` + `jq` (all in the base
  image) it still enumerates via crt.sh, resolves, and probes the web.

---

## Modes (Sn1per-style)

```
reconx --target <domain|ip|url> --mode <flyover|recon|full|vuln>
```

| Mode | Phases | Use when |
|------|--------|----------|
| `flyover` | subdomains → DNS → web probe+tech → WAF/CDN | Fast surface sweep (cheapest) |
| `recon` *(default)* | subs → DNS → ports → web → WAF → content → takeover → urls | Standard mapping |
| `full` | `recon` + JS secrets/endpoints → screenshots → vuln scan | A promising host is identified (adds active sub-brute) |
| `vuln` | subs → DNS → web → subdomain-takeover → vuln scan | Targeted vuln pass |

Options: `--out DIR`, `--threads N`, `--top-ports N`, `--no-vulns`, `--quiet`.

---

## Phases & tool resolution (graceful degradation)

| Phase | Preferred tool | Fallback |
|-------|----------------|----------|
| Subdomains (passive) | `subfinder`, `assetfinder` | `crt.sh` via `curl`/`jq` |
| Subdomains (active brute, full mode) | `dnsx` + builtin list | `dig`/`host` + builtin list |
| DNS resolve | `dnsx` | `dig` / `host` |
| Ports | `naabu` | `nmap --top-ports` |
| Web probe + tech | `httpx` | `curl` (+ `whatweb`) |
| WAF / CDN | `wafw00f` | response-header heuristics via `curl` |
| Content discovery | `ffuf` / `gobuster` (+ wordlist) | built-in curl path list |
| Subdomain takeover | `nuclei -tags takeover` / `subjack` | dangling-CNAME provider check via `dig`/`host` |
| Historical / crawled URLs | `gau` / `waybackurls` / `katana` | Wayback Machine CDX API via `curl` |
| JS secrets / endpoints | `nuclei -tags exposure` + JS grep | `curl` + regex over linked `.js` |
| Screenshots | `gowitness` / `httpx -screenshot` | skipped (needs headless Chromium) |
| Vulnerabilities | `nuclei` | `nmap --script vuln` |

Force a fallback (or work around a shadowed binary name) with
`RECONX_DISABLE="httpx subfinder ..."`.

---

## Artifacts (Osmedeus-style)

Each run creates `recon-<host>-<timestamp>/`:

```
summary.md       human-readable report (counts + top findings)
result.json      machine-readable counts + provenance
subdomains.txt   hosts.txt    ports.txt
web.txt          tech.txt     waf.txt
content.txt      takeover.txt urls.txt
secrets.txt      vulns.txt    screenshots/
```

Stdout prints a compact, delimited block the agent (and `bb-triage`) can parse:

```
===== RECONX SUMMARY (example.com / full) =====
subdomains=7 live_hosts=7 open_ports=0 web=4 waf=4 content=0 takeover=0 urls=0 js_secrets=0 screenshots=0 vulns=0
artifacts: .../recon-example.com-<ts>  (summary.md, result.json + per-phase .txt)
--- web (sample) ---
https://example.com
...
===== END RECONX SUMMARY =====
```

---

## Installation

`reconx` ships in the repo at [`recon/reconx`](../recon/reconx) and is installed
to `/usr/local/bin/reconx` by the Dockerfile. The modern toolset is installed by
[`scripts/install-recon-tools.sh`](../scripts/install-recon-tools.sh)
(ProjectDiscovery suite + ffuf + assetfinder; `whatweb`/`dirb`/`libpcap` via apt).

Rebuild the container to pick it up:

```bash
docker compose build
```

Skip the heavy Go installs (keep only fallbacks) with a build arg:

```bash
docker compose build --build-arg RECONX_SKIP_TOOLS=1
```

Outside Docker, just run it directly: `bash recon/reconx --target <t>`.

---

## How the agent uses it

The stage prompts ([`pentestgpt/prompts/stages.py`](../pentestgpt/prompts/stages.py))
tell the GLM agent that `reconx` is its **primary** recon tool and to start with
`--mode flyover`/`recon`, read the `RECONX SUMMARY`, then `cat`/`grep` specific
artifact files for detail — instead of dumping whole files into its reasoning and
burning the token budget.

Example agent step (ReAct JSON it emits):

```json
{"thought": "map the surface first", "action": "bash",
 "command": "reconx --target https://target.example --mode recon"}
```

---

## Authorized use only

`reconx` performs active scanning (port scans, content discovery, vuln checks).
Only run it against targets you are explicitly authorized to test. You own scope.

---

## Testing

```bash
uv run pytest tests/unit/test_reconx.py -v
```

Covers existence, `bash -n` syntax, help/usage/error exit codes, a localhost-only
fallback run that produces valid `result.json`, and that the agent prompts
advertise `reconx`.
