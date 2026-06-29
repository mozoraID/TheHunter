# bb-triage — autonomous hunt + triage

Two pieces work together inside the container (`docker compose run --rm pentestgpt`):

1. **`instruction.sh`** — generates the autonomous BugBunny-style instruction that
   PentestGPT runs (recon → scan → exploit → validate, strict scope, verified-only
   findings, platform-correct attribution header).
2. **`run_triage.sh`** — the existing 4-stage triage pipeline (auto-detects program +
   scope, so it can be called with just the logfile).

## instruction.sh

```
/workspace/bb-triage/instruction.sh <platform> <username> <scope_pattern>
```

- `<platform>` — `intigriti` | `hackerone` | `bugcrowd` | `hackenproof` |
  `yeswehack` | `bugrap` | `immunefi` | … (unknown platforms get a generic
  `X-Bug-Bounty-Researcher` header).
- `<username>` — your researcher handle; embedded in the attribution header.
- `<scope_pattern>` — e.g. `*.myfone.dk` (same grammar run_triage.sh understands).

It prints the full instruction to stdout. Example:

```bash
/workspace/bb-triage/instruction.sh intigriti ijusthunter "*.myfone.dk"
```

## One-line hunt + triage (your workflow)

Use the **`bb`** wrapper (`/workspace/bb`) — it runs `pentestgpt --mode pentest
--no-telemetry "$@"` and saves a timestamped log to `/workspace/scan-<ts>.log`.
The bare `pentestgpt` binary does **not** accept `--workspace`; `bb` owns the
workspace/log handling and passes `--target` / `--instruction` straight through.

```bash
bb --target https://partners.zellepay.com --mode pentest --no-telemetry \
  --instruction "$(/workspace/bb-triage/instruction.sh hackerone ijusthunter '*.zellepay.com')" \
&& /workspace/bb-triage/run_triage.sh $(ls -t /workspace/scan-*.log | head -1)
```

> `bb` already injects `--mode pentest --no-telemetry`, so passing them again is
> redundant (harmless — last value wins) and can be dropped:
>
> ```bash
> bb --target https://partners.zellepay.com \
>   --instruction "$(/workspace/bb-triage/instruction.sh hackerone ijusthunter '*.zellepay.com')" \
> && /workspace/bb-triage/run_triage.sh $(ls -t /workspace/scan-*.log | head -1)
> ```

## Optional convenience alias

Drop this into the container shell (e.g. paste it once per session, or add it to
`~/.bashrc` inside the container) so you don't retype the long instruction:

```bash
bbhunt() {
  bb --target "$1" \
    --instruction "$(/workspace/bb-triage/instruction.sh "${2:-intigriti}" ijusthunter "${3:-*.$(echo $1 | sed -E 's#https?://([^/]*\.)?([^./]+\.[^./]+).*#\2#')}")" \
  && /workspace/bb-triage/run_triage.sh $(ls -t /workspace/scan-*.log | head -1)
}
```

Then just:

```bash
bbhunt https://api.myfone.dk intigriti "*.myfone.dk"
```

- `$2` (platform) defaults to `intigriti`.
- `$3` (scope) defaults to `*.<apex>` derived from the target URL.
- Replace `ijusthunter` with your own handle.

## Triage / verify discipline (zero false positives)

The pipeline is tuned so public, by-design artifacts never reach the ACTIONABLE
bucket, while real-impact classes are never auto-dropped:

- **Missing security headers** (X-XSS-Protection, Permissions-Policy, CSP, HSTS,
  X-Content-Type-Options, Referrer-Policy, COOP/COEP/CORP) are `OUT_OF_SCOPE`
  for generic/HackerOne programs — unless the title ties the header to a
  *demonstrated* exploit (e.g. "missing CSP enabling stored XSS at /x with PoC").
- **Public client-side keys** (New Relic NREUM / license key, Stripe `pk_live_`/
  `pk_test_`, Google Maps/Analytics/GTM `AIza…`, Sentry public DSN, Segment write
  key, Firebase web config `apiKey`, Mapbox `pk.`, Datadog client token, …) are
  `OUT_OF_SCOPE` ("public client-side key") and are never counted by
  `verify_findings.py` as "real sensitive data" — even when they ship inside a
  `<script>`/`window.NREUM` blob on a 200 HTML page.
- **Exposed OpenAPI/Swagger schema** stays `REVIEW` but capped at
  Low/Informational unless it embeds a secret or grants unauthenticated data
  access; a 200 schema dump alone is never ACTIONABLE.
- A **200 / 401 / 403 / 405** or a page that merely renders HTML is never
  ACTIONABLE on its own. ACTIONABLE = in-scope **and** content-proven impact
  **and** confidence ≥ MEDIUM. IDOR needs *another* user's data; info-disclosure
  needs a real secret/PII; a source map needs `200 + valid JSON + non-empty
  sourcesContent`.
- Never auto-dropped (even at LOW severity): auth bypass, IDOR/BOLA, privilege
  escalation, SQLi/RCE/SSRF, business-logic flaws, hardcoded real secrets,
  source maps with `sourcesContent`, or anything CVSS ≥ 7.0.

`instruction.sh` also emits **active test procedures** so the agent goes deep:
rate-limit burst testing (10–20 rapid failed-auth requests; "no rate limiting"
only if no `429`/`Retry-After`/`RateLimit-*` ever appears), unauthenticated
schema-endpoint enumeration, and source-map `sourcesContent` validation.
