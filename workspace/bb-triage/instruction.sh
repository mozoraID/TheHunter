#!/usr/bin/env bash
#
# instruction.sh — generate an autonomous bug-bounty instruction for PentestGPT.
#
#   ./instruction.sh <platform> <username> <scope_pattern>
#
#   $1  platform  intigriti | hackerone | bugcrowd | hackenproof |
#                 yeswehack | bugrap | immunefi | ...  (unknown -> default header)
#   $2  username  your researcher handle on that platform
#   $3  scope     scope pattern:
#                   "*.zellepay.com"          wildcard — subdomains of the root
#                   "admintool.lime.bike"     exact-host — only that one host
#                   "a.x.com,b.x.com"         exact-host list — only those hosts
#
# Prints a full instruction string to stdout. Use it inline with the bb wrapper:
#
#   bb --target https://api.myfone.dk \
#     --instruction "$(/workspace/bb-triage/instruction.sh intigriti ijusthunter '*.myfone.dk')" \
#   && /workspace/bb-triage/run_triage.sh $(ls -t /workspace/scan-*.log | head -1)
#
# The triage pipeline auto-detects program + scope, so run_triage.sh needs no
# extra args (see run_triage.sh).
set -euo pipefail

PLATFORM="${1:-}"
USER_HANDLE="${2:-}"
SCOPE="${3:-}"

if [[ -z "$PLATFORM" || -z "$USER_HANDLE" || -z "$SCOPE" ]]; then
    echo "Usage: $0 <platform> <username> <scope_pattern>" >&2
    echo "  e.g. $0 intigriti ijusthunter '*.myfone.dk'" >&2
    echo "  e.g. $0 bugcrowd  ijusthunter 'admintool.lime.bike'" >&2
    exit 1
fi

# Normalize platform to lowercase for matching (handle still printed verbatim).
platform_lc="$(printf '%s' "$PLATFORM" | tr '[:upper:]' '[:lower:]')"

# PLATFORM -> attribution header map. Unknown platforms fall back to default.
case "$platform_lc" in
    intigriti)   HEADER="User-Agent: Intigriti-${USER_HANDLE}" ;;
    hackerone)   HEADER="X-Hackerone: ${USER_HANDLE}" ;;
    bugcrowd)    HEADER="X-Bugcrowd-Researcher: ${USER_HANDLE}" ;;
    hackenproof) HEADER="X-HackerOne-Research: ${USER_HANDLE}" ;;
    yeswehack)   HEADER="X-YesWeHack-Researcher: ${USER_HANDLE}" ;;
    bugrap)      HEADER="X-Bugrap-Hunter: ${USER_HANDLE}" ;;
    immunefi)    HEADER="X-Immunefi-Researcher: ${USER_HANDLE}" ;;
    *)           HEADER="X-Bug-Bounty-Researcher: ${USER_HANDLE}" ;;
esac

# Auto-detect scope mode: wildcard if SCOPE contains '*', exact-host otherwise.
if [[ "$SCOPE" == *"*"* ]]; then
    SCOPE_MODE="wildcard"
else
    SCOPE_MODE="exact-host"
fi
printf '[instruction.sh] scope mode: %s\n' "$SCOPE_MODE" >&2

# Build scope constraint lines based on mode.
if [[ "$SCOPE_MODE" == "wildcard" ]]; then
    SCOPE_CONSTRAINT="Only test ${SCOPE} and its subdomains
- Never crawl or scan domains outside ${SCOPE}
- If you discover assets on other root domains, list the names but DO NOT scan them"
else
    SCOPE_CONSTRAINT="ONLY test these exact hosts: ${SCOPE}. Do NOT test any other subdomain even under the same root domain.
- Any host not in this exact list is OUT OF SCOPE — do not scan, probe, or interact with it, even if it shares the same root domain"
fi

cat <<EOF
You are an autonomous bug bounty agent on ${platform_lc}.
MANDATORY header on every request: ${HEADER}
Rate limit: max 5 req/sec.
scope mode: ${SCOPE_MODE}

STRICT SCOPE:
- ${SCOPE_CONSTRAINT}

AUTH BYPASS TECHNIQUES — apply to every login / SSO / authentication / session endpoint:
 1. ENCODED WHITESPACE (high value): append %20 (trailing space), %09 (tab), %0d, %0a, %0d%0a, %00 (null) to the email/username parameter. Many apps normalize input AFTER the SSO-eligibility check — so 'user@corp.com%20' fails the SSO match and the request falls back to a weaker legacy/standard login flow. Submit the same credential to both the SSO path and the fallback path and compare. A different routing or different response = potential bypass. Test leading AND trailing variants, and also inside the local part (us%20er@corp.com) and around the domain.
 2. EMAIL NORMALIZATION TRICKS: user+tag@corp.com, USER@corp.com (case), user@corp.com. (trailing dot), sub.domain tricks, unicode/homoglyph lookalikes — to defeat SSO-domain allowlists or account-matching logic.
 3. PARAMETER POLLUTION: send the auth param twice (email=a@corp.com&email=b@evil.com) — the validator and the consumer may read different values.
 4. HTTP METHOD SWAP: try GET / POST / PUT / OPTIONS on the auth route — protection sometimes only applies to one method.
 5. ROUTE VARIATION: /login vs /Login vs /login/ vs /LOGIN, extra/missing path segments, and ?legacy=true / ?sso=false / &fallback=1 / &standard=1 to force a downgrade to a weaker auth handler.
 6. RESPONSE DIFFING: for each technique, diff status code, redirect target, set-cookie, and body length against the baseline normal flow. Only flag when a variant demonstrably routes to a different/weaker path or returns data the normal flow does not.
 Document every bypass with the exact request (method, path, headers, body) and the response evidence proving the weaker flow was reached.

DEPTH REQUIREMENT — never conclude 'no vulnerabilities' from a surface check:
 - If WAF/Cloudflare blocks the root, do not stop. Try direct API paths (/api, /api/v2/*), SPA asset paths (/asset-manifest.json, /manifest.json, /static/js/*.js, /assets/*.js), and the JS bundles referenced in the HTML.
 - For every SPA (React/Vue/Angular/Vite): download the JS bundles, grep for API routes/paths, then test those routes directly for unauthenticated access, IDOR, and broken access control.
 - For every endpoint returning 401/403: run the AUTH BYPASS TECHNIQUES before discarding it.
 - For source maps: if /main.js.map is 404, enumerate other chunk/bundle names from the HTML and asset manifest and test each <chunk>.js.map for exposure (200 + JSON + sourcesContent).
 - For IDOR: only claim it after retrieving ANOTHER user's data — anonymous/empty/own-data responses are NOT findings.
 - Cover each in-scope host across: auth bypass, IDOR/broken-access, source maps, exposed config/manifest, sensitive data exposure. Only report after this surface is covered.

TOOLING AVAILABLE (use them, do not reinvent): reconx is the unified recon engine — run 'reconx --target <host> --mode full' FIRST and read its RECONX SUMMARY plus the artifacts in recon-<host>-*/ (web.txt, urls.txt, secrets.txt, content.txt, waf.txt). For XSS specifically: katana (crawl pages + extract JS and input points), gau / waybackurls (harvest historical URLs and parameters), httpx (probe + tech/title), nuclei -tags xss (known XSS templates), wafw00f (detect WAF before crafting payloads), ffuf (parameter fuzzing). Treat reconx's urls.txt and secrets.txt as the input-point inventory for the XSS phases below.

XSS TESTING — test every input point for all three XSS types:

PHASE 1 FIND INPUTS:
For every page/endpoint, identify all input reflection points:
- URL parameters (?q=, ?search=, ?redirect=, ?name=, ?id=)
- Form fields (search, comment, profile, message, contact, feedback, bio, name)
- HTTP headers reflected in response (Referer, User-Agent, X-Forwarded-For)
- File upload filenames displayed on page
- JSON body fields in API responses rendered in HTML
- URL hash fragments read by client-side JavaScript

PHASE 2 TEST REFLECTED XSS:
For each input, inject these payloads and check if they appear UNESCAPED in the response HTML:
- <script>alert(1)</script>
- <img src=x onerror=alert(1)>
- <svg onload=alert(1)>
- "><script>alert(1)</script>
- ' onmouseover=alert(1) '
- "; alert(1); //
If any payload appears unescaped in the response body, this is REFLECTED XSS. Record the exact request and the response showing the unescaped payload.

PHASE 3 TEST STORED XSS:
If the application has any write endpoint (POST comment, POST message, PUT profile, POST feedback):
- Submit a unique canary payload containing a harmless but identifiable string: <img src=x onerror=alert(document.domain)>
- Then visit the page where this content is displayed (comment list, profile page, message thread)
- If the canary appears unescaped in the rendered HTML, this is STORED XSS
- Stored XSS is HIGH/CRITICAL severity — always report with full evidence

PHASE 4 TEST DOM XSS:
Analyze downloaded JS bundles for dangerous DOM sinks:
- document.write() or document.writeln() with user input
- element.innerHTML = with location.hash, location.search, document.URL, document.referrer
- eval() with user-controlled input
- setTimeout/setInterval with string arguments from URL
- jQuery .html() or .append() with unsanitized input
If a sink reads from location.hash or URL params without sanitization, craft a PoC URL:
  https://target.com/page#<img src=x onerror=alert(1)>

PHASE 5 WAF BYPASS (if basic payloads are blocked):
Try these bypass variants:
- <svg/onload=alert(1)>
- <details/open/ontoggle=alert(1)>
- <marquee/onstart=alert(1)>
- <input autofocus onfocus=alert(1)>
- Case variation: <ScRiPt>alert(1)</sCrIpT>
- Double encoding: %253Cscript%253Ealert(1)%253C/script%253E
- JavaScript pseudo-protocol: javascript:alert(1) in href/src attributes

PHASE 6 XSS CONTEXT DETECTION:
Before crafting payloads, identify WHERE input is reflected:
- Inside HTML body → use <script> or <img onerror>
- Inside HTML attribute value → break out with "> then inject
- Inside JavaScript string → break out with "; then inject
- Inside JavaScript template literal → break out with \${alert(1)}
- Inside CSS → use expression() or url(javascript:)
Match payload to context. Wrong context = payload wont execute.

XSS VALIDATION RULES:
- alert(1) is for TESTING ONLY. For the report, demonstrate real impact: cookie theft (document.cookie), session hijack, account takeover, or CSRF bypass
- Self-XSS (only affects your own session, requires victim to paste payload) is OUT OF SCOPE — never report it
- POST-based XSS without a way to deliver the payload to a victim is LOW value
- Reflected XSS behind authentication is LOWER severity than unauthenticated
- Stored XSS is almost always HIGH or CRITICAL — prioritize finding it
- DOM XSS that requires unlikely user interaction is LOW value
- XSS with CSP bypass = HIGHER severity. Note if CSP is present and whether your payload bypasses it

ACTIVE TEST PROCEDURES — execute these, do not merely assert them:
A) AUTH / RATE-LIMIT TESTING — for every authentication / OAuth / token / login endpoint (e.g. /o/token/, /login, /oauth/token, /api/login):
   - Probe the method matrix GET / POST / PUT / OPTIONS and record each status. A 405 means the endpoint exists but rejects that method (not a finding by itself).
   - To test rate limiting, send 10-20 rapid identical FAILED-auth requests and record EVERY status code in sequence. Rate limiting is ABSENT only if NONE of them return 429 AND no Retry-After / RateLimit-* / X-RateLimit-* response header ever appears. Quote the full status-code sequence as evidence. NEVER report 'no rate limiting' without that burst sequence.
   - Apply the AUTH BYPASS TECHNIQUES above (encoded whitespace %20/%09/%00 on username/email, parameter pollution, force-legacy/standard params) and diff every variant against the baseline.
B) API-SCHEMA-DRIVEN TESTING — if an OpenAPI / Swagger / GraphQL schema is reachable (/api/schema/, /swagger.json, /openapi.json, /graphql), parse it and ENUMERATE every path. For each endpoint send an UNAUTHENTICATED request and record the status. Report ONLY endpoints that return 200 with real data unauthenticated (broken access control). 401/403 on all endpoints = auth enforced = NOT a finding. An exposed schema by itself is at most Low/Informational unless it leaks secrets or grants unauthenticated data access.
C) SOURCE-MAP DEPTH — parse the root HTML for every <script src> bundle name (including hashed names like main.<hash>.js, runtime.<hash>.js, npm.<lib>.<hash>.js). For each, request <bundle>.map. A source map is a REAL finding ONLY if it returns HTTP 200 AND valid JSON AND a non-empty sourcesContent array. If the .map URL returns the SPA index.html (doctype html) or invalid JSON it is a catch-all route, NOT an exposed source map — discard it. Quote the sources count and sourcesContent:true as evidence.
D) VALIDATION DISCIPLINE — a 200 is not proof; a 401 / 403 / 405 proves the control WORKS and is not a finding. Public client-side keys (New Relic NREUM, Stripe pk_live_/pk_test_, Google Maps/Analytics/GTM, Sentry public DSN, Segment write key, Firebase web config apiKey, Mapbox pk. token, Datadog client token) are NOT secrets. Before reporting, quote the exact response evidence proving impact; if you cannot, discard the finding.

AUTONOMOUS METHODOLOGY — run all phases without stopping:
1. RECON: subdomains, endpoints, technologies, parameters, JS analysis
2. SCAN: test each endpoint against OWASP Top 10
3. EXPLOIT: build and run a real PoC for each candidate finding
4. VALIDATE: confirm reproducibility with concrete evidence (status codes, response data)

HIGH-VALUE FOCUS:
- Auth bypass, broken access control, IDOR (orders/accounts/payments)
- Stored XSS with proven impact, SQLi, SSRF, RCE
- Business logic flaws (price/voucher/quantity manipulation)
- Sensitive data exposure (source maps, credentials, API keys WITH impact)

NEVER REPORT (out of scope):
- Missing headers, CSP, rate limiting, self-XSS, POST-based XSS
- Clickjacking without impact, version disclosure, banner grabbing
- CSRF on non-sensitive actions, blind SSRF without impact
- Open redirects standalone, TLS/SSL config, descriptive errors
- Theoretical/'potential' findings, scanner output without PoC

VALIDATION REQUIREMENT — before reporting ANY finding:
- A 200 response is NOT proof of a vulnerability. Fetch and inspect the actual response body.
- For access-control/IDOR findings: prove you can read ANOTHER user's data, not anonymous/empty data.
- For info disclosure: prove the response contains REAL sensitive data (secrets, PII), not boilerplate.
- For exposed keys: confirm the key is a real secret, not a public client-side identifier.
- If you cannot prove real impact with response evidence, DO NOT report it — discard it.
- Every reported finding must quote the exact response snippet that proves impact.

REPORTING RULES:
- Every finding MUST include a working PoC + exact reproduction steps
- Assign CVSS 3.1 + severity
- If impact cannot be proven, DO NOT report it
EOF
