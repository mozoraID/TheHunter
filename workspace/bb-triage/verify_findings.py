#!/usr/bin/env python3
"""verify_findings.py — prove (or disprove) findings with a live HTTP check.

``bb_triage.py`` marks a finding REVIEW purely from the *text* of the report,
so things that read like real issues but aren't accessible slipped through and
we burned time hand-verifying them:

    trace.axd      → 403 (exists but forbidden) — not actually disclosing
    HTTP TRACE     → 501 (not implemented)      — "advertised but blocked"
    Source Maps    → 200 + 9MB + sourcesContent — genuinely exposed ✓
    SameSite/CSRF  → load-balancer cookie nit   — no URL to prove

This stage curls each REVIEW / NEEDS_POC finding's PoC URL(s) and applies a
finding-type-specific check on the actual RESPONSE BODY (a 200 alone is never
enough), then tags the finding with a status and a confidence:

  VERIFIED     the live response *body* proves the finding with at least MEDIUM
               confidence — e.g. a source map is 200 + valid JSON + has
               ``sourcesContent``; an info-disclosure body carries a real secret
               or PII; an IDOR returns non-anonymous data.
  UNVERIFIED   the live response contradicts it OR a 200 carries no content
               proof: anonymous/empty data (no IDOR), an auth-error body under a
               200 wrapper (auth enforced), a public client-side key (by design),
               a boilerplate file (no secret), 403/404/501, or no testable URL.

Each verification carries a ``confidence`` (HIGH = real impact proven, MEDIUM =
suspicious / needs a manual look, LOW = likely false positive) and quotes the
relevant body snippet as evidence. Only VERIFIED findings with confidence
>= MEDIUM reach the ACTIONABLE bucket in summary.py — never a status code alone.

Requests use ``User-Agent: Intigriti-ijusthunter`` and are throttled to at
most 5 requests/second. Only in-scope hosts are ever contacted — a
WRONG_SCOPE finding is left untouched (``SKIPPED``) so verification never
re-introduces scope drift.

Usage
-----
    verify_findings.py --in scan_triage_scoped.json
    verify_findings.py --in scan_triage.json --scope "*.myfone.dk" --out v.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, unquote, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bb_triage import C  # noqa: E402
from scope_check import host_in_scope, host_matches, parse_scope  # noqa: E402

USER_AGENT = "Intigriti-ijusthunter"
MAX_RPS = 5.0                      # rate limit ceiling
MIN_INTERVAL = 1.0 / MAX_RPS       # >= 0.2s between any two requests
DEFAULT_TIMEOUT = 12
MAX_BODY = 50 * 1024 * 1024        # cap source-map reads at 50MB

VERIFY_COLOR = {
    "VERIFIED": C.GREEN,
    "UNVERIFIED": C.YELLOW,
    "SKIPPED": C.GREY,
}


# --------------------------------------------------------------------------- #
# HTTP (stdlib, rate-limited, TLS-permissive like `curl -k`)
# --------------------------------------------------------------------------- #


class Http:
    """Tiny rate-limited HTTP client returning (status, body_bytes, error)."""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT) -> None:
        self.timeout = timeout
        self._last = 0.0
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    def _throttle(self) -> None:
        wait = MIN_INTERVAL - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

    def request(self, url: str, method: str = "GET", read_body: bool = False):
        """Return (status:int|None, body:bytes, error:str). status None on failure."""
        self._throttle()
        req = urllib.request.Request(url, method=method)
        req.add_header("User-Agent", USER_AGENT)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                body = resp.read(MAX_BODY) if read_body else b""
                return resp.status, body, ""
        except urllib.error.HTTPError as e:
            # 4xx/5xx still carry a status we want to inspect.
            body = b""
            if read_body:
                try:
                    body = e.read(MAX_BODY)
                except Exception:
                    pass
            return e.code, body, ""
        except urllib.error.URLError as e:
            return None, b"", f"request failed: {e.reason}"
        except Exception as e:  # noqa: BLE001 — surface any transport error as reason
            return None, b"", f"request failed: {e}"


# --------------------------------------------------------------------------- #
# Finding-type classification + per-type checks
# --------------------------------------------------------------------------- #

_AXD_RE = re.compile(r"\b(trace|elmah|glimpse)\.axd\b", re.IGNORECASE)

# --- Content-proof detectors (a 200 alone is never enough) ----------------- #

# Body markers that mean the response is NOT another user's data: an anonymous /
# guest / empty / placeholder payload. Seen e.g. on Dyson's
# /esi/1.0/gb/user/?lang=en -> {"credentialID":"anonymous", ...}.
_ANON_RE = re.compile(
    r"\"?credential[_-]?id\"?\s*[:=]\s*\"?\s*anonymous"
    r"|\banonymous\b|\bguest\b|not\s+logged\s*in|\bunauthenticated\b"
    r"|\"user(name|id)?\"\s*:\s*(null|\"\")|\"data\"\s*:\s*(null|\[\]|\{\})",
    re.IGNORECASE,
)

# Body markers that mean authentication is properly enforced even under a 200
# wrapper (some gateways return 200 with an auth-error JSON body).
_AUTH_FAIL_RE = re.compile(
    r"failed\s+to\s+authenticate|authentication\s+(failed|required)"
    r"|\bunauthorized\b|\bforbidden\b|access\s+denied|invalid\s+(token|credentials|api[\s_-]*key)"
    r"|not\s+authenticated|please\s+log\s*in"
    r"|\"(error|message|status)\"\s*:\s*\"?(unauthorized|forbidden|authentication|access\s+denied)"
    r"|\"(status|code)\"\s*:\s*\"?(401|403)\b",
    re.IGNORECASE,
)

# A REAL secret: high-entropy/structured credentials whose exposure is impactful.
_SECRET_RE = re.compile(
    r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----"
    r"|\bAKIA[0-9A-Z]{16}\b"                              # AWS access key id
    r"|\bASIA[0-9A-Z]{16}\b"                              # AWS temp key id
    r"|\bsk_(?:live|test)_[0-9A-Za-z]{10,}"               # Stripe SECRET key
    r"|\bgh[pousr]_[0-9A-Za-z]{20,}"                      # GitHub token
    r"|\bxox[baprs]-[0-9A-Za-z-]{10,}"                    # Slack token
    r"|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}"  # JWT
    r"|(?:client[_-]?secret|api[_-]?secret|private[_-]?key|secret[_-]?key"
    r"|access[_-]?token|aws[_-]?secret|db[_-]?password|password|passwd)"
    r"\s*[\"':=]+\s*[\"']?[^\s\"'<>,{}]{6,}",
    re.IGNORECASE,
)

# A PUBLIC, client-side identifier that LOOKS like a key but is meant to ship in
# the browser — exposing it is by design, not a vulnerability.
_PUBLIC_KEY_RE = re.compile(
    r"nreum|newrelic|new\s*relic|licensekey|applicationid"   # New Relic browser agent
    r"|aizasy[0-9A-Za-z_-]{10,}|maps\.googleapis|google\s*maps"  # Google Maps browser key
    r"|recaptcha|sitekey|data-sitekey"                      # reCAPTCHA site key
    r"|\bpk_(?:live|test)_|publishable[_-]?key"             # Stripe PUBLISHABLE key
    r"|gtm-[0-9a-z]+|googletagmanager|ua-\d{4,}-\d"         # GA / GTM ids
    r"|intercom|segmentwritekey|ingest\.sentry|sentry.*public",
    re.IGNORECASE,
)

# Extra PII / sensitive-field markers for info-disclosure bodies.
_PII_RE = re.compile(
    r"\"(password|token|secret|api[_-]?key|access[_-]?token|credit[_-]?card"
    r"|card[_-]?number|cvv|ssn|iban|tax[_-]?id|date[_-]?of[_-]?birth)\"\s*:"
    r"|\b\d{3}-\d{2}-\d{4}\b"                               # US SSN
    r"|-----BEGIN\b",
    re.IGNORECASE,
)

# Boilerplate files that are 200 but carry no secret (Drupal CHANGELOG without a
# version line, an empty/standard robots.txt, a default page).
_BOILERPLATE_RE = re.compile(
    r"drupal\.org/project|gnu\s+general\s+public\s+license"
    r"|this\s+is\s+a\s+default\s+|apache2?\s+default\s+page",
    re.IGNORECASE,
)


# --------------------------------------------------------------------------- #
# Hardened content-proof helpers
# --------------------------------------------------------------------------- #
# These override / supplement the narrower detectors above so that public
# client-side keys, login forms (<input type="password">), JS source
# ("password"===t.type), OpenAPI schemas, and plain HTML pages are NEVER counted
# as "real sensitive data". A 200 that merely renders HTML proves nothing.

# Expanded public/browser key denylist — ships in the browser BY DESIGN, so its
# presence is never evidence of impact. (Overrides the narrower one above.)
_PUBLIC_KEY_RE = re.compile(
    r"nreum|newrelic|new\s*relic|nr-data\.net|js-agent\.newrelic|licensekey|applicationid"
    r"|aiza[0-9a-z_-]{10,}|maps\.googleapis|google\s*maps|googletagmanager|gtm-[0-9a-z]+"
    r"|\bua-\d{4,}-\d|\bg-[a-z0-9]{8,}\b|google[\s-]*analytics"
    r"|recaptcha|sitekey|data-sitekey"
    r"|\bpk_(?:live|test)_[0-9a-z]+|publishable[_-]?key"
    r"|\bpk\.[a-z0-9]{20,}|mapbox"
    r"|ingest\.sentry|sentry[_-]?dsn|sentry.*public|public.*dsn"
    r"|segment(?:write)?key|cdn\.segment"
    r"|statsig|client-[a-z0-9]{24,}"
    r"|pub[0-9a-f]{32}|datadoghq|dd[_-]?client[_-]?token|client[_-]?token"
    r"|amplitude|firebaseapp\.com|firebaseio\.com|messagingsenderid|measurementid"
    r"|intercom|hotjar|mixpanel|fullstory",
    re.IGNORECASE,
)

# Unambiguous, structured secrets — real regardless of surrounding text.
_STRUCTURED_SECRET_RE = re.compile(
    r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----"
    r"|\bAKIA[0-9A-Z]{16}\b|\bASIA[0-9A-Z]{16}\b"
    r"|\bsk_(?:live|test)_[0-9A-Za-z]{16,}"
    r"|\bgh[pousr]_[0-9A-Za-z]{30,}"
    r"|\bxox[baprs]-[0-9A-Za-z-]{20,}"
    r"|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    re.IGNORECASE,
)

# A named secret assigned a real, quoted, key-shaped value. Does NOT match the
# bare word "password" in a login form or JS source — it needs `name:"value12+"`.
_ASSIGNED_SECRET_RE = re.compile(
    r"(?:client[_-]?secret|api[_-]?secret|secret[_-]?key|private[_-]?key"
    r"|aws[_-]?secret(?:[_-]?access[_-]?key)?|db[_-]?password|database[_-]?password"
    r"|refresh[_-]?token|access[_-]?token|bearer[_-]?token|auth[_-]?token)"
    r"[\"']?\s*[:=]\s*[\"'][A-Za-z0-9+/_=.\-]{12,}[\"']",
    re.IGNORECASE,
)

# Real PII/credential as a JSON field with a non-trivial value. The trailing
# :"value" is what makes this safe against HTML attributes like type="password".
_PII_FIELD_RE = re.compile(
    r"[\"'](?:password|passwd|token|secret|api[_-]?key|access[_-]?token|refresh[_-]?token"
    r"|credit[_-]?card|card[_-]?number|cvv|ssn|iban|tax[_-]?id|social[_-]?security"
    r"|date[_-]?of[_-]?birth|dob)[\"']\s*:\s*[\"'][^\"']{4,}[\"']",
    re.IGNORECASE,
)
_DIRECT_PII_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b|-----BEGIN\b")

# Missing-header findings: out-of-scope by category unless tied to a real exploit.
_MISSING_HEADER_RE = re.compile(
    r"missing\s+(?:security\s+)?header|security\s+header"
    r"|x[\s-]*xss[\s-]*protection|permissions[\s-]*policy"
    r"|content[\s-]*security[\s-]*policy|\bcsp\b|\bhsts\b|strict[\s-]*transport"
    r"|x[\s-]*content[\s-]*type[\s-]*options|referrer[\s-]*policy"
    r"|x[\s-]*frame[\s-]*options|cross[\s-]*origin[\s-]*(?:opener|embedder|resource)[\s-]*policy",
    re.IGNORECASE,
)
_HEADER_EXPLOIT_RE = re.compile(
    r"stored\s+xss|reflected\s+xss|enabl\w*\s+(?:stored\s+|reflected\s+)?xss"
    r"|script\s+inject|csp\s+bypass|clickjack\w*\s+(?:poc|exploit)|account\s+takeover"
    r"|with\s+(?:a\s+)?poc|demonstrated\s+exploit",
    re.IGNORECASE,
)


def _ctx_is_public(text: str, m) -> bool:
    """True when a secret-looking match sits next to a known public-key marker."""
    window = text[max(0, m.start() - 100): m.end() + 100]
    return bool(_PUBLIC_KEY_RE.search(window))


def _has_real_secret(text: str) -> bool:
    """A genuine secret is present — not a public client-side key, not a login
    form / JS word. Public-key context disqualifies an otherwise-matching token."""
    for rx in (_STRUCTURED_SECRET_RE, _ASSIGNED_SECRET_RE):
        for m in rx.finditer(text):
            if not _ctx_is_public(text, m):
                return True
    return False


def _has_real_pii(text: str) -> bool:
    for m in _PII_FIELD_RE.finditer(text):
        if not _ctx_is_public(text, m):
            return True
    return bool(_DIRECT_PII_RE.search(text))


def _is_schema_body(text: str) -> bool:
    """The body is an OpenAPI/Swagger schema (an endpoint catalogue)."""
    head = text[:4000].lower()
    if re.search(r"[\"']?openapi[\"']?\s*[:=]\s*[\"']?3", head):
        return True
    if re.search(r"[\"']?swagger[\"']?\s*[:=]\s*[\"']?2", head):
        return True
    return "openapi" in head and "paths" in head


def _is_html_document(body: bytes) -> bool:
    head = body[:512].lstrip().lower()
    return head.startswith(b"<!doctype html") or head.startswith(b"<html")


def classify_type(finding: dict, urls: list[str]) -> str:
    title = (finding.get("title", "") + " " + finding.get("detail", "")).lower()
    blob = title + " " + " ".join(urls).lower()
    if re.search(r"\.map\b", blob) or "source map" in title:
        return "source_map"
    # Missing-header findings are out-of-scope by category: a 200 + HTML body is
    # not an exploit. Only escape if the title ties the header to a demonstrated
    # exploit (stored XSS with PoC, clickjacking PoC, ...).
    if _MISSING_HEADER_RE.search(title) and not _HEADER_EXPLOIT_RE.search(title):
        return "missing_header"
    # XSS findings: route to the dedicated reflection check (after missing_header
    # so a bare "missing X-XSS-Protection header" stays a header nit, not XSS).
    if re.search(r"\bxss\b|cross[\s-]*site[\s-]*scripting|script\s+injection", title):
        return "xss"
    if _AXD_RE.search(blob) or "trace.axd" in title or "elmah" in title:
        return "debug_endpoint"
    # Exposed OpenAPI/Swagger/GraphQL schema is Low/Informational unless it embeds
    # a secret or grants unauth data access — route to the info-disclosure check,
    # not auth/IDOR, so a 200 schema dump is never mistaken for a bypass.
    if (re.search(r"\b(?:openapi|swagger)\b|api\s+schema|swagger\.json|openapi\.json"
                  r"|graphql\s+schema", blob)
            and not re.search(r"bypass|\bidor\b|broken\s+access|unauthenticated\s+access"
                              r"|injection", finding.get("title", "").lower())):
        return "info_disclosure"
    if re.search(r"\bhttp\s+(trace|options|put|delete)\b", title) \
            or re.search(r"\b(trace|options)\s+method\b", title):
        return "http_method"
    # Access-control / IDOR / BOLA: must prove ANOTHER user's data is readable.
    if re.search(r"\bidor\b|\bbola\b|broken\s+access|access\s+control"
                 r"|privilege\s+escalation|unauthor(ized|ised)\s+access"
                 r"|horizontal\s+(priv|access)|insecure\s+direct\s+object", title):
        return "access_control"
    # Exposed credential / API key: must prove the key is a real secret.
    if re.search(r"\bapi\s*key\b|\bsecret\b|\bcredential|\btoken\b|hard[\s-]*coded"
                 r"|exposed\s+key|access\s+key", title):
        return "exposed_key"
    # Auth/login endpoint reachable: must prove auth is actually bypassed.
    if re.search(r"\bauth(entication|orization)?\b|\blogin\b|\bsign[\s-]*in\b"
                 r"|session\s+(fixation|hijack)|jwt|oauth|bypass", title):
        return "auth_endpoint"
    return "info_disclosure"


def _strip_query(url: str) -> str:
    return url.split("?", 1)[0]


def _method_for(finding: dict) -> str:
    t = finding.get("title", "").lower()
    for m in ("trace", "options", "put", "delete"):
        if re.search(rf"\b{m}\b", t):
            return m.upper()
    return "OPTIONS"


def select_urls(ftype: str, urls: list[str]) -> list[str]:
    """Pick the most relevant PoC URL(s) to actually test for this type."""
    if ftype == "source_map":
        maps = [u for u in urls if _strip_query(u).lower().endswith(".map")]
        return maps[:3] or urls[:1]
    if ftype == "debug_endpoint":
        axd = [u for u in urls if _AXD_RE.search(u)]
        return axd[:1] or urls[:1]
    if ftype == "http_method":
        # Test the base origin (method behaviour is host-level).
        u = urls[0]
        p = urlparse(u)
        return [f"{p.scheme}://{p.netloc}/"]
    # access_control / exposed_key / auth_endpoint / info_disclosure: probe the
    # concrete PoC endpoint(s) and inspect their bodies.
    return urls[:2]


# --------------------------------------------------------------------------- #
# Body evidence helpers
# --------------------------------------------------------------------------- #


def _snippet(body: bytes, limit: int = 120) -> str:
    """A single-line, whitespace-collapsed body excerpt for the report."""
    text = body.decode("utf-8", "replace")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def _is_empty_body(body: bytes) -> bool:
    return body.strip() in (b"", b"{}", b"[]", b"null", b'""')


def _fail(url: str, status, reason: str, body: bytes = b"") -> dict:
    """A failed check is always LOW confidence (likely false positive)."""
    return {"url": url, "status": status, "ok": False, "confidence": "LOW",
            "reason": reason, "evidence": _snippet(body) if body else ""}


def _pass(url: str, status, reason: str, confidence: str, body: bytes = b"") -> dict:
    return {"url": url, "status": status, "ok": True, "confidence": confidence,
            "reason": reason, "evidence": _snippet(body) if body else ""}


def check_missing_header(http: Http, url: str) -> dict:
    """Missing-header findings are out-of-scope by category: a 200 + HTML page is
    not an exploit, and these are explicitly OOS on nearly every program. They
    are never verified without a demonstrated attack (handled in triage)."""
    return _fail(url, None, "missing-header finding, no demonstrated exploit")


def check_source_map(http: Http, url: str) -> dict:
    status, body, err = http.request(url, read_body=True)
    if err:
        return _fail(url, None, err)
    if status != 200:
        return _fail(url, status, f"HTTP {status}, not accessible")
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return _fail(url, status, "HTTP 200 but body is not valid JSON (not a source map)", body)
    if not isinstance(data, dict) or "sourcesContent" not in data:
        return _fail(url, status, "valid JSON but no 'sourcesContent' key (source not embedded)", body)
    n = len(data.get("sourcesContent") or [])
    # Real source code embedded and downloadable -> proven impact.
    return _pass(url, status,
                 f"200 + valid source map, sourcesContent has {n} file(s), {len(body)} bytes",
                 "HIGH")


def check_debug_endpoint(http: Http, url: str) -> dict:
    status, body, err = http.request(url, read_body=True)
    if err:
        return _fail(url, None, err)
    if status != 200:
        return _fail(url, status, f"HTTP {status} — not accessible / not disclosing")
    if _is_empty_body(body):
        return _fail(url, status, "HTTP 200 but empty body — nothing disclosed", body)
    text = body.decode("utf-8", "replace").lower()
    # An actual ASP.NET trace / debug page carries recognisable structure.
    if re.search(r"application\s+trace|request\s+details|physical\s+directory"
                 r"|server\s+variables|trace\s+information|stack\s+trace", text):
        return _pass(url, status, "HTTP 200 + debug/trace content present — endpoint disclosing",
                     "HIGH", body)
    return _pass(url, status, "HTTP 200 — endpoint accessible (content not clearly a debug dump)",
                 "MEDIUM", body)


def check_http_method(http: Http, url: str, method: str) -> dict:
    status, _, err = http.request(url, method=method)
    if err:
        return _fail(url, None, err)
    # 200 = handled, 405 = method known but not allowed (still "exists").
    if status in (200, 405):
        return _pass(url, status, f"{method} returns HTTP {status} — method is handled", "MEDIUM")
    return _fail(url, status, f"{method} returns HTTP {status} — method not implemented/available")


def check_access_control(http: Http, url: str) -> dict:
    """IDOR/BOLA: a 200 only counts if the body holds ANOTHER user's data."""
    status, body, err = http.request(url, read_body=True)
    if err:
        return _fail(url, None, err)
    if status != 200:
        return _fail(url, status, f"HTTP {status} — endpoint not reachable, no IDOR")
    if _is_empty_body(body):
        return _fail(url, status, "returns empty data, no IDOR", body)
    if _ANON_RE.search(body.decode("utf-8", "replace")):
        return _fail(url, status, "returns anonymous/empty data, no IDOR", body)
    if _AUTH_FAIL_RE.search(body.decode("utf-8", "replace")):
        return _fail(url, status, "auth properly enforced (error body under 200)", body)
    if _is_html_document(body):
        return _fail(url, status, "returns an HTML page, not another user's data — no IDOR", body)
    # Non-anonymous, non-empty data: suspicious but we cannot prove it belongs to
    # *another* user without a second identity — flag for a manual look (MEDIUM).
    return _pass(url, status,
                 "returns non-anonymous data — confirm it is ANOTHER user's data manually",
                 "MEDIUM", body)


def check_exposed_key(http: Http, url: str) -> dict:
    """Exposed key: a 200 only counts if a REAL secret (not a public id) shows."""
    status, body, err = http.request(url, read_body=True)
    if err:
        return _fail(url, None, err)
    if status != 200:
        return _fail(url, status, f"HTTP {status} — resource not accessible")
    text = body.decode("utf-8", "replace")
    if _has_real_secret(text):
        return _pass(url, status, "real secret/credential present in response", "HIGH", body)
    if _PUBLIC_KEY_RE.search(text):
        return _fail(url, status, "public client-side key, by design", body)
    return _fail(url, status, "no real secret in response (no impactful credential found)", body)


def check_auth_endpoint(http: Http, url: str) -> dict:
    """Auth endpoint: a 200 wrapper around an auth-error body is NOT a bypass."""
    status, body, err = http.request(url, read_body=True)
    if err:
        return _fail(url, None, err)
    if status in (401, 403):
        return _fail(url, status, f"HTTP {status} — auth properly enforced")
    text = body.decode("utf-8", "replace")
    if status == 200 and _AUTH_FAIL_RE.search(text):
        return _fail(url, status, "auth properly enforced (error body under 200)", body)
    if status == 200 and _is_html_document(body):
        return _fail(url, status, "returns an HTML page, not authenticated data — no bypass", body)
    if status == 200 and not _is_empty_body(body) and not _ANON_RE.search(text):
        return _pass(url, status,
                     "HTTP 200 with non-anonymous data — confirm protected access manually",
                     "MEDIUM", body)
    return _fail(url, status, "no proof of auth bypass (anonymous/empty/blocked)", body)


def check_info(http: Http, url: str) -> dict:
    """Info disclosure: a 200 only counts if the body holds REAL sensitive data."""
    status, body, err = http.request(url, read_body=True)
    if err:
        return _fail(url, None, err)
    if status != 200:
        return _fail(url, status, f"HTTP {status} — not accessible")
    if _is_empty_body(body):
        return _fail(url, status, "HTTP 200 but empty body — nothing disclosed", body)
    text = body.decode("utf-8", "replace")
    # An OpenAPI/Swagger schema listing endpoint names is Low/Informational unless
    # it actually embeds a real secret — never sensitive just for existing.
    if _is_schema_body(text):
        if _has_real_secret(text):
            return _pass(url, status, "schema embeds a real secret/credential", "HIGH", body)
        return _fail(url, status,
                     "OpenAPI/Swagger schema lists endpoint names only — "
                     "Low/Informational, no secret or unauth data access", body)
    if _has_real_secret(text) or _has_real_pii(text):
        return _pass(url, status, "real sensitive data (secret/PII) present in response", "HIGH", body)
    if _PUBLIC_KEY_RE.search(text):
        return _fail(url, status, "only public client-side key(s) present — by design, not sensitive", body)
    if _is_html_document(body):
        return _fail(url, status, "renders an HTML page — no real sensitive data disclosed", body)
    if _BOILERPLATE_RE.search(text):
        return _fail(url, status, "no sensitive data in response (generic/boilerplate file)", body)
    return _fail(url, status, "no sensitive data in response", body)


# A payload "looks like XSS" if it opens a dangerous tag, sets an inline event
# handler, or uses the javascript: pseudo-protocol.
_XSS_TOKEN_RE = re.compile(
    r"<\s*(?:script|svg|img|iframe|details|marquee|input|body|video|audio|a)\b"
    r"|on(?:error|load|mouseover|focus|toggle|start|click)\s*="
    r"|javascript:",
    re.IGNORECASE,
)


def _html_encode(s: str) -> str:
    """The standard HTML-entity encoding a safe template would apply."""
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


def _xss_payloads_from_url(url: str) -> list[str]:
    """Injected XSS payload(s) carried by the PoC URL (query values + #fragment)."""
    parts = urlparse(url)
    raw: list[str] = [v for _k, v in parse_qsl(parts.query, keep_blank_values=True)]
    if parts.fragment:
        raw.append(unquote(parts.fragment))
    return [v for v in raw if v and _XSS_TOKEN_RE.search(v)]


def check_xss(http: Http, url: str) -> dict:
    """Reflected / DOM XSS: prove the injected payload is reflected UNESCAPED.

    HIGH      the exact payload appears verbatim (unescaped) in the response body
    MEDIUM    the input is reflected but only partially encoded (manual review)
    UNVERIFIED (LOW) payload is fully HTML-encoded, not reflected, or no inline
              payload to test (stored/blind XSS needs a manual canary check)
    """
    payloads = _xss_payloads_from_url(url)
    status, body, err = http.request(url, read_body=True)
    if err:
        return _fail(url, None, err)
    if status is None:
        return _fail(url, status, "no response from PoC URL")
    text = body.decode("utf-8", "replace")
    low = text.lower()

    if not payloads:
        # Stored/blind XSS PoC URLs carry no inline payload to reflect here.
        return _fail(url, status,
                     "no inline XSS payload in PoC URL (stored/blind) — "
                     "verify canary on the display page manually", body)

    # HIGH — exact injected payload reflected unescaped == executable.
    for p in payloads:
        if p in text:
            return _pass(url, status,
                         "injected XSS payload reflected UNESCAPED in response body — exploitable",
                         "HIGH", body)
    # UNVERIFIED — payload reflected but fully HTML-encoded (&lt;..&gt;) == safe.
    for p in payloads:
        enc = _html_encode(p)
        if enc in text or enc.lower() in low:
            return _fail(url, status,
                         "payload reflected but HTML-encoded (&lt;..&gt;) — not exploitable", body)
    # MEDIUM — input reflected with partial encoding (e.g. quotes differ).
    for p in payloads:
        no_quotes = p.replace('"', "").replace("'", "")
        if no_quotes and no_quotes in text:
            return _pass(url, status,
                         "input reflected with partial encoding (quotes/escapes differ) — "
                         "manual XSS review", "MEDIUM", body)
        alnum = re.sub(r"[^a-zA-Z0-9]", "", p)
        if len(alnum) >= 6 and alnum.lower() in re.sub(r"[^a-zA-Z0-9]", "", low):
            return _pass(url, status,
                         "user input reflected (encoding inconclusive) — manual XSS review",
                         "MEDIUM", body)
    # Not reflected at all.
    return _fail(url, status, "XSS payload not reflected in response — unverified", body)


# --------------------------------------------------------------------------- #
# Per-finding verification
# --------------------------------------------------------------------------- #


def _primary_host(finding: dict, patterns: list[str]) -> str:
    """The finding's primary affected host, taken from its ``hosts`` field.

    ``bb_triage`` populates ``hosts`` from the finding's target/host field
    (falling back to the report body) precisely so the affected asset is not
    confused with hosts mentioned only in passing. We honour that here and
    never fall back to PoC-URL hostnames — those may point at a different
    domain (e.g. a JS file) than the one the finding is actually about.
    """
    for h in finding.get("hosts", []) or []:
        h = (h or "").strip().lower().rstrip(".")
        if h and (not patterns or host_in_scope(h, patterns)):
            return h
    return ""


def verify_finding(http: Http, finding: dict, patterns: list[str]) -> dict:
    # Only auto-verify actionable findings; leave OUT_OF_SCOPE / SKIP alone.
    if finding.get("verdict") not in ("REVIEW", "NEEDS_POC"):
        return {"status": "SKIPPED", "confidence": "LOW",
                "reason": f"verdict {finding.get('verdict')} — not auto-verified",
                "checks": []}
    # Never contact out-of-scope hosts from the verifier.
    if finding.get("scope") == "WRONG_SCOPE":
        return {"status": "SKIPPED", "confidence": "LOW",
                "reason": "WRONG_SCOPE — not contacted", "checks": []}

    urls = finding.get("poc_urls", []) or []
    # Keep only http(s) URLs on in-scope, concrete hosts (drop shell vars etc.).
    urls = [u for u in urls
            if urlparse(u).hostname
            and "$" not in u
            and (not patterns or host_in_scope(urlparse(u).hostname, patterns))]

    # Anchor verification on the finding's PRIMARY AFFECTED HOST (its host/target
    # field), not on whatever PoC URLs were scraped from the report body. A
    # finding like "staging environment accessible" on
    # kyc-staging.prod.platform.clearme.com often carries incidental PoC URLs
    # pointing at a JS bundle on an unrelated CDN domain — curling those would
    # mis-verify the finding. So: keep only PoC URLs that actually live on the
    # affected host, and if none do, probe the host itself.
    primary_host = _primary_host(finding, patterns)
    if primary_host:
        on_host = [u for u in urls
                   if host_matches((urlparse(u).hostname or "").lower(), primary_host)]
        urls = on_host or [f"https://{primary_host}/"]

    if not urls:
        return {"status": "UNVERIFIED", "confidence": "LOW",
                "reason": "no in-scope PoC URL or affected host to auto-verify — check manually",
                "checks": []}

    ftype = classify_type(finding, urls)

    # Self-XSS is out of scope (victim must attack themselves) — never verify it
    # as a real finding even if it slipped through as REVIEW.
    if ftype == "xss":
        blob = (finding.get("title", "") + " " + finding.get("detail", "")).lower()
        if re.search(r"self[\s-]*xss", blob):
            return {"status": "UNVERIFIED", "type": "xss", "confidence": "LOW",
                    "reason": "self-XSS — out of scope (victim must attack themselves)",
                    "evidence": "", "checks": []}

    targets = select_urls(ftype, urls)
    method = _method_for(finding)

    checks: list[dict] = []
    for url in targets:
        if ftype == "missing_header":
            checks.append(check_missing_header(http, url))
        elif ftype == "xss":
            checks.append(check_xss(http, url))
        elif ftype == "source_map":
            checks.append(check_source_map(http, url))
        elif ftype == "debug_endpoint":
            checks.append(check_debug_endpoint(http, url))
        elif ftype == "http_method":
            checks.append(check_http_method(http, url, method))
        elif ftype == "access_control":
            checks.append(check_access_control(http, url))
        elif ftype == "exposed_key":
            checks.append(check_exposed_key(http, url))
        elif ftype == "auth_endpoint":
            checks.append(check_auth_endpoint(http, url))
        else:
            checks.append(check_info(http, url))

    ok = any(c["ok"] for c in checks)
    # Reason: the passing check, or the first failing one.
    lead = next((c for c in checks if c["ok"]), checks[0])
    confidence = lead.get("confidence", "LOW")
    # A finding is only VERIFIED when the live RESPONSE BODY proves impact AND the
    # proof is at least MEDIUM confidence. A 200 with no content proof is LOW and
    # stays UNVERIFIED, so summary.py never promotes status-code-only hits to
    # ACTIONABLE (ACTIONABLE = in-scope + VERIFIED + confidence >= MEDIUM).
    verified = ok and confidence in ("HIGH", "MEDIUM")
    return {
        "status": "VERIFIED" if verified else "UNVERIFIED",
        "type": ftype,
        "confidence": confidence if verified else "LOW",
        "reason": lead["reason"],
        "evidence": lead.get("evidence", ""),
        "checks": checks,
    }


def run(data: dict, patterns: list[str]) -> dict:
    http = Http()
    for f in data.get("findings", []):
        f["verification"] = verify_finding(http, f, patterns)
    data["verify_summary"] = {
        s: sum(1 for f in data.get("findings", [])
               if f.get("verification", {}).get("status") == s)
        for s in ("VERIFIED", "UNVERIFIED", "SKIPPED")
    }
    return data


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #


def render(data: dict) -> str:
    out: list[str] = []
    out.append(C.wrap("─" * 64, C.CYAN))
    out.append(C.wrap(" VERIFY FINDINGS", C.BOLD, C.CYAN)
               + C.wrap(f"   UA: {USER_AGENT}  |  <= {int(MAX_RPS)} req/s", C.DIM))
    out.append(C.wrap("─" * 64, C.CYAN))

    for f in data.get("findings", []):
        v = f.get("verification", {})
        status = v.get("status", "SKIPPED")
        if status == "SKIPPED" and f.get("verdict") not in ("REVIEW", "NEEDS_POC"):
            continue  # don't clutter with OUT_OF_SCOPE/SKIP rows
        color = VERIFY_COLOR.get(status, C.RESET)
        badge = C.wrap(f"{status:<11}", C.BOLD, color)
        conf = v.get("confidence", "LOW")
        conf_color = {"HIGH": C.GREEN, "MEDIUM": C.YELLOW}.get(conf, C.GREY)
        conf_tag = C.wrap(f"[{conf}]", C.BOLD, conf_color)
        out.append(f"  {badge} {conf_tag} #{f.get('id', '?'):<5} {f.get('title', '')}")
        out.append(C.wrap(f"             └─ {v.get('reason', '')}", C.GREY))
        if v.get("evidence"):
            out.append(C.wrap(f"                ⤷ body: {v.get('evidence')}", C.DIM))
        for c in v.get("checks", []):
            mark = C.wrap("✓", C.GREEN) if c.get("ok") else C.wrap("✗", C.YELLOW)
            st = c.get("status")
            out.append(C.wrap(f"                {mark} [{st}] {c.get('url', '')}", C.GREY))
            if c.get("evidence"):
                out.append(C.wrap(f"                   \"{c.get('evidence')}\"", C.DIM))

    s = data.get("verify_summary", {})
    out.append("")
    out.append(C.wrap(" VERIFY SUMMARY", C.BOLD))
    out.append(f"   {C.wrap('VERIFIED   ', C.GREEN)} {s.get('VERIFIED', 0)}")
    out.append(f"   {C.wrap('UNVERIFIED ', C.YELLOW)} {s.get('UNVERIFIED', 0)}")
    out.append(f"   {C.wrap('SKIPPED    ', C.GREY)} {s.get('SKIPPED', 0)}")
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="verify_findings.py",
        description="Live-verify REVIEW/NEEDS_POC findings by curling their PoC URLs.",
    )
    p.add_argument("--in", dest="infile", required=True,
                   help="Scoped JSON from scope_check.py (or triage JSON).")
    p.add_argument("--scope",
                   help="Scope pattern (only needed if the JSON lacks scope_pattern).")
    p.add_argument("--out", dest="outfile",
                   help="Where to write verified JSON (default: <in>_verified.json).")
    p.add_argument("--no-color", action="store_true", help="Disable colored output.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.no_color or not sys.stdout.isatty():
        C.disable()

    with open(args.infile, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    scope = args.scope or data.get("scope_pattern", "")
    patterns = parse_scope(scope) if scope else []

    data = run(data, patterns)
    print(render(data))

    outfile = args.outfile or args.infile.replace(".json", "_verified.json")
    if outfile == args.infile:
        outfile = args.infile + ".verified"
    with open(outfile, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    sys.stderr.write(C.wrap(f"\nWrote verified JSON to {outfile}\n", C.GREEN))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
