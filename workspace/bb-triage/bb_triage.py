#!/usr/bin/env python3
"""bb_triage.py - Bug bounty triage for PentestGPT scan logs.

Parses PentestGPT findings and scores each against per-program out-of-scope
rules, then emits a colorized verdict report (plus optional JSON).

Four finding formats are understood, matching real `pentestgpt --mode pentest`
output saved by the `bb` wrapper into /workspace/scan-*.log. The same finding
often appears in several of them; `parse_log` de-duplicates by title so each
logical finding is reported once (keeping the copy with the richest evidence):

  1. Bracketed section:  `### [CRITICAL] Open Redirect - Multiple Vectors`
     followed by a body of `- **Type**`, `- **Description**`,
     `**Evidence/PoC**`, `- **Impact**`, `- **Remediation**`, separated by
     `---`. Group headers like `### CRITICAL VULNERABILITIES` are NOT findings.

  2. Markdown table rows: `| 1 | **High** | Missing Security Headers | t | Done |`
     Only rows that carry a real severity value (bold/emoji decoration is
     stripped) are treated as findings, so recon tables (`| Port | ... |`) and
     count/distribution tables (`| **HIGH** | 3 | ... |`) are ignored.

  3. Loose severity banner whose title is the next header line:
         ## 🔴 CRITICAL FINDING
         ### **Source Maps Publicly Exposed on v3.myfone.dk**

  4. Numbered list under a banner:
         ### 🔥 CRITICAL FINDINGS DOCUMENTED
         1. **Production Source Maps Exposure (CVSS 7.5)**
         2. **ASP.NET Trace Handler Exposed (CVSS 7.5)**

Verdicts
--------
REVIEW       Valid, in-scope finding that ships with a proof-of-concept.
NEEDS_POC    Valid, in-scope finding but no PoC/evidence yet.
OUT_OF_SCOPE Matches a program out-of-scope vuln type or keyword.
SKIP         Informational / no-real-impact noise.

Program + scope are auto-detected from the log content (the mandated auth
header + asset domain identify the program; the `[INFO] Target:` line yields
the scope), so `--program` is optional. Pass it only to override detection.

Usage
-----
    bb_triage.py --log /workspace/scan-2026-06-24.log          # auto-detect
    bb_triage.py --log /workspace/scan-2026-06-24.log --program dstny
    cat scan.log | bb_triage.py --stdin --program mexc --json-out out.json
    bb_triage.py --log scan.log --detect          # print PROGRAM=/SCOPE= only
    bb_triage.py --list-programs
    bb_triage.py --log scan.log --rules custom.json --program myprog
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

# --------------------------------------------------------------------------- #
# Terminal color
# --------------------------------------------------------------------------- #


class C:
    """ANSI color codes (auto-disabled when stdout is not a TTY)."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GREY = "\033[90m"

    _enabled = True

    @classmethod
    def disable(cls) -> None:
        cls._enabled = False

    @classmethod
    def wrap(cls, text: str, *codes: str) -> str:
        if not cls._enabled or not codes:
            return text
        return "".join(codes) + text + cls.RESET


# Verdict -> color
VERDICT_COLOR = {
    "REVIEW": C.GREEN,
    "NEEDS_POC": C.YELLOW,
    "OUT_OF_SCOPE": C.RED,
    "SKIP": C.GREY,
}

VERDICT_ORDER = ["REVIEW", "NEEDS_POC", "OUT_OF_SCOPE", "SKIP"]

SEVERITIES = {"critical", "high", "medium", "low", "info", "informational"}


# --------------------------------------------------------------------------- #
# Built-in program rules
# --------------------------------------------------------------------------- #
# Each program maps to:
#   out_of_scope_vuln_types : list[str]  (regex, matched case-insensitively)
#   out_of_scope_keywords   : list[str]  (plain substrings, case-insensitive)
#
# Note on the "without X" categories (blind SSRF, subdomain takeover, CSRF,
# API key): these are written as *qualified* regexes so that a clearly-proven
# variant (e.g. a subdomain takeover with a PoC, an SSRF with demonstrated
# impact) is NOT auto-rejected. Only the unproven / no-impact phrasing matches.

# Impact qualifiers reused by several category counters. When one of these
# matches the finding TITLE (or PoC body), the otherwise out-of-scope category
# is KEPT for manual review because a path to real impact is present. The guard
# is deliberately one-directional: keeping is generous, filtering is strict.
_AUTH_ENDPOINT = (
    r"\blogin\b|\bsign[\s-]*in\b|\bsso\b|\bauth(?:entication)?\b|\botp\b"
    r"|one[\s-]*time[\s-]*(?:password|code)|password[\s-]*reset|forgot[\s-]*password"
    r"|2fa|mfa|two[\s-]*factor|verification\s+code|\bregistration\b|\bsign[\s-]*up\b"
    r"|credential|token\s+endpoint"
)
_CORS_IMPACT = (
    r"credential|withcredentials|cookie|authenticat|bearer|session|token"
    r"|/api/|/user|/account|/profile|/wallet|/payment|sensitive|\bpii\b|email"
    r"|financial|personal\s+data"
)
# Internal infra data reflected in a response body: hostname / private IP / k8s
# pod / cloud ARN / account-id. Exposing it aids targeted infrastructure attacks.
_INFRA_EXPOSURE = (
    r"internal\s+(?:host\s*name|hostname|host|ip\s+address|ip|fqdn|endpoint|service)"
    r"|kubernetes|\bk8s\b|pod[\s-]*name|container[\s-]*name|\bnamespace\b"
    r"|\barn:aws|aws\s+arn|account[\s-]*(?:id|number)|private\s+ip"
    r"|\brds\b|\becs\b|metadata\s+endpoint|169\.254\.169\.254"
)
_HAS_CVE = r"cve-\d{4}-\d{3,7}"

# Rate-limiting must be the PRIMARY subject of the title. The OLD pattern had a
# bare `|rate[\s-]*limit(ing)?\b` alternative that matched the words ANYWHERE —
# so triage (which scanned the whole finding body) flagged "Internal Hostname
# Exposure via /healthcheck" out-of-scope purely because its remediation prose
# said "implement rate limiting". This now only fires when the title starts with
# rate-limit phrasing, pairs it with a no/missing/lack qualifier, or is
# immediately followed by missing/absent/not-enforced.
_RATE_LIMIT_PATTERN = (
    r"^\W*(?:no|missing|lack(?:ing|s)?(?:\s+of)?|absence\s+of|weak|insufficient|without|absent)?\s*"
    r"rate[\s-]*limit(?:ing)?\b"
    r"|\b(?:no|missing|lack(?:ing|s)?(?:\s+of)?|absence\s+of|weak|insufficient|without|absent)\s+"
    r"rate[\s-]*limit"
    r"|\brate[\s-]*limit(?:ing)?\b\s+(?:is\s+)?(?:missing|absent|not\s+(?:implemented|enforced|present)|disabled)"
)

# Out-of-scope categories. Each entry is:
#   (title_pattern, human_label, impact_counter, kept_message)
# A finding is OUT_OF_SCOPE only when its TITLE (the primary subject — never an
# incidental substring in the PoC/remediation body) matches title_pattern AND
# the impact_counter does NOT match. If the counter matches, the finding is kept
# as REVIEW with kept_message. Patterns are subject-anchored: they describe what
# the finding IS, not merely words it contains. (FIX 1 + FIX 2.)
_OOS_CATEGORIES: list[tuple[str, str, Optional[str], Optional[str]]] = [
    (r"missing\s+security\s+headers?\b",
     "missing security header (no exploitability demonstrated)",
     r"sensitive\s+(?:action|form)|state[\s-]*chang|\bfund|transfer|payment|account\s+takeover",
     "security header on a sensitive/state-changing action — needs a clickjacking PoC"),
    (r"\bx-frame-options\b|\bclickjack\w*|ui\s*redress",
     "missing security header (clickjacking, no exploitability demonstrated)",
     r"sensitive\s+(?:action|form)|state[\s-]*chang|\bfund|transfer|payment|account\s+takeover",
     "clickjacking on a sensitive/state-changing action — needs a framing PoC"),
    (r"\bhsts\b|strict[\s-]*transport[\s-]*security|hsts\s+preload",
     "missing HSTS (transport best-practice)", None, None),
    (r"content[\s-]*security[\s-]*policy|missing\s+csp|\bcsp\b\s+(?:header|missing|not\s+set|weak)"
     r"|\bcsp\b\s+with",
     "missing/weak CSP (best-practice)",
     r"\bxss\b|script\s+inject|csp\s+bypass|html\s+inject",
     "CSP gap tied to an XSS / script-injection vector"),
    # Specific browser security headers (X-XSS-Protection, Permissions-Policy,
    # X-Content-Type-Options, Referrer-Policy, COOP/COEP/CORP, Expect-CT). These
    # are explicitly OOS on nearly every program; the counter requires the title
    # to tie the header to a *demonstrated* exploit (note: the bare word "xss" in
    # "X-XSS-Protection" is NOT enough — a real stored/reflected XSS PoC is).
    (r"x[\s-]*xss[\s-]*protection|permissions[\s-]*policy|x[\s-]*content[\s-]*type[\s-]*options"
     r"|referrer[\s-]*policy|x[\s-]*permitted[\s-]*cross[\s-]*domain[\s-]*policies"
     r"|cross[\s-]*origin[\s-]*(?:opener|embedder|resource)[\s-]*policy|expect[\s-]*ct",
     "missing security header (best-practice, no exploitability demonstrated)",
     r"stored\s+xss|reflected\s+xss|enabl\w*\s+(?:stored\s+|reflected\s+)?xss|script\s+inject"
     r"|csp\s+bypass|clickjack\w*\s+(?:poc|exploit)|account\s+takeover"
     r"|with\s+(?:a\s+)?poc|demonstrated\s+exploit",
     "missing header tied to a demonstrated exploit (XSS/clickjacking PoC)"),
    (_RATE_LIMIT_PATTERN,
     "rate limiting on a non-critical endpoint",
     _AUTH_ENDPOINT,
     "rate limiting on authentication endpoint — credential-stuffing / brute-force path"),
    (r"\bcors\b|cross[\s-]*origin\s+resource|cross[\s-]*origin\s+misconfig",
     "CORS on a public / non-credentialed endpoint",
     _CORS_IMPACT,
     "credentialed CORS on sensitive endpoint — needs manual impact verification"),
    (r"\btls\b|\bssl\b|weak\s+cipher|insecure\s+(?:transport|protocol)|deprecated\s+tls",
     "TLS/SSL configuration (no exploited impact)", None, None),
    (r"version\s+(?:disclosure|exposure)|software\s+version\s+(?:exposure|disclosure)"
     r"|server\s+version\s+(?:disclosure|exposure|banner)|\bserver\s+version\b|banner\s+grabb",
     "version/banner disclosure",
     _HAS_CVE + r"|exploitable\s+cve|working\s+exploit",
     "version disclosure tied to a referenced CVE — check exploitability"),
    (r"technolog(?:y|ies)\s+(?:stack\s+)?(?:disclosure|exposure|fingerprint|identification)"
     r"|tech\s+stack\s+(?:disclosure|exposure)|software\s+fingerprint",
     "technology-stack disclosure", None, None),
    (r"cookie\s+(?:flag|attribute|secure|httponly|samesite|without)",
     "cookie attribute best-practice (no session impact)",
     r"session\s+(?:hijack|theft|fixation)|steal\s+session|\bxss\b",
     "cookie flag tied to a session theft / fixation chain"),
    (r"self[\s-]*xss",
     "self-XSS (victim must attack themselves)", None, None),
    (r"csrf\b.{0,40}(?:no|without|low|minimal|non[\s-]*sensitive)\s+impact"
     r"|low[\s-]*impact\s+csrf|csrf\s+on\s+(?:logout|non[\s-]*sensitive)",
     "low/no-impact CSRF",
     r"account\s+takeover|\bfund|transfer|payment|state[\s-]*chang|email\s+change|password\s+change",
     "CSRF on a sensitive state-changing action"),
    (r"email\s+spoof|\bspf\b|\bdmarc\b|\bdkim\b",
     "email authentication policy (SPF/DMARC/DKIM)", None, None),
    (r"theoretical|hypothetical|purely\s+informational|best[\s-]*practice\s+(?:only|issue)",
     "theoretical / best-practice-only issue", None, None),
    (r"blind\s+ssrf",
     "unconfirmed blind SSRF",
     r"confirmed|collaborator|interactsh|\boob\b|out[\s-]*of[\s-]*band|exfil|\brce\b|internal\s+read",
     "blind SSRF with OOB / confirmed impact"),
    (r"(?:api|access)\s+key.{0,40}(?:no|without|low)\s+(?:impact|sensitivity)"
     r"|exposed\s+(?:api\s+)?key.{0,30}(?:no|without|low)\s+impact"
     r"|public\s+(?:client[\s-]*side\s+)?(?:api\s+)?key|google\s+maps\s+api\s+key"
     r"|new\s+relic|nreum|browser\s+(?:monitoring\s+)?(?:license\s+)?key"
     r"|publishable\s+key|\bpk_(?:live|test)_|stripe\s+publishable"
     r"|sentry\s+(?:public\s+)?dsn|public\s+dsn|segment\s+write\s+key"
     r"|firebase\s+(?:web\s+)?(?:config|api\s*key)|mapbox\s+(?:public\s+)?token"
     r"|datadog\s+client\s+token|amplitude\s+api\s+key|statsig\s+client",
     "public client-side key (client-side by design)",
     r"\bsecret\b|server[\s-]*side|write\s+access|privileged|private\s+key",
     "server-side / secret key material exposed"),
    (r"(?:potential|possible)\s+subdomain\s+takeover"
     r"|subdomain\s+takeover.{0,60}(?:unconfirmed|without\s+proof|no\s+proof|"
     r"claimable|nxdomain|dangling|not\s+verified)",
     "unconfirmed subdomain takeover",
     r"claimed|verified|confirmed|\bpoc\b|took\s+over|served\s+content",
     "confirmed / claimed subdomain takeover"),
    (r"robots\.txt|sitemap\.xml",
     "robots.txt / sitemap enumeration (no sensitive paths)",
     r"admin|internal|secret|credential|backup|\.git|private|sensitive\s+path|api[\s-]*key",
     "robots.txt / sitemap discloses sensitive or admin paths"),
    (r"(?:internal|full|file|directory)\s+path\s+disclosure|\bpath\s+disclosure\b",
     "generic path disclosure in an error response",
     _INFRA_EXPOSURE,
     "internal infrastructure data in API response — aids targeted attacks"),
    (r"infrastructure\s+(?:disclosure|exposure|leak)|\bcloudflare\b|\bakamai\b"
     r"|\bfastly\b|cdn\s+(?:disclosure|fingerprint)|origin\s+ip\s+disclosure",
     "CDN / infrastructure fingerprinting (public info)", None, None),
    (r"session\s+(?:id|identifier|token|cookie)\s+(?:format\s+)?(?:disclosure|exposure)"
     r"|session\s+id\s+format",
     "session-identifier format nit (no fixation/hijack PoC)",
     r"fixation|hijack|predict|brute[\s-]*force|takeover",
     "session-id weakness with a fixation / hijack path"),
    (r"descriptive\s+error|detailed\s+error\s+message|verbose\s+error"
     r"|error\s+message.{0,30}(?:internal|disclosure|structure)|stack\s+trace\s+(?:disclosure|exposure)",
     "verbose error / stack-trace message",
     r"credential|password|secret|token|api[\s-]*key|\baws\b|jdbc|connection\s+string",
     "error / stack-trace that leaks credentials or secrets"),
    (r"missing\s+https|no\s+https|lack\s+of\s+https|http\s+instead\s+of\s+https"
     r"|cleartext\s+(?:transmission|transport|http)|unencrypted\s+(?:http|transport)",
     "missing HTTPS / cleartext transport (config nit)",
     r"credential|password|token|session|api[\s-]*key|sensitive",
     "cleartext transport of credentials / sensitive data"),
    (r"autocomplete\s+(?:enabled|on|attribute|not\s+disabled)|missing\s+autocomplete",
     "autocomplete-enabled form field (browser-controlled)", None, None),
    (r"host\s+header\s+(?:injection|attack|poisoning)?.{0,30}(?:without|no|low)\s+impact"
     r"|host\s+header\s+without\s+impact",
     "host-header issue (no demonstrated impact)",
     r"\bssrf\b|cache\s+poison|password\s+reset\s+poison|account\s+takeover|web\s+cache",
     "host-header injection with cache-poisoning / reset-poisoning impact"),
    (r"(?:known\s+)?vulnerable\s+(?:js\s+)?librar.{0,40}(?:without|no)\s+(?:poc|proof|impact)"
     r"|outdated\s+librar.{0,40}(?:without|no)\s+(?:poc|proof|impact)",
     "vulnerable library reported without a PoC",
     r"\bpoc\b|exploit|" + _HAS_CVE + r"|working\s+exploit",
     "vulnerable library with a working PoC / exploit"),
    (r"open\s+redirect.{0,30}(?:standalone|without\s+impact|no\s+impact|low\s+impact)"
     r"|standalone\s+open\s+redirect",
     "standalone open redirect (no impact chain)",
     r"oauth|token\s+(?:theft|leak)|account\s+takeover|\bssrf\b|credential|saml",
     "open redirect chained to OAuth / token theft / ATO"),
]

# Backwards-compatible flat list of regex strings — consumed by BUILTIN_RULES,
# load_rules, list_programs and the JSON `matched` field. Derived from the
# categories above so the raw patterns and their labels/counters never drift.
_COMMON_OOS = [pat for (pat, _label, _counter, _kept) in _OOS_CATEGORIES]

# Fast lookup: raw pattern string -> (label, counter, kept_message).
_OOS_LABELS: dict[str, tuple[str, Optional[str], Optional[str]]] = {
    pat: (label, counter, kept) for (pat, label, counter, kept) in _OOS_CATEGORIES
}

BUILTIN_RULES: dict[str, dict[str, list[str]]] = {
    "dstny": {
        "out_of_scope_vuln_types": list(_COMMON_OOS),
        "out_of_scope_keywords": [
            "missing security headers",
            "missing header",
            "no rate limiting",
            "rate limiting",
            "rate-limit",
            "cors misconfiguration",
            "weak ssl",
            "weak tls",
            "version disclosure",
            "technology stack disclosure",
            "technology stack identification",
            "tech stack disclosure",
            "banner grabbing",
            "cookie flag",
            "clickjacking",
            "self-xss",
            "self xss",
            "email spoofing",
            "spf record",
            "dmarc",
            "theoretical",
            # NOTE: deliberately NOT blanket-blocking "blind ssrf" /
            # "subdomain takeover" / "csrf" / "api key" here — those are
            # handled by the qualified regexes so proven variants stay valid.
        ],
    },
    "mexc": {
        "out_of_scope_vuln_types": list(_COMMON_OOS)
        + [
            r"reflected\s+self[\s-]*xss",
            r"denial\s+of\s+service|\bdos\b|\bddos\b",
            r"physical\s+attack|social\s+engineer",
            r"(account|user|email)\s+enumeration",
            r"\botp\b\s+brute",
        ],
        "out_of_scope_keywords": [
            "missing security headers",
            "rate limiting",
            "cors misconfiguration",
            "clickjacking",
            "self-xss",
            "denial of service",
            "ddos",
            "social engineering",
            "user enumeration",
            "account enumeration",
            "spf record",
            "dmarc",
            "email spoofing",
        ],
    },
    "ad": {
        "out_of_scope_vuln_types": list(_COMMON_OOS)
        + [
            r"password\s+policy",
            r"username\s+enumeration",
            r"account\s+lockout",
            r"verbose\s+error|stack\s+trace\s+(disclosure|exposure)",
        ],
        "out_of_scope_keywords": [
            "missing security headers",
            "rate limiting",
            "clickjacking",
            "self-xss",
            "password policy",
            "username enumeration",
            "account lockout",
            "verbose error",
            "stack trace disclosure",
            "spf record",
            "dmarc",
        ],
    },
    "rabby": {
        "out_of_scope_vuln_types": list(_COMMON_OOS)
        + [
            r"phishing|fake\s+site",
            r"third[\s-]*party\s+(library|dependency).{0,40}(no|without)\s+impact",
            r"\bdust(ing)?\s+attack",
            r"known\s+token\s+scam|scam\s+token",
            r"front[\s-]*end\s+only.{0,30}(no|without)\s+impact",
        ],
        "out_of_scope_keywords": [
            "missing security headers",
            "rate limiting",
            "cors misconfiguration",
            "clickjacking",
            "self-xss",
            "phishing",
            "dusting attack",
            "scam token",
            "third party library",
            "spf record",
            "dmarc",
            "email spoofing",
        ],
    },
    "clear": {
        "name": "CLEAR (HackerOne)",
        "out_of_scope_vuln_types": list(_COMMON_OOS)
        + [
            r"self[\s-]*xss",
            r"scanner\s+report",
            r"google\s+maps\s+api",
            r"email\s+enumeration",
            r"user\s+enumeration",
            r"autocomplete",
            r"rate\s+limit",
            r"missing\s+header",
            r"security\s+header",
            r"clickjacking",
            r"theoretical",
            r"csrf.*low",
            r"known\s+vulnerable\s+librar",
            r"prismic",
            r"wayback\s+machine",
            r"x-bug-bounty\s+header",
            r"version\s+disclosure",
            r"banner",
        ],
        "out_of_scope_keywords": [
            "retire.js",
            "nessus",
            "openvas",
            "qualys",
            "missing autocomplete",
            "self-xss",
        ],
        "notes": "Requires X-Bug-Bounty: HackerOne-<username> on all requests. "
        "No physical device testing.",
    },
    "hackerone": {
        "name": "Generic HackerOne Program",
        "out_of_scope_vuln_types": list(_COMMON_OOS)
        + [
            r"self[\s-]*xss",
            r"rate\s+limit",
            r"missing\s+header",
            r"security\s+header",
            r"clickjacking",
            r"theoretical",
            r"email\s+enumeration",
            r"user\s+enumeration",
            r"autocomplete",
            r"version\s+disclosure",
            r"banner\s+grabbing",
            r"csrf.*low\s+impact",
            r"csrf.*no\s+impact",
            r"missing\s+cookie",
            r"spf",
            r"dmarc",
            r"dkim",
            r"known\s+vulnerable\s+librar.*no.*poc",
        ],
        "out_of_scope_keywords": [
            "retire.js",
            "nessus",
            "openvas",
            "qualys",
            "prowler",
            "missing autocomplete",
            "self-xss",
        ],
        "notes": "Generic HackerOne core ineligible findings applied.",
    },
    "oppo": {
        "name": "OPPO (HackerOne)",
        "out_of_scope_vuln_types": [
            r"self-xss", r"post.*xss", r"json hijacking.*no sensitive",
            r"csrf.*no sensitive", r"csrf.*shopping cart", r"csrf.*logout",
            r"csrf.*forum", r"csrf.*like", r"csrf.*comment",
            r"meaningless.*xss", r"scanner.*report", r"automated.*scan",
            r"directory traversal.*non-sensitive", r"non-sensitive.*traversal",
            r"middleware version", r"version disclosure", r"banner",
            r"clickjacking.*meaningless", r"clickjacking.*no sensitive",
            r"http request smuggling", r"cors.*user interaction",
            r"brute force.*cannot.*exploit",
            r"verification code.*cracking.*distributed",
            r"intranet.*ip.*domain", r"ip.*address.*leak",
            r"exception.*meaningless", r"meaningless.*exception",
            r"product.*function.*defect", r"compatibility",
            r"theoretical", r"cannot.*reproduced", r"purely.*guess",
        ],
        "out_of_scope_keywords": [
            "self-xss", "post-based xss", "scanner report",
            "meaningless clickjacking", "json hijacking no sensitive",
        ],
        "notes": "Header required: X-HackerOne-Research: <username>. Manual "
        "verification mandatory. AI reports without screenshots = rejected.",
    },
}


# Common out-of-scope keyword substrings shared by the generic baseline and any
# program that does not enumerate its own keyword list. Plain (case-insensitive)
# substrings — the heavy lifting is done by the _COMMON_OOS regexes above; these
# just catch the exact phrasings PentestGPT tends to emit verbatim.
_GENERIC_KEYWORDS = [
    "missing security headers",
    "missing header",
    "security header",
    "content-security-policy",
    "missing content-security-policy",
    "csp",
    "hsts",
    "rate limiting",
    "rate-limit",
    "rate limit",
    "version disclosure",
    "banner grabbing",
    "robots.txt",
    "sitemap.xml",
    "infrastructure disclosure",
    "cloudflare",
    "akamai",
    "session id format",
    "technology stack",
    "tech stack disclosure",
    "path disclosure",
    "descriptive error message",
    "detailed error message",
    "verbose error",
    "stack trace",
    "weak tls",
    "weak ssl",
    "missing https",
    "clickjacking",
    "self-xss",
    "self xss",
    "spf record",
    "dmarc",
    "dkim",
    "cookie flag",
    "autocomplete",
    "theoretical",
    "retire.js",
    "nessus",
    "openvas",
    "qualys",
]


# Generic baseline: every common out-of-scope pattern. Any program that is not
# specifically configured falls back to the "hackerone" entry, but this entry is
# what a caller gets if they explicitly ask for `--program generic`, and it is
# the single source the README/`--list-programs` use to describe the baseline.
BUILTIN_RULES["generic"] = {
    "name": "Generic baseline (all common OOS patterns)",
    "out_of_scope_vuln_types": list(_COMMON_OOS),
    "out_of_scope_keywords": list(_GENERIC_KEYWORDS),
    "notes": "Baseline out-of-scope ruleset; applied to any program that is not "
    "specifically configured (via the hackerone fallback).",
}

# Programs/platforms that share the generic baseline. They exist as explicit
# keys so auto-detection (detect_program) and `--program X` never fall through
# to an empty rule set — every one of them carries the full _COMMON_OOS set.
for _generic_program, _generic_label in (
    ("dyson", "Dyson (HackerOne)"),
    ("zelle", "Zelle (HackerOne)"),
    ("hackenproof", "Generic HackenProof Program"),
    ("intigriti", "Generic Intigriti Program"),
):
    BUILTIN_RULES.setdefault(
        _generic_program,
        {
            "name": _generic_label,
            "out_of_scope_vuln_types": list(_COMMON_OOS),
            "out_of_scope_keywords": list(_GENERIC_KEYWORDS),
            "notes": "Generic baseline out-of-scope rules.",
        },
    )


# Informational severities -> SKIP
INFORMATIONAL = {"info", "informational", "none", "n/a", "na"}

# Generic group-header titles that are NOT findings even if bracketed oddly.
_GROUP_TITLES = {
    "vulnerabilities", "vulnerability", "findings", "finding", "priority",
    "summary", "report", "high priority", "medium priority", "low priority",
    "critical vulnerabilities", "high vulnerabilities", "medium vulnerabilities",
    "low vulnerabilities",
}

# Strong PoC markers: concrete, reproducible evidence. These outweigh any
# speculative wording that merely appears in an Impact/risk discussion (e.g.
# "potential exposure of API keys" next to a working `curl` proof).
_POC_STRONG = [
    r"\bpoc\b",
    r"proof[\s-]*of[\s-]*concept",
    r"\bexploited\b|\breproduced\b",
    r"evidence/?poc|evidence\s*:",
    r"request\s*/\s*response|http\s+request|http\s+response",
    r"screenshot",
    r"\bcurl\b",
    r"```",  # fenced command/output block in the body
    r"step[\s-]*by[\s-]*step",
    r"\bverified\b",
]

# Weak PoC hints: suggestive but not conclusive; deferred to if no strong
# marker and no speculative wording is present.
_POC_WEAK = [
    r"exploit(able)?",
    r"reproduc",
    r"payload",
    r"\bdemonstrat",
]

# Tokens that signal the finding is unproven / speculative (no PoC).
_POC_NEGATIVE = [
    r"\bpotential\b",
    r"\bpossible\b",
    r"\bsuspected\b",
    r"\bmight\b|\bmay\s+be\b",
    r"theoretical|hypothetical",
    r"unconfirmed|not\s+confirmed",
    r"needs?\s+(further\s+)?(verification|confirmation|testing|investigation)",
]


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


# A hostname token: dotted labels ending in a TLD. Permissive enough to catch
# `v3.myfone.dk`, `liveproxy.sippeer.dk`, `flexgateway.io`; the trailing `.int`
# (internal gateway) is intentionally matched too so scope_check can flag it.
_HOST_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b",
    re.IGNORECASE,
)
# A URL inside a PoC/evidence body (curl lines, fenced blocks, prose).
_URL_RE = re.compile(r"https?://[^\s)\"'`<>|\\]+", re.IGNORECASE)

# Tokens that look host-shaped but are filenames / noise, not real hosts.
_HOST_BLOCKLIST_SUFFIX = (
    ".js", ".map", ".css", ".json", ".html", ".axd", ".php", ".aspx",
    ".png", ".jpg", ".svg", ".ico", ".txt", ".xml", ".zip", ".bak",
)


def extract_hosts(*texts: str) -> list[str]:
    """Pull plausible hostnames out of finding text, de-duplicated, in order.

    Skips obvious filenames (``main.js``, ``trace.axd``) that share the
    label.label shape but are not hosts.
    """
    seen: dict[str, None] = {}
    for text in texts:
        if not text:
            continue
        for m in _HOST_RE.finditer(text):
            host = m.group(1).lower().rstrip(".")
            if host.endswith(_HOST_BLOCKLIST_SUFFIX):
                continue
            # Require a recognisable TLD-ish last label and >=2 labels.
            if host.count(".") < 1:
                continue
            seen.setdefault(host, None)
    return list(seen)


def extract_urls(*texts: str) -> list[str]:
    """Pull http(s) URLs out of finding text, de-duplicated, in order."""
    seen: dict[str, None] = {}
    for text in texts:
        if not text:
            continue
        for m in _URL_RE.finditer(text):
            url = m.group(0).rstrip(".,;)")
            seen.setdefault(url, None)
    return list(seen)


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    target: str = ""
    status: str = ""
    detail: str = ""
    raw: str = ""

    # Filled by triage()
    verdict: str = ""
    reason: str = ""
    matched: list[str] = field(default_factory=list)

    @property
    def haystack(self) -> str:
        return " ".join(
            x for x in (self.title, self.status, self.detail, self.raw) if x
        ).lower()

    @property
    def hosts(self) -> list[str]:
        """Affected hostnames: prefer the explicit target field, else PoC body.

        Using the target field as the primary source keeps incidental hosts
        mentioned in a PoC (e.g. crt.sh, an internal gateway referenced in
        passing) from being treated as the affected asset.
        """
        # Strip parenthetical tech notes — `api.myfone.dk (IIS 10.0 / ASP.NET
        # 4.0)` should yield only the host, not `asp.net`.
        target_clean = re.sub(r"\([^)]*\)", " ", self.target)
        primary = extract_hosts(target_clean)
        if primary:
            return primary
        return extract_hosts(self.detail, self.raw)

    @property
    def poc_urls(self) -> list[str]:
        return extract_urls(self.detail, self.raw, self.target)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity,
            "title": self.title,
            "target": self.target,
            "status": self.status,
            "verdict": self.verdict,
            "reason": self.reason,
            "matched": self.matched,
            # Enrichment consumed by scope_check.py / verify_findings.py.
            "hosts": self.hosts,
            "poc_urls": self.poc_urls,
            "detail": self.detail,
        }


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

_TABLE_SEP_RE = re.compile(r"^\s*\|?[\s:|\-]+\|?\s*$")
# A finding section header REQUIRES brackets: `### [CRITICAL] Title`.
_FINDING_HEADER_RE = re.compile(
    r"^#{1,6}\s*\[\s*(critical|high|medium|low|info|informational)\s*\]\s*(.+?)\s*$",
    re.IGNORECASE,
)
# A new top-level report section (e.g. `## VULNERABILITY IDENTIFICATION REPORT`)
# terminates the current finding body.
_TOP_SECTION_RE = re.compile(r"^#{1,2}\s+\S")

# An optional log-level prefix the streaming writer prepends to lines.
_LOG_PREFIX_RE = re.compile(r"^\s*\[(?:INFO|TOOL|STATE|SUCCESS|WARN|ERROR|DEBUG)\]\s*")

# Any markdown header line; group(1) is the heading text (decoration stripped
# later). Used to find the title that follows a `### CRITICAL FINDING` banner.
_ANY_HEADER_RE = re.compile(r"^\s*#{1,6}\s*(.+?)\s*$")

_SEV_WORD = r"(critical|high|medium|low|info|informational)"

# Format B: a severity banner whose *title* is on the next header line, e.g.
#   ## 🔴 CRITICAL FINDING
#   ### **Source Maps Publicly Exposed on v3.myfone.dk**
# Singular "FINDING" only — plural "FINDINGS" is the Format C list banner.
_LOOSE_BANNER_RE = re.compile(
    rf"^\s*#{{1,6}}\s*[\W_]*{_SEV_WORD}\s+finding\b", re.IGNORECASE
)

# Format C: a list banner that introduces numbered findings, e.g.
#   ### 🔥 CRITICAL FINDINGS DOCUMENTED
#   1. **Production Source Maps Exposure (CVSS 7.5)**
_LIST_BANNER_RE = re.compile(
    rf"^\s*#{{1,6}}\s*[\W_]*{_SEV_WORD}\s+findings\b"
    r".*\b(documented|identified|summary|overview)\b",
    re.IGNORECASE,
)

# A numbered list item: `1. **Title (CVSS 7.5)**` (bold optional).
_NUM_ITEM_RE = re.compile(r"^\s*\d+\.\s+(.+?)\s*$")


def parse_log(text: str) -> list[Finding]:
    """Parse every supported finding format and de-duplicate the results.

    Real PentestGPT logs repeat the same finding across several presentations:
    a bracketed `### [HIGH] Title` block, a `## CRITICAL FINDING` banner, a
    `### CRITICAL FINDINGS DOCUMENTED` numbered list, and a markdown summary
    table. We parse richest-first (sections carry full PoC bodies) so the
    surviving copy after de-dup keeps the best evidence.
    """
    findings: list[Finding] = []
    findings.extend(_parse_sections(text))       # ### [HIGH] Title  (+ body)
    findings.extend(_parse_loose_banners(text))  # ## CRITICAL FINDING / next hdr
    findings.extend(_parse_numbered_lists(text))  # ### CRITICAL FINDINGS + 1. ..
    findings.extend(_parse_tables(text))         # | # | Severity | Title | ... |

    findings = _dedupe(findings)

    # Re-number any findings lacking an explicit id, keeping order stable.
    auto = 0
    for f in findings:
        if not f.id:
            auto += 1
            f.id = f"F{auto}"
    return findings


# Tokens that carry no discriminating meaning when comparing two titles.
_SIG_STOP = {
    "the", "and", "for", "with", "from", "this", "that", "via", "all", "any",
    "missing", "production", "critical", "high", "medium", "low", "info",
    "informational", "exposed", "exposure", "disclosure", "information",
    "publicly", "public", "risk", "issue", "issues", "finding", "findings",
    "vulnerability", "vulnerabilities", "attack", "protection", "across",
    "multiple", "cvss", "cwe", "poc", "potential", "possible", "weakness",
    "weaknesses", "services", "service", "domains", "domain", "enabled",
}


def _signature(title: str) -> frozenset[str]:
    """Significant, decoration-free tokens used for duplicate detection."""
    toks = re.findall(r"[a-z0-9]+", _clean_token(title).lower())
    return frozenset(t for t in toks if len(t) >= 3 and t not in _SIG_STOP)


def _same_finding(a: frozenset[str], b: frozenset[str]) -> bool:
    if not a or not b:
        return False
    inter = a & b
    # Subset match (e.g. {source,maps} ⊂ {source,maps,myfone}) ...
    if inter == a or inter == b:
        return min(len(a), len(b)) >= 2
    # ... or strong overlap by Jaccard similarity.
    return len(inter) / len(a | b) >= 0.5


def _dedupe(findings: list[Finding]) -> list[Finding]:
    kept: list[Finding] = []
    sigs: list[frozenset[str]] = []
    for f in findings:
        sig = _signature(f.title)
        match = next((i for i, s in enumerate(sigs) if _same_finding(sig, s)), None)
        if match is None:
            kept.append(f)
            sigs.append(sig)
            continue
        # Duplicate: keep the first (richest-format) title/severity, but fold in
        # every copy's text so PoC detection sees evidence from any presentation
        # (e.g. a terse list item plus a section with a working `curl`).
        prior = kept[match]
        if len(f.detail) > len(prior.detail):
            prior.detail = f.detail
        prior.raw = f"{prior.raw}\n{f.raw}"
        prior.target = prior.target or f.target
        prior.status = prior.status or f.status
    return kept


def _clean_token(s: str) -> str:
    """Strip markdown bold/italics, backticks, and leading/trailing emoji/symbols.

    Lets `**High**`, `` `High` ``, `✅ Confirmed`, `🔴 Source Maps` reduce to the
    bare text so severities and titles are recognised regardless of decoration.
    """
    s = s.strip().strip("*`").strip()
    # Trim leading/trailing decoration (emoji, bullets, ✅/❌, colons) but keep
    # meaningful brackets so "Missing Headers (All Services)" stays intact.
    s = re.sub(r"^[^0-9A-Za-z(\[]+", "", s)
    s = re.sub(r"[^0-9A-Za-z)\]]+$", "", s)
    return s.strip()


def _norm_sev(cell: str) -> Optional[str]:
    """Return the canonical severity for a cell, or None (handles `**High**`)."""
    tok = _clean_token(cell).lower()
    return tok if tok in SEVERITIES else None


def _split_row(line: str) -> list[str]:
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    return [c.strip() for c in line.split("|")]


def _looks_like_table_row(line: str) -> bool:
    s = line.strip()
    return s.startswith("|") and s.count("|") >= 2


def _severity_cell(cells: Iterable[str]) -> Optional[str]:
    for c in cells:
        sev = _norm_sev(c)
        if sev:
            return sev
    return None


def _plausible_title(title: str) -> bool:
    """A real finding title has wording, not just a number/severity/symbol.

    Filters out distribution/count-table rows like `| **HIGH** | 3 | ... |`
    whose positionally-derived "title" is just a count.
    """
    t = _clean_token(title)
    if len(t) < 4:
        return False
    if t.lower() in SEVERITIES:
        return False
    return bool(re.search(r"[A-Za-z]{3,}", t))


def _parse_tables(text: str) -> list[Finding]:
    """Parse markdown tables, but only rows that carry a severity value.

    This naturally skips recon tables (ports, assets, tech stacks) which have
    no severity column, while still catching headerless finding tables like
    `| 1 | High | Title | target | Confirmed |`.
    """
    findings: list[Finding] = []
    header: Optional[list[str]] = None

    for line in text.splitlines():
        if not _looks_like_table_row(line):
            header = None
            continue
        if _TABLE_SEP_RE.match(line):
            continue
        cells = _split_row(line)
        sev = _severity_cell(cells)

        if sev is None:
            # Could be a header row defining columns; remember it for mapping.
            joined = " ".join(cells).lower()
            if any(k in joined for k in
                   ("severity", "title", "vuln", "finding", "type", "status")):
                header = [_clean_token(c).lower() for c in cells]
            continue

        finding = _finding_from_cells(cells, header, sev, raw=line)
        # Skip rows whose "title" is just a count/severity (distribution tables).
        if _plausible_title(finding.title):
            findings.append(finding)
    return findings


def _finding_from_cells(
    cells: list[str], header: Optional[list[str]], sev: str, raw: str
) -> Finding:
    def col(*names: str) -> str:
        if not header:
            return ""
        for n in names:
            if n in header:
                idx = header.index(n)
                if idx < len(cells):
                    return cells[idx]
        return ""

    fid = col("id", "#", "no")
    title = col("title", "vuln", "vulnerability", "type", "finding", "description")
    target = col("target", "host", "endpoint", "url", "service", "asset", "domain")
    status = col("status", "state")

    # Positional fallback (id | severity | title | target | status), anchored
    # on the location of the severity cell.
    if not (title and target and status):
        sev_idx = next(
            (i for i, c in enumerate(cells) if _norm_sev(c)), 1
        )
        fid = fid or (cells[sev_idx - 1] if sev_idx >= 1 else "")
        rest = cells[sev_idx + 1:]
        title = title or (rest[0] if len(rest) > 0 else "")
        target = target or (rest[1] if len(rest) > 1 else "")
        status = status or (rest[2] if len(rest) > 2 else "")

    return Finding(
        id=_clean_token(fid),
        severity=sev,
        title=_clean_token(title),
        target=_clean_token(target),
        status=_clean_token(status),
        raw=raw,
    )


def _collect_body(lines, start, stop_pred):
    """Gather a finding body from `start`, honouring fenced code blocks.

    A terminator (next finding header / new top section) is only honoured
    outside ``` fences — otherwise a `# comment` or `## heading` *inside* a
    bash/nginx PoC block would prematurely cut off the evidence.
    """
    body: list[str] = []
    i = start
    in_fence = False
    while i < len(lines):
        line = lines[i]
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            body.append(line)
            i += 1
            continue
        if not in_fence and stop_pred(line):
            break
        body.append(line)
        i += 1
    return body, i


def _parse_sections(text: str) -> list[Finding]:
    """Parse `### [SEVERITY] Title` blocks (bracketed headers only)."""
    findings: list[Finding] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = _FINDING_HEADER_RE.match(lines[i])
        if not m:
            i += 1
            continue
        severity = m.group(1)
        title = _clean_title(m.group(2))

        # Skip group headers that slipped through (e.g. "[High] Vulnerabilities").
        if title.lower() in _GROUP_TITLES or not title:
            i += 1
            continue

        body, i = _collect_body(
            lines,
            i + 1,
            lambda ln: bool(_FINDING_HEADER_RE.match(ln) or _TOP_SECTION_RE.match(ln)),
        )
        detail = "\n".join(body).strip()
        findings.append(
            Finding(
                id="",
                severity=severity,
                title=title,
                detail=detail,
                target=_extract_field(detail, "service", "target", "host", "url", "endpoint"),
                status=_extract_field(detail, "status", "state"),
                raw=f"### [{severity}] {title}\n{detail}",
            )
        )
    return findings


def _clean_title(raw: str) -> str:
    """Normalise a heading into a finding title.

    Strips decoration, a leading ordinal (`#1:`, `2.`, `#3 -`) and a trailing
    `(CVSS 7.5)` / `(CWE-540)` parenthetical so the same finding reads the same
    across formats.
    """
    t = _clean_token(raw)
    t = re.sub(r"^#?\s*\d+\s*[:.\)\-]\s*", "", t)          # leading ordinal
    t = re.sub(r"\s*\((?:cvss|cwe)[^)]*\)\s*$", "", t, flags=re.IGNORECASE)
    return t.strip()


def _parse_loose_banners(text: str) -> list[Finding]:
    """Format B: `## CRITICAL FINDING` banner; title is the next header line.

        ## 🔴 CRITICAL FINDING
        ### **Source Maps Publicly Exposed on v3.myfone.dk**
        ...body...
    """
    findings: list[Finding] = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        bare = _LOG_PREFIX_RE.sub("", line)
        m = _LOOSE_BANNER_RE.match(bare)
        if not m:
            continue
        # The title is the immediately following non-blank line, and it must
        # itself be a markdown header (otherwise this is just prose).
        j = i + 1
        while j < len(lines) and not lines[j].strip():
            j += 1
        if j >= len(lines):
            continue
        hm = _ANY_HEADER_RE.match(_LOG_PREFIX_RE.sub("", lines[j]))
        if not hm:
            continue
        title = _clean_title(hm.group(1))
        if not title or title.lower() in _GROUP_TITLES:
            continue
        body, _ = _collect_body(
            lines,
            j + 1,
            lambda ln: bool(_ANY_HEADER_RE.match(_LOG_PREFIX_RE.sub("", ln))),
        )
        detail = "\n".join(body).strip()
        findings.append(
            Finding(
                id="",
                severity=m.group(1).lower(),
                title=title,
                detail=detail,
                target=_extract_field(detail, "service", "target", "host", "url"),
                status=_extract_field(detail, "status", "state"),
                raw=f"{title}\n{detail}",
            )
        )
    return findings


def _parse_numbered_lists(text: str) -> list[Finding]:
    """Format C: a `CRITICAL FINDINGS DOCUMENTED` banner + a numbered list.

        ### 🔥 CRITICAL FINDINGS DOCUMENTED
        1. **Production Source Maps Exposure (CVSS 7.5)**
           - 9MB+ of source code publicly accessible
        2. **ASP.NET Trace Handler Exposed (CVSS 7.5)**
    """
    findings: list[Finding] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        bare = _LOG_PREFIX_RE.sub("", lines[i])
        m = _LIST_BANNER_RE.match(bare)
        if not m:
            i += 1
            continue
        severity = m.group(1).lower()
        i += 1
        # Consume the numbered items that follow (blank lines are allowed
        # between items; any other non-item line ends the list).
        while i < len(lines):
            stripped = _LOG_PREFIX_RE.sub("", lines[i])
            if not stripped.strip():
                i += 1
                continue
            item = _NUM_ITEM_RE.match(stripped)
            if not item:
                break
            title = _clean_title(item.group(1))
            body: list[str] = []
            i += 1
            while i < len(lines):
                nxt = _LOG_PREFIX_RE.sub("", lines[i])
                if _NUM_ITEM_RE.match(nxt) or _ANY_HEADER_RE.match(nxt):
                    break
                if not nxt.strip() and body:
                    # blank line: peek — if the next non-blank isn't a sub-bullet
                    # the item's body has ended.
                    break
                body.append(lines[i])
                i += 1
            if title and title.lower() not in _GROUP_TITLES and _plausible_title(title):
                detail = "\n".join(body).strip()
                findings.append(
                    Finding(
                        id="",
                        severity=severity,
                        title=title,
                        detail=detail,
                        raw=f"{title}\n{detail}",
                    )
                )
    return findings


def _extract_field(text: str, *names: str) -> str:
    for name in names:
        m = re.search(
            rf"(?im)^\s*[-*]*\s*\**{re.escape(name)}\**\s*[:=]\s*(.+)$", text
        )
        if m:
            return m.group(1).strip().strip("*").strip()
    return ""


# --------------------------------------------------------------------------- #
# Triage logic
# --------------------------------------------------------------------------- #


def _any_match(patterns: Iterable[str], text: str) -> Optional[str]:
    for p in patterns:
        try:
            if re.search(p, text, re.IGNORECASE):
                return p
        except re.error:
            if p.lower() in text:
                return p
    return None


def _keyword_match(keywords: Iterable[str], text: str) -> Optional[str]:
    for k in keywords:
        if k.lower() in text:
            return k
    return None


def has_poc(f: Finding) -> bool:
    text = f.haystack
    # Concrete evidence wins outright, even if the Impact section hedges with
    # words like "potential" / "possible".
    if _any_match(_POC_STRONG, text):
        return True
    if _any_match(_POC_NEGATIVE, text):
        return False
    if _any_match(_POC_WEAK, text):
        return True
    status = f.status.lower()
    if status in {"exploited", "verified", "reproduced", "proven", "confirmed poc"}:
        return True
    return False


# Identifies cookie/SameSite/CSRF best-practice rules (patterns or keywords)
# so they can be lifted for a CSRF finding that carries demonstrated impact.
_COOKIE_RULE_HINT = re.compile(r"cookie|samesite|csrf", re.IGNORECASE)

_CSRF_HINT_RE = re.compile(
    r"\bcsrf\b|cross[\s-]*site\s+request\s+forgery|\bxsrf\b", re.IGNORECASE
)


def _is_csrf_with_impact(f: Finding, text: str) -> bool:
    """True when the finding is framed as CSRF and shows risk/impact or a PoC."""
    if not _CSRF_HINT_RE.search(text):
        return False
    return (
        has_poc(f)
        or "impact" in text
        or "account takeover" in text
        or "session riding" in text
    )


# Scanner severities of High/Critical correspond to CVSS >= 7.0.
_HIGH_SEVERITIES = {"high", "critical"}

# Vulnerability *classes* that must NEVER be auto-filtered when named in the
# TITLE — regardless of wording or severity. These have no low-value variant, so
# they win even at LOW severity. (FIX 2, rule 7.) Order matters: first match.
_NEVER_OOS_TITLE: list[tuple[str, str]] = [
    (r"\bauth(?:entication|orization)?\s+bypass\b"
     r"|\bbypass(?:ing)?\s+(?:auth|authentication|login|2fa|mfa)\b"
     r"|broken\s+authentication",
     "authentication bypass"),
    (r"\bidor\b|insecure\s+direct\s+object|broken\s+object[\s-]*level\s+auth"
     r"|\bbola\b|object[\s-]*level\s+authoriz",
     "IDOR / broken object-level authorization"),
    (r"privilege\s+escalat|priv[\s-]*esc\b|vertical\s+(?:privilege\s+)?escalat"
     r"|horizontal\s+(?:privilege\s+)?escalat",
     "privilege escalation"),
    (r"\bsql\s*injection\b|\bsqli\b|blind\s+sql",
     "SQL injection"),
    (r"\brce\b|remote\s+code\s+execution|command\s+injection|\bos\s+command\b"
     r"|arbitrary\s+code",
     "RCE finding"),
    (r"insecure\s+deserializ|deserialization\s+(?:vuln|attack)",
     "insecure deserialization"),
    (r"business\s+logic|payment\s+bypass|price\s+manipulat|race\s+condition"
     r"|negative\s+(?:amount|balance)",
     "business logic flaw"),
    (r"hardcoded\s+(?:secret|credential|api[\s-]*key|password|token)"
     r"|exposed\s+(?:secret|credential|private\s+key)"
     r"|leaked\s+(?:secret|credential|api[\s-]*key|password|token)",
     "hardcoded secret / credential"),
    (r"source\s*maps?\b(?=.{0,60}sourcescontent)|sourcescontent",
     "source map with sourcesContent"),
    # XSS classes are real injection findings — never auto-OOS on a keyword. Each
    # is kept for REVIEW with a class-specific hint. (Self-XSS is the exception:
    # it stays OUT_OF_SCOPE via the _COMMON_OOS "self-xss" category and is NOT
    # matched by any pattern below.)
    (r"\bstored\s+xss\b|persistent\s+xss",
     "stored XSS"),
    (r"\breflected\s+xss\b",
     "reflected XSS"),
    (r"\bdom[\s-]*(?:based\s+)?xss\b",
     "DOM XSS — verify dangerous sink + source in JS"),
    (r"\bpost[\s-]*based\s+xss\b",
     "POST-based XSS — needs delivery mechanism PoC"),
]

_CVE_RE = re.compile(_HAS_CVE, re.IGNORECASE)
_INFRA_EXPOSURE_RE = re.compile(_INFRA_EXPOSURE, re.IGNORECASE)
_NEVER_OOS_TITLE_RES = [
    (re.compile(p, re.IGNORECASE), label) for p, label in _NEVER_OOS_TITLE
]

# Categories that, even at High/Critical severity, stay out-of-scope when their
# impact-counter does not fire (the scanner over-rates severity, so a mis-rated
# "Missing Security Headers [HIGH]" must still filter). The CVSS>=7 rescue in
# _never_oos_reason is therefore suppressed whenever a category matched.
_CommonOOSSet = frozenset(_COMMON_OOS)


def _match_oos_category(
    title: str, vuln_types: list[str]
) -> Optional[tuple[str, str, Optional[str], Optional[str]]]:
    """First OOS category whose pattern matches the finding TITLE, or None.

    Only categories whose raw pattern is part of this program's
    ``vuln_types`` are considered, so a program with a bespoke rule set is not
    silently widened. Matching the *title* — not the whole body — is the core
    false-positive fix: an unrelated finding is no longer filtered because a
    category's words appear in its PoC/remediation prose.
    """
    for entry in _OOS_CATEGORIES:
        if entry[0] not in vuln_types:
            continue
        try:
            if re.search(entry[0], title, re.IGNORECASE):
                return entry
        except re.error:
            continue
    return None


def _never_oos_reason(
    f: Finding, matched_category: Optional[tuple]
) -> Optional[str]:
    """Reason the finding must stay in scope, or None.

    1. A high-impact vuln *class* named in the title always wins (even LOW sev).
    2. Otherwise, a CVE id or CVSS>=7 keeps the finding ONLY when it did not
       already match a low-value OOS category — so a mis-rated "Missing Security
       Headers [HIGH]" still filters, while a genuinely uncategorised
       high-severity finding is preserved for review.
    """
    title = f.title or ""
    cls: Optional[str] = None
    for rx, label in _NEVER_OOS_TITLE_RES:
        if rx.search(title):
            cls = label
            break
    cvss_high = (f.severity or "").strip().lower() in _HIGH_SEVERITIES

    if cls and cvss_high:
        return f"CVSS >= 7.0 / {cls}"
    if cls:
        return cls
    if matched_category is None:
        if _CVE_RE.search(f.haystack):
            return "CVE referenced — needs manual review"
        if cvss_high:
            return "CVSS >= 7.0 (high/critical severity — manual review required)"
    return None


def _humanize_oos(token: str) -> str:
    """Readable label for a non-category OOS match (program-specific pattern or
    keyword): use the category label map if present, else de-noise the regex."""
    if token in _OOS_LABELS:
        return _OOS_LABELS[token][0]
    s = re.sub(r"[\\^$()?:|{}\[\].*+]", " ", token)
    s = re.sub(r"\s+", " ", s).strip()
    return s or "low-value / out-of-scope finding"


def triage(f: Finding, rules: dict[str, list[str]]) -> Finding:
    sev = f.severity.strip().lower()

    # 1. Informational noise -> SKIP.
    if sev in INFORMATIONAL:
        f.verdict = "SKIP"
        f.reason = f"informational severity ({f.severity or 'none'})"
        return f

    title_l = (f.title or "").lower()
    body = f.haystack
    vuln_types = rules.get("out_of_scope_vuln_types", [])
    keywords = rules.get("out_of_scope_keywords", [])

    # Which low-value OOS category (if any) is the TITLE primarily about?
    # Matching the title rather than the whole body is the false-positive fix.
    category = _match_oos_category(title_l, vuln_types)

    # 2. IMPACT KEEP: a categorised finding whose impact-counter fires is kept
    #    for review with a category-specific note. The counter is matched
    #    against the TITLE only — matching the body would over-keep, because the
    #    body of a CSP nit routinely says "XSS" and a subdomain nit says
    #    "confirmed". Impact must be the finding's stated subject. Runs BEFORE
    #    the severity guard so the specific impact reason wins (e.g. credentialed
    #    CORS, or rate-limiting on a login endpoint).
    if category is not None:
        _pat, label, counter, kept = category
        if counter and re.search(counter, title_l, re.IGNORECASE):
            f.verdict = "REVIEW"
            f.reason = f"kept: {kept or label}"
            return f

    # 3. Internal infrastructure data reflected in a response (hostname / pod /
    #    ARN / account-id) aids targeted attacks -> always keep for review.
    if _INFRA_EXPOSURE_RE.search(title_l):
        f.verdict = "REVIEW"
        f.reason = (
            "kept: internal infrastructure data in API response — "
            "aids targeted attacks"
        )
        return f

    # 4. Never auto-OOS high-impact classes / CVSS >= 7.0. The severity rescue
    #    does not override a matched low-value category (see _never_oos_reason).
    never = _never_oos_reason(f, category)
    if never:
        f.verdict = "REVIEW"
        f.reason = f"kept: {never}"
        return f

    # 5. CSRF with demonstrated impact: a real CSRF is in-scope even though it
    #    touches cookie/SameSite territory; don't let the bare best-practice
    #    cookie/CSRF rule auto-reject it.
    if _is_csrf_with_impact(f, body) and (
        category is None or _COOKIE_RULE_HINT.search(category[0])
    ):
        f.verdict = "REVIEW"
        f.reason = "kept: CSRF with demonstrated impact"
        return f

    # 6. Out-of-scope by category (title is primarily a low-value finding and no
    #    impact counter fired).
    if category is not None:
        _pat, label, _counter, _kept = category
        f.verdict = "OUT_OF_SCOPE"
        f.reason = f"matches OOS pattern: {label}"
        f.matched = [_pat]
        return f

    # 7. Out-of-scope by a program-specific EXTRA pattern / keyword — matched
    #    against the TITLE, not the body.
    extras = [p for p in vuln_types if p not in _CommonOOSSet]
    hit = _any_match(extras, title_l)
    if hit:
        f.verdict = "OUT_OF_SCOPE"
        f.reason = f"matches OOS pattern: {_humanize_oos(hit)}"
        f.matched = [hit]
        return f
    kw = _keyword_match(keywords, title_l)
    if kw:
        f.verdict = "OUT_OF_SCOPE"
        f.reason = f"matches OOS pattern: {_humanize_oos(kw)}"
        f.matched = [kw]
        return f

    # 7c. Exposed API schema (OpenAPI/Swagger/GraphQL): keep for review but cap
    #     the hint — a schema that only lists endpoint names is Low/Informational
    #     unless it leaks secrets or grants unauthenticated data access.
    if re.search(
        r"\b(?:openapi|swagger)\b|api\s+schema|swagger\.json|openapi\.json"
        r"|graphql\s+schema",
        title_l,
    ) and not re.search(
        r"bypass|\bidor\b|broken\s+access|unauth|injection|secret|credential",
        title_l,
    ):
        f.verdict = "REVIEW"
        f.reason = ("kept: exposed API schema — Low/Informational unless secrets "
                    "or unauthenticated data access proven")
        return f

    # 8. Valid, in-scope finding -> REVIEW (has PoC) or NEEDS_POC.
    if has_poc(f):
        f.verdict = "REVIEW"
        f.reason = "kept: valid, in-scope, PoC present"
    else:
        f.verdict = "NEEDS_POC"
        f.reason = "valid, in-scope, no PoC/evidence yet"
    return f


# --------------------------------------------------------------------------- #
# Self-tests (impact-focused filter regression)
# --------------------------------------------------------------------------- #


def run_self_tests() -> int:
    """Exercise the impact filter against the canonical mock findings.

    Returns 0 if every case matches its expected verdict + reason fragment,
    else 1. Invoked via ``bb_triage.py --self-test``.
    """
    rules = load_rules("hackerone", None)
    cases = [
        ("Internal Hostname Exposure via /healthcheck Endpoint", "low", "",
         "REVIEW", "kept: internal infrastructure data in API response"),
        ("Missing X-Frame-Options Header", "low", "",
         "OUT_OF_SCOPE", "matches OOS pattern: missing security header"),
        ("CORS Misconfiguration on /api/v2/user with credentials=true", "high",
         "Endpoint reflects Origin and returns user email + session token; "
         "withCredentials=true.",
         "REVIEW", "kept: credentialed CORS on sensitive endpoint"),
        ("Rate Limiting Missing on Login Endpoint", "medium", "",
         "REVIEW", "kept: rate limiting on authentication endpoint"),
        ("Apache Tomcat 9.0.83 Version Disclosure", "low", "",
         "OUT_OF_SCOPE", "matches OOS pattern: version/banner disclosure"),
        ("Apache Tomcat 9.0.83 CVE-2024-9999 Remote Code Execution", "critical",
         "",
         "REVIEW", "kept: CVSS >= 7.0 / RCE finding"),
        # XSS verdict rules.
        ("Self-XSS in profile page", "medium", "",
         "OUT_OF_SCOPE", "self-XSS"),
        ("Stored XSS in comment field", "medium", "",
         "REVIEW", "kept: stored XSS"),
        ("Reflected XSS in search parameter", "medium", "",
         "REVIEW", "kept: reflected XSS"),
        ("DOM-based XSS via location.hash sink", "medium", "",
         "REVIEW", "verify dangerous sink"),
        ("POST-based XSS in contact form", "medium", "",
         "REVIEW", "needs delivery mechanism"),
    ]

    passed = 0
    print(C.wrap("Impact-filter self-tests", C.BOLD, C.CYAN))
    print(C.wrap("─" * 64, C.CYAN))
    for i, (title, sev, detail, want_verdict, want_reason) in enumerate(cases, 1):
        f = Finding(id=f"F{i}", severity=sev, title=title, detail=detail,
                    raw=f"{title}\n{detail}")
        triage(f, rules)
        ok = f.verdict == want_verdict and want_reason.lower() in f.reason.lower()
        passed += ok
        tag = C.wrap("PASS", C.GREEN) if ok else C.wrap("FAIL", C.RED)
        print(f"  [{tag}] #{i} [{sev.upper()}] {title}")
        print(C.wrap(f"        -> {f.verdict}: {f.reason}", C.GREY))
        if not ok:
            print(C.wrap(f"        expected {want_verdict} / '{want_reason}'", C.YELLOW))
    print(C.wrap("─" * 64, C.CYAN))
    summary = f" {passed}/{len(cases)} passed"
    print(C.wrap(summary, C.BOLD, C.GREEN if passed == len(cases) else C.RED))
    return 0 if passed == len(cases) else 1


def run_triage(
    findings: list[Finding], rules: dict[str, list[str]]
) -> list[Finding]:
    return [triage(f, rules) for f in findings]


# --------------------------------------------------------------------------- #
# Rules loading
# --------------------------------------------------------------------------- #


def load_rules(program: Optional[str], rules_path: Optional[str]) -> dict[str, list[str]]:
    """Resolve rules: custom JSON file overrides/extends built-ins.

    Critically, this never returns an *empty* rule set. If ``program`` is not a
    configured built-in (e.g. auto-detected "dyson" before it had an entry, or a
    brand-new program), it falls back to the generic ``hackerone`` baseline so
    out-of-scope filtering still happens. An empty rule set would pass every
    finding (missing headers, rate limiting, robots.txt, ...) as in-scope, which
    makes triage useless — see _DEFAULT_PROGRAM.
    """
    base: dict[str, list[str]] = {
        "out_of_scope_vuln_types": [],
        "out_of_scope_keywords": [],
    }
    # Resolve the effective program: a known built-in, or the generic fallback.
    effective = program if (program and program in BUILTIN_RULES) else _DEFAULT_PROGRAM
    if effective in BUILTIN_RULES:
        base = {
            "out_of_scope_vuln_types": list(BUILTIN_RULES[effective]["out_of_scope_vuln_types"]),
            "out_of_scope_keywords": list(BUILTIN_RULES[effective]["out_of_scope_keywords"]),
        }

    if rules_path:
        with open(rules_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if program and program in data:
            data = data[program]
        for key in ("out_of_scope_vuln_types", "out_of_scope_keywords"):
            extra = data.get(key, [])
            if extra:
                base[key] = list(dict.fromkeys(base[key] + list(extra)))
    return base


# --------------------------------------------------------------------------- #
# Auto-detection (program + scope) from raw log content
# --------------------------------------------------------------------------- #
# So users never have to pass --program / scope by hand: the scan log already
# carries the program's fingerprint (the auth header the program mandates, plus
# the asset domain) and the target it was pointed at.
#
# Each signature is (program, header_indicators, domain_indicators). A program
# matches when the log contains ANY header indicator AND ANY domain indicator
# (both lowercased). Order matters: Intigriti maps to both `dstny` and `ad`, so
# the domain indicator disambiguates and the first satisfied row wins.

_DEFAULT_PROGRAM = "hackerone"

_PROGRAM_SIGNATURES: list[tuple[str, list[str], list[str]]] = [
    ("clear", ["x-bug-bounty: hackerone-", "x-bug-bounty:hackerone-"],
     ["clearme.com", "clearme"]),
    ("oppo", ["x-hackerone-research"], ["oppo.com", "opposhop.cn"]),
    ("dyson", ["x-hackerone:"], ["dyson.com", "dyson"]),
    ("dstny", ["intigriti"], ["dstny", "myfone", "flexgateway"]),
    ("ad", ["intigriti"], ["ad.nl", "dpgmedia"]),
    ("mexc", ["bugrap"], ["mexc"]),
    ("rabby", ["bugrap"], ["rabby"]),
]


def detect_program(log_text: str) -> str:
    """Infer the bug-bounty program from scan log content.

    Returns a built-in program key (see ``BUILTIN_RULES``) or the generic
    ``"hackerone"`` fallback when no fingerprint matches.
    """
    text = log_text.lower()
    for program, headers, domains in _PROGRAM_SIGNATURES:
        if any(h in text for h in headers) and any(d in text for d in domains):
            return program
    return _DEFAULT_PROGRAM


# The IP-scoped scan target the streaming writer records first, e.g.
#   [INFO] Target: https://api.myfone.dk
_INFO_TARGET_RE = re.compile(r"\[INFO\]\s*Target\s*[:=]\s*(\S+)", re.IGNORECASE)
# Fallback: any `Target: <url>` mention (e.g. inside an asset-inventory block).
_TARGET_RE = re.compile(r"\bTarget\s*[:=]\s*(?:https?://)?(\S+)", re.IGNORECASE)

# Second-level public suffixes where the registrable root is the last THREE
# labels (e.g. example.co.uk). Extend as programs in those ccTLDs appear.
_SECOND_LEVEL_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "co.jp", "co.nz",
    "co.za", "com.br", "co.in",
}


def _host_from_target(token: str) -> str:
    """Strip scheme, path, query and port from a target token -> bare host."""
    token = token.strip().strip("\"'<>(),")
    token = re.sub(r"^https?://", "", token, flags=re.IGNORECASE)
    token = token.split("/")[0].split("\\")[0]
    token = token.split("?")[0].split(":")[0]  # drop query + port
    return token.lower().rstrip(".")


def root_domain(host: str) -> str:
    """Reduce a hostname to its registrable root (api.myfone.dk -> myfone.dk)."""
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in _SECOND_LEVEL_TLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def detect_scope(log_text: str) -> Optional[str]:
    """Infer the scope pattern from the scan target in the log.

    The scan was pointed at one specific host, so the detected scope mirrors it
    exactly — it must NOT silently widen a subdomain target to the whole root:

      ``[INFO] Target: https://shop.tiktok.com`` -> ``shop.tiktok.com`` (exact)
      ``[INFO] Target: https://tiktok.com``      -> ``*.tiktok.com``   (apex)

    Only an apex/root target (``tiktok.com``, ``dyson.com``) expands to a
    ``*.root`` wildcard, because scanning the root implies its subdomains. A
    specific subdomain target stays exact, matching what ``instruction.sh``
    derives (no ``*`` in scope => exact-host). Returns None when no usable target
    is present (caller can then leave scope unset). Pass an explicit scope to
    ``run_triage.sh`` to override.
    """
    m = _INFO_TARGET_RE.search(log_text) or _TARGET_RE.search(log_text)
    if not m:
        return None
    host = _host_from_target(m.group(1))
    if not host or "." not in host:
        return None
    root = root_domain(host)
    # Apex target -> include subdomains; specific subdomain -> keep it exact.
    if host == root:
        return f"*.{root}"
    return host


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #


def render_report(
    findings: list[Finding],
    program: Optional[str],
    target_filter: Optional[str],
) -> str:
    out: list[str] = []
    title = "BUG BOUNTY TRIAGE"
    if program:
        title += f"  —  program: {program}"
    out.append(C.wrap("═" * 64, C.CYAN))
    out.append(C.wrap(f" {title}", C.BOLD, C.CYAN))
    out.append(C.wrap("═" * 64, C.CYAN))

    if not findings:
        out.append(C.wrap("  No findings parsed from input.", C.YELLOW))
        return "\n".join(out)

    for f in findings:
        color = VERDICT_COLOR.get(f.verdict, C.RESET)
        badge = C.wrap(f"{f.verdict:<12}", C.BOLD, color)
        sev = C.wrap(f"[{f.severity or '-'}]", C.DIM)
        out.append(f"  {badge} #{f.id:<5} {sev} {f.title}")
        detail = f.reason
        if f.matched:
            detail += C.wrap(f"  (~ {f.matched[0]})", C.DIM)
        out.append(C.wrap(f"             └─ {detail}", C.GREY))

    counts = {v: 0 for v in VERDICT_ORDER}
    for f in findings:
        counts[f.verdict] = counts.get(f.verdict, 0) + 1

    out.append("")
    out.append(C.wrap("─" * 64, C.CYAN))
    out.append(C.wrap(" SUMMARY", C.BOLD))
    for v in VERDICT_ORDER:
        c = VERDICT_COLOR.get(v, C.RESET)
        out.append(f"   {C.wrap(f'{v:<12}', c)} {counts.get(v, 0)}")
    out.append(f"   {C.wrap('TOTAL       ', C.BOLD)} {len(findings)}")

    review = [f for f in findings if f.verdict == "REVIEW"]
    needs = [f for f in findings if f.verdict == "NEEDS_POC"]
    out.append("")
    out.append(C.wrap(" ACTION ITEMS", C.BOLD))
    if review:
        out.append(C.wrap(f"   ▶ Submit/verify {len(review)} REVIEW finding(s):", C.GREEN))
        for f in review:
            out.append(f"       • #{f.id} {f.title}")
    if needs:
        out.append(C.wrap(f"   ▶ Build PoC for {len(needs)} finding(s):", C.YELLOW))
        for f in needs:
            out.append(f"       • #{f.id} {f.title}")
    if not review and not needs:
        out.append(C.wrap("   ✓ Nothing actionable — all out-of-scope or informational.", C.GREY))

    out.append(C.wrap("═" * 64, C.CYAN))
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bb_triage.py",
        description="Triage PentestGPT scan logs against bug bounty out-of-scope rules.",
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument("--log", metavar="FILE", help="Path to a PentestGPT scan log.")
    src.add_argument("--stdin", action="store_true", help="Read log from stdin.")
    p.add_argument("--program", help="Program name for built-in rules "
                   f"({', '.join(BUILTIN_RULES)}). Auto-detected from the log "
                   "when omitted.")
    p.add_argument("--rules", metavar="JSON", help="Custom rules JSON (overrides/extends built-ins).")
    p.add_argument("--target", help="Only triage findings whose target/body matches this substring.")
    p.add_argument("--json-out", metavar="FILE", help="Write structured results to a JSON file.")
    p.add_argument("--list-programs", action="store_true", help="List built-in programs and exit.")
    p.add_argument("--self-test", action="store_true",
                   help="Run the impact-filter self-tests and exit.")
    p.add_argument("--detect", action="store_true",
                   help="Print auto-detected PROGRAM/SCOPE (shell-eval'able) and exit.")
    p.add_argument("--no-color", action="store_true", help="Disable colored output.")
    return p


def list_programs() -> None:
    print(C.wrap("Built-in programs:", C.BOLD))
    for name, rules in BUILTIN_RULES.items():
        nt = len(rules["out_of_scope_vuln_types"])
        nk = len(rules["out_of_scope_keywords"])
        print(f"  {C.wrap(name, C.CYAN, C.BOLD):<12} "
              f"{nt} vuln-type patterns, {nk} keywords")


def read_input(args: argparse.Namespace) -> str:
    if args.stdin:
        return sys.stdin.read()
    if args.log:
        with open(args.log, "r", encoding="utf-8") as fh:
            return fh.read()
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return ""


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.no_color or not sys.stdout.isatty():
        C.disable()

    if args.list_programs:
        list_programs()
        return 0

    if args.self_test:
        return run_self_tests()

    text = read_input(args)
    if not text.strip():
        # Genuine "no source" error only when nothing was wired up at all.
        has_source = bool(args.log or args.stdin or not sys.stdin.isatty())
        if not has_source:
            sys.stderr.write(
                C.wrap("error: no input. Use --log FILE, --stdin, or pipe data.\n", C.RED)
            )
            return 2
        # Empty file / pipe — not an error; just no findings to parse.
        sys.stderr.write(C.wrap("No findings parsed (empty log).\n", C.CYAN))
        program = args.program or _DEFAULT_PROGRAM
        if args.json_out:
            payload = {
                "program": program,
                "target": getattr(args, "target", None),
                "total": 0,
                "summary": {v: 0 for v in VERDICT_ORDER},
                "findings": [],
            }
            with open(args.json_out, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
            sys.stderr.write(C.wrap(f"\nWrote JSON results to {args.json_out}\n", C.GREEN))
        return 1  # exit 1 = nothing actionable (same as a log with 0 REVIEW findings)

    # Auto-detect program + scope from the log so callers don't have to pass
    # them. An explicit --program always wins over detection.
    detected_program = detect_program(text)
    detected_scope = detect_scope(text)
    program = args.program or detected_program

    if args.detect:
        # Machine-readable for `eval "$(bb_triage.py --log X --detect)"`.
        print(f"PROGRAM={program}")
        print(f"SCOPE={detected_scope or ''}")
        return 0

    if not args.program:
        sys.stderr.write(
            C.wrap(f"[auto] program: {program} | scope: {detected_scope or '(unknown)'}\n",
                   C.CYAN)
        )

    # A program with no specific configuration must NEVER fall back to an empty
    # rule set (which would pass all noise as in-scope). load_rules() resolves it
    # to the generic hackerone baseline; tell the user that is what happened.
    if program not in BUILTIN_RULES:
        sys.stderr.write(
            C.wrap(f"[info] program '{program}' not specifically configured — "
                   "using generic hackerone OOS rules\n", C.CYAN)
        )

    rules = load_rules(program, args.rules)
    findings = parse_log(text)

    if args.target:
        needle = args.target.lower()
        findings = [
            f for f in findings
            if needle in f.target.lower() or needle in f.raw.lower()
        ]

    findings = run_triage(findings, rules)

    print(render_report(findings, program, args.target))

    if args.json_out:
        payload = {
            "program": program,
            "target": args.target,
            "total": len(findings),
            "summary": {
                v: sum(1 for f in findings if f.verdict == v) for v in VERDICT_ORDER
            },
            "findings": [f.to_dict() for f in findings],
        }
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        sys.stderr.write(C.wrap(f"\nWrote JSON results to {args.json_out}\n", C.GREEN))

    actionable = any(f.verdict in ("REVIEW", "NEEDS_POC") for f in findings)
    return 0 if actionable else 1


if __name__ == "__main__":
    raise SystemExit(main())
