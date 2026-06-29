#!/usr/bin/env python3
"""scope_check.py — flag findings that drift outside the program scope.

PentestGPT crawls links it discovers, so a scan seeded at ``api.myfone.dk``
ends up reporting on ``v3.myfone.dk``, ``liveproxy.sippeer.dk`` and the
internal ``flexgateway.int`` gateway too. Some of those are in scope (the
program's wildcard covers ``*.myfone.dk``) and some are not — and we kept
wasting time manually deciding which.

This stage reads the ``_triage.json`` produced by ``bb_triage.py``, compares
each finding's affected host(s) against a scope pattern, and tags the finding:

  IN_SCOPE     at least one affected host matches the scope pattern.
  WRONG_SCOPE  the finding has host(s), none of which match the scope.

WRONG_SCOPE findings are NOT dropped — a wildcard program may legitimately
cover a sibling root, so they are shown separately with a
"verify scope manually" note for a human to decide.

Scope pattern grammar (comma-separated, any number of entries):
    *.myfone.dk                   wildcard — the apex and every subdomain
    api.myfone.dk                 exact-host — only that one host
    api.x.com,admin.x.com        exact-host list — only those hosts

Scope modes (auto-detected from the pattern):
    wildcard    any pattern contains "*" — subdomains accepted
    exact-host  no "*" anywhere — ONLY the listed hosts match; bare-root
                extension (_looks_like_root) is disabled in this mode

Usage
-----
    scope_check.py --in scan_triage.json --scope "*.myfone.dk"
    scope_check.py --in scan_triage.json --scope "api.myfone.dk" --out scoped.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

# Reuse the color helper and host extractor from the triage module so the two
# stages render and parse hosts identically.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bb_triage import C, extract_hosts  # noqa: E402

SCOPE_COLOR = {
    "IN_SCOPE": C.GREEN,
    "WRONG_SCOPE": C.MAGENTA,
}


# --------------------------------------------------------------------------- #
# Scope matching
# --------------------------------------------------------------------------- #


def parse_scope(pattern: str) -> list[str]:
    """Split a comma/space separated scope spec into normalised patterns."""
    parts = [p.strip().lower().rstrip(".") for p in pattern.replace(" ", ",").split(",")]
    return [p for p in parts if p]


def detect_scope_mode(patterns: list[str]) -> str:
    """'wildcard' if any pattern uses *, else 'exact-host'."""
    return "wildcard" if any("*" in p for p in patterns) else "exact-host"


def host_matches(host: str, pat: str, strict: bool = False) -> bool:
    """True if a single host matches a single scope pattern.

    ``*.example.com`` matches the apex (``example.com``) and any depth of
    subdomain (``a.b.example.com``). A bare ``api.example.com`` matches only
    that exact host. In non-strict mode, a bare ``example.com`` also accepts
    its subdomains (programs that list a root domain almost always mean the
    whole tree). In strict (exact-host) mode, bare-root extension is disabled —
    only the listed host(s) exactly match.
    """
    host = host.lower().rstrip(".")
    if pat.startswith("*."):
        base = pat[2:]
        return host == base or host.endswith("." + base)
    # Exact host match always applies.
    if host == pat:
        return True
    # In strict mode (exact-host scope) never extend bare roots to subdomains.
    if strict:
        return False
    # Bare-root pattern (no wildcard, not a multi-label host like api.x.y):
    # treat a registrable-looking root as covering its subdomains.
    return host.endswith("." + pat) and pat.count(".") >= 1 and "*" not in pat \
        and _looks_like_root(pat)


def _looks_like_root(pat: str) -> bool:
    """Heuristic: a 2-label name (``myfone.dk``) reads as a root domain.

    Three+ labels (``api.myfone.dk``) read as a specific host, so we do NOT
    silently extend them to cover deeper subdomains.
    """
    return pat.count(".") == 1


def host_in_scope(host: str, patterns: list[str], strict: bool = False) -> bool:
    return any(host_matches(host, p, strict=strict) for p in patterns)


def classify(hosts: list[str], patterns: list[str], strict: bool = False) -> dict:
    """Return scope verdict + the in/out host split for a finding."""
    if not hosts:
        return {
            "scope": "IN_SCOPE",
            "scope_reason": "no affected host identified — assumed in-scope",
            "in_scope_hosts": [],
            "out_of_scope_hosts": [],
        }
    in_hosts = [h for h in hosts if host_in_scope(h, patterns, strict=strict)]
    out_hosts = [h for h in hosts if h not in in_hosts]
    if in_hosts:
        reason = "host(s) match scope: " + ", ".join(in_hosts)
        if out_hosts:
            reason += f" (also touches out-of-scope: {', '.join(out_hosts)})"
        return {
            "scope": "IN_SCOPE",
            "scope_reason": reason,
            "in_scope_hosts": in_hosts,
            "out_of_scope_hosts": out_hosts,
        }
    return {
        "scope": "WRONG_SCOPE",
        "scope_reason": "host(s) outside scope: " + ", ".join(out_hosts)
        + " — verify scope manually",
        "in_scope_hosts": [],
        "out_of_scope_hosts": out_hosts,
    }


def _finding_hosts(finding: dict) -> list[str]:
    """Affected hosts for a finding, tolerant of older triage JSON.

    Prefers the ``hosts`` field written by the enriched bb_triage.py; falls
    back to re-extracting from the target/detail for legacy JSON.
    """
    hosts = finding.get("hosts")
    if hosts:
        return hosts
    target = finding.get("target", "")
    target_clean = re.sub(r"\([^)]*\)", " ", target)
    found = extract_hosts(target_clean)
    if found:
        return found
    return extract_hosts(finding.get("detail", ""))


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #


def run(data: dict, patterns: list[str]) -> dict:
    mode = detect_scope_mode(patterns)
    strict = mode == "exact-host"
    sys.stderr.write(f"scope mode: {mode}\n")
    for f in data.get("findings", []):
        f.update(classify(_finding_hosts(f), patterns, strict=strict))
    data["scope_pattern"] = ",".join(patterns)
    data["scope_mode"] = mode
    data["scope_summary"] = {
        s: sum(1 for f in data.get("findings", []) if f.get("scope") == s)
        for s in ("IN_SCOPE", "WRONG_SCOPE")
    }
    return data


def render(data: dict) -> str:
    out: list[str] = []
    mode = data.get("scope_mode", "wildcard")
    out.append(C.wrap("─" * 64, C.CYAN))
    out.append(C.wrap(" SCOPE CHECK", C.BOLD, C.CYAN)
               + C.wrap(f"   scope: {data.get('scope_pattern', '')}"
                        f"   mode: {mode}", C.DIM))
    out.append(C.wrap("─" * 64, C.CYAN))

    findings = data.get("findings", [])
    in_scope = [f for f in findings if f.get("scope") == "IN_SCOPE"]
    wrong = [f for f in findings if f.get("scope") == "WRONG_SCOPE"]

    for f in findings:
        scope = f.get("scope", "IN_SCOPE")
        color = SCOPE_COLOR.get(scope, C.RESET)
        badge = C.wrap(f"{scope:<11}", C.BOLD, color)
        out.append(f"  {badge} #{f.get('id', '?'):<5} {f.get('title', '')}")
        out.append(C.wrap(f"             └─ {f.get('scope_reason', '')}", C.GREY))

    out.append("")
    out.append(C.wrap(" SCOPE SUMMARY", C.BOLD))
    out.append(f"   {C.wrap('IN_SCOPE   ', C.GREEN)} {len(in_scope)}")
    out.append(f"   {C.wrap('WRONG_SCOPE', C.MAGENTA)} {len(wrong)}")
    if wrong:
        out.append("")
        if mode == "exact-host":
            footer = "   ⚠ WRONG_SCOPE findings are outside the exact-host list — do not test:"
        else:
            footer = ("   ⚠ WRONG_SCOPE findings need a manual scope decision "
                      "(wildcard may still cover them):")
        out.append(C.wrap(footer, C.MAGENTA))
        for f in wrong:
            hosts = ", ".join(f.get("out_of_scope_hosts", [])) or "?"
            out.append(f"       • #{f.get('id')} {f.get('title')}  [{hosts}]")
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scope_check.py",
        description="Tag triage findings IN_SCOPE / WRONG_SCOPE against a scope pattern.",
    )
    p.add_argument("--in", dest="infile", required=True,
                   help="Triage JSON produced by bb_triage.py (--json-out).")
    p.add_argument("--scope", required=True,
                   help='Scope pattern: "api.myfone.dk", "*.myfone.dk", '
                        'or "*.myfone.dk,*.flexgateway.io".')
    p.add_argument("--out", dest="outfile",
                   help="Where to write the scoped JSON (default: <in>_scoped.json).")
    p.add_argument("--no-color", action="store_true", help="Disable colored output.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.no_color or not sys.stdout.isatty():
        C.disable()

    patterns = parse_scope(args.scope)
    if not patterns:
        sys.stderr.write(C.wrap("error: empty scope pattern\n", C.RED))
        return 2

    with open(args.infile, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    data = run(data, patterns)
    print(render(data))

    outfile = args.outfile or args.infile.replace(".json", "_scoped.json")
    if outfile == args.infile:
        outfile = args.infile + ".scoped"
    with open(outfile, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    sys.stderr.write(C.wrap(f"\nWrote scoped JSON to {outfile}\n", C.GREEN))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
