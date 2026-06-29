#!/usr/bin/env python3
"""summary.py — Stage 4: the one screen worth acting on.

Consolidates verdict (bb_triage) + scope (scope_check) + live verification
(verify_findings) from the verified JSON into a single prioritised view:

  ✅ ACTIONABLE      in-scope, VERIFIED, in-scope vuln type — submit/work these.
  ⚠ NEEDS A LOOK     in-scope but UNVERIFIED — live check contradicted the
                     report (403/404/501/no URL); a human decides.
  🔶 WRONG SCOPE     host outside the scope pattern — wildcard may still cover
                     it, so verify scope manually before discarding.
  ··· filtered       OUT_OF_SCOPE vuln types / informational / SKIP — hidden.

Usage
-----
    summary.py --in scan_triage_scoped_verified.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bb_triage import C  # noqa: E402


def _is_actionable(f: dict) -> bool:
    return (
        f.get("verdict") in ("REVIEW", "NEEDS_POC")
        and f.get("scope", "IN_SCOPE") == "IN_SCOPE"
        and f.get("verification", {}).get("status") == "VERIFIED"
    )


def _needs_look(f: dict) -> bool:
    return (
        f.get("verdict") in ("REVIEW", "NEEDS_POC")
        and f.get("scope", "IN_SCOPE") == "IN_SCOPE"
        and f.get("verification", {}).get("status") == "UNVERIFIED"
    )


def render(data: dict) -> str:
    findings = data.get("findings", [])
    actionable = [f for f in findings if _is_actionable(f)]
    needs = [f for f in findings if _needs_look(f)]
    wrong = [f for f in findings if f.get("scope") == "WRONG_SCOPE"]

    out: list[str] = []
    out.append(C.wrap("═" * 64, C.CYAN))
    out.append(C.wrap(" FINAL TRIAGE SUMMARY", C.BOLD, C.CYAN)
               + C.wrap(f"   program: {data.get('program', '?')}"
                        f"  scope: {data.get('scope_pattern', '?')}", C.DIM))
    out.append(C.wrap("═" * 64, C.CYAN))

    out.append(C.wrap(f" ✅ ACTIONABLE  (in-scope + verified)   [{len(actionable)}]", C.BOLD, C.GREEN))
    if actionable:
        for f in actionable:
            hosts = ", ".join(f.get("in_scope_hosts", []) or f.get("hosts", []))
            out.append(f"    • #{f.get('id')} [{f.get('severity', '-')}] {f.get('title')}"
                       + C.wrap(f"  — {hosts}", C.DIM))
            out.append(C.wrap(f"        {f.get('verification', {}).get('reason', '')}", C.GREY))
    else:
        out.append(C.wrap("    (nothing fully verified — see NEEDS A LOOK below)", C.GREY))

    out.append("")
    out.append(C.wrap(f" ⚠  NEEDS A LOOK  (in-scope, live check failed)   [{len(needs)}]", C.BOLD, C.YELLOW))
    for f in needs:
        out.append(f"    • #{f.get('id')} [{f.get('severity', '-')}] {f.get('title')}")
        out.append(C.wrap(f"        {f.get('verification', {}).get('reason', '')}", C.GREY))

    out.append("")
    out.append(C.wrap(f" 🔶 WRONG SCOPE  (verify scope manually)   [{len(wrong)}]", C.BOLD, C.MAGENTA))
    for f in wrong:
        hosts = ", ".join(f.get("out_of_scope_hosts", []))
        out.append(f"    • #{f.get('id')} [{f.get('severity', '-')}] {f.get('title')}"
                   + C.wrap(f"  — {hosts}", C.DIM))

    # Counts of what we hid, for transparency.
    hidden = [f for f in findings
              if f not in actionable and f not in needs and f not in wrong]
    out.append("")
    out.append(C.wrap("─" * 64, C.CYAN))
    out.append(C.wrap(f" filtered out (out-of-scope vuln type / informational): {len(hidden)}", C.GREY))
    out.append(C.wrap("═" * 64, C.CYAN))
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="summary.py",
        description="Print the final actionable summary from a verified triage JSON.",
    )
    p.add_argument("--in", dest="infile", required=True,
                   help="Verified JSON from verify_findings.py.")
    p.add_argument("--no-color", action="store_true", help="Disable colored output.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.no_color or not sys.stdout.isatty():
        C.disable()
    with open(args.infile, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    print(render(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
