#!/usr/bin/env bash
#
# run_triage.sh — full triage pipeline for a PentestGPT scan log.
#
#   ./run_triage.sh <logfile> [program] [scope_pattern]
#
# Only the logfile is required: program and scope are auto-detected from the
# log content when omitted (see bb_triage.py detect_program/detect_scope).
# Pass them only to override detection.
#
#   ./run_triage.sh /workspace/scan-2026-06-25_004630.log          # auto
#   ./run_triage.sh /workspace/scan-2026-06-25_004630.log dstny "*.myfone.dk"
#
# Four stages, each writing a JSON beside the log so you can inspect any step:
#
#   1. bb_triage.py       parse findings, drop out-of-scope *vuln types*
#                         (missing headers, rate-limit, ...)  -> _triage.json
#   2. scope_check.py     tag findings IN_SCOPE / WRONG_SCOPE vs the scope
#                         pattern, so crawl drift to sibling roots
#                         (sippeer.dk, flexgateway.io) is flagged not buried
#                                                            -> _scoped.json
#   3. verify_findings.py curl each REVIEW/NEEDS_POC finding's PoC URL and
#                         downgrade the ones that don't hold up live
#                         (trace.axd 403, HTTP TRACE 501)     -> _verified.json
#   4. summary.py         print only VERIFIED + IN_SCOPE as actionable.
#
# Scope pattern grammar (comma-separated):
#   api.myfone.dk                  exact host
#   *.myfone.dk                    apex + all subdomains
#   *.myfone.dk,*.flexgateway.io   multiple patterns
set -uo pipefail

LOGFILE="${1:-}"
PROGRAM="${2:-}"
SCOPE="${3:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -z "$LOGFILE" ]]; then
    echo "Usage: $0 <logfile> [program] [scope_pattern]" >&2
    echo "  e.g. $0 /workspace/scan-2026-06-25_004630.log   # auto-detect" >&2
    exit 1
fi
if [[ ! -f "$LOGFILE" ]]; then
    echo "error: log file not found: $LOGFILE" >&2
    exit 1
fi

PY="$(command -v python3 || command -v python)"
if [[ -z "$PY" ]]; then
    echo "error: python3 not found on PATH" >&2
    exit 1
fi

# Fill in any missing program/scope by auto-detecting from the log content.
if [[ -z "$PROGRAM" || -z "$SCOPE" ]]; then
    DETECT="$("$PY" "$SCRIPT_DIR/bb_triage.py" --log "$LOGFILE" --detect)"
    DET_PROGRAM="$(printf '%s\n' "$DETECT" | sed -n 's/^PROGRAM=//p')"
    DET_SCOPE="$(printf '%s\n' "$DETECT" | sed -n 's/^SCOPE=//p')"
    PROGRAM="${PROGRAM:-$DET_PROGRAM}"
    SCOPE="${SCOPE:-$DET_SCOPE}"
    echo "[auto] program: $PROGRAM | scope: ${SCOPE:-(unknown)}"
fi

BASE="${LOGFILE%.log}"
TRIAGE_JSON="${BASE}_triage.json"
SCOPED_JSON="${BASE}_scoped.json"
VERIFIED_JSON="${BASE}_verified.json"

echo "[run_triage] program: $PROGRAM | scope: $SCOPE | log: $LOGFILE"
echo

# Stage 1 — triage (vuln-type out-of-scope filtering). Exit 1 just means
# "nothing actionable"; later stages still run so the report is complete.
echo "── stage 1/4: triage ─────────────────────────────────────────"
"$PY" "$SCRIPT_DIR/bb_triage.py" \
    --log "$LOGFILE" \
    --program "$PROGRAM" \
    --json-out "$TRIAGE_JSON"

# Stage 2 — scope check (wrong-domain filtering). Skipped if scope is unknown
# (no detectable target); stage 3 then runs straight off the triage output.
echo
echo "── stage 2/4: scope check ────────────────────────────────────"
if [[ -n "$SCOPE" ]]; then
    "$PY" "$SCRIPT_DIR/scope_check.py" \
        --in "$TRIAGE_JSON" \
        --scope "$SCOPE" \
        --out "$SCOPED_JSON" || true
else
    echo "[skip] no scope detected — passing triage output through unchanged"
    cp "$TRIAGE_JSON" "$SCOPED_JSON" 2>/dev/null || true
fi

# Stage 3 — live verification of REVIEW/NEEDS_POC findings.
echo
echo "── stage 3/4: verify (live curl) ─────────────────────────────"
"$PY" "$SCRIPT_DIR/verify_findings.py" \
    --in "$SCOPED_JSON" \
    --out "$VERIFIED_JSON" || true

# Stage 4 — final actionable summary.
echo
echo "── stage 4/4: final summary ──────────────────────────────────"
"$PY" "$SCRIPT_DIR/summary.py" --in "$VERIFIED_JSON" || true

echo
echo "[run_triage] artifacts:"
echo "   triage   : $TRIAGE_JSON"
echo "   scoped   : $SCOPED_JSON"
echo "   verified : $VERIFIED_JSON"
