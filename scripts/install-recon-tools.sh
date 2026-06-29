#!/usr/bin/env bash
# =============================================================================
# install-recon-tools.sh — install the modern toolset that powers `reconx`.
#
# reconx degrades gracefully (curl/dig/nmap fallbacks), but with these tools it
# matches the depth of reconFTW / Sn1per / Osmedeus. Every install is best-effort
# so a single failure never breaks the Docker build.
#
# Skip entirely with: RECONX_SKIP_TOOLS=1
# =============================================================================
set -u

if [ "${RECONX_SKIP_TOOLS:-0}" = "1" ]; then
  echo "[install-recon-tools] RECONX_SKIP_TOOLS=1 — skipping modern toolset."
  exit 0
fi

GOBIN_DIR="/usr/local/bin"
log()  { printf '[install-recon-tools] %s\n' "$*"; }
warn() { printf '[install-recon-tools] WARN: %s\n' "$*" >&2; }

# ---- 1. Ensure Go (needed to `go install` the Go-based tools) --------------
if ! command -v go >/dev/null 2>&1; then
  log "installing Go toolchain"
  GO_VER="1.23.4"
  ARCH="$(uname -m)"; case "$ARCH" in x86_64) GOARCH=amd64 ;; aarch64|arm64) GOARCH=arm64 ;; *) GOARCH=amd64 ;; esac
  if curl -fsSL "https://go.dev/dl/go${GO_VER}.linux-${GOARCH}.tar.gz" -o /tmp/go.tgz; then
    rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz && rm -f /tmp/go.tgz
  else
    warn "could not download Go — Go-based tools will be skipped"
  fi
fi
export PATH="/usr/local/go/bin:${PATH}"
export GOBIN="$GOBIN_DIR"
export GOPATH="${GOPATH:-/root/go}"
export GOFLAGS="-buildvcs=false"

go_install() {
  local name="$1" pkg="$2"
  command -v go >/dev/null 2>&1 || { warn "go missing — skip $name"; return; }
  log "go install $name"
  if go install "$pkg" >/dev/null 2>&1; then
    log "  installed $name -> $GOBIN_DIR"
  else
    warn "failed to install $name ($pkg)"
  fi
}

# ---- 2. ProjectDiscovery suite + classic Go tools --------------------------
# Core surface mapping (reconFTW + Osmedeus + Sn1per shared toolset)
go_install subfinder   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
go_install httpx       "github.com/projectdiscovery/httpx/cmd/httpx@latest"
go_install dnsx        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
go_install naabu       "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
go_install nuclei      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
go_install assetfinder "github.com/tomnomnom/assetfinder@latest"
go_install ffuf        "github.com/ffuf/ffuf/v2@latest"
# reconFTW-style depth: takeover, historical URLs, crawling, JS; + screenshots
go_install subjack     "github.com/haccer/subjack@latest"
go_install gau         "github.com/lc/gau/v2/cmd/gau@latest"
go_install waybackurls "github.com/tomnomnom/waybackurls@latest"
go_install katana      "github.com/projectdiscovery/katana/cmd/katana@latest"
go_install gowitness   "github.com/sensepost/gowitness@latest"

# ---- 3. Nuclei templates (best-effort; nuclei also self-updates on first run)
if command -v nuclei >/dev/null 2>&1; then
  log "downloading nuclei templates"
  nuclei -update-templates >/dev/null 2>&1 || warn "nuclei template update failed (will retry at runtime)"
fi

# ---- 4. Report ------------------------------------------------------------
log "tool availability:"
for t in subfinder httpx dnsx naabu nuclei ffuf assetfinder subjack gau waybackurls katana gowitness wafw00f whatweb nmap dig jq curl; do
  if command -v "$t" >/dev/null 2>&1; then printf '  [x] %s\n' "$t"; else printf '  [ ] %s (reconx will use a fallback)\n' "$t"; fi
done
log "done."
exit 0
