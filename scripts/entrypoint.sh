#!/usr/bin/env bash
# PentestGPT Container Entrypoint
# Sets up authentication based on PENTESTGPT_AUTH_MODE environment variable

set -e

AUTH_MODE="${PENTESTGPT_AUTH_MODE:-manual}"
CCR_CONFIG_DIR="/home/pentester/.claude-code-router"
CCR_CONFIG_FILE="${CCR_CONFIG_DIR}/config.json"
BASHRC_FILE="/home/pentester/.bashrc"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Router configurations for different modes
OPENROUTER_ROUTER='{"default":"openrouter,openai/gpt-5.1","background":"openrouter,openai/gpt-5.1","think":"openrouter,openai/gpt-5.1","longContext":"openrouter,openai/gpt-5.1","longContextThreshold":60000,"webSearch":"openrouter,google/gemini-3-pro-preview"}'
LOCAL_ROUTER='{"default":"localLLM,openai/gpt-oss-20b","background":"localLLM,openai/gpt-oss-20b","think":"localLLM,qwen/qwen3-coder-30b","longContext":"localLLM,qwen/qwen3-coder-30b","longContextThreshold":60000,"webSearch":"localLLM,openai/gpt-oss-20b"}'

setup_ccr() {
    local mode="$1"
    local api_key="$2"
    local template_file="/app/scripts/ccr-config-template.json"

    # Create CCR config directory if needed
    mkdir -p "$CCR_CONFIG_DIR"

    # Check if template exists
    if [ ! -f "$template_file" ]; then
        echo -e "${YELLOW}Error: CCR config template not found at $template_file${NC}"
        exit 1
    fi

    # Copy template and substitute placeholders
    cp "$template_file" "$CCR_CONFIG_FILE"

    # Substitute API key (for openrouter mode)
    if [ -n "$api_key" ]; then
        sed -i "s/__OPENROUTER_API_KEY__/${api_key}/g" "$CCR_CONFIG_FILE"
    fi

    # Substitute Router config based on mode (use | as delimiter to avoid conflicts with /)
    if [ "$mode" = "openrouter" ]; then
        sed -i "s|\"__ROUTER_CONFIG__\"|${OPENROUTER_ROUTER}|g" "$CCR_CONFIG_FILE"
        local display_model="openai/gpt-5.1"
    else
        sed -i "s|\"__ROUTER_CONFIG__\"|${LOCAL_ROUTER}|g" "$CCR_CONFIG_FILE"
        local display_model="localLLM (qwen/qwen3-coder-30b, openai/gpt-oss-20b)"
    fi

    echo -e "${BLUE}Starting Claude Code Router...${NC}"

    # Start CCR daemon (nohup to keep it running)
    nohup ccr start > /tmp/ccr.log 2>&1 &

    # Wait for CCR to be ready
    sleep 2

    # Check if CCR is running by testing the port
    if nc -z 127.0.0.1 3456 2>/dev/null; then
        echo -e "${GREEN}CCR daemon running on port 3456${NC}"
    else
        echo -e "${YELLOW}Warning: CCR may not have started properly. Check /tmp/ccr.log${NC}"
    fi

    # Add CCR activation to .bashrc so it persists in interactive shells
    # Remove any existing ccr activation lines first
    sed -i '/# CCR activation/d' "$BASHRC_FILE" 2>/dev/null || true
    sed -i '/eval "$(ccr activate)"/d' "$BASHRC_FILE" 2>/dev/null || true

    # Add ccr activation to bashrc
    echo "# CCR activation for ${mode}" >> "$BASHRC_FILE"
    echo 'eval "$(ccr activate 2>/dev/null)" || true' >> "$BASHRC_FILE"

    # Also export for the current session (will be inherited by exec'd shell)
    eval "$(ccr activate 2>/dev/null)" || true

    echo -e "${GREEN}CCR activated with ${mode} backend${NC}"
    echo -e "${BLUE}Default model: ${display_model}${NC}"
}

# --- First-run setup: pick Free/Paid plan + paste Cloudflare creds ---
# Saved config (plan + creds + budgets) persists in the bind-mounted workspace,
# so the wizard only runs the first time. Re-run `pentestgpt-setup` to change.
SETUP_FILE="${PENTESTGPT_SETUP_FILE:-/workspace/.pentestgpt-setup.env}"
if [ -f "$SETUP_FILE" ]; then
    # shellcheck disable=SC1090
    . "$SETUP_FILE"
elif [ -t 0 ] && [ -x /usr/local/bin/pentestgpt-setup ]; then
    /usr/local/bin/pentestgpt-setup || true
    if [ -f "$SETUP_FILE" ]; then
        # shellcheck disable=SC1090
        . "$SETUP_FILE"
    fi
fi

echo ""
echo -e "${BLUE}=== PentestGPT Agent Brain ===${NC}"
echo -e "${GREEN}Brain: GLM 5.2 via Cloudflare Workers AI${NC} (model: ${CLOUDFLARE_MODEL:-@cf/zai-org/glm-5.2})"
if [ -n "${CLOUDFLARE_ACCOUNT_ID:-}" ] && [ -n "${CLOUDFLARE_API_TOKEN:-}" ]; then
    echo -e "Plan: ${GREEN}${PENTESTGPT_PLAN:-free}${NC}  |  per-scan: ${GREEN}${CF_MAX_TOKENS_PER_SCAN:-10000}${NC} neurons  |  creds: ${GREEN}set${NC}"
    echo -e "${BLUE}(switch plan / update creds anytime:${NC} ${GREEN}pentestgpt-setup${BLUE})${NC}"
else
    echo -e "${YELLOW}No credentials yet — run ${GREEN}pentestgpt-setup${YELLOW} to choose a plan and log in.${NC}"
fi
echo -e "${BLUE}==============================${NC}"
echo ""

# --- Bug-bounty workflow: make /workspace scripts runnable on every start ---
# /workspace is a host bind-mount and is gitignored, so the executable bit is
# not version-controlled and can be stripped whenever files are created/edited
# from the host (e.g. via Windows/WSL sync). Re-apply +x here so the wrapper and
# bb-triage scripts are always runnable in a fresh container, and put /workspace
# on PATH so both `/workspace/bb` and bare `bb` work.
if [ -d /workspace ]; then
    [ -f /workspace/bb ] && chmod +x /workspace/bb 2>/dev/null || true
    if [ -d /workspace/bb-triage ]; then
        chmod +x /workspace/bb-triage/*.sh /workspace/bb-triage/*.py 2>/dev/null || true
    fi
fi

# Ensure /workspace is on PATH for interactive shells too (persists via .bashrc).
case ":${PATH}:" in
    *":/workspace:"*) ;;
    *) export PATH="/workspace:${PATH}" ;;
esac
sed -i '/# bb workspace PATH/d' "$BASHRC_FILE" 2>/dev/null || true
sed -i '\#export PATH="/workspace:\$PATH"#d' "$BASHRC_FILE" 2>/dev/null || true
echo '# bb workspace PATH' >> "$BASHRC_FILE"
echo 'export PATH="/workspace:$PATH"' >> "$BASHRC_FILE"

# Execute the passed command or start bash
# Use bash -l to ensure .bashrc is sourced (for ccr activation)
if [ "$1" = "/bin/bash" ]; then
    exec /bin/bash --login
else
    exec "$@"
fi
