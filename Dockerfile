# PentestGPT Docker Image
# Lightweight penetration testing environment with PentestGPT

FROM ubuntu:24.04

LABEL description="PentestGPT - AI-Powered Penetration Testing Assistant"
LABEL version="1.0.0"

# Prevent interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Update and install system dependencies
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
    # Build essentials
    build-essential \
    software-properties-common \
    ca-certificates \
    gnupg \
    # Python
    python3.12 \
    python3-pip \
    python3-venv \
    python3-dev \
    # Essential pentesting tools
    nmap \
    netcat-openbsd \
    curl \
    wget \
    git \
    sudo \
    # reconx toolset: web fingerprint, WAF detect, content-discovery wordlists, naabu's libpcap
    whatweb \
    wafw00f \
    dirb \
    libpcap-dev \
    # Network utilities
    net-tools \
    dnsutils \
    whois \
    # VPN (for HackTheBox/TryHackMe connectivity)
    openvpn \
    # Text processing
    jq \
    ripgrep \
    # Terminal
    tmux \
    && apt-get autoremove -y \
    && apt-get autoclean \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js v20 (required for Claude Code Router)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# Remove EXTERNALLY-MANAGED marker to allow pip installs in Docker
# Also remove system Python packages that conflict with dependencies
RUN rm -f /usr/lib/python3.*/EXTERNALLY-MANAGED && \
    apt-get remove -y python3-cryptography && \
    apt-get autoremove -y

# Install Claude Code Router globally (for OpenRouter/local LLM support)
RUN npm install -g @musistudio/claude-code-router

# Create non-root user
RUN useradd -m -s /bin/bash pentester && \
    usermod -aG sudo pentester && \
    echo "pentester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set up working directories (including ccr config)
RUN mkdir -p /workspace /app /home/pentester/.claude /home/pentester/.claude-code-router && \
    chown -R pentester:pentester /workspace /app /home/pentester/.claude /home/pentester/.claude-code-router

# Switch to pentester user
USER pentester
WORKDIR /app

# Install Claude Code CLI (native installer — no npm needed)
RUN curl -fsSL https://claude.ai/install.sh | bash

# Install uv for Python dependency management
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

ENV PATH="/home/pentester/.local/bin:$PATH"

# --- Unified recon engine (reconx) + its modern toolset ---
# reconx distills reconFTW + Sn1per + Osmedeus into one engine. It runs with just
# the base tools above (graceful fallbacks), and the installer adds the modern
# suite (subfinder/httpx/dnsx/naabu/nuclei/ffuf/...) for full depth.
# Installed BEFORE the app source so editing pentestgpt/ does not re-trigger the
# (slow) Go toolchain install. Set RECONX_SKIP_TOOLS=1 to skip the heavy installs.
COPY recon/ /app/recon/
COPY scripts/install-recon-tools.sh /app/scripts/install-recon-tools.sh
ARG RECONX_SKIP_TOOLS=0
ENV RECONX_SKIP_TOOLS=${RECONX_SKIP_TOOLS}
USER root
RUN install -m 0755 /app/recon/reconx /usr/local/bin/reconx && \
    chmod +x /app/scripts/install-recon-tools.sh && \
    /app/scripts/install-recon-tools.sh || true
USER pentester

# Copy project files (changes here no longer invalidate the recon-tools layer)
COPY --chown=pentester:pentester pyproject.toml README.md /app/
COPY --chown=pentester:pentester pentestgpt/ /app/pentestgpt/
COPY --chown=pentester:pentester scripts/entrypoint.sh /home/pentester/entrypoint.sh
COPY --chown=pentester:pentester scripts/pentestgpt-setup.sh /app/scripts/pentestgpt-setup.sh
COPY --chown=pentester:pentester scripts/ccr-config-template.json /app/scripts/ccr-config-template.json

# Install Python dependencies as root to system Python
ENV PIP_BREAK_SYSTEM_PACKAGES=1
USER root
RUN /home/pentester/.local/bin/uv pip install --system /app && \
    chmod +x /home/pentester/entrypoint.sh && \
    install -m 0755 /app/scripts/pentestgpt-setup.sh /usr/local/bin/pentestgpt-setup

# Switch back to pentester user for runtime
USER pentester

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Default working directory for penetration tests
WORKDIR /workspace

# Use entrypoint script for auth setup
ENTRYPOINT ["/home/pentester/entrypoint.sh"]

# Default command - interactive bash
# Users can run: pentestgpt --target X
CMD ["/bin/bash"]
