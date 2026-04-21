#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  Fatah2 — One-command installer
#  Crafted by Pr0fessor SnApe
#
#  Usage:   bash install.sh
#  Supports: Kali · Parrot · Arch · Ubuntu/Debian · Fedora/RHEL
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
R='\033[1;31m' G='\033[1;32m' Y='\033[1;33m'
C='\033[1;36m' P='\033[1;35m' D='\033[0;90m' N='\033[0m'

banner() {
cat << 'EOF'

  ███████╗ █████╗ ████████╗ █████╗ ██╗  ██╗██████╗
  ██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██║  ██║╚════██╗
  █████╗  ███████║   ██║   ███████║███████║ █████╔╝
  ██╔══╝  ██╔══██║   ██║   ██╔══██║██╔══██║██╔═══╝
  ██║     ██║  ██║   ██║   ██║  ██║██║  ██║███████╗
  ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝

EOF
echo -e "  ${P}Advanced Recon Suite  ·  v1.0.0${N}"
echo -e "  ${D}Crafted by Pr0fessor SnApe${N}"
echo -e "  ${D}──────────────────────────────────${N}\n"
}

ok()   { echo -e "  ${G}[✓]${N} $*"; }
info() { echo -e "  ${C}[*]${N} $*"; }
warn() { echo -e "  ${Y}[!]${N} $*"; }
err()  { echo -e "  ${R}[✗]${N} $*"; }
sep()  { echo -e "  ${D}──────────────────────────────────${N}"; }

banner

# ── Detect package manager ────────────────────────────────────────────────────
if   command -v apt-get &>/dev/null; then PKG=apt
elif command -v pacman  &>/dev/null; then PKG=pacman
elif command -v dnf     &>/dev/null; then PKG=dnf
elif command -v yum     &>/dev/null; then PKG=yum
else
  err "No supported package manager found."
  err "Install: python3, pip3, golang, git manually, then re-run."
  exit 1
fi
info "Package manager: $PKG"

# ── System packages ───────────────────────────────────────────────────────────
info "Installing system dependencies..."
case "$PKG" in
  apt)
    sudo apt-get update -qq 2>/dev/null
    sudo apt-get install -y -qq git curl wget python3 python3-pip \
      python3-venv golang-go massdns 2>/dev/null || true
    ;;
  pacman)
    sudo pacman -Sy --noconfirm git curl wget python python-pip go \
      massdns 2>/dev/null || true
    ;;
  dnf|yum)
    sudo "$PKG" install -y -q git curl wget python3 python3-pip \
      golang 2>/dev/null || true
    warn "massdns may need manual build on RPM systems"
    ;;
esac
ok "System packages ready"

# ── Go PATH ───────────────────────────────────────────────────────────────────
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$GOPATH/bin:$PATH"
if ! grep -q 'go/bin' ~/.bashrc 2>/dev/null; then
  echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.bashrc
  info "Added Go bin to ~/.bashrc"
fi

# ── Check Go ─────────────────────────────────────────────────────────────────
if ! command -v go &>/dev/null; then
  err "Go not found. Install from https://go.dev/dl/ then re-run this script."
  exit 1
fi
ok "Go: $(go version | awk '{print $3}')"

# ── Install Go tools ──────────────────────────────────────────────────────────
sep
info "Installing Go-based recon tools..."

go_install() {
  local name=$1 pkg=$2
  if command -v "$name" &>/dev/null; then
    ok "$name already installed"
  else
    info "Installing $name ..."
    if go install "$pkg" 2>/dev/null; then
      ok "$name installed"
    else
      warn "$name failed — will be skipped during scans"
    fi
  fi
}

go_install subfinder   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
go_install assetfinder "github.com/tomnomnom/assetfinder@latest"
go_install httpx       "github.com/projectdiscovery/httpx/cmd/httpx@latest"
go_install katana      "github.com/projectdiscovery/katana/cmd/katana@latest"
go_install amass       "github.com/owasp-amass/amass/v4/...@master"

# ── Install Sublist3r ─────────────────────────────────────────────────────────
sep
info "Installing Sublist3r..."
if command -v sublist3r &>/dev/null; then
  ok "Sublist3r already installed"
else
  if pip3 install sublist3r --break-system-packages -q 2>/dev/null || \
     pip3 install sublist3r -q 2>/dev/null; then
    ok "Sublist3r installed via pip"
  else
    warn "pip install failed — trying git clone..."
    git clone --depth=1 https://github.com/aboul3la/Sublist3r.git \
      /opt/Sublist3r 2>/dev/null || true
    if [ -f /opt/Sublist3r/sublist3r.py ]; then
      sudo ln -sf /opt/Sublist3r/sublist3r.py /usr/local/bin/sublist3r
      pip3 install -r /opt/Sublist3r/requirements.txt \
        --break-system-packages -q 2>/dev/null || true
      ok "Sublist3r installed from source"
    else
      warn "Sublist3r not installed — will be skipped"
    fi
  fi
fi

# ── Python virtualenv ─────────────────────────────────────────────────────────
sep
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/.venv"

info "Creating Python virtual environment..."
python3 -m venv "$VENV"
source "$VENV/bin/activate"
pip install --upgrade pip -q
pip install -r "$SCRIPT_DIR/requirements.txt" -q
ok "Python environment ready at $VENV"

# ── Output directories ────────────────────────────────────────────────────────
mkdir -p "$SCRIPT_DIR/reports" "$SCRIPT_DIR/logs"
ok "Output directories created"

# ── Global wrapper ────────────────────────────────────────────────────────────
WRAPPER="/usr/local/bin/fatah2"
sudo tee "$WRAPPER" > /dev/null << WRAPPER
#!/usr/bin/env bash
source "$VENV/bin/activate"
exec python3 "$SCRIPT_DIR/fatah2.py" "\$@"
WRAPPER
sudo chmod +x "$WRAPPER"
ok "Global command installed: fatah2"

# ── Summary ───────────────────────────────────────────────────────────────────
sep
echo ""
echo -e "  ${G}Installation complete!${N}"
echo ""
echo -e "  ${C}Quick start:${N}"
echo -e "    ${P}fatah2${N}                          ← interactive mode"
echo -e "    ${P}fatah2 -d example.com${N}           ← direct scan"
echo -e "    ${P}fatah2 -d example.com --depth deep${N}"
echo -e "    ${P}fatah2 serve --port 8080${N}        ← API server"
echo ""
echo -e "  ${C}Tool status:${N}"
for tool in subfinder assetfinder amass katana httpx sublist3r massdns; do
  if command -v "$tool" &>/dev/null; then
    echo -e "    ${G}✓${N}  $tool"
  else
    echo -e "    ${Y}✗${N}  $tool ${D}(not found — scanner skipped automatically)${N}"
  fi
done
echo ""
echo -e "  ${D}Fatah2 — crafted by Pr0fessor SnApe${N}"
echo ""
