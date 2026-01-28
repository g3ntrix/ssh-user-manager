#!/bin/bash

# SSH User Manager - Installation Script
# This script downloads and installs SSH User Manager on your system

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration
REPO_URL="https://github.com/g3ntrix/ssh-user-manager.git"
INSTALL_DIR="/opt/ssh-user-manager"
BIN_LINK="/usr/local/bin/ssh-user-manager"
CONFIG_DIR="/etc/ssh-user-manager"
VERSION="3.0"

# Check root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}This installer requires root privileges${NC}"
    echo "Run with: sudo bash install.sh"
    exit 1
fi

echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║ ${BOLD}SSH User Manager v${VERSION} Installer${NC}${CYAN}      ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
echo ""

# Check dependencies
echo -e "${YELLOW}Checking dependencies...${NC}"
missing_deps=0

check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "  ${RED}✗${NC} $1 is not installed"
        missing_deps=$((missing_deps + 1))
        return 1
    else
        echo -e "  ${GREEN}✓${NC} $1 found"
        return 0
    fi
}

check_command "git"
check_command "iptables"
check_command "useradd"
check_command "chage"
check_command "nethogs" || {
    echo -e "  ${YELLOW}! nethogs will be installed automatically${NC}"
}

echo ""

if [ $missing_deps -gt 0 ] && ! command -v git &> /dev/null; then
    echo -e "${RED}Please install git and try again${NC}"
    exit 1
fi

# Create installation directory
echo -e "${YELLOW}Creating installation directory...${NC}"
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"

# Clone or update repository
if [ -d "$INSTALL_DIR/.git" ]; then
    echo -e "${YELLOW}Updating existing installation...${NC}"
    cd "$INSTALL_DIR"
    git pull origin main 2>/dev/null || git pull origin master 2>/dev/null || true
else
    echo -e "${YELLOW}Downloading SSH User Manager...${NC}"
    if [ -d "$INSTALL_DIR" ] && [ "$(ls -A $INSTALL_DIR)" ]; then
        echo -e "${YELLOW}Backing up existing files...${NC}"
        mv "$INSTALL_DIR" "${INSTALL_DIR}.backup.$(date +%s)"
        mkdir -p "$INSTALL_DIR"
    fi
    git clone "$REPO_URL" "$INSTALL_DIR" 2>/dev/null || {
        echo -e "${RED}Failed to clone repository${NC}"
        echo "Make sure the repository is accessible and try again:"
        echo "  git clone $REPO_URL $INSTALL_DIR"
        exit 1
    }
fi

cd "$INSTALL_DIR"

# Make main script executable
echo -e "${YELLOW}Setting permissions...${NC}"
chmod 755 ssh-user-manager.sh
chmod 755 bin/* 2>/dev/null || true

# Create symlink
echo -e "${YELLOW}Creating command symlink...${NC}"
ln -sf "$INSTALL_DIR/ssh-user-manager.sh" "$BIN_LINK"
chmod 755 "$BIN_LINK"

# Function to setup SSH daemon to allow password authentication
setup_sshd_config() {
    local sshd_config="/etc/ssh/sshd_config"
    
    if [ ! -f "$sshd_config" ]; then
        echo -e "    ${YELLOW}⊘${NC} SSHD config not found"
        return 0
    fi
    
    # Backup original if not already backed up
    if [ ! -f "${sshd_config}.original" ]; then
        cp "$sshd_config" "${sshd_config}.original"
    fi
    
    # Enable password authentication
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' "$sshd_config"
    sed -i 's/^#*KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/' "$sshd_config"
    sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' "$sshd_config"
    sed -i 's/^#*UsePAM.*/UsePAM yes/' "$sshd_config"
    
    # Enable SSH tunneling/forwarding for VPN use
    sed -i 's/^#*AllowTcpForwarding.*/AllowTcpForwarding yes/' "$sshd_config"
    sed -i 's/^#*AllowStreamLocalForwarding.*/AllowStreamLocalForwarding yes/' "$sshd_config"
    sed -i 's/^#*GatewayPorts.*/GatewayPorts yes/' "$sshd_config"
    sed -i 's/^#*PermitTunnel.*/PermitTunnel yes/' "$sshd_config"
    sed -i 's/^#*TCPKeepAlive.*/TCPKeepAlive yes/' "$sshd_config"
    
    # Add settings if they don't exist
    grep -q "^PasswordAuthentication" "$sshd_config" || echo "PasswordAuthentication yes" >> "$sshd_config"
    grep -q "^UsePAM" "$sshd_config" || echo "UsePAM yes" >> "$sshd_config"
    grep -q "^AllowTcpForwarding" "$sshd_config" || echo "AllowTcpForwarding yes" >> "$sshd_config"
    grep -q "^PermitTunnel" "$sshd_config" || echo "PermitTunnel yes" >> "$sshd_config"
    grep -q "^GatewayPorts" "$sshd_config" || echo "GatewayPorts yes" >> "$sshd_config"
    grep -q "^TCPKeepAlive" "$sshd_config" || echo "TCPKeepAlive yes" >> "$sshd_config"
    
    # Restart SSH service
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || service ssh restart 2>/dev/null
    
    echo -e "    ${GREEN}✓${NC} SSH password auth + VPN tunneling enabled"
}

# Function to setup PAM configuration
setup_pam_config() {
    local pam_file="/etc/pam.d/common-password"
    
    # Only modify if it exists (Debian/Ubuntu systems)
    if [ ! -f "$pam_file" ]; then
        echo -e "    ${YELLOW}⊘${NC} PAM config not found (non-Debian system)"
        return 0
    fi
    
    # Check if already configured
    if grep -q "SSH User Manager" "$pam_file" 2>/dev/null; then
        echo -e "    ${GREEN}✓${NC} PAM already configured"
        return 0
    fi
    
    # Backup original
    cp "$pam_file" "${pam_file}.backup.$(date +%s)"
    
    # Create proper PAM configuration
    cat > "$pam_file" << 'EOFPAM'
# Updated by SSH User Manager - $(date)
# /etc/pam.d/common-password - password-related modules common to all services
#
# This file is included from other service-specific PAM config files,
# and should contain a list of modules that define the services to be
# used to change user passwords.  The default is pam_unix.

# Explanation of pam_unix options:
# The "yescrypt" option enables hashed passwords using the yescrypt algorithm,
# introduced in Debian 11. Without this option, the default is Unix crypt.
# Prior releases used the option "sha512"; if a shadow password hash will be
# shared between Debian 11 and older releases replace "yescrypt" with "sha512"
# for compatibility. The "obscure" option replaces the old `OBSCURE_CHECKS_ENAB'
# option in login.defs. See the pam_unix manpage for other options.

# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.
# To take advantage of this, it is recommended that you configure any
# local modules either before or after the default block, and use
# pam-auth-update to manage selection of other modules. See
# pam-auth-update(8) for details.

# here are the per-package modules (the "Primary" block)
password   [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass yescrypt
# here's the fallback if no module succeeds
password   requisite pam_deny.so
# prime the stack with a positive return value if there isn't one already;
# this avoids us returning an error just because nothing sets a success code
# since the modules above will each just jump around
password   required pam_permit.so
# and here are more per-package modules (the "Additional" block)
# end of pam-auth-update config
EOFPAM
    
    echo -e "    ${GREEN}✓${NC} PAM configured"
}

# Initialize configuration
echo -e "${YELLOW}Initializing configuration...${NC}"
touch "$CONFIG_DIR/traffic_usage.dat"
touch "$CONFIG_DIR/traffic_limits.dat"
touch "$CONFIG_DIR/expiry_times.dat"
touch "$CONFIG_DIR/baseline.dat"
touch "$CONFIG_DIR/traffic_locked.dat"
chmod 600 "$CONFIG_DIR"/*.dat

# Configure SSH and PAM
echo -e "${YELLOW}Configuring SSH authentication...${NC}"
setup_sshd_config
setup_pam_config

# Install nethogs if needed
if ! command -v nethogs &> /dev/null; then
    echo -e "${YELLOW}Installing nethogs for traffic monitoring...${NC}"
    if command -v apt-get &> /dev/null; then
        # Kill any stuck apt processes
        killall apt apt-get 2>/dev/null || true
        rm -f /var/lib/apt/lists/lock /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend 2>/dev/null || true
        dpkg --configure -a 2>/dev/null || true
        apt-get update -qq 2>/dev/null || true
        apt-get install -y nethogs >/dev/null 2>&1 && echo -e "  ${GREEN}✓${NC} nethogs installed" || echo -e "  ${YELLOW}!${NC} Install manually: sudo apt install nethogs"
    elif command -v yum &> /dev/null; then
        yum install -y nethogs >/dev/null 2>&1 && echo -e "  ${GREEN}✓${NC} nethogs installed"
    elif command -v pacman &> /dev/null; then
        pacman -Sy --noconfirm nethogs >/dev/null 2>&1 && echo -e "  ${GREEN}✓${NC} nethogs installed"
    else
        echo -e "  ${YELLOW}!${NC} Install nethogs manually for traffic monitoring"
    fi
fi

# Success message
echo ""
echo -e "${GREEN}✓ Installation complete!${NC}"
echo ""
echo -e "${CYAN}Usage:${NC}"
echo -e "  ${BOLD}ssh-user-manager${NC}       - Run the interactive menu"
echo -e "  ${BOLD}sudo ssh-user-manager${NC}  - Run with administrative access (required)"
echo ""
echo -e "${CYAN}Configuration files:${NC}"
echo -e "  ${BOLD}$CONFIG_DIR${NC}"
echo ""
echo -e "${CYAN}Installation directory:${NC}"
echo -e "  ${BOLD}$INSTALL_DIR${NC}"
echo ""
echo -e "${YELLOW}Quick start:${NC}"
echo "  1. Run: ${BOLD}sudo ssh-user-manager${NC}"
echo "  2. Select '1' to create a new user"
echo "  3. Follow the prompts"
echo ""
