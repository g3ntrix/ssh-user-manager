#!/bin/bash

# SSH User Manager v3.0
# Complete user management with traffic tracking for SSH VPN
# Requires: iptables, xt_owner module (usually included in kernel)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Config
CONFIG_DIR="/etc/ssh-user-manager"
TRAFFIC_FILE="$CONFIG_DIR/traffic_usage.dat"
LIMITS_FILE="$CONFIG_DIR/traffic_limits.dat"
EXCLUDED_USERS="nobody|linuxuser"
PAM_COMMON_PASSWORD="/etc/pam.d/common-password"

# Check root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Run as root: sudo $0${NC}"
    exit 1
fi

# Setup PAM configuration for SSH authentication
setup_pam_ssh() {
    if [ ! -f "$PAM_COMMON_PASSWORD" ]; then
        return 0  # File doesn't exist on non-Debian systems
    fi
    
    # Check if already configured
    if grep -q "SSH User Manager" "$PAM_COMMON_PASSWORD" 2>/dev/null; then
        return 0
    fi
    
    # Backup original if not already backed up
    if [ ! -f "${PAM_COMMON_PASSWORD}.original" ]; then
        cp "$PAM_COMMON_PASSWORD" "${PAM_COMMON_PASSWORD}.original"
    fi
    
    # Create proper PAM configuration for SSH key + password authentication
    cat > "$PAM_COMMON_PASSWORD" << 'EOFPAM'
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
}

# Initialize
init() {
    mkdir -p "$CONFIG_DIR"
    touch "$TRAFFIC_FILE" "$LIMITS_FILE" "$CONFIG_DIR/expiry_times.dat" "$CONFIG_DIR/baseline.dat" "$CONFIG_DIR/traffic_locked.dat"
    
    # Setup PAM configuration for SSH authentication
    setup_pam_ssh
    
    # Ensure nethogs is installed
    which nethogs >/dev/null 2>&1 || apt-get install -y nethogs >/dev/null 2>&1
    
    # Setup rules for all existing users and enforce limits
    for user in $(get_users); do
        setup_user_iptables "$user"
        # Kick users who are over their limit
        check_and_enforce_limit "$user"
    done
}

# Get managed users
get_users() {
    awk -F: -v ex="$EXCLUDED_USERS" '$3 >= 1000 && $3 < 65534 && $1 !~ ex {print $1}' /etc/passwd
}

# Format bytes
format_bytes() {
    local b=$1
    # Clean and validate input
    b=$(echo "$b" | tr -d '\n \t')
    b=${b:-0}
    
    # Validate it's a number
    if ! [[ "$b" =~ ^[0-9]+$ ]]; then
        echo "0 B"
        return
    fi
    
    if [ "$b" -ge 1073741824 ] 2>/dev/null; then
        printf "%.2f GB" "$(awk "BEGIN {printf \"%.2f\", $b/1073741824}")"
    elif [ "$b" -ge 1048576 ] 2>/dev/null; then
        printf "%.2f MB" "$(awk "BEGIN {printf \"%.2f\", $b/1048576}")"
    elif [ "$b" -ge 1024 ] 2>/dev/null; then
        printf "%.2f KB" "$(awk "BEGIN {printf \"%.2f\", $b/1024}")"
    else
        echo "$b B"
    fi
}

# Days to date
days_to_date() {
    date -d "+$1 days" +%Y-%m-%d
}

# Setup traffic tracking for a user
setup_user_iptables() {
    local user=$1
    # Ensure nethogs is available
    which nethogs >/dev/null 2>&1 || apt-get install -y nethogs >/dev/null 2>&1
}

# File to store baseline /proc/io values (what we've already counted)
BASELINE_FILE="$CONFIG_DIR/baseline.dat"

# Get current /proc/io total for user's SSH session processes
# Looks for sshd, sshd-session, bash, sh processes owned by user
get_proc_io_raw() {
    local user=$1
    local total=0
    
    # Get all PIDs for user's session processes
    local pids=$(pgrep -u "$user" 'sshd|sshd-session|bash|sh' 2>/dev/null | tr '\n' ' ')
    [ -z "$pids" ] && echo "0" && return
    
    for pid in $pids; do
        if [ -f "/proc/$pid/io" ]; then
            local rchar=$(awk '/^rchar:/{print $2}' /proc/$pid/io 2>/dev/null | tr -d '\n')
            local wchar=$(awk '/^wchar:/{print $2}' /proc/$pid/io 2>/dev/null | tr -d '\n')
            # Validate integers
            rchar=${rchar:-0}
            wchar=${wchar:-0}
            # Strip any whitespace
            rchar=$(echo "$rchar" | tr -d ' \t\n')
            wchar=$(echo "$wchar" | tr -d ' \t\n')
            total=$((total + rchar + wchar))
        fi
    done
    
    echo "$total"
}

# Get baseline (already counted traffic) for user
get_baseline() {
    local user=$1
    local baseline=$(grep "^$user:" "$BASELINE_FILE" 2>/dev/null | tail -1 | cut -d: -f2 | tr -d '\n \t')
    echo "${baseline:-0}"
}

# Set baseline for user
set_baseline() {
    local user=$1
    local value=$2
    sed -i "/^$user:/d" "$BASELINE_FILE" 2>/dev/null
    echo "$user:$value" >> "$BASELINE_FILE"
}

# Get session traffic = current /proc/io - baseline (what's new since last save)
get_session_traffic() {
    local user=$1
    local raw=$(get_proc_io_raw "$user")
    local baseline=$(get_baseline "$user")
    
    # Clean and validate values
    raw=$(echo "$raw" | tr -d '\n \t')
    baseline=$(echo "$baseline" | tr -d '\n \t')
    raw=${raw:-0}
    baseline=${baseline:-0}
    
    # If no active session, return 0
    [ "$raw" -eq 0 ] 2>/dev/null && echo "0" && return
    
    # If baseline is higher than raw, session restarted - use raw as new traffic
    if [ "$baseline" -gt "$raw" ] 2>/dev/null; then
        echo "$raw"
    else
        echo $((raw - baseline))
    fi
}

# Get accumulated traffic from nethogs (for real-time speed display)
get_realtime_traffic() {
    local user=$1
    
    # Quick 1-second sample
    local nh_output=$(timeout 2 nethogs -t -c 1 2>/dev/null | grep -i "$user" | tail -1)
    
    if [ -n "$nh_output" ]; then
        local sent=$(echo "$nh_output" | awk '{print $(NF-1)}')
        local recv=$(echo "$nh_output" | awk '{print $NF}')
        echo "↑ ${sent:-0} KB/s  ↓ ${recv:-0} KB/s"
    else
        echo "No active session"
    fi
}

# Debug function - call from menu to see what's happening
debug_traffic() {
    local user=$1
    echo -e "\n${CYAN}=== Traffic Debug for $user ===${NC}"
    
    echo -e "\n${YELLOW}1. SSHD processes for user:${NC}"
    local pids=$(pgrep -u "$user" sshd 2>/dev/null)
    if [ -z "$pids" ]; then
        echo "  No active sshd processes"
    else
        for pid in $pids; do
            echo "  PID: $pid"
            if [ -f "/proc/$pid/io" ]; then
                echo "  /proc/$pid/io (rchar/wchar = network bytes):"
                awk '/^rchar:|^wchar:|^read_bytes:|^write_bytes:/' /proc/$pid/io 2>/dev/null | sed 's/^/    /'
            fi
        done
    fi
    
    echo -e "\n${YELLOW}2. Nethogs live rate (2 sec sample):${NC}"
    timeout 3 nethogs -t -c 1 2>/dev/null | grep -i "$user" | tail -1 | sed 's/^/  /'
    [ $? -ne 0 ] && echo "  No data captured"
    
    echo -e "\n${YELLOW}3. Session traffic (from /proc/io):${NC}"
    local session=$(get_proc_io_traffic "$user")
    echo "  Current session: $(format_bytes $session)"
    
    echo -e "\n${YELLOW}4. Saved traffic:${NC}"
    local saved=$(grep "^$user:" "$TRAFFIC_FILE" 2>/dev/null | tail -1 | cut -d: -f2 | tr -d '\n \t')
    echo "  Previously saved: $(format_bytes ${saved:-0})"
    
    echo -e "\n${YELLOW}5. Total traffic:${NC}"
    local total=$(get_traffic "$user")
    echo "  Total (saved + session): $(format_bytes $total)"
    
    read -p "Press Enter to continue..."
}

# Get total traffic (saved + unsaved session traffic)
get_traffic() {
    local user=$1
    local saved=$(grep "^$user:" "$TRAFFIC_FILE" 2>/dev/null | tail -1 | cut -d: -f2 | tr -d '\n \t')
    local session=$(get_session_traffic "$user")
    
    # Clean and validate
    saved=${saved:-0}
    session=${session:-0}
    
    # Protection against negative/corrupted values
    if [ "$saved" -lt 0 ] 2>/dev/null; then
        saved=0
    fi
    if [ "$session" -lt 0 ] 2>/dev/null; then
        session=0
    fi
    
    echo $((saved + session))
}

# Save traffic: add session traffic to saved total and update baseline
save_traffic() {
    local user=$1
    local raw=$(get_proc_io_raw "$user")
    
    # Clean and validate
    raw=$(echo "$raw" | tr -d '\n \t')
    raw=${raw:-0}
    
    # Only save if user has an active session with traffic
    if [ "$raw" -gt 0 ] 2>/dev/null; then
        local session=$(get_session_traffic "$user")
        local saved=$(grep "^$user:" "$TRAFFIC_FILE" 2>/dev/null | tail -1 | cut -d: -f2 | tr -d '\n \t')
        
        # Clean and validate
        session=${session:-0}
        saved=${saved:-0}
        
        # Only add if there's actual new session traffic
        if [ "$session" -gt 0 ] 2>/dev/null; then
            local new_total=$((saved + session))
            
            # Protection against overflow - if total goes negative, cap it
            if [ "$new_total" -lt 0 ] 2>/dev/null; then
                new_total=$saved
            fi
            
            sed -i "/^$user:/d" "$TRAFFIC_FILE"
            echo "$user:$new_total" >> "$TRAFFIC_FILE"
            
            # Update baseline to current raw value so we don't double-count
            set_baseline "$user" "$raw"
        fi
    fi
    # If user is offline (raw=0), don't touch baseline or saved traffic
}

# Reset traffic for user (also resets baseline and unlocks if locked)
reset_traffic() {
    local user=$1
    sed -i "/^$user:/d" "$TRAFFIC_FILE"
    echo "$user:0" >> "$TRAFFIC_FILE"
    
    # Set baseline to current raw so we start fresh
    local raw=$(get_proc_io_raw "$user")
    set_baseline "$user" "$raw"
    
    # Unlock user if they were locked for traffic
    unlock_user_if_traffic_locked "$user"
}

# Get/Set traffic limit
get_limit() {
    local user=$1
    local limit=$(grep "^$user:" "$LIMITS_FILE" 2>/dev/null | tail -1 | cut -d: -f2 | tr -d '\n \t')
    echo "${limit:-0}"
}

set_limit() {
    local user=$1 limit=$2
    
    # Clean and validate limit
    limit=$(echo "$limit" | tr -d '\n \t')
    limit=${limit:-0}
    
    sed -i "/^$user:/d" "$LIMITS_FILE"
    echo "$user:$limit" >> "$LIMITS_FILE"
    
    # If setting a new limit, check if user should be unlocked
    if [ "$limit" -eq 0 ] 2>/dev/null; then
        # Removing limit - unlock if was locked for traffic
        unlock_user_if_traffic_locked "$user"
    else
        # Check if new limit allows user to be unlocked
        local traffic=$(get_traffic "$user")
        if [ "$traffic" -lt "$limit" ] 2>/dev/null; then
            unlock_user_if_traffic_locked "$user"
        fi
    fi
}

# File to track users locked due to traffic limit
LOCKED_FILE="$CONFIG_DIR/traffic_locked.dat"

# Lock user account due to traffic limit
lock_user_for_traffic() {
    local user=$1
    usermod -L "$user" 2>/dev/null
    # Track that this user was locked for traffic reasons
    grep -q "^$user$" "$LOCKED_FILE" 2>/dev/null || echo "$user" >> "$LOCKED_FILE"
}

# Unlock user if they were locked due to traffic
unlock_user_if_traffic_locked() {
    local user=$1
    if grep -q "^$user$" "$LOCKED_FILE" 2>/dev/null; then
        usermod -U "$user" 2>/dev/null
        sed -i "/^$user$/d" "$LOCKED_FILE"
    fi
}

# Check if user is locked for traffic
is_traffic_locked() {
    local user=$1
    grep -q "^$user$" "$LOCKED_FILE" 2>/dev/null
}

# Check if user is over limit and enforce it
check_and_enforce_limit() {
    local user=$1
    local traffic=$(get_traffic "$user")
    local limit=$(get_limit "$user")
    
    # Clean and validate
    traffic=${traffic:-0}
    limit=${limit:-0}
    
    # If no limit or unlimited, ensure user is unlocked (if was traffic-locked)
    if [ "$limit" -eq 0 ] 2>/dev/null; then
        unlock_user_if_traffic_locked "$user"
        return 0
    fi
    
    # If over limit, lock account and kill sessions
    if [ "$traffic" -ge "$limit" ] 2>/dev/null; then
        save_traffic "$user"
        kill_user_sessions "$user"
        lock_user_for_traffic "$user"
        return 1  # Over limit
    else
        # Under limit - make sure they're unlocked
        unlock_user_if_traffic_locked "$user"
    fi
    
    return 0  # OK
}

# Get expiry date
get_expiry() {
    local exp=$(chage -l "$1" 2>/dev/null | grep "Account expires" | cut -d: -f2 | xargs)
    [ "$exp" = "never" ] || [ -z "$exp" ] && echo "Never" || echo "$exp"
}

# Check if expired
is_expired() {
    local exp=$(get_expiry "$1")
    [ "$exp" = "Never" ] && return 1
    local exp_ts=$(date -d "$exp" +%s 2>/dev/null)
    [ -n "$exp_ts" ] && [ $(date +%s) -gt $exp_ts ] && return 0
    return 1
}

# Kill user sessions
kill_user_sessions() {
    local user=$1
    pkill -KILL -u "$user" 2>/dev/null
    # Kill SSH sessions
    for pid in $(ps aux | grep "sshd:.*$user" | grep -v grep | awk '{print $2}'); do
        kill -9 "$pid" 2>/dev/null
    done
}

# Print header
header() {
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}${BOLD}       SSH User Manager v3.0            ${NC}${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════╝${NC}"
    echo ""
}

# Print line
line() {
    echo -e "${BLUE}──────────────────────────────────────────────${NC}"
}

# Wait for key
pause() {
    echo ""
    read -p "Press Enter to continue..."
}

# User selection menu
select_user() {
    local prompt=${1:-"Select user"}
    local users=($(get_users))
    
    if [ ${#users[@]} -eq 0 ]; then
        echo -e "${YELLOW}No users found${NC}"
        return 1
    fi
    
    echo -e "${CYAN}$prompt:${NC}"
    echo ""
    for i in "${!users[@]}"; do
        local u=${users[$i]}
        local status="${GREEN}●${NC}"
        is_expired "$u" && status="${RED}●${NC}"
        echo -e "  ${BOLD}$((i+1))${NC}. $u $status"
    done
    echo ""
    echo -e "  ${BOLD}0${NC}. Cancel"
    echo ""
    
    read -p "Choice: " sel
    [ "$sel" = "0" ] && return 1
    
    if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le ${#users[@]} ]; then
        SELECTED_USER="${users[$((sel-1))]}"
        return 0
    fi
    
    echo -e "${RED}Invalid selection${NC}"
    return 1
}

#═══════════════════════════════════════════════════════════════════
# USER MANAGEMENT
#═══════════════════════════════════════════════════════════════════

create_user() {
    header
    echo -e "${GREEN}➕ Create New User${NC}"
    line
    echo ""
    
    read -p "Username: " username
    [ -z "$username" ] && echo -e "${RED}Username required${NC}" && pause && return
    
    if id "$username" &>/dev/null; then
        echo -e "${RED}User already exists${NC}"
        pause
        return
    fi
    
    read -sp "Password: " pass
    echo ""
    read -sp "Confirm: " pass2
    echo ""
    
    [ "$pass" != "$pass2" ] && echo -e "${RED}Passwords don't match${NC}" && pause && return
    [ -z "$pass" ] && echo -e "${RED}Password required${NC}" && pause && return
    
    echo ""
    echo -e "${CYAN}Expiration:${NC}"
    echo "  1. 1 hour      4. 7 days"
    echo "  2. 6 hours     5. Custom"
    echo "  3. 1 day       6. Never"
    read -p "Choice [4]: " exp_choice
    
    local exp_hours=0
    case ${exp_choice:-4} in
        1) exp_hours=1 ;;
        2) exp_hours=6 ;;
        3) exp_hours=24 ;;
        4) exp_hours=$((7 * 24)) ;;
        5) 
            read -p "Enter duration (e.g., 2h, 3d, 1w): " custom_exp
            case "$custom_exp" in
                *h) exp_hours=${custom_exp%h} ;;
                *d) exp_hours=$((${custom_exp%d} * 24)) ;;
                *w) exp_hours=$((${custom_exp%w} * 24 * 7)) ;;
                *) exp_hours=$custom_exp ;;
            esac
            ;;
        6) exp_hours=0 ;;
        *) exp_hours=$((7 * 24)) ;;
    esac
    
    echo ""
    echo -e "${CYAN}Traffic Limit:${NC}"
    echo "  1. 100 MB      5. 5 GB"
    echo "  2. 500 MB      6. 10 GB"
    echo "  3. 1 GB        7. Custom"
    echo "  4. 2 GB        8. Unlimited"
    read -p "Choice [8]: " lim_choice
    
    case ${lim_choice:-8} in
        1) limit=$((100 * 1048576)) ;;
        2) limit=$((500 * 1048576)) ;;
        3) limit=$((1 * 1073741824)) ;;
        4) limit=$((2 * 1073741824)) ;;
        5) limit=$((5 * 1073741824)) ;;
        6) limit=$((10 * 1073741824)) ;;
        7) 
            read -p "Enter limit (e.g., 500m, 2g): " custom_lim
            case "$custom_lim" in
                *m|*M) limit=$((${custom_lim%[mM]} * 1048576)) ;;
                *g|*G) limit=$((${custom_lim%[gG]} * 1073741824)) ;;
                *) limit=$((custom_lim * 1073741824)) ;;
            esac
            ;;
        8) limit=0 ;;
        *) limit=0 ;;
    esac
    
    echo ""
    echo -e "${YELLOW}Creating user...${NC}"
    
    # Create user with /bin/false shell (VPN only, no terminal access)
    useradd -m -s /bin/false "$username" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to create user${NC}"
        pause
        return
    fi
    
    # Set password
    echo "$username:$pass" | chpasswd 2>/dev/null
    if [ $? -ne 0 ]; then
        # Fallback to openssl
        local hash=$(openssl passwd -6 "$pass")
        usermod -p "$hash" "$username"
    fi
    
    # Set expiry
    if [ "$exp_hours" -gt 0 ]; then
        local exp_date=$(date -d "+$exp_hours hours" +%Y-%m-%d)
        local exp_datetime=$(date -d "+$exp_hours hours" "+%Y-%m-%d %H:%M")
        chage -E "$exp_date" "$username"
        # Store exact expiry time for display
        echo "$username:$(date -d "+$exp_hours hours" +%s)" >> "$CONFIG_DIR/expiry_times.dat"
    fi
    
    # Set traffic limit
    set_limit "$username" "$limit"
    
    # Initialize traffic
    echo "$username:0" >> "$TRAFFIC_FILE"
    
    # Setup iptables
    setup_user_iptables "$username"
    
    echo ""
    echo -e "${GREEN}✓ User '$username' created successfully${NC}"
    echo -e "  ${CYAN}Access: VPN/Tunneling only (no shell access)${NC}"
    if [ "$exp_hours" -gt 0 ]; then
        if [ "$exp_hours" -lt 24 ]; then
            echo -e "  Expires in: ${exp_hours} hour(s)"
        else
            echo -e "  Expires in: $((exp_hours / 24)) day(s)"
        fi
    else
        echo -e "  Expires: Never"
    fi
    [ "$limit" -gt 0 ] && echo -e "  Traffic limit: $(format_bytes $limit)" || echo -e "  Traffic: Unlimited"
    
    pause
}

delete_user() {
    header
    echo -e "${RED}🗑️  Delete User${NC}"
    line
    echo ""
    
    select_user "Select user to delete" || { pause; return; }
    
    echo ""
    echo -e "${YELLOW}User: $SELECTED_USER${NC}"
    echo ""
    read -p "Type 'yes' to confirm deletion: " confirm
    
    if [ "$confirm" != "yes" ]; then
        echo -e "${YELLOW}Cancelled${NC}"
        pause
        return
    fi
    
    echo ""
    echo -e "${YELLOW}Deleting user...${NC}"
    
    # Kill all sessions first
    kill_user_sessions "$SELECTED_USER"
    sleep 1
    
    # Remove iptables rules
    local uid=$(id -u "$SELECTED_USER" 2>/dev/null)
    [ -n "$uid" ] && iptables -D SSH_TRAFFIC -m owner --uid-owner "$uid" -j RETURN 2>/dev/null
    
    # Remove from config files
    sed -i "/^$SELECTED_USER:/d" "$TRAFFIC_FILE" 2>/dev/null
    sed -i "/^$SELECTED_USER:/d" "$LIMITS_FILE" 2>/dev/null
    
    # Delete user and home directory
    userdel -rf "$SELECTED_USER" 2>/dev/null
    
    # Double check home dir removal
    rm -rf "/home/$SELECTED_USER" 2>/dev/null
    
    # Remove from any groups
    for group in $(groups "$SELECTED_USER" 2>/dev/null); do
        gpasswd -d "$SELECTED_USER" "$group" 2>/dev/null
    done
    
    # Remove cron jobs
    crontab -r -u "$SELECTED_USER" 2>/dev/null
    
    # Remove mail spool
    rm -f "/var/mail/$SELECTED_USER" 2>/dev/null
    
    echo -e "${GREEN}✓ User '$SELECTED_USER' completely removed${NC}"
    pause
}

list_users() {
    header
    echo -e "${CYAN}👥 User List${NC}"
    line
    echo ""
    
    local users=($(get_users))
    
    if [ ${#users[@]} -eq 0 ]; then
        echo -e "${YELLOW}No users found${NC}"
        pause
        return
    fi
    
    printf "${BOLD}%-12s %-10s %-12s %-12s %-10s${NC}\n" "USER" "STATUS" "EXPIRES" "TRAFFIC" "LIMIT"
    line
    
    for user in "${users[@]}"; do
        local status="${GREEN}Active${NC}"
        is_expired "$user" && status="${RED}Expired${NC}"
        
        local exp=$(get_expiry "$user")
        local traffic=$(format_bytes $(get_traffic "$user"))
        local limit=$(get_limit "$user")
        local limit_str="Unlimited"
        [ -n "$limit" ] && [ "$limit" -gt 0 ] && limit_str=$(format_bytes "$limit")
        
        printf "%-12s %-18b %-12s %-12s %-10s\n" "$user" "$status" "$exp" "$traffic" "$limit_str"
    done
    
    pause
}

show_online() {
    header
    echo -e "${CYAN}🟢 Online Users${NC}"
    line
    echo ""
    
    local found=0
    
    printf "${BOLD}%-12s %-15s %-20s${NC}\n" "USER" "IP" "LOGIN TIME"
    line
    
    while read line; do
        local user=$(echo "$line" | awk '{print $1}')
        local ip=$(echo "$line" | awk '{print $5}' | tr -d '()')
        local time=$(echo "$line" | awk '{print $3, $4}')
        
        echo "$user" | grep -qE "^($EXCLUDED_USERS|root)$" && continue
        
        printf "%-12s %-15s %-20s\n" "$user" "$ip" "$time"
        found=1
    done < <(who 2>/dev/null)
    
    [ $found -eq 0 ] && echo -e "${YELLOW}No users online${NC}"
    
    echo ""
    echo -e "${CYAN}SSH connections: $(ss -tn 2>/dev/null | grep ':22 ' | wc -l)${NC}"
    
    pause
}

#═══════════════════════════════════════════════════════════════════
# PASSWORD & EXPIRATION
#═══════════════════════════════════════════════════════════════════

change_password() {
    header
    echo -e "${YELLOW}🔑 Change Password${NC}"
    line
    echo ""
    
    select_user "Select user" || { pause; return; }
    
    echo ""
    read -sp "New password: " pass
    echo ""
    read -sp "Confirm: " pass2
    echo ""
    
    [ "$pass" != "$pass2" ] && echo -e "${RED}Passwords don't match${NC}" && pause && return
    [ -z "$pass" ] && echo -e "${RED}Password required${NC}" && pause && return
    
    echo "$SELECTED_USER:$pass" | chpasswd 2>/dev/null
    if [ $? -ne 0 ]; then
        local hash=$(openssl passwd -6 "$pass")
        usermod -p "$hash" "$SELECTED_USER"
    fi
    
    echo -e "${GREEN}✓ Password changed${NC}"
    pause
}

manage_expiry() {
    header
    echo -e "${YELLOW}📅 Manage Expiration${NC}"
    line
    echo ""
    
    select_user "Select user" || { pause; return; }
    
    local current=$(get_expiry "$SELECTED_USER")
    echo ""
    echo -e "Current: ${CYAN}$current${NC}"
    echo ""
    
    echo "1. Add 1 hour       5. Add 7 days"
    echo "2. Add 6 hours      6. Custom"
    echo "3. Add 1 day        7. Remove expiration"
    echo "4. Add 3 days       8. Deactivate now"
    echo ""  
    echo "0. Cancel"
    echo ""
    read -p "Choice: " choice
    
    local exp_hours=0
    case $choice in
        1) exp_hours=1 ;;
        2) exp_hours=6 ;;
        3) exp_hours=24 ;;
        4) exp_hours=$((3 * 24)) ;;
        5) exp_hours=$((7 * 24)) ;;
        6) 
            read -p "Enter duration (e.g., 2h, 3d, 1w): " custom_exp
            case "$custom_exp" in
                *h) exp_hours=${custom_exp%h} ;;
                *d) exp_hours=$((${custom_exp%d} * 24)) ;;
                *w) exp_hours=$((${custom_exp%w} * 24 * 7)) ;;
                *) exp_hours=$custom_exp ;;
            esac
            ;;
        7) chage -E -1 "$SELECTED_USER"; echo -e "${GREEN}✓ Expiration removed${NC}"; pause; return ;;
        8) chage -E 0 "$SELECTED_USER"; kill_user_sessions "$SELECTED_USER"; echo -e "${RED}✓ User deactivated${NC}"; pause; return ;;
        0) return ;;
    esac
    
    if [ "$exp_hours" -gt 0 ]; then
        local exp_date=$(date -d "+$exp_hours hours" +%Y-%m-%d)
        chage -E "$exp_date" "$SELECTED_USER"
        echo -e "${GREEN}✓ Extended by $exp_hours hour(s)${NC}"
        echo -e "  New expiry: $(get_expiry $SELECTED_USER)"
    fi
    
    pause
}

#═══════════════════════════════════════════════════════════════════
# TRAFFIC MANAGEMENT
#═══════════════════════════════════════════════════════════════════

manage_traffic() {
    header
    echo -e "${CYAN}📊 Manage Traffic${NC}"
    line
    echo ""
    
    select_user "Select user" || { pause; return; }
    
    local traffic=$(get_traffic "$SELECTED_USER")
    local limit=$(get_limit "$SELECTED_USER")
    
    echo ""
    echo -e "User: ${CYAN}$SELECTED_USER${NC}"
    echo -e "Used: ${YELLOW}$(format_bytes $traffic)${NC}"
    [ -n "$limit" ] && [ "$limit" -gt 0 ] && echo -e "Limit: $(format_bytes $limit)" || echo "Limit: Unlimited"
    echo ""
    
    echo "1. Set 100 MB       5. Set 5 GB"
    echo "2. Set 500 MB       6. Set 10 GB"
    echo "3. Set 1 GB         7. Custom"
    echo "4. Set 2 GB         8. Remove limit"
    echo ""
    echo "9. Reset usage      0. Cancel"
    echo ""
    read -p "Choice: " choice
    
    local new_limit=0
    case $choice in
        1) new_limit=$((100 * 1048576)) ;;
        2) new_limit=$((500 * 1048576)) ;;
        3) new_limit=$((1 * 1073741824)) ;;
        4) new_limit=$((2 * 1073741824)) ;;
        5) new_limit=$((5 * 1073741824)) ;;
        6) new_limit=$((10 * 1073741824)) ;;
        7) 
            read -p "Enter limit (e.g., 500m, 2g): " custom_lim
            case "$custom_lim" in
                *m|*M) new_limit=$(awk "BEGIN {printf \"%.0f\", ${custom_lim%[mM]} * 1048576}") ;;
                *g|*G) new_limit=$(awk "BEGIN {printf \"%.0f\", ${custom_lim%[gG]} * 1073741824}") ;;
                *) new_limit=$(awk "BEGIN {printf \"%.0f\", $custom_lim * 1073741824}") ;;
            esac
            ;;
        8) new_limit=0; set_limit "$SELECTED_USER" 0; echo -e "${GREEN}✓ Limit removed${NC}"; pause; return ;;
        9) reset_traffic "$SELECTED_USER"; echo -e "${GREEN}✓ Traffic reset${NC}"; pause; return ;;
        0) return ;;
    esac
    
    if [ "$new_limit" -gt 0 ]; then
        set_limit "$SELECTED_USER" "$new_limit"
        echo -e "${GREEN}✓ Limit set to $(format_bytes $new_limit)${NC}"
    fi
    
    pause
}

# Get real-time speed from nethogs for a user
get_user_speed() {
    local user=$1
    local nh_line=$(timeout 2 nethogs -t -c 1 2>/dev/null | grep -i "$user" | tail -1)
    
    if [ -n "$nh_line" ]; then
        local sent=$(echo "$nh_line" | awk '{print $(NF-1)}')
        local recv=$(echo "$nh_line" | awk '{print $NF}')
        echo "${sent:-0}|${recv:-0}"
    else
        echo "0|0"
    fi
}

# Real-time traffic monitor
view_traffic() {
    local users=($(get_users))
    
    if [ ${#users[@]} -eq 0 ]; then
        header
        echo -e "${YELLOW}No users found${NC}"
        pause
        return
    fi
    
    # Loop until user presses q
    while true; do
        # Get nethogs data - need at least 2 cycles to get real data
        # Format: "sshd-session: USERNAME/PID/UID   SENT   RECEIVED"
        local nh_data=$(timeout 3 nethogs -t -c 2 2>/dev/null | grep "sshd-session")
        
        clear
        echo ""
        echo -e "  ${BOLD}${CYAN}📊 TRAFFIC MONITOR${NC}                              $(date '+%H:%M:%S')"
        echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        
        for user in "${users[@]}"; do
            local traffic=$(get_traffic "$user")
            local limit=$(get_limit "$user")
            local status=""
            local speed_info=""
            local bar=""
            
            # Check if online and get speed
            # Use multiple methods: pgrep for sshd, or 'who' command for SSH sessions
            local is_online=false
            if pgrep -u "$user" sshd >/dev/null 2>&1 || who | grep -q "^$user "; then
                is_online=true
                # Search for "sshd-session: USERNAME/" pattern
                local speed_line=$(echo "$nh_data" | grep "sshd-session: $user/" | tail -1)
                
                if [ -n "$speed_line" ]; then
                    # Format: sshd-session: user/pid/uid   0.123   0.456
                    # Use awk to get last two fields
                    local sent=$(echo "$speed_line" | awk '{print $(NF-1)}')
                    local recv=$(echo "$speed_line" | awk '{print $NF}')
                    speed_info="↑$(printf '%.1f' $sent) ↓$(printf '%.1f' $recv) KB/s"
                else
                    speed_info="${CYAN}active${NC}"
                fi
            fi
            
            # Calculate percentage and status
            local pct=0
            local limit_str="unlimited"
            if [ -n "$limit" ] && [ "$limit" -gt 0 ]; then
                pct=$((traffic * 100 / limit))
                limit_str=$(format_bytes "$limit")
                
                if [ $traffic -ge $limit ]; then
                    # ENFORCE: Lock account and kill session if over limit
                    if $is_online; then
                        save_traffic "$user"
                        kill_user_sessions "$user"
                        lock_user_for_traffic "$user"
                        is_online=false
                    fi
                    if ! is_traffic_locked "$user"; then
                        lock_user_for_traffic "$user"
                    fi
                    status="${RED}▌LOCKED${NC}"
                    speed_info="${RED}blocked${NC}"
                elif [ $pct -ge 90 ]; then
                    status="${YELLOW}▌${pct}%${NC}"
                else
                    status="${GREEN}▌${pct}%${NC}"
                fi
                
                # Create progress bar
                local filled=$((pct / 5))
                [ $filled -gt 20 ] && filled=20
                local empty=$((20 - filled))
                if [ $pct -ge 100 ]; then
                    bar="${RED}$(printf '█%.0s' $(seq 1 20))${NC}"
                elif [ $pct -ge 90 ]; then
                    bar="${YELLOW}$(printf '█%.0s' $(seq 1 $filled))${NC}$(printf '░%.0s' $(seq 1 $empty))"
                else
                    bar="${GREEN}$(printf '█%.0s' $(seq 1 $filled))${NC}$(printf '░%.0s' $(seq 1 $empty))"
                fi
            else
                status="${GREEN}▌OK${NC}"
                bar="$(printf '░%.0s' $(seq 1 20))"
            fi
            
            # Save traffic for online users (so it's not lost if they disconnect)
            if $is_online; then
                save_traffic "$user"
            fi
            
            # Online indicator
            local online_dot=""
            if $is_online; then
                online_dot="${GREEN}●${NC}"
            else
                online_dot="${YELLOW}○${NC}"
                speed_info="${YELLOW}offline${NC}"
            fi
            
            # Print user row
            echo -e "  $online_dot ${BOLD}$user${NC}"
            echo -e "    Used: $(format_bytes $traffic) / $limit_str  $status"
            echo -e "    [$bar]"
            if $is_online || [ "$speed_info" = "${YELLOW}offline${NC}" ]; then
                echo -e "    $speed_info"
            fi
            echo ""
        done
        
        echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "  ${CYAN}R${NC} Refresh  ${CYAN}Q${NC} Back"
        echo ""
        
        # Read with timeout for auto-refresh
        read -t 3 -n 1 -s key
        case "$key" in
            q|Q) break ;;
            r|R|'') ;;
        esac
    done
}

#═══════════════════════════════════════════════════════════════════
# MAIN MENU
#═══════════════════════════════════════════════════════════════════

main_menu() {
    while true; do
        header
        echo -e "${BOLD}Main Menu${NC}"
        line
        echo ""
        echo -e "  ${BOLD}USER MANAGEMENT${NC}"
        echo -e "    ${CYAN}1${NC}. Create user        ${CYAN}4${NC}. Online users"
        echo -e "    ${CYAN}2${NC}. Delete user        ${CYAN}5${NC}. List all users"
        echo -e "    ${CYAN}3${NC}. Change password"
        echo ""
        echo -e "  ${BOLD}ACCOUNT SETTINGS${NC}"
        echo -e "    ${CYAN}6${NC}. Manage expiration"
        echo ""
        echo -e "  ${BOLD}TRAFFIC${NC}"
        echo -e "    ${CYAN}7${NC}. Traffic Monitor    ${CYAN}8${NC}. Manage limits"
        echo ""
        line
        echo -e "    ${CYAN}0${NC}. Exit"
        echo ""
        
        read -p "Choice: " choice
        
        case $choice in
            1) create_user ;;
            2) delete_user ;;
            3) change_password ;;
            4) show_online ;;
            5) list_users ;;
            6) manage_expiry ;;
            7) view_traffic ;;
            8) manage_traffic ;;
            0)
                # Save traffic before exit
                for u in $(get_users); do save_traffic "$u"; done
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
        esac
    done
}

# Run
init
main_menu