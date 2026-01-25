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

# Check root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Run as root: sudo $0${NC}"
    exit 1
fi

# Initialize
init() {
    mkdir -p "$CONFIG_DIR"
    touch "$TRAFFIC_FILE" "$LIMITS_FILE" "$CONFIG_DIR/expiry_times.dat" "$CONFIG_DIR/baseline.dat"
    
    # Ensure nethogs is installed
    which nethogs >/dev/null 2>&1 || apt-get install -y nethogs >/dev/null 2>&1
    
    # Setup rules for all existing users
    for user in $(get_users); do
        setup_user_iptables "$user"
    done
}

# Get managed users
get_users() {
    awk -F: -v ex="$EXCLUDED_USERS" '$3 >= 1000 && $3 < 65534 && $1 !~ ex {print $1}' /etc/passwd
}

# Format bytes
format_bytes() {
    local b=$1
    if [ "$b" -ge 1073741824 ]; then
        printf "%.2f GB" "$(awk "BEGIN {printf \"%.2f\", $b/1073741824}")"
    elif [ "$b" -ge 1048576 ]; then
        printf "%.2f MB" "$(awk "BEGIN {printf \"%.2f\", $b/1048576}")"
    elif [ "$b" -ge 1024 ]; then
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

# Get current /proc/io total for user's sshd processes
get_proc_io_raw() {
    local user=$1
    local total=0
    
    local pids=$(pgrep -u "$user" sshd 2>/dev/null)
    [ -z "$pids" ] && echo "0" && return
    
    for pid in $pids; do
        if [ -f "/proc/$pid/io" ]; then
            local rchar=$(awk '/^rchar:/{print $2}' /proc/$pid/io 2>/dev/null)
            local wchar=$(awk '/^wchar:/{print $2}' /proc/$pid/io 2>/dev/null)
            total=$((total + ${rchar:-0} + ${wchar:-0}))
        fi
    done
    
    echo "$total"
}

# Get baseline (already counted traffic) for user
get_baseline() {
    local user=$1
    grep "^$user:" "$BASELINE_FILE" 2>/dev/null | cut -d: -f2
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
    
    # If no active session, return 0
    [ "$raw" -eq 0 ] && echo "0" && return
    
    # If baseline is higher than raw, session restarted - use raw as new traffic
    if [ "${baseline:-0}" -gt "$raw" ]; then
        echo "$raw"
    else
        echo $((raw - ${baseline:-0}))
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
    local saved=$(grep "^$user:" "$TRAFFIC_FILE" 2>/dev/null | cut -d: -f2)
    echo "  Previously saved: $(format_bytes ${saved:-0})"
    
    echo -e "\n${YELLOW}5. Total traffic:${NC}"
    local total=$(get_traffic "$user")
    echo "  Total (saved + session): $(format_bytes $total)"
    
    read -p "Press Enter to continue..."
}

# Get total traffic (saved + unsaved session traffic)
get_traffic() {
    local user=$1
    local saved=$(grep "^$user:" "$TRAFFIC_FILE" 2>/dev/null | cut -d: -f2)
    local session=$(get_session_traffic "$user")
    echo $((${saved:-0} + ${session:-0}))
}

# Save traffic: add session traffic to saved total and update baseline
save_traffic() {
    local user=$1
    local session=$(get_session_traffic "$user")
    local saved=$(grep "^$user:" "$TRAFFIC_FILE" 2>/dev/null | cut -d: -f2)
    local raw=$(get_proc_io_raw "$user")
    
    # Add session traffic to saved total
    local new_total=$((${saved:-0} + ${session:-0}))
    
    sed -i "/^$user:/d" "$TRAFFIC_FILE"
    echo "$user:$new_total" >> "$TRAFFIC_FILE"
    
    # Update baseline to current raw value so we don't double-count
    set_baseline "$user" "$raw"
}

# Reset traffic for user (also resets baseline)
reset_traffic() {
    local user=$1
    sed -i "/^$user:/d" "$TRAFFIC_FILE"
    echo "$user:0" >> "$TRAFFIC_FILE"
    
    # Set baseline to current raw so we start fresh
    local raw=$(get_proc_io_raw "$user")
    set_baseline "$user" "$raw"
}

# Get/Set traffic limit
get_limit() {
    local user=$1
    grep "^$user:" "$LIMITS_FILE" 2>/dev/null | cut -d: -f2
}

set_limit() {
    local user=$1 limit=$2
    sed -i "/^$user:/d" "$LIMITS_FILE"
    echo "$user:$limit" >> "$LIMITS_FILE"
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
    
    # Create user
    useradd -m -s /bin/bash "$username" 2>/dev/null
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
        clear
        echo -e "${BOLD}${CYAN}"
        echo "  ╔═══════════════════════════════════════════════════════════════════════╗"
        echo "  ║                    📊 REAL-TIME TRAFFIC MONITOR                       ║"
        echo "  ╚═══════════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        printf "  ${BOLD}%-10s │ %-10s │ %-10s │ %-12s │ %-10s │ %-8s${NC}\n" "USER" "↑ UP" "↓ DOWN" "TOTAL" "LIMIT" "STATUS"
        echo "  ──────────┼────────────┼────────────┼──────────────┼────────────┼─────────"
        
        for user in "${users[@]}"; do
            local traffic=$(get_traffic "$user")
            local limit=$(get_limit "$user")
            local status="${GREEN}OK${NC}"
            local limit_str="∞"
            local up="-"
            local down="-"
            
            # Check if online
            if pgrep -u "$user" sshd >/dev/null 2>&1; then
                # Get speed from nethogs (quick sample)
                local speed_data=$(timeout 2 nethogs -t -c 1 2>/dev/null | grep -i "$user" | tail -1)
                if [ -n "$speed_data" ]; then
                    up=$(echo "$speed_data" | awk '{printf "%.1f KB/s", $(NF-1)}')
                    down=$(echo "$speed_data" | awk '{printf "%.1f KB/s", $NF}')
                else
                    up="${CYAN}online${NC}"
                    down="-"
                fi
            else
                up="${YELLOW}offline${NC}"
            fi
            
            if [ -n "$limit" ] && [ "$limit" -gt 0 ]; then
                limit_str=$(format_bytes "$limit")
                if [ $traffic -ge $limit ]; then
                    status="${RED}OVER${NC}"
                else
                    local pct=$((traffic * 100 / limit))
                    if [ $pct -ge 90 ]; then
                        status="${YELLOW}${pct}%${NC}"
                    else
                        status="${GREEN}${pct}%${NC}"
                    fi
                fi
            fi
            
            printf "  %-10s │ %-18b │ %-18b │ %-12s │ %-10s │ %-8b\n" \
                "$user" "$up" "$down" "$(format_bytes $traffic)" "$limit_str" "$status"
        done
        
        echo ""
        echo "  ──────────────────────────────────────────────────────────────────────────"
        echo -e "  ${CYAN}[R]${NC} Refresh   ${CYAN}[S]${NC} Save traffic   ${CYAN}[Q]${NC} Back to menu"
        echo ""
        
        # Read with timeout for auto-refresh feel, or wait for keypress
        read -t 5 -n 1 -s key
        case "$key" in
            q|Q) break ;;
            s|S) 
                for u in "${users[@]}"; do save_traffic "$u"; done
                echo -e "  ${GREEN}Traffic saved!${NC}"
                sleep 1
                ;;
            r|R|'') ;; # Refresh
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