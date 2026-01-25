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
    touch "$TRAFFIC_FILE" "$LIMITS_FILE"
    
    # Check if xt_owner module is available
    if ! lsmod | grep -q "xt_owner"; then
        modprobe xt_owner 2>/dev/null
    fi
    
    # Setup rules for all existing users
    # Note: owner match only works in OUTPUT chain
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
    # Ensure conntrack is available
    which conntrack >/dev/null 2>&1 || apt-get install -y conntrack >/dev/null 2>&1
    touch "$CONFIG_DIR/session_$user.dat" 2>/dev/null
}

# Get live session traffic using multiple methods
get_session_traffic() {
    local user=$1
    local total=0
    
    # Method 1: Try /proc/[pid]/io for sshd processes
    local pids=$(pgrep -u "$user" sshd 2>/dev/null)
    if [ -n "$pids" ]; then
        for pid in $pids; do
            if [ -f "/proc/$pid/io" ]; then
                local rbytes=$(awk '/^read_bytes:/{print $2}' /proc/$pid/io 2>/dev/null)
                local wbytes=$(awk '/^write_bytes:/{print $2}' /proc/$pid/io 2>/dev/null)
                total=$((total + ${rbytes:-0} + ${wbytes:-0}))
            fi
        done
    fi
    
    # Method 2: If /proc/io gave 0, try conntrack
    if [ "$total" -eq 0 ] && which conntrack >/dev/null 2>&1; then
        # Get all SSH connections and sum bytes
        # conntrack output has bytes= field
        local conn_bytes=$(conntrack -L -p tcp --dport 22 2>/dev/null | \
            awk -F'bytes=' '{for(i=2;i<=NF;i++){split($i,a," ");sum+=a[1]}} END{print sum+0}')
        total=${conn_bytes:-0}
    fi
    
    # Method 3: If still 0, try reading from /proc/net/dev differences
    # (This would need baseline tracking, skip for now)
    
    echo "$total"
}

# Debug function - call from menu to see what's happening
debug_traffic() {
    local user=$1
    echo -e "\n${CYAN}=== Traffic Debug for $user ===${NC}"
    
    echo -e "\n${YELLOW}1. SSHD processes for user:${NC}"
    pgrep -u "$user" sshd 2>/dev/null | while read pid; do
        echo "  PID: $pid"
        if [ -f "/proc/$pid/io" ]; then
            echo "  /proc/$pid/io:"
            cat /proc/$pid/io 2>/dev/null | sed 's/^/    /'
        fi
    done
    
    echo -e "\n${YELLOW}2. All processes for user:${NC}"
    ps -u "$user" -o pid,comm,rss 2>/dev/null | head -10
    
    echo -e "\n${YELLOW}3. Conntrack SSH connections:${NC}"
    conntrack -L -p tcp --dport 22 2>/dev/null | head -5
    
    echo -e "\n${YELLOW}4. SS socket stats:${NC}"
    ss -tnp 2>/dev/null | grep -E "ssh|:22" | head -5
    
    echo -e "\n${YELLOW}5. Current traffic calculation:${NC}"
    local traffic=$(get_session_traffic "$user")
    echo "  Raw bytes: $traffic"
    echo "  Formatted: $(format_bytes $traffic)"
    
    read -p "Press Enter to continue..."
}

# Get total traffic (saved + current session)
get_traffic() {
    local user=$1
    local saved=$(grep "^$user:" "$TRAFFIC_FILE" 2>/dev/null | cut -d: -f2)
    local current=$(get_session_traffic "$user")
    echo $((${saved:-0} + ${current:-0}))
}

# Save traffic counter (accumulates session data)
save_traffic() {
    local user=$1
    local current=$(get_session_traffic "$user")
    local saved=$(grep "^$user:" "$TRAFFIC_FILE" 2>/dev/null | cut -d: -f2)
    local total=$((${saved:-0} + ${current:-0}))
    
    sed -i "/^$user:/d" "$TRAFFIC_FILE"
    echo "$user:$total" >> "$TRAFFIC_FILE"
}

# Reset traffic for user
reset_traffic() {
    local user=$1
    sed -i "/^$user:/d" "$TRAFFIC_FILE"
    echo "$user:0" >> "$TRAFFIC_FILE"
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
    echo "  1. 7 days      4. 365 days"
    echo "  2. 30 days     5. Custom"
    echo "  3. 90 days     6. Never"
    read -p "Choice [2]: " exp_choice
    
    case ${exp_choice:-2} in
        1) exp_days=7 ;;
        2) exp_days=30 ;;
        3) exp_days=90 ;;
        4) exp_days=365 ;;
        5) read -p "Days: " exp_days ;;
        6) exp_days=0 ;;
        *) exp_days=30 ;;
    esac
    
    echo ""
    echo -e "${CYAN}Traffic Limit:${NC}"
    echo "  1. 5 GB        4. 100 GB"
    echo "  2. 10 GB       5. Custom"
    echo "  3. 50 GB       6. Unlimited"
    read -p "Choice [6]: " lim_choice
    
    case ${lim_choice:-6} in
        1) limit=$((5 * 1073741824)) ;;
        2) limit=$((10 * 1073741824)) ;;
        3) limit=$((50 * 1073741824)) ;;
        4) limit=$((100 * 1073741824)) ;;
        5) read -p "Limit in GB: " gb; limit=$((gb * 1073741824)) ;;
        6) limit=0 ;;
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
    if [ "$exp_days" -gt 0 ]; then
        chage -E "$(days_to_date $exp_days)" "$username"
    fi
    
    # Set traffic limit
    set_limit "$username" "$limit"
    
    # Initialize traffic
    echo "$username:0" >> "$TRAFFIC_FILE"
    
    # Setup iptables
    setup_user_iptables "$username"
    
    echo ""
    echo -e "${GREEN}✓ User '$username' created successfully${NC}"
    [ "$exp_days" -gt 0 ] && echo -e "  Expires: $(days_to_date $exp_days)"
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
    
    echo "1. Add 7 days       5. Custom days"
    echo "2. Add 30 days      6. Remove expiration"
    echo "3. Add 90 days      7. Deactivate now"
    echo "4. Add 365 days     0. Cancel"
    echo ""
    read -p "Choice: " choice
    
    case $choice in
        1) chage -E "$(days_to_date 7)" "$SELECTED_USER" ;;
        2) chage -E "$(days_to_date 30)" "$SELECTED_USER" ;;
        3) chage -E "$(days_to_date 90)" "$SELECTED_USER" ;;
        4) chage -E "$(days_to_date 365)" "$SELECTED_USER" ;;
        5) read -p "Days: " d; chage -E "$(days_to_date $d)" "$SELECTED_USER" ;;
        6) chage -E -1 "$SELECTED_USER" ;;
        7) chage -E 0 "$SELECTED_USER"; kill_user_sessions "$SELECTED_USER" ;;
        0) return ;;
    esac
    
    echo -e "${GREEN}✓ Updated. New expiry: $(get_expiry $SELECTED_USER)${NC}"
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
    
    echo "1. Set limit 5 GB      5. Custom limit"
    echo "2. Set limit 10 GB     6. Remove limit"
    echo "3. Set limit 50 GB     7. Reset usage"
    echo "4. Set limit 100 GB    0. Cancel"
    echo ""
    read -p "Choice: " choice
    
    case $choice in
        1) set_limit "$SELECTED_USER" $((5 * 1073741824)) ;;
        2) set_limit "$SELECTED_USER" $((10 * 1073741824)) ;;
        3) set_limit "$SELECTED_USER" $((50 * 1073741824)) ;;
        4) set_limit "$SELECTED_USER" $((100 * 1073741824)) ;;
        5) read -p "Limit in GB: " gb; set_limit "$SELECTED_USER" $((gb * 1073741824)) ;;
        6) set_limit "$SELECTED_USER" 0 ;;
        7) reset_traffic "$SELECTED_USER"; echo -e "${GREEN}✓ Traffic reset${NC}"; pause; return ;;
        0) return ;;
    esac
    
    echo -e "${GREEN}✓ Limit updated${NC}"
    pause
}

view_traffic() {
    header
    echo -e "${CYAN}📈 Traffic Usage${NC}"
    line
    echo ""
    
    local users=($(get_users))
    
    if [ ${#users[@]} -eq 0 ]; then
        echo -e "${YELLOW}No users found${NC}"
        pause
        return
    fi
    
    printf "${BOLD}%-12s %-15s %-15s %-10s${NC}\n" "USER" "USED" "LIMIT" "STATUS"
    line
    
    for user in "${users[@]}"; do
        local traffic=$(get_traffic "$user")
        local limit=$(get_limit "$user")
        local status="${GREEN}OK${NC}"
        local limit_str="Unlimited"
        
        if [ -n "$limit" ] && [ "$limit" -gt 0 ]; then
            limit_str=$(format_bytes "$limit")
            local pct=$((traffic * 100 / limit))
            if [ $traffic -ge $limit ]; then
                status="${RED}EXCEEDED${NC}"
            elif [ $pct -ge 90 ]; then
                status="${YELLOW}${pct}%${NC}"
            else
                status="${GREEN}${pct}%${NC}"
            fi
        fi
        
        printf "%-12s %-15s %-15s %-10b\n" "$user" "$(format_bytes $traffic)" "$limit_str" "$status"
    done
    
    pause
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
        echo -e "    ${CYAN}7${NC}. View traffic       ${CYAN}8${NC}. Manage limits"
        echo -e "    ${CYAN}9${NC}. Debug traffic"
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
            9) 
                header
                echo "Select user to debug:"
                select_user
                [ -n "$SELECTED_USER" ] && debug_traffic "$SELECTED_USER"
                ;;
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
