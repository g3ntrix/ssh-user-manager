#!/bin/bash

# SSH User Manager with Traffic & Expiration Management
# Requires root privileges to run

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration directory
CONFIG_DIR="/etc/ssh-user-manager"
TRAFFIC_FILE="$CONFIG_DIR/traffic_limits.conf"
TRAFFIC_LOG="$CONFIG_DIR/traffic_usage.dat"
USER_CHAINS_FILE="$CONFIG_DIR/user_chains.conf"

# System users to exclude from management (add usernames separated by |)
EXCLUDED_USERS="nobody|linuxuser"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: This script must be run as root or with sudo${NC}"
    exit 1
fi

# Initialize configuration directory and files
init_config() {
    if [ ! -d "$CONFIG_DIR" ]; then
        mkdir -p "$CONFIG_DIR"
    fi
    if [ ! -f "$TRAFFIC_FILE" ]; then
        touch "$TRAFFIC_FILE"
    fi
    if [ ! -f "$TRAFFIC_LOG" ]; then
        touch "$TRAFFIC_LOG"
    fi
    if [ ! -f "$USER_CHAINS_FILE" ]; then
        touch "$USER_CHAINS_FILE"
    fi
    
    # Create SSH-USER-TRAFFIC chain if it doesn't exist
    iptables -N SSH-USER-TRAFFIC 2>/dev/null
    
    # Make sure chain is in INPUT and OUTPUT
    iptables -C INPUT -j SSH-USER-TRAFFIC 2>/dev/null || iptables -I INPUT -j SSH-USER-TRAFFIC
    iptables -C OUTPUT -j SSH-USER-TRAFFIC 2>/dev/null || iptables -I OUTPUT -j SSH-USER-TRAFFIC
}

# Initialize on script start
init_config

# Function to get user list
get_users() {
    awk -F: -v excluded="$EXCLUDED_USERS" '$3 >= 1000 && $3 < 65534 && $1 !~ excluded {print $1}' /etc/passwd
}

# Function to display main menu
show_menu() {
    clear
    echo "========================================"
    echo "    SSH User Manager v2.0"
    echo "========================================"
    echo "1. Create new user"
    echo "2. Delete user"
    echo "3. List all users"
    echo "4. Show online users"
    echo "5. Change user password"
    echo "6. Manage user expiration"
    echo "7. Manage traffic limits"
    echo "8. View traffic usage"
    echo "9. Add traffic manually"
    echo "10. Exit"
    echo "========================================"
}

# Function to convert days to date
days_to_date() {
    local days=$1
    date -d "+$days days" +%Y-%m-%d
}

# Function to create user
create_user() {
    echo -e "\n${GREEN}=== Create New User ===${NC}"
    read -p "Enter username: " username
    
    # Check if user already exists
    if id "$username" &>/dev/null; then
        echo -e "${RED}Error: User '$username' already exists${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    # Get password
    read -sp "Enter password for '$username': " password
    echo ""
    read -sp "Confirm password: " password_confirm
    echo ""
    
    if [ "$password" != "$password_confirm" ]; then
        echo -e "${RED}Error: Passwords do not match${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    if [ -z "$password" ]; then
        echo -e "${RED}Error: Password cannot be empty${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    # Get expiration
    echo ""
    echo "Set account expiration:"
    echo "1. 7 days"
    echo "2. 30 days"
    echo "3. 90 days"
    echo "4. 365 days"
    echo "5. Custom days"
    echo "6. No expiration"
    read -p "Select option [1-6]: " exp_choice
    
    case $exp_choice in
        1) exp_days=7 ;;
        2) exp_days=30 ;;
        3) exp_days=90 ;;
        4) exp_days=365 ;;
        5) 
            read -p "Enter number of days: " exp_days
            if ! [[ "$exp_days" =~ ^[0-9]+$ ]]; then
                echo -e "${RED}Invalid number${NC}"
                read -p "Press Enter to continue..."
                return
            fi
            ;;
        6) exp_days=0 ;;
        *) exp_days=30 ;;
    esac
    
    # Get traffic limit
    echo ""
    echo "Set traffic limit (download + upload):"
    echo "1. 1 GB"
    echo "2. 5 GB"
    echo "3. 10 GB"
    echo "4. 50 GB"
    echo "5. 100 GB"
    echo "6. Custom GB"
    echo "7. Unlimited"
    read -p "Select option [1-7]: " traffic_choice
    
    case $traffic_choice in
        1) traffic_limit=1 ;;
        2) traffic_limit=5 ;;
        3) traffic_limit=10 ;;
        4) traffic_limit=50 ;;
        5) traffic_limit=100 ;;
        6) 
            read -p "Enter limit in GB: " traffic_limit
            if ! [[ "$traffic_limit" =~ ^[0-9]+$ ]]; then
                echo -e "${RED}Invalid number${NC}"
                read -p "Press Enter to continue..."
                return
            fi
            ;;
        7) traffic_limit=0 ;;
        *) traffic_limit=0 ;;
    esac
    
    # Create user with home directory
    useradd -m -s /bin/bash "$username"
    
    if [ $? -eq 0 ]; then
        # Generate password hash using openssl and set directly (bypasses PAM)
        password_hash=$(openssl passwd -6 "$password")
        usermod -p "$password_hash" "$username"
        
        if [ $? -eq 0 ]; then
            # Set expiration if specified
            if [ "$exp_days" -gt 0 ]; then
                exp_date=$(days_to_date $exp_days)
                chage -E "$exp_date" "$username"
                echo -e "${GREEN}User '$username' created. Expires: $exp_date${NC}"
            else
                echo -e "${GREEN}User '$username' created with no expiration${NC}"
            fi
            
            # Save traffic limit
            if [ "$traffic_limit" -gt 0 ]; then
                # Remove old entry if exists
                sed -i "/^$username:/d" "$TRAFFIC_FILE" 2>/dev/null
                # Add new entry (limit in bytes)
                traffic_bytes=$((traffic_limit * 1073741824))
                echo "$username:$traffic_bytes:0" >> "$TRAFFIC_FILE"
                echo -e "${GREEN}Traffic limit set: ${traffic_limit} GB${NC}"
            else
                sed -i "/^$username:/d" "$TRAFFIC_FILE" 2>/dev/null
                echo "$username:0:0" >> "$TRAFFIC_FILE"
                echo -e "${GREEN}Traffic: Unlimited${NC}"
            fi
            
            # Setup iptables accounting for user
            setup_traffic_accounting "$username"
            
            echo -e "${YELLOW}User can now connect via SSH${NC}"
        else
            userdel -r "$username" 2>/dev/null
            echo -e "${RED}Failed to set password. User removed.${NC}"
        fi
    else
        echo -e "${RED}Failed to create user${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

# Function to setup iptables traffic accounting for a user
setup_traffic_accounting() {
    local username=$1
    
    # Create a unique chain for this user
    local chain_name="USER_${username}"
    
    # Create chain if it doesn't exist
    iptables -N "$chain_name" 2>/dev/null
    
    # Flush existing rules in user chain
    iptables -F "$chain_name" 2>/dev/null
    
    # Add counting rules (just count, don't block)
    iptables -A "$chain_name" -j RETURN
    
    # Remove old jumps to this chain
    iptables -D SSH-USER-TRAFFIC -m comment --comment "user:$username" -j "$chain_name" 2>/dev/null
    
    # Add jump to user chain from main tracking chain
    iptables -A SSH-USER-TRAFFIC -m comment --comment "user:$username" -j "$chain_name"
    
    # Record that this user has a chain
    grep -q "^$username$" "$USER_CHAINS_FILE" 2>/dev/null || echo "$username" >> "$USER_CHAINS_FILE"
    
    # Initialize traffic log entry if not exists
    if ! grep -q "^$username:" "$TRAFFIC_LOG" 2>/dev/null; then
        echo "$username:0" >> "$TRAFFIC_LOG"
    fi
}

# Function to get current iptables bytes for user
get_iptables_bytes() {
    local username=$1
    local chain_name="USER_${username}"
    
    # Get bytes from the user's chain (both INPUT and OUTPUT contribute)
    local bytes=$(iptables -L "$chain_name" -v -n -x 2>/dev/null | tail -n +3 | awk '{sum += $2} END {print sum+0}')
    echo "${bytes:-0}"
}

# Function to save current traffic and reset counters
save_traffic() {
    local username=$1
    local chain_name="USER_${username}"
    
    # Get current bytes from iptables
    local current_bytes=$(get_iptables_bytes "$username")
    
    # Get saved bytes
    local saved_bytes=$(grep "^$username:" "$TRAFFIC_LOG" 2>/dev/null | cut -d: -f2)
    saved_bytes=${saved_bytes:-0}
    
    # Add current to saved
    local total_bytes=$((saved_bytes + current_bytes))
    
    # Update the log file
    sed -i "/^$username:/d" "$TRAFFIC_LOG" 2>/dev/null
    echo "$username:$total_bytes" >> "$TRAFFIC_LOG"
    
    # Reset the iptables counter for this user
    iptables -Z "$chain_name" 2>/dev/null
    
    echo "$total_bytes"
}

# Function to get traffic usage for a user (saved + current)
get_traffic_usage() {
    local username=$1
    
    # Get current bytes from iptables
    local current_bytes=$(get_iptables_bytes "$username")
    
    # Get saved bytes from log
    local saved_bytes=$(grep "^$username:" "$TRAFFIC_LOG" 2>/dev/null | cut -d: -f2)
    saved_bytes=${saved_bytes:-0}
    
    # Return total
    local total=$((saved_bytes + current_bytes))
    echo "$total"
}

# Function to reset traffic for a user
reset_traffic() {
    local username=$1
    local chain_name="USER_${username}"
    
    # Reset saved traffic
    sed -i "/^$username:/d" "$TRAFFIC_LOG" 2>/dev/null
    echo "$username:0" >> "$TRAFFIC_LOG"
    
    # Reset iptables counter
    iptables -Z "$chain_name" 2>/dev/null
}

# Function to format bytes to human readable
format_bytes() {
    local bytes=$1
    if [ "$bytes" -ge 1073741824 ]; then
        local gb=$((bytes / 1073741824))
        local remainder=$((bytes % 1073741824))
        local decimal=$((remainder * 100 / 1073741824))
        printf "%d.%02d GB" "$gb" "$decimal"
    elif [ "$bytes" -ge 1048576 ]; then
        local mb=$((bytes / 1048576))
        local remainder=$((bytes % 1048576))
        local decimal=$((remainder * 100 / 1048576))
        printf "%d.%02d MB" "$mb" "$decimal"
    elif [ "$bytes" -ge 1024 ]; then
        local kb=$((bytes / 1024))
        local remainder=$((bytes % 1024))
        local decimal=$((remainder * 100 / 1024))
        printf "%d.%02d KB" "$kb" "$decimal"
    else
        echo "$bytes B"
    fi
}

# Function to delete user
delete_user() {
    echo -e "\n${RED}=== Delete User ===${NC}"
    
    mapfile -t users < <(get_users)
    
    if [ ${#users[@]} -eq 0 ]; then
        echo -e "${YELLOW}No users found${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo "Select user to delete:"
    echo "0. Cancel"
    for i in "${!users[@]}"; do
        echo "$((i+1)). ${users[$i]}"
    done
    echo ""
    
    read -p "Enter selection: " selection
    
    if [ "$selection" = "0" ]; then
        echo -e "${YELLOW}Cancelled${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt ${#users[@]} ]; then
        echo -e "${RED}Invalid selection${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    username="${users[$((selection-1))]}"
    
    read -p "Delete user '$username'? (yes/no): " confirm
    
    if [ "$confirm" = "yes" ]; then
        # Remove iptables chain and rules
        local chain_name="USER_${username}"
        iptables -D SSH-USER-TRAFFIC -m comment --comment "user:$username" -j "$chain_name" 2>/dev/null
        iptables -F "$chain_name" 2>/dev/null
        iptables -X "$chain_name" 2>/dev/null
        
        # Remove from config files
        sed -i "/^$username:/d" "$TRAFFIC_FILE" 2>/dev/null
        sed -i "/^$username:/d" "$TRAFFIC_LOG" 2>/dev/null
        sed -i "/^$username$/d" "$USER_CHAINS_FILE" 2>/dev/null
        
        # Delete user
        userdel -r "$username" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}User '$username' deleted${NC}"
        else
            userdel "$username" 2>/dev/null
            rm -rf "/home/$username" 2>/dev/null
            echo -e "${YELLOW}User deleted (some cleanup may be needed)${NC}"
        fi
    else
        echo -e "${YELLOW}Cancelled${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

# Function to list users with details
list_users() {
    echo -e "\n${GREEN}=== User List ===${NC}"
    printf "%-12s %-12s %-15s %-12s %-10s\n" "Username" "Status" "Expires" "Traffic Used" "Limit"
    echo "------------------------------------------------------------------------"
    
    mapfile -t users < <(get_users)
    
    if [ ${#users[@]} -eq 0 ]; then
        echo -e "${YELLOW}No users found${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    for username in "${users[@]}"; do
        # Get expiration date
        exp_date=$(chage -l "$username" 2>/dev/null | grep "Account expires" | cut -d: -f2 | xargs)
        if [ "$exp_date" = "never" ] || [ -z "$exp_date" ]; then
            exp_date="Never"
            status="${GREEN}Active${NC}"
        else
            # Check if expired
            exp_epoch=$(date -d "$exp_date" +%s 2>/dev/null)
            now_epoch=$(date +%s)
            if [ -n "$exp_epoch" ] && [ "$now_epoch" -gt "$exp_epoch" ]; then
                status="${RED}Expired${NC}"
            else
                status="${GREEN}Active${NC}"
            fi
        fi
        
        # Get traffic info
        traffic_used=$(get_traffic_usage "$username")
        traffic_used_fmt=$(format_bytes "$traffic_used")
        
        # Get traffic limit from config
        traffic_info=$(grep "^$username:" "$TRAFFIC_FILE" 2>/dev/null)
        if [ -n "$traffic_info" ]; then
            traffic_limit=$(echo "$traffic_info" | cut -d: -f2)
            if [ -n "$traffic_limit" ] && [ "$traffic_limit" -gt 0 ] 2>/dev/null; then
                traffic_limit_fmt=$(format_bytes "$traffic_limit")
            else
                traffic_limit_fmt="Unlimited"
            fi
        else
            traffic_limit_fmt="Unlimited"
        fi
        
        printf "%-12s %-12b %-15s %-12s %-10s\n" "$username" "$status" "$exp_date" "$traffic_used_fmt" "$traffic_limit_fmt"
    done
    
    echo ""
    read -p "Press Enter to continue..."
}

# Function to show online users
show_online() {
    echo -e "\n${CYAN}=== Online Users ===${NC}"
    echo ""
    
    # Get SSH connections
    online=$(who 2>/dev/null | grep -v "^root " | awk '{print $1, $2, $3, $4, $5}')
    
    if [ -z "$online" ]; then
        echo -e "${YELLOW}No users currently online${NC}"
    else
        printf "%-15s %-10s %-20s %-15s\n" "Username" "TTY" "Login Time" "From"
        echo "------------------------------------------------------------"
        
        who 2>/dev/null | while read line; do
            username=$(echo "$line" | awk '{print $1}')
            tty=$(echo "$line" | awk '{print $2}')
            login_time=$(echo "$line" | awk '{print $3, $4}')
            from=$(echo "$line" | awk '{print $5}' | tr -d '()')
            
            # Skip excluded users
            if echo "$username" | grep -qE "^($EXCLUDED_USERS|root)$"; then
                continue
            fi
            
            printf "%-15s %-10s %-20s %-15s\n" "$username" "$tty" "$login_time" "$from"
        done
    fi
    
    echo ""
    
    # Show active SSH sessions count
    ssh_count=$(ss -tn 2>/dev/null | grep ":22 " | wc -l)
    echo -e "${CYAN}Active SSH connections: $ssh_count${NC}"
    
    echo ""
    read -p "Press Enter to continue..."
}

# Function to change password
change_password() {
    echo -e "\n${YELLOW}=== Change Password ===${NC}"
    
    mapfile -t users < <(get_users)
    
    if [ ${#users[@]} -eq 0 ]; then
        echo -e "${YELLOW}No users found${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo "Select user:"
    echo "0. Cancel"
    for i in "${!users[@]}"; do
        echo "$((i+1)). ${users[$i]}"
    done
    echo ""
    
    read -p "Enter selection: " selection
    
    if [ "$selection" = "0" ]; then
        read -p "Press Enter to continue..."
        return
    fi
    
    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt ${#users[@]} ]; then
        echo -e "${RED}Invalid selection${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    username="${users[$((selection-1))]}"
    
    read -sp "Enter new password: " password
    echo ""
    read -sp "Confirm password: " password_confirm
    echo ""
    
    if [ "$password" != "$password_confirm" ]; then
        echo -e "${RED}Passwords do not match${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    if [ -z "$password" ]; then
        echo -e "${RED}Password cannot be empty${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    password_hash=$(openssl passwd -6 "$password")
    usermod -p "$password_hash" "$username"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Password changed for '$username'${NC}"
    else
        echo -e "${RED}Failed to change password${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

# Function to manage expiration
manage_expiration() {
    echo -e "\n${YELLOW}=== Manage Expiration ===${NC}"
    
    mapfile -t users < <(get_users)
    
    if [ ${#users[@]} -eq 0 ]; then
        echo -e "${YELLOW}No users found${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo "Select user:"
    echo "0. Cancel"
    for i in "${!users[@]}"; do
        exp_date=$(chage -l "${users[$i]}" 2>/dev/null | grep "Account expires" | cut -d: -f2 | xargs)
        echo "$((i+1)). ${users[$i]} (Expires: $exp_date)"
    done
    echo ""
    
    read -p "Enter selection: " selection
    
    if [ "$selection" = "0" ]; then
        read -p "Press Enter to continue..."
        return
    fi
    
    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt ${#users[@]} ]; then
        echo -e "${RED}Invalid selection${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    username="${users[$((selection-1))]}"
    
    echo ""
    echo "Set new expiration for '$username':"
    echo "1. Extend 7 days from now"
    echo "2. Extend 30 days from now"
    echo "3. Extend 90 days from now"
    echo "4. Extend 365 days from now"
    echo "5. Custom days from now"
    echo "6. Remove expiration"
    echo "7. Deactivate user now"
    read -p "Select option [1-7]: " exp_choice
    
    case $exp_choice in
        1) 
            exp_date=$(days_to_date 7)
            chage -E "$exp_date" "$username"
            echo -e "${GREEN}Expiration set to: $exp_date${NC}"
            ;;
        2) 
            exp_date=$(days_to_date 30)
            chage -E "$exp_date" "$username"
            echo -e "${GREEN}Expiration set to: $exp_date${NC}"
            ;;
        3) 
            exp_date=$(days_to_date 90)
            chage -E "$exp_date" "$username"
            echo -e "${GREEN}Expiration set to: $exp_date${NC}"
            ;;
        4) 
            exp_date=$(days_to_date 365)
            chage -E "$exp_date" "$username"
            echo -e "${GREEN}Expiration set to: $exp_date${NC}"
            ;;
        5)
            read -p "Enter number of days: " days
            if [[ "$days" =~ ^[0-9]+$ ]]; then
                exp_date=$(days_to_date $days)
                chage -E "$exp_date" "$username"
                echo -e "${GREEN}Expiration set to: $exp_date${NC}"
            else
                echo -e "${RED}Invalid number${NC}"
            fi
            ;;
        6)
            chage -E -1 "$username"
            echo -e "${GREEN}Expiration removed for '$username'${NC}"
            ;;
        7)
            chage -E 0 "$username"
            echo -e "${YELLOW}User '$username' deactivated${NC}"
            ;;
        *)
            echo -e "${YELLOW}No changes made${NC}"
            ;;
    esac
    
    read -p "Press Enter to continue..."
}

# Function to manage traffic limits
manage_traffic() {
    echo -e "\n${YELLOW}=== Manage Traffic Limits ===${NC}"
    
    mapfile -t users < <(get_users)
    
    if [ ${#users[@]} -eq 0 ]; then
        echo -e "${YELLOW}No users found${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo "Select user:"
    echo "0. Cancel"
    for i in "${!users[@]}"; do
        traffic_info=$(grep "^${users[$i]}:" "$TRAFFIC_FILE" 2>/dev/null)
        if [ -n "$traffic_info" ]; then
            limit=$(echo "$traffic_info" | cut -d: -f2)
            if [ "$limit" -gt 0 ]; then
                limit_fmt=$(format_bytes "$limit")
            else
                limit_fmt="Unlimited"
            fi
        else
            limit_fmt="Unlimited"
        fi
        echo "$((i+1)). ${users[$i]} (Limit: $limit_fmt)"
    done
    echo ""
    
    read -p "Enter selection: " selection
    
    if [ "$selection" = "0" ]; then
        read -p "Press Enter to continue..."
        return
    fi
    
    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt ${#users[@]} ]; then
        echo -e "${RED}Invalid selection${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    username="${users[$((selection-1))]}"
    
    echo ""
    echo "Set traffic limit for '$username':"
    echo "1. 1 GB"
    echo "2. 5 GB"
    echo "3. 10 GB"
    echo "4. 50 GB"
    echo "5. 100 GB"
    echo "6. Custom GB"
    echo "7. Unlimited"
    echo "8. Reset usage counter"
    read -p "Select option [1-8]: " traffic_choice
    
    case $traffic_choice in
        1) traffic_limit=1 ;;
        2) traffic_limit=5 ;;
        3) traffic_limit=10 ;;
        4) traffic_limit=50 ;;
        5) traffic_limit=100 ;;
        6) 
            read -p "Enter limit in GB: " traffic_limit
            if ! [[ "$traffic_limit" =~ ^[0-9]+$ ]]; then
                echo -e "${RED}Invalid number${NC}"
                read -p "Press Enter to continue..."
                return
            fi
            ;;
        7) traffic_limit=0 ;;
        8)
            # Reset traffic counter for user
            reset_traffic "$username"
            echo -e "${GREEN}Traffic counter reset for '$username'${NC}"
            read -p "Press Enter to continue..."
            return
            ;;
        *)
            echo -e "${YELLOW}No changes made${NC}"
            read -p "Press Enter to continue..."
            return
            ;;
    esac
    
    # Update traffic limit
    sed -i "/^$username:/d" "$TRAFFIC_FILE" 2>/dev/null
    if [ "$traffic_limit" -gt 0 ]; then
        traffic_bytes=$((traffic_limit * 1073741824))
        echo "$username:$traffic_bytes:0" >> "$TRAFFIC_FILE"
        echo -e "${GREEN}Traffic limit set to ${traffic_limit} GB${NC}"
    else
        echo "$username:0:0" >> "$TRAFFIC_FILE"
        echo -e "${GREEN}Traffic set to unlimited${NC}"
    fi
    
    # Ensure iptables rule exists
    setup_traffic_accounting "$username"
    
    read -p "Press Enter to continue..."
}

# Function to view traffic usage
view_traffic() {
    echo -e "\n${CYAN}=== Traffic Usage ===${NC}"
    printf "%-15s %-15s %-15s %-10s\n" "Username" "Used" "Limit" "Status"
    echo "------------------------------------------------------------"
    
    mapfile -t users < <(get_users)
    
    if [ ${#users[@]} -eq 0 ]; then
        echo -e "${YELLOW}No users found${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    for username in "${users[@]}"; do
        # Get current usage
        traffic_used=$(get_traffic_usage "$username")
        traffic_used_fmt=$(format_bytes "$traffic_used")
        
        # Get limit from config
        traffic_info=$(grep "^$username:" "$TRAFFIC_FILE" 2>/dev/null)
        if [ -n "$traffic_info" ]; then
            traffic_limit=$(echo "$traffic_info" | cut -d: -f2)
            if [ -n "$traffic_limit" ] && [ "$traffic_limit" -gt 0 ] 2>/dev/null; then
                traffic_limit_fmt=$(format_bytes "$traffic_limit")
                
                # Calculate percentage and status
                if [ "$traffic_used" -ge "$traffic_limit" ] 2>/dev/null; then
                    status="${RED}EXCEEDED${NC}"
                elif [ "$traffic_limit" -gt 0 ] 2>/dev/null; then
                    percent=$((traffic_used * 100 / traffic_limit))
                    if [ "$percent" -ge 90 ]; then
                        status="${YELLOW}${percent}%${NC}"
                    else
                        status="${GREEN}${percent}%${NC}"
                    fi
                else
                    status="${GREEN}OK${NC}"
                fi
            else
                traffic_limit_fmt="Unlimited"
                status="${GREEN}OK${NC}"
            fi
        else
            traffic_limit_fmt="Unlimited"
            status="${GREEN}OK${NC}"
        fi
        
        printf "%-15s %-15s %-15s %-10b\n" "$username" "$traffic_used_fmt" "$traffic_limit_fmt" "$status"
    done
    
    echo ""
    read -p "Press Enter to continue..."
}

# Function to manually add traffic (for testing or manual accounting)
add_traffic_manual() {
    echo -e "\n${YELLOW}=== Add Traffic Manually ===${NC}"
    
    mapfile -t users < <(get_users)
    
    if [ ${#users[@]} -eq 0 ]; then
        echo -e "${YELLOW}No users found${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo "Select user:"
    echo "0. Cancel"
    for i in "${!users[@]}"; do
        current=$(get_traffic_usage "${users[$i]}")
        current_fmt=$(format_bytes "$current")
        echo "$((i+1)). ${users[$i]} (Current: $current_fmt)"
    done
    echo ""
    
    read -p "Enter selection: " selection
    
    if [ "$selection" = "0" ]; then
        read -p "Press Enter to continue..."
        return
    fi
    
    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt ${#users[@]} ]; then
        echo -e "${RED}Invalid selection${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    username="${users[$((selection-1))]}"
    
    echo ""
    echo "Add traffic for '$username':"
    echo "1. Add 100 MB"
    echo "2. Add 500 MB"
    echo "3. Add 1 GB"
    echo "4. Add 5 GB"
    echo "5. Custom MB"
    read -p "Select option [1-5]: " add_choice
    
    case $add_choice in
        1) add_bytes=$((100 * 1048576)) ;;
        2) add_bytes=$((500 * 1048576)) ;;
        3) add_bytes=$((1 * 1073741824)) ;;
        4) add_bytes=$((5 * 1073741824)) ;;
        5)
            read -p "Enter amount in MB: " add_mb
            if ! [[ "$add_mb" =~ ^[0-9]+$ ]]; then
                echo -e "${RED}Invalid number${NC}"
                read -p "Press Enter to continue..."
                return
            fi
            add_bytes=$((add_mb * 1048576))
            ;;
        *)
            echo -e "${YELLOW}Cancelled${NC}"
            read -p "Press Enter to continue..."
            return
            ;;
    esac
    
    # Get current saved bytes
    local saved_bytes=$(grep "^$username:" "$TRAFFIC_LOG" 2>/dev/null | cut -d: -f2)
    saved_bytes=${saved_bytes:-0}
    
    # Add to saved
    local new_total=$((saved_bytes + add_bytes))
    
    # Update the log file
    sed -i "/^$username:/d" "$TRAFFIC_LOG" 2>/dev/null
    echo "$username:$new_total" >> "$TRAFFIC_LOG"
    
    local added_fmt=$(format_bytes "$add_bytes")
    local total_fmt=$(format_bytes "$new_total")
    echo -e "${GREEN}Added $added_fmt to '$username'. New total: $total_fmt${NC}"
    
    read -p "Press Enter to continue..."
}

# Main loop
while true; do
    show_menu
    read -p "Select an option [1-10]: " choice
    
    case $choice in
        1) create_user ;;
        2) delete_user ;;
        3) list_users ;;
        4) show_online ;;
        5) change_password ;;
        6) manage_expiration ;;
        7) manage_traffic ;;
        8) view_traffic ;;
        9) add_traffic_manual ;;
        10)
            echo -e "${GREEN}Exiting...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            sleep 1
            ;;
    esac
done
