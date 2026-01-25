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
TRAFFIC_LOG="$CONFIG_DIR/traffic_usage.log"

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
    echo "9. Exit"
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
    local uid=$(id -u "$username" 2>/dev/null)
    
    if [ -z "$uid" ]; then
        return
    fi
    
    # Remove existing rules for this user
    iptables -D OUTPUT -m owner --uid-owner "$uid" -j ACCEPT 2>/dev/null
    iptables -D INPUT -m owner --uid-owner "$uid" -j ACCEPT 2>/dev/null
    
    # Add new accounting rules
    iptables -A OUTPUT -m owner --uid-owner "$uid" -j ACCEPT 2>/dev/null
}

# Function to get traffic usage for a user
get_traffic_usage() {
    local username=$1
    local uid=$(id -u "$username" 2>/dev/null)
    
    if [ -z "$uid" ]; then
        echo "0"
        return
    fi
    
    # Get bytes from iptables OUTPUT chain for this user
    local bytes=$(iptables -L OUTPUT -v -n 2>/dev/null | grep "owner UID match $uid" | awk '{print $2}')
    
    if [ -z "$bytes" ]; then
        bytes=0
    fi
    
    # Convert K, M, G suffixes to bytes
    if [[ "$bytes" == *K ]]; then
        bytes=$(echo "$bytes" | sed 's/K//' | awk '{printf "%.0f", $1 * 1024}')
    elif [[ "$bytes" == *M ]]; then
        bytes=$(echo "$bytes" | sed 's/M//' | awk '{printf "%.0f", $1 * 1048576}')
    elif [[ "$bytes" == *G ]]; then
        bytes=$(echo "$bytes" | sed 's/G//' | awk '{printf "%.0f", $1 * 1073741824}')
    fi
    
    echo "$bytes"
}

# Function to format bytes to human readable
format_bytes() {
    local bytes=$1
    if [ "$bytes" -ge 1073741824 ]; then
        echo "$(echo "scale=2; $bytes / 1073741824" | bc) GB"
    elif [ "$bytes" -ge 1048576 ]; then
        echo "$(echo "scale=2; $bytes / 1048576" | bc) MB"
    elif [ "$bytes" -ge 1024 ]; then
        echo "$(echo "scale=2; $bytes / 1024" | bc) KB"
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
        # Remove iptables rules
        local uid=$(id -u "$username" 2>/dev/null)
        if [ -n "$uid" ]; then
            iptables -D OUTPUT -m owner --uid-owner "$uid" -j ACCEPT 2>/dev/null
        fi
        
        # Remove from traffic config
        sed -i "/^$username:/d" "$TRAFFIC_FILE" 2>/dev/null
        
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
            if [ "$traffic_limit" -gt 0 ]; then
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
            # Reset iptables counters for user
            local uid=$(id -u "$username" 2>/dev/null)
            if [ -n "$uid" ]; then
                iptables -Z OUTPUT 2>/dev/null
            fi
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
            if [ "$traffic_limit" -gt 0 ]; then
                traffic_limit_fmt=$(format_bytes "$traffic_limit")
                
                # Calculate percentage and status
                if [ "$traffic_used" -ge "$traffic_limit" ]; then
                    status="${RED}EXCEEDED${NC}"
                else
                    percent=$((traffic_used * 100 / traffic_limit))
                    if [ "$percent" -ge 90 ]; then
                        status="${YELLOW}${percent}%${NC}"
                    else
                        status="${GREEN}${percent}%${NC}"
                    fi
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

# Main loop
while true; do
    show_menu
    read -p "Select an option [1-9]: " choice
    
    case $choice in
        1) create_user ;;
        2) delete_user ;;
        3) list_users ;;
        4) show_online ;;
        5) change_password ;;
        6) manage_expiration ;;
        7) manage_traffic ;;
        8) view_traffic ;;
        9)
            echo -e "${GREEN}Exiting...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            sleep 1
            ;;
    esac
done
