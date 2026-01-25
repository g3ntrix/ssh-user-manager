#!/bin/bash

# SSH User Manager
# Requires root privileges to run

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# System users to exclude from management (add usernames separated by |)
EXCLUDED_USERS="nobody|linuxuser"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: This script must be run as root or with sudo${NC}"
    exit 1
fi

# Function to display menu
show_menu() {
    clear
    echo "================================"
    echo "    SSH User Manager"
    echo "================================"
    echo "1. Create new user"
    echo "2. Delete user"
    echo "3. List all users"
    echo "4. Change user password"
    echo "5. Exit"
    echo "================================"
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
    
    # Create user with home directory
    useradd -m -s /bin/bash "$username"
    
    if [ $? -eq 0 ]; then
        # Generate password hash using openssl and set directly (bypasses PAM)
        password_hash=$(openssl passwd -6 "$password")
        usermod -p "$password_hash" "$username"
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}User '$username' created successfully with password${NC}"
            echo -e "${YELLOW}User can now connect via SSH${NC}"
        else
            # Clean up the user if password setting failed
            userdel -r "$username" 2>/dev/null
            echo -e "${RED}Failed to set password. User removed.${NC}"
        fi
    else
        echo -e "${RED}Failed to create user${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

# Function to delete user
delete_user() {
    echo -e "\n${RED}=== Delete User ===${NC}"
    
    # Get list of regular users (UID >= 1000, exclude system users)
    mapfile -t users < <(awk -F: -v excluded="$EXCLUDED_USERS" '$3 >= 1000 && $3 < 65534 && $1 !~ excluded {print $1}' /etc/passwd)
    
    if [ ${#users[@]} -eq 0 ]; then
        echo -e "${YELLOW}No regular users found${NC}"
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
        echo -e "${YELLOW}Deletion cancelled${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    # Validate selection
    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt ${#users[@]} ]; then
        echo -e "${RED}Invalid selection${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    username="${users[$((selection-1))]}"
    
    # Prevent deleting root
    if [ "$username" = "root" ]; then
        echo -e "${RED}Error: Cannot delete root user${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    # Confirm deletion
    read -p "Delete user '$username' and their home directory? (yes/no): " confirm
    
    if [ "$confirm" = "yes" ]; then
        # Delete user and home directory
        userdel -r "$username" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}User '$username' deleted successfully${NC}"
        else
            # Try without removing home directory if it fails
            userdel "$username" 2>/dev/null
            if [ $? -eq 0 ]; then
                echo -e "${YELLOW}User '$username' deleted (home directory may still exist)${NC}"
                # Try to remove home directory manually
                rm -rf "/home/$username" 2>/dev/null
            else
                echo -e "${RED}Failed to delete user${NC}"
            fi
        fi
    else
        echo -e "${YELLOW}Deletion cancelled${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

# Function to list users
list_users() {
    echo -e "\n${GREEN}=== SSH Users ===${NC}"
    echo "Username          UID    Home Directory"
    echo "----------------------------------------"
    
    # List users with UID >= 1000, exclude system users like nobody and linuxuser
    awk -F: -v excluded="$EXCLUDED_USERS" '$3 >= 1000 && $3 < 65534 && $1 !~ excluded {printf "%-15s   %-6s %s\n", $1, $3, $6}' /etc/passwd
    
    echo ""
    read -p "Press Enter to continue..."
}

# Function to change user password
change_password() {
    echo -e "\n${YELLOW}=== Change User Password ===${NC}"
    
    # Get list of regular users (exclude system users)
    mapfile -t users < <(awk -F: -v excluded="$EXCLUDED_USERS" '$3 >= 1000 && $3 < 65534 && $1 !~ excluded {print $1}' /etc/passwd)
    
    if [ ${#users[@]} -eq 0 ]; then
        echo -e "${YELLOW}No regular users found${NC}"
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
        echo -e "${YELLOW}Operation cancelled${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    # Validate selection
    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt ${#users[@]} ]; then
        echo -e "${RED}Invalid selection${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    username="${users[$((selection-1))]}"
    
    # Get new password
    read -sp "Enter new password for '$username': " password
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
    
    # Set password using openssl hash (bypasses PAM)
    password_hash=$(openssl passwd -6 "$password")
    usermod -p "$password_hash" "$username"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Password changed successfully for '$username'${NC}"
    else
        echo -e "${RED}Failed to change password${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

# Main loop
while true; do
    show_menu
    read -p "Select an option [1-5]: " choice
    
    case $choice in
        1)
            create_user
            ;;
        2)
            delete_user
            ;;
        3)
            list_users
            ;;
        4)
            change_password
            ;;
        5)
            echo -e "${GREEN}Exiting...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option. Please try again.${NC}"
            sleep 1
            ;;
    esac
done