#!/bin/bash

# SSH User Manager
# Requires root privileges to run

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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
    
    # Create user with home directory
    useradd -m -s /bin/bash "$username"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}User '$username' created successfully${NC}"
        
        # Set password
        echo "Setting password for user '$username':"
        passwd "$username"
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Password set successfully${NC}"
            echo -e "${YELLOW}User '$username' can now connect via SSH${NC}"
        else
            echo -e "${RED}Failed to set password${NC}"
        fi
    else
        echo -e "${RED}Failed to create user${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

# Function to delete user
delete_user() {
    echo -e "\n${RED}=== Delete User ===${NC}"
    read -p "Enter username to delete: " username
    
    # Check if user exists
    if ! id "$username" &>/dev/null; then
        echo -e "${RED}Error: User '$username' does not exist${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    # Prevent deleting root
    if [ "$username" = "root" ]; then
        echo -e "${RED}Error: Cannot delete root user${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    # Confirm deletion
    read -p "Are you sure you want to delete user '$username'? (yes/no): " confirm
    
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
    echo -e "\n${GREEN}=== System Users (UID >= 1000) ===${NC}"
    echo "Username          UID    Home Directory"
    echo "----------------------------------------"
    
    # List users with UID >= 1000 (regular users, not system users)
    awk -F: '$3 >= 1000 {printf "%-15s   %-6s %s\n", $1, $3, $6}' /etc/passwd
    
    echo ""
    read -p "Press Enter to continue..."
}

# Function to change user password
change_password() {
    echo -e "\n${YELLOW}=== Change User Password ===${NC}"
    read -p "Enter username: " username
    
    # Check if user exists
    if ! id "$username" &>/dev/null; then
        echo -e "${RED}Error: User '$username' does not exist${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo "Setting new password for user '$username':"
    passwd "$username"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Password changed successfully${NC}"
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
