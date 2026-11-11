# shellcheck shell=bash
##
# THIS SCRIPT IS MEANT TO BE SOURCED!
##
# Colors
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
MAGENTA='\e[35m'
CYAN='\e[36m'
BOLD='\e[1m'
END_COLOR='\e[0m'

# Function to display a colored divider
divider() {
    local color=$1
    local label=$2
    echo -e "\n${color}${BOLD}===============================================================${END_COLOR}"
    echo -e "${color}${BOLD}  ${label}${END_COLOR}"
    echo -e "${color}${BOLD}===============================================================${END_COLOR}"
}

# Function to display labeled output with color
label() {
    local text=$1
    local value=$2
    local color=${3:-$END_COLOR}
    echo -e "${BOLD}${text}${END_COLOR} ${color}${value}${END_COLOR}"
}

# Function to highlight suspicious items
highlight() {
    local color=$1
    local text=$2
    echo -e "${color}${BOLD}[!]${END_COLOR} ${color}${text}${END_COLOR}"
}
