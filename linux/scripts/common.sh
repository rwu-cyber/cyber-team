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

# bail [STATUS] TEXT
#
# print TEXT and exit STATUS
#   STATUS defaults to 1
bail(){
    local text
		local status

		if (($# == 2));
		 then
		  status="$1"
			text="$2"
		 else
		  status=1
			text="$1"
		fi
    printf "(%s)[%s] ${BOLD}${RED}FATAL:${END_COLOR} %b bailing!\n" "$0" "${FUNCNAME[1]}" "$text"
    exit "$status"
}
