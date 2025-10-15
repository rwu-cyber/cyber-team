#!/bin/bash

# check if script was run as sudo
if [[ $EUID -ne 0 ]]; then
   printf "This script must be run as root.\n Please run using sudo."
   exit 1
fi

printf "Creating local admin account...\n\n"

# prompt username
printf "New account name: "
read user

if [ -z "$user" ]; then
	echo "No input detected."
	exit 1
fi

# add the user
adduser "$user" --ingroup sudo

# check if the command worked
if [ $? -ne 0 ]; then
	printf "Command Failed!"
else
	printf "User '$user' created successfully!"
fi
