#!/bin/bash

# Download the Python script
curl -s https://enc.blitzdnd.com/encrypt.py -o encrypt.py

# Check if the download was successful
if [ $? -ne 0 ]; then
    echo "Failed to download the encryption script."
    exit 1
fi

# Prompt for password
read -s -p "Enter password for encryption/decryption: " password < /dev/tty
echo

# Prompt for mode
while true; do
    read -p "Enter 'e' for encryption or 'd' for decryption: " mode < /dev/tty
    if [[ $mode == "e" || $mode == "d" ]]; then
        break
    else
        echo "Invalid input. Please enter 'e' or 'd'."
    fi
done

# Run the Python script
python3 encrypt.py "$password" "$mode"

# Clean up
rm encrypt.py
