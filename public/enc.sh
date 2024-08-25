#!/bin/bash

# Download the Python script
curl -s https://enc.blitzdnd.com/encrypt.py -o encrypt.py

# Check if the download was successful
if [ $? -ne 0 ]; then
    echo "Failed to download the encryption script."
    exit 1
fi

# Prompt for password
read -s -p "Enter password for encryption/decryption: " password
echo

# Prompt for mode
read -p "Enter 'e' for encryption or 'd' for decryption: " mode

# Run the Python script
python3 encrypt.py "$password" "$mode"

# Clean up
rm encrypt.py