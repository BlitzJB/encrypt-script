"""
File Encryption and Decryption Module

This module provides functionality to encrypt and decrypt files using Fernet symmetric encryption.
It includes features such as checksum verification and metadata embedding for enhanced security and data integrity.

Usage:
    python encrypt.py <password> <mode>

    where:
        <password> is the encryption/decryption key
        <mode> is either 'e' for encryption or 'd' for decryption
"""

import os
import json
import uuid
import hashlib
import sys
import logging
from typing import Dict, Tuple, List, Optional
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
import base64
from tqdm import tqdm

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EncryptionError(Exception):
    """Custom exception for encryption-related errors."""
    pass

def get_key(password: str) -> bytes:
    """
    Derive an encryption key from a password.

    Args:
        password (str): The user-provided password.

    Returns:
        bytes: The derived encryption key.
    """
    password = password.encode()
    salt = b'salt_'  # In a real-world scenario, use a secure random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

def calculate_checksum(data: bytes) -> str:
    """
    Calculate MD5 checksum of given data.

    Args:
        data (bytes): The data to calculate checksum for.

    Returns:
        str: The hexadecimal representation of the MD5 checksum.
    """
    return hashlib.md5(data).hexdigest()

def process_file(file_path: str, key: bytes, encrypt: bool = True, all_metadata: Optional[Dict] = None) -> Tuple[bool, Dict]:
    """
    Process (encrypt or decrypt) a single file.

    Args:
        file_path (str): Path to the file to be processed.
        key (bytes): The encryption/decryption key.
        encrypt (bool): True for encryption, False for decryption.
        all_metadata (Dict): Metadata for all files in the batch.

    Returns:
        Tuple[bool, Dict]: A tuple containing a success flag and updated metadata.
    """
    try:
        with open(file_path, 'rb') as file:
            data = file.read()
        fernet = Fernet(key)
        
        if encrypt:
            checksum = calculate_checksum(data)
            original_name = os.path.basename(file_path)
            new_file_name = f"{uuid.uuid4()}.enc"
            file_metadata = {
                'original_name': original_name,
                'checksum': checksum
            }
            all_metadata[new_file_name] = file_metadata
            
            metadata_json = json.dumps(all_metadata).encode()
            processed = fernet.encrypt(metadata_json + b'|||' + data)
            
            new_file_path = os.path.join(os.path.dirname(file_path), new_file_name)
        else:
            decrypted = fernet.decrypt(data)
            metadata_json, original_data = decrypted.split(b'|||', 1)
            all_metadata = json.loads(metadata_json.decode())
            
            file_metadata = all_metadata[os.path.basename(file_path)]
            original_name = file_metadata['original_name']
            new_file_path = os.path.join(os.path.dirname(file_path), original_name)
            
            checksum = calculate_checksum(original_data)
            if checksum != file_metadata['checksum']:
                raise ValueError("Checksum mismatch")
            
            processed = original_data

        with open(new_file_path, 'wb') as new_file:
            new_file.write(processed)
        os.remove(file_path)
        return True, all_metadata
    except (InvalidToken, ValueError, IOError) as e:
        logger.error(f"Error processing {file_path}: {str(e)}")
        return False, all_metadata

def main(password: str, mode: str) -> None:
    """
    Main function to handle file encryption or decryption.

    Args:
        password (str): The encryption/decryption password.
        mode (str): 'e' for encryption, 'd' for decryption.
    """
    try:
        key = get_key(password)
        
        if mode == 'e':
            files = [f for f in os.listdir('.') if os.path.isfile(f) and not f.endswith('.enc') and not f.endswith('.py')]
            all_metadata: Dict = {}
            encrypt = True
        elif mode == 'd':
            files = [f for f in os.listdir('.') if f.endswith('.enc')]
            all_metadata = None
            encrypt = False
        else:
            raise ValueError("Invalid mode selected. Use 'e' for encryption or 'd' for decryption.")

        total_files = len(files)
        processed_files = 0
        failed_files = 0
        
        logger.info(f"Processing {total_files} files:")
        
        with tqdm(total=total_files, desc="Overall Progress", unit="file") as pbar:
            for file in files:
                success, all_metadata = process_file(file, key, encrypt, all_metadata)
                if success:
                    processed_files += 1
                    logger.info(f"Successfully processed: {file}")
                else:
                    failed_files += 1
                    logger.warning(f"Failed to process: {file}")
                pbar.update(1)

        logger.info("Operation completed.")
        logger.info(f"Successfully processed: {processed_files} files")
        logger.info(f"Failed to process: {failed_files} files")

    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        logger.error("Usage: python encrypt.py <password> <mode>")
        sys.exit(1)
    password = sys.argv[1]
    mode = sys.argv[2]
    main(password, mode)