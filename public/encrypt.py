import os
import json
import uuid
import hashlib
import sys
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
import base64
from tqdm import tqdm

def get_key(password):
    password = password.encode()
    salt = b'salt_'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def calculate_checksum(data):
    return hashlib.md5(data).hexdigest()

def process_file(file_path, key, encrypt=True, all_metadata=None):
    try:
        with open(file_path, 'rb') as file:
            data = file.read()
        fernet = Fernet(key)
        
        if encrypt:
            checksum = calculate_checksum(data)
            original_name = os.path.basename(file_path)
            new_file_name = str(uuid.uuid4()) + '.enc'
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
    except (InvalidToken, Exception) as e:
        print(f"Error processing {file_path}: {str(e)}")
        return False, all_metadata

def main(password, mode):
    key = get_key(password)
    
    if mode == 'e':
        files = [f for f in os.listdir('.') if os.path.isfile(f) and not f.endswith('.enc') and not f.endswith('.py')]
        all_metadata = {}
        encrypt = True
    elif mode == 'd':
        files = [f for f in os.listdir('.') if f.endswith('.enc')]
        all_metadata = None
        encrypt = False
    else:
        print("Invalid mode selected.")
        return

    total_files = len(files)
    processed_files = 0
    failed_files = 0
    
    print(f"\nProcessing {total_files} files:")
    
    with tqdm(total=total_files, desc="Overall Progress", unit="file") as pbar:
        for file in files:
            success, all_metadata = process_file(file, key, encrypt, all_metadata)
            if success:
                processed_files += 1
                tqdm.write(f"Successfully processed: {file}")
            else:
                failed_files += 1
                tqdm.write(f"Failed to process: {file}")
            pbar.update(1)

    print(f"\nOperation completed.")
    print(f"Successfully processed: {processed_files} files")
    print(f"Failed to process: {failed_files} files")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python encrypt.py <password> <mode>")
        sys.exit(1)
    password = sys.argv[1]
    mode = sys.argv[2]
    main(password, mode)