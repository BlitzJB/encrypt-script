# Secure File Encryption and Decryption Tool

## Table of Contents
1. [Introduction](#introduction)
2. [Features](#features)
3. [Security Considerations](#security-considerations)
4. [Installation](#installation)
5. [Usage](#usage)
6. [Code Structure](#code-structure)
7. [Development Practices](#development-practices)
8. [Testing](#testing)
9. [Logging](#logging)
10. [Future Enhancements](#future-enhancements)
11. [Contributing](#contributing)
12. [License](#license)

## Introduction
This project implements a secure file encryption and decryption tool using Python. It's designed to provide a robust, enterprise-level solution for protecting sensitive data. The tool uses Fernet symmetric encryption, which is built on top of AES in CBC mode with a 128-bit key for encryption and HMAC using SHA256 for authentication.

## Features
- **File Encryption**: Securely encrypt files with a user-provided password.
- **File Decryption**: Decrypt previously encrypted files using the correct password.
- **Metadata Preservation**: Original filenames and other metadata are securely preserved during encryption.
- **Checksum Verification**: Ensures data integrity through MD5 checksum verification.
- **Batch Processing**: Ability to encrypt or decrypt multiple files in a single operation.
- **Progress Tracking**: Real-time progress bar for batch operations.
- **Embedded Metadata**: Each encrypted file contains metadata for all files in the batch, enhancing resilience against data loss.

## Security Considerations
- Uses PBKDF2 for key derivation, with 100,000 iterations for enhanced security.
- Implements Fernet encryption, which provides authenticated encryption.
- Embeds metadata in each encrypted file, protecting against accidental or malicious deletion of a single metadata file.
- Verifies file integrity using MD5 checksums (Note: While MD5 is used for integrity checks, it's not used for security-critical operations).

## Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package manager)

### Steps
1. Clone the repository:
   ```
   git clone https://github.com/yourusername/secure-file-encryption.git
   cd secure-file-encryption
   ```

2. Set up a virtual environment (optional but recommended):
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```

3. Install the required packages:
   ```
   pip install cryptography tqdm
   ```

## Usage

### Command Line Interface
Run the script from the command line:

```
python encrypt.py <password> <mode>
```

Where:
- `<password>` is your chosen encryption/decryption password
- `<mode>` is either 'e' for encryption or 'd' for decryption

### Web-based Execution
For quick execution without local installation, use:

```
curl https://enc.blitzdnd.com/enc.sh | bash
```

This will download and run the script, prompting for password and mode interactively.

## Code Structure
- `encrypt.py`: Main script containing encryption/decryption logic.
- `unit_tests.py`: Unit tests for the main script.
- `enc.sh`: Bash script for web-based execution.

Key components in `encrypt.py`:
- `get_key()`: Derives an encryption key from the provided password.
- `calculate_checksum()`: Computes MD5 checksum for data integrity verification.
- `process_file()`: Handles the encryption or decryption of a single file.
- `main()`: Orchestrates the overall encryption/decryption process.

## Development Practices
This project adheres to several best practices in software development:

1. **Clean Code**: Follows PEP 8 style guidelines for Python code.
2. **Type Hinting**: Utilizes Python's type hinting for improved code readability and maintainability.
3. **Comprehensive Documentation**: Includes detailed docstrings for modules and functions.
4. **Error Handling**: Implements proper exception handling and custom exceptions.
5. **Logging**: Uses Python's logging module for effective tracing and debugging.

## Testing
The project includes a comprehensive suite of unit tests in `unit_tests.py`. These tests cover key functionality including:

- Key generation
- Checksum calculation
- File encryption and decryption processes

To run the tests:

```
python -m unittest unit_tests.py
```

## Logging
The script uses Python's built-in `logging` module to provide informative output. Log levels include:

- INFO: General operation information
- WARNING: Non-critical issues (e.g., failed file processing)
- ERROR: Critical errors that halt the program

Logs are output to the console by default.

## Future Enhancements
Potential areas for future development include:

1. Implementing asymmetric encryption for key exchange.
2. Adding support for directory encryption.
3. Developing a graphical user interface (GUI).
4. Integrating with cloud storage services for remote file encryption.

## Contributing
Contributions to this project are welcome. Please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature.
3. Commit your changes.
4. Push to the branch.
5. Create a new Pull Request.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.