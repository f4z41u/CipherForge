```
   ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗ ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
  ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
  ██║     ██║██████╔╝███████║█████╗  ██████╔╝█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  
  ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  
  ╚██████╗██║██║     ██║  ██║███████╗██║  ██║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
   ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```

Advanced command-line encryption tool using ChaCha20-Poly1305 authenticated encryption with Argon2id key derivation.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- ChaCha20-Poly1305 authenticated encryption (AEAD)
- Argon2id password-based key derivation
- Optional zlib compression
- Batch file operations
- Tamper detection with authentication tags
- Colorful CLI interface
- Memory-efficient streaming for large files
- Secure key generation and management

## Installation

```bash
pip install -r requirements.txt
```

**Requirements:** Python 3.8+, cryptography, argon2-cffi, click, colorama, tqdm

## Quick Start

```bash
# Generate a key
python main.py generate-key -o my.key

# Encrypt a file
python main.py encrypt -i file.txt -o file.enc -k my.key

# Decrypt a file
python main.py decrypt -i file.enc -o file.txt -k my.key

# Password-based encryption
python main.py encrypt -i file.txt -o file.enc -p

# Compress and encrypt
python main.py encrypt -i file.txt -o file.enc -k my.key -c

# Batch operations
python main.py batch-encrypt -i "*.txt" -o encrypted/ -k my.key
```

## Commands

### `generate-key` - Generate encryption key
```bash
python main.py generate-key -o <keyfile> [--force]
```

### `encrypt` - Encrypt files
```bash
python main.py encrypt -i <input> -o <output> [-k <keyfile> | -p] [-c]

Options:
  -k, --keyfile    Use key file
  -p, --password   Use password
  -c, --compress   Enable compression
```

### `decrypt` - Decrypt files
```bash
python main.py decrypt -i <input> -o <output> [-k <keyfile> | -p]
```

### `batch-encrypt` / `batch-decrypt` - Process multiple files
```bash
python main.py batch-encrypt -i "<pattern>" -o <dir> [-k <keyfile> | -p] [-c]
python main.py batch-decrypt -i "<pattern>" -o <dir> [-k <keyfile> | -p]
```

### `info` - Display tool information
```bash
python main.py info
```

## Technical Details

| Feature | Specification |
|---------|--------------|
| Encryption | ChaCha20-Poly1305 (AEAD) |
| Key Size | 256 bits |
| Nonce | 96 bits (random per operation) |
| Authentication | Poly1305 MAC (128-bit) |
| Key Derivation | Argon2id (3 iterations, 64MB memory, 4 threads) |
| Compression | zlib level 6 |

## Security

- **Authenticated encryption**: Prevents tampering and forgery
- **Strong key derivation**: Argon2id protects against brute-force attacks
- **Random nonces**: Unique per encryption operation
- **No key recovery**: Lost keys/passwords cannot be recovered

## File Format

```
[8 bytes]  Magic: "CFORGE01"
[2 bytes]  Version: 1
[16 bytes] Salt
[8 bytes]  Data length
[N bytes]  Encrypted data (nonce + ciphertext + tag)
```

## Important Notes

**Password-based encryption:**
- Salt is stored in a separate `.salt` file
- Keep the `.salt` file with the encrypted file
- For batch operations, salt is saved as `batch.salt`

**Key files:**
- Store in a secure location separate from encrypted files
- Back up to multiple secure locations
- Never share keys through insecure channels

**Best practices:**
- Use strong passwords (12+ characters recommended)
- Test decryption before deleting original files
- Use compression for text files, logs, and JSON
- Keep backup copies of important data

## Documentation

For detailed documentation, examples, and use cases, see [DOCUMENTATION.md](DOCUMENTATION.md).

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Author

**Fazalu Rahman**

---

For help: `python main.py --help` or `python main.py <command> --help`
