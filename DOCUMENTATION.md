# CipherForge - Complete Documentation

Comprehensive guide for CipherForge encryption tool.

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Getting Started](#getting-started)
- [Command Reference](#command-reference)
- [Usage Examples](#usage-examples)
- [Security Features](#security-features)
- [File Format](#file-format)
- [Use Cases](#use-cases)
- [Troubleshooting](#troubleshooting)
- [Performance](#performance)
- [Advanced Topics](#advanced-topics)

---

## Overview

CipherForge is a command-line tool for encrypting and decrypting files using modern cryptographic standards. It provides both key-file and password-based encryption with optional compression.

### Key Features

- **ChaCha20-Poly1305**: Modern authenticated encryption cipher
- **Argon2id**: Strong password-based key derivation
- **Compression**: Optional zlib compression to reduce file size
- **Batch Processing**: Encrypt/decrypt multiple files at once
- **Tamper Detection**: Authentication tags prevent data modification
- **User-Friendly**: Colorful CLI with clear progress indicators

### When to Use CipherForge

- Protecting sensitive documents before cloud storage
- Securing backups
- Encrypting files for secure transfer
- Protecting API keys and configuration files
- Meeting data protection compliance requirements

---

## Installation

### System Requirements

- Python 3.8 or higher
- pip package manager
- 50 MB free disk space for dependencies

### Installation Steps

1. **Clone or download the repository**

```bash
git clone https://github.com/f4z41u/CipherForge.git
cd CipherForge
```

2. **Install dependencies**

```bash
pip install -r requirements.txt
```

3. **Verify installation**

```bash
python main.py --version
python main.py info
```

### Dependencies

- `cryptography>=42.0.0` - Cryptographic operations
- `argon2-cffi>=23.1.0` - Password hashing
- `click>=8.1.7` - CLI framework
- `colorama>=0.4.6` - Colored output
- `tqdm>=4.66.1` - Progress bars

---

## Getting Started

### First Steps

1. **Display help and information**

```bash
python main.py --help
python main.py info
```

2. **Generate your first encryption key**

```bash
python main.py generate-key -o my_first.key
```

3. **Encrypt a test file**

```bash
echo "Hello, CipherForge!" > test.txt
python main.py encrypt -i test.txt -o test.enc -k my_first.key
```

4. **Decrypt it back**

```bash
python main.py decrypt -i test.enc -o test_restored.txt -k my_first.key
cat test_restored.txt
```

---

## Command Reference

### generate-key

Generate a cryptographically secure 256-bit encryption key.

**Syntax:**
```bash
python main.py generate-key -o <output_file> [--force]
```

**Options:**
- `-o, --output PATH` - Output file path (required)
- `--force` - Overwrite existing file

**Example:**
```bash
python main.py generate-key -o master.key
```

**Output:**
- Creates a key file with base64-encoded 256-bit key
- Sets file permissions to 600 (Unix/Linux)
- Displays security warnings

**Key File Format:**
```
# CipherForge Key File
# Keep this file secure and never share it!
# Key (Base64): <key-string>
<key-string>
```

---

### encrypt

Encrypt a file using ChaCha20-Poly1305.

**Syntax:**
```bash
python main.py encrypt -i <input> -o <output> [options]
```

**Options:**
- `-i, --input PATH` - Input file to encrypt (required)
- `-o, --output PATH` - Output encrypted file (required)
- `-k, --keyfile PATH` - Use key file for encryption
- `-p, --password` - Use password-based encryption
- `-c, --compress` - Compress before encrypting
- `--info` - Display encryption information

**Examples:**

**Key file encryption:**
```bash
python main.py encrypt -i document.pdf -o document.pdf.enc -k my.key
```

**Password encryption:**
```bash
python main.py encrypt -i secret.txt -o secret.enc -p
```
*Prompts for password interactively*

**With compression:**
```bash
python main.py encrypt -i large_file.log -o large_file.enc -k my.key -c
```

**Operation Flow:**

1. Load encryption key (from file or derive from password)
2. Read input file
3. Compress data (if `-c` flag used)
4. Generate random nonce
5. Encrypt with ChaCha20-Poly1305
6. Add authentication tag
7. Package in container format
8. Write to output file
9. For password mode: save salt file

**Output Statistics:**
- Original file size
- Compressed size (if applicable)
- Final encrypted size
- Compression ratio

---

### decrypt

Decrypt a file encrypted by CipherForge.

**Syntax:**
```bash
python main.py decrypt -i <input> -o <output> [options]
```

**Options:**
- `-i, --input PATH` - Input encrypted file (required)
- `-o, --output PATH` - Output decrypted file (required)
- `-k, --keyfile PATH` - Use key file for decryption
- `-p, --password` - Use password-based decryption
- `--no-decompress` - Skip automatic decompression

**Examples:**

**Key file decryption:**
```bash
python main.py decrypt -i document.pdf.enc -o document.pdf -k my.key
```

**Password decryption:**
```bash
python main.py decrypt -i secret.enc -o secret.txt -p
```
*Prompts for password and loads salt file*

**Operation Flow:**

1. Load decryption key
2. Read encrypted container
3. Verify magic number and version
4. Extract nonce and ciphertext
5. Decrypt and verify authentication tag
6. Decompress if needed
7. Write to output file

**Important:**
- For password-based decryption, the `.salt` file must exist
- Authentication failure indicates wrong key/password or tampering

---

### batch-encrypt

Encrypt multiple files matching patterns.

**Syntax:**
```bash
python main.py batch-encrypt -i <pattern> -o <dir> [options]
```

**Options:**
- `-i, --input PATTERN` - File pattern (can be specified multiple times)
- `-o, --output PATH` - Output directory (required)
- `-k, --keyfile PATH` - Use key file
- `-p, --password` - Use password
- `-c, --compress` - Enable compression
- `--ext TEXT` - Extension for encrypted files (default: `.enc`)

**Examples:**

**Encrypt all text files:**
```bash
python main.py batch-encrypt -i "*.txt" -o encrypted/ -k my.key
```

**Multiple patterns:**
```bash
python main.py batch-encrypt -i "*.txt" -i "*.pdf" -i "*.docx" -o secure/ -k my.key -c
```

**With password:**
```bash
python main.py batch-encrypt -i "documents/*" -o backup_encrypted/ -p -c
```

**Custom extension:**
```bash
python main.py batch-encrypt -i "*.txt" -o encrypted/ -k my.key --ext .locked
```

**Notes:**
- Creates output directory if it doesn't exist
- For password mode, saves salt as `batch.salt` in output directory
- Displays summary of successful and failed operations
- Continues on errors (doesn't stop at first failure)

---

### batch-decrypt

Decrypt multiple files matching patterns.

**Syntax:**
```bash
python main.py batch-decrypt -i <pattern> -o <dir> [options]
```

**Options:**
- `-i, --input PATTERN` - File pattern (can be specified multiple times)
- `-o, --output PATH` - Output directory (required)
- `-k, --keyfile PATH` - Use key file
- `-p, --password` - Use password
- `--ext TEXT` - Extension to remove (default: `.enc`)

**Examples:**

**Decrypt all .enc files:**
```bash
python main.py batch-decrypt -i "encrypted/*.enc" -o decrypted/ -k my.key
```

**With password:**
```bash
python main.py batch-decrypt -i "backup_encrypted/*" -o restored/ -p
```
*Looks for `batch.salt` file*

**Custom extension:**
```bash
python main.py batch-decrypt -i "encrypted/*.locked" -o plain/ -k my.key --ext .locked
```

---

### info

Display detailed information about CipherForge.

**Syntax:**
```bash
python main.py info
```

**Displays:**
- Banner and tool name
- Encryption algorithm details
- Key derivation specifications
- List of features
- Usage examples

---

## Usage Examples

### Example 1: Secure Personal Documents

```bash
# Create a personal key
python main.py generate-key -o ~/secure/personal.key

# Encrypt documents
python main.py encrypt -i passport_scan.pdf -o passport_scan.enc -k ~/secure/personal.key
python main.py encrypt -i tax_return_2025.pdf -o tax_return_2025.enc -k ~/secure/personal.key

# Store encrypted files in cloud
# Keep key file secure on local machine
```

### Example 2: Password-Protected Archive

```bash
# Encrypt entire directory with password
python main.py batch-encrypt -i "important_docs/*" -o encrypted_docs/ -p -c

# Upload encrypted_docs/ to cloud storage
# Save batch.salt file securely (NOT in cloud)

# Later, decrypt when needed
python main.py batch-decrypt -i "encrypted_docs/*" -o restored_docs/ -p
```

### Example 3: Secure File Sharing

```bash
# Generate one-time key for sharing
python main.py generate-key -o share_key.key

# Encrypt file
python main.py encrypt -i confidential_report.docx -o report.enc -k share_key.key

# Send report.enc via email
# Send share_key.key via different secure channel (Signal, WhatsApp, etc.)
```

### Example 4: Backup Strategy

```bash
# Weekly backup script
#!/bin/bash

# Compress and encrypt database dumps
python main.py batch-encrypt \
  -i "backups/db_*.sql" \
  -o backups/encrypted/ \
  -k /secure/backup.key \
  -c

# Upload encrypted backups
rclone sync backups/encrypted/ remote:encrypted_backups/

# Keep key file local and backed up to secure locations
```

### Example 5: Development Secrets

```bash
# Encrypt environment files
python main.py encrypt -i .env -o .env.enc -p
python main.py encrypt -i config/secrets.json -o config/secrets.json.enc -p

# Add to .gitignore:
# .env
# config/secrets.json
# *.salt

# Commit encrypted versions
git add .env.enc config/secrets.json.enc
git commit -m "Add encrypted configuration"

# Teammates decrypt with shared password
python main.py decrypt -i .env.enc -o .env -p
```

---

## Security Features

### ChaCha20-Poly1305 Encryption

**ChaCha20** is a stream cipher designed by Daniel J. Bernstein:
- 256-bit key size
- 96-bit nonce
- Fast software implementation
- Resistant to timing attacks
- Used in TLS 1.3, SSH, VPN protocols

**Poly1305** is a message authentication code:
- 128-bit authentication tag
- Prevents tampering and forgery
- Verifies both ciphertext and any associated data

**AEAD (Authenticated Encryption with Associated Data):**
- Combines encryption and authentication
- Single operation provides confidentiality and integrity
- No need for separate MAC calculation

### Argon2id Key Derivation

**Argon2** won the Password Hashing Competition in 2015.

**Argon2id** is a hybrid mode combining:
- Argon2d (data-dependent, resistant to GPU attacks)
- Argon2i (data-independent, resistant to side-channel attacks)

**CipherForge Configuration:**
- Time cost: 3 iterations
- Memory cost: 64 MB (65536 KB)
- Parallelism: 4 threads
- Output: 256-bit key
- Salt: 128-bit random value

**Why these parameters?**
- OWASP recommended for password storage
- Balance between security and usability
- Takes 1-3 seconds on modern hardware
- Resists brute-force and dictionary attacks
- Memory-hard (defeats GPU/ASIC attacks)

### Security Best Practices

**Key Management:**
- Use cryptographically secure random key generation
- Store keys separate from encrypted data
- Use hardware security modules (HSMs) for critical keys
- Implement key rotation policies
- Back up keys to multiple secure locations

**Password Selection:**
- Minimum 8 characters (12+ recommended)
- Mix of uppercase, lowercase, digits, symbols
- Avoid dictionary words and common patterns
- Use a password manager
- Don't reuse passwords across systems

**Operational Security:**
- Test decryption before deleting originals
- Keep salt files with encrypted data (for password mode)
- Use different keys for different security domains
- Monitor for unauthorized access attempts
- Have a key recovery plan for critical data

---

## File Format

### Container Structure

CipherForge uses a custom container format for portability and version management.

```
Byte Range    | Field          | Description
--------------|----------------|-----------------------------------
0-7           | Magic          | "CFORGE01" (identifies file type)
8-9           | Version        | Format version (currently 1)
10-25         | Salt           | 16-byte salt for metadata
26-33         | Data Length    | 64-bit unsigned integer
34-45         | Nonce          | 96-bit random nonce
46-(N-17)     | Ciphertext     | Encrypted data
(N-16)-N      | Auth Tag       | 128-bit Poly1305 MAC
```

### Format Details

**Magic Number:**
- Fixed 8-byte identifier: `CFORGE01`
- Allows file type detection
- Version number embedded for future compatibility

**Salt:**
- 128-bit random value
- Stored for metadata purposes
- For password-based encryption, actual KDF salt stored separately

**Nonce:**
- 96 bits (12 bytes)
- Randomly generated per encryption
- Never reused with same key
- Required for ChaCha20-Poly1305

**Authentication Tag:**
- 128-bit Poly1305 MAC
- Appended to ciphertext by AEAD operation
- Verified during decryption
- Prevents tampering and forgery

### Version Compatibility

Current version: 1

Future versions will maintain backward compatibility:
- New features added via optional fields
- Magic number updated for breaking changes
- Decryption checks version and handles appropriately

---

## Use Cases

### 1. Personal Data Protection

**Scenario:** Protecting sensitive personal documents

**Implementation:**
```bash
# One-time setup
python main.py generate-key -o ~/.cipherforge/personal.key
chmod 600 ~/.cipherforge/personal.key

# Encrypt sensitive files
for file in passport.pdf ssn.txt bank_statements.pdf; do
    python main.py encrypt -i "$file" -o "${file}.enc" -k ~/.cipherforge/personal.key
    rm "$file"  # Remove original after verifying decryption works
done
```

### 2. Cloud Storage Encryption

**Scenario:** Zero-knowledge cloud storage

**Implementation:**
```bash
# Encrypt before upload
python main.py batch-encrypt \
    -i "local_files/*" \
    -o cloud_sync/encrypted/ \
    -k ~/secure/cloud.key \
    -c

# Sync encrypted files
rclone sync cloud_sync/encrypted/ dropbox:encrypted/

# Key stays local - cloud provider can't access data
```

### 3. Secure Collaboration

**Scenario:** Sharing files securely with team

**Implementation:**
```bash
# Team lead generates shared key
python main.py generate-key -o team_shared.key

# Encrypt project files
python main.py batch-encrypt \
    -i "project_docs/*" \
    -o secure_share/ \
    -k team_shared.key

# Distribute key securely (in person, secure messenger)
# Upload encrypted files to shared drive
# Team members decrypt with shared key
```

### 4. Database Backup Encryption

**Scenario:** Automated encrypted backups

**Script:**
```bash
#!/bin/bash
# backup.sh

DATE=$(date +%Y%m%d)
BACKUP_DIR="/backups"
KEY="/secure/backup.key"

# Dump database
pg_dump mydb > "$BACKUP_DIR/db_$DATE.sql"

# Encrypt with compression
python main.py encrypt \
    -i "$BACKUP_DIR/db_$DATE.sql" \
    -o "$BACKUP_DIR/db_$DATE.sql.enc" \
    -k "$KEY" \
    -c

# Remove plaintext
rm "$BACKUP_DIR/db_$DATE.sql"

# Upload encrypted backup
aws s3 cp "$BACKUP_DIR/db_$DATE.sql.enc" s3://backups/

# Clean old backups (keep 30 days)
find "$BACKUP_DIR" -name "*.enc" -mtime +30 -delete
```

### 5. Secure Development

**Scenario:** Managing API keys and secrets

**Implementation:**
```bash
# Encrypt secrets file
python main.py encrypt -i .env -o .env.enc -p

# Add to version control
git add .env.enc
git commit -m "Add encrypted secrets"

# In .gitignore:
.env
*.salt

# Team members decrypt
python main.py decrypt -i .env.enc -o .env -p
# Enter shared password
```

### 6. Compliance and Auditing

**Scenario:** Meeting GDPR/HIPAA requirements

**Requirements:**
- Encryption at rest
- Access control
- Audit trail

**Implementation:**
```bash
# Encrypt PII data
python main.py batch-encrypt \
    -i "customer_data/*.csv" \
    -o encrypted_pii/ \
    -k /hsm/compliance.key \
    -c

# Log encryption operations
echo "$(date): Encrypted customer_data/*.csv" >> audit.log

# Store encryption keys in HSM
# Implement key rotation policy
# Maintain encryption key inventory
```

---

## Troubleshooting

### Common Issues

#### 1. "Authentication failed" Error

**Cause:**
- Wrong decryption key or password
- File was tampered with or corrupted
- Missing or incorrect salt file

**Solution:**
```bash
# Verify you're using the correct key
python main.py decrypt -i file.enc -o file.txt -k correct_key.key

# For password mode, ensure salt file exists
ls -la file.enc.salt

# Check file integrity
file file.enc  # Should show data
```

#### 2. "Salt file not found" Error

**Cause:**
- Password-based decryption without salt file

**Solution:**
```bash
# Salt file must be in same directory
# For single files: filename.enc.salt
# For batch: batch.salt in output directory

# Verify salt file location
ls -la *.salt

# If salt file is lost, decryption is impossible
```

#### 3. Module Import Errors

**Cause:**
- Missing dependencies

**Solution:**
```bash
# Reinstall dependencies
pip install -r requirements.txt --upgrade

# Check Python version
python --version  # Should be 3.8+

# Virtual environment recommended
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

#### 4. Permission Denied

**Cause:**
- Insufficient file permissions

**Solution:**
```bash
# Check permissions
ls -la file.txt

# Fix permissions
chmod 644 file.txt

# For key files
chmod 600 key.key
```

#### 5. Out of Memory

**Cause:**
- Very large file with compression

**Solution:**
```bash
# Disable compression for large files
python main.py encrypt -i large.dat -o large.enc -k my.key
# (no -c flag)

# Check available memory
free -h  # Linux
```

#### 6. Slow Key Derivation

**Observation:**
- Password-based operations take several seconds

**Explanation:**
- This is intentional for security
- Argon2id is designed to be slow (memory-hard)
- Protects against brute-force attacks

**If too slow:**
- Use key files instead of passwords for batch operations
- Key derivation only happens once per operation

---

## Performance

### Benchmarks

Tested on: Intel i7-10700K, 32GB RAM, NVMe SSD

| Operation | File Size | Time | Throughput |
|-----------|-----------|------|------------|
| Encryption (no compression) | 10 MB | 0.05s | 200 MB/s |
| Encryption (no compression) | 100 MB | 0.5s | 200 MB/s |
| Encryption (no compression) | 1 GB | 5s | 200 MB/s |
| Encryption (with compression) | 10 MB | 0.2s | 50 MB/s |
| Encryption (with compression) | 100 MB | 2.0s | 50 MB/s |
| Decryption | 100 MB | 0.5s | 200 MB/s |
| Key derivation (Argon2id) | - | 1-3s | - |

**Notes:**
- ChaCha20 is very fast in software
- Compression adds significant overhead
- Key derivation time is intentional (security feature)
- Batch operations are sequential

### Optimization Tips

**1. Compression:**
```bash
# Use compression for text files
python main.py encrypt -i logs.txt -o logs.enc -k my.key -c

# Skip compression for already-compressed files
python main.py encrypt -i video.mp4 -o video.enc -k my.key
# (no -c flag)
```

**2. Batch Operations:**
```bash
# Use key files for batch operations
# Avoid password mode (key derivation for each file)

# Efficient
python main.py batch-encrypt -i "*.txt" -o enc/ -k my.key

# Less efficient
python main.py batch-encrypt -i "*.txt" -o enc/ -p
```

**3. Large Files:**
```bash
# Disable compression for large files
# Streaming handles memory efficiently
python main.py encrypt -i 10GB.dat -o 10GB.enc -k my.key
```

**4. Network Storage:**
```bash
# Encrypt locally, then upload
python main.py encrypt -i file.txt -o file.enc -k my.key
rsync file.enc remote:/backup/

# Don't encrypt over network mount
```

---

## Advanced Topics

### Custom Key Derivation

For specific use cases, you can modify key derivation parameters:

**Edit `key_manager.py`:**
```python
# Increase security (slower)
ARGON2_TIME_COST = 5        # More iterations
ARGON2_MEMORY_COST = 131072 # 128 MB memory

# Faster (less secure)
ARGON2_TIME_COST = 2
ARGON2_MEMORY_COST = 32768  # 32 MB
```

### Scripting and Automation

**Python Integration:**
```python
from key_manager import KeyManager
from file_handler import FileHandler

# Generate key
key = KeyManager.generate_random_key()

# Encrypt
handler = FileHandler(key)
stats = handler.encrypt_file("input.txt", "output.enc", compress=True)
print(f"Encrypted {stats['original_size']} bytes")
```

**Bash Script:**
```bash
#!/bin/bash
# auto_encrypt.sh

WATCH_DIR="/home/user/sensitive"
ENC_DIR="/home/user/encrypted"
KEY="/home/user/.keys/auto.key"

# Watch directory and auto-encrypt new files
inotifywait -m -e create "$WATCH_DIR" |
while read path action file; do
    python main.py encrypt \
        -i "$path$file" \
        -o "$ENC_DIR/${file}.enc" \
        -k "$KEY"
    rm "$path$file"
done
```

### Key Rotation

```bash
#!/bin/bash
# rotate_keys.sh

OLD_KEY="old.key"
NEW_KEY="new.key"

# Generate new key
python main.py generate-key -o "$NEW_KEY"

# Decrypt with old key, encrypt with new
for file in encrypted/*.enc; do
    basename=$(basename "$file" .enc)
    python main.py decrypt -i "$file" -o "temp/$basename" -k "$OLD_KEY"
    python main.py encrypt -i "temp/$basename" -o "reencrypted/${basename}.enc" -k "$NEW_KEY"
done

# Verify and cleanup
# ...
```

### Integration with Cloud Services

**AWS S3:**
```bash
# Encrypt before upload
python main.py encrypt -i data.csv -o data.enc -k my.key
aws s3 cp data.enc s3://mybucket/

# Download and decrypt
aws s3 cp s3://mybucket/data.enc .
python main.py decrypt -i data.enc -o data.csv -k my.key
```

**Rclone:**
```bash
# Encrypt and sync
python main.py batch-encrypt -i "docs/*" -o encrypted/ -k my.key
rclone sync encrypted/ remote:backup/
```

---

## FAQ

**Q: Can I recover data if I lose the key/password?**  
A: No. CipherForge uses strong encryption with no backdoors. Lost keys mean lost data.

**Q: Can I change the encryption algorithm?**  
A: Not without modifying the code. ChaCha20-Poly1305 is hardcoded for security and compatibility.

**Q: Is it safe to store encrypted files in the cloud?**  
A: Yes, if you keep the key/password secure and separate from the encrypted files.

**Q: How do I verify file integrity?**  
A: The authentication tag automatically verifies integrity during decryption.

**Q: Can I encrypt directories?**  
A: Use batch-encrypt with a pattern like `directory/*` or `directory/**/*`.

**Q: What's the maximum file size?**  
A: No hard limit. Large files are handled with streaming to minimize memory usage.

**Q: Can I use CipherForge in commercial projects?**  
A: Yes, it's MIT licensed. See LICENSE file for details.

**Q: How do I contribute?**  
A: Submit pull requests on GitHub or report issues.

---

## References

- [ChaCha20-Poly1305 RFC 8439](https://tools.ietf.org/html/rfc8439)
- [Argon2 Specification](https://github.com/P-H-C/phc-winner-argon2)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST Cryptographic Standards](https://csrc.nist.gov/)

---

**CipherForge** - Created by Fazalu Rahman
