# 🔒 CipherForge

<div align="center">

```
   ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗ ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
  ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
  ██║     ██║██████╔╝███████║█████╗  ██████╔╝█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  
  ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  
  ╚██████╗██║██║     ██║  ██║███████╗██║  ██║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
   ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```

**⚔️ Advanced CLI Encryption Tool with ChaCha20-Poly1305 ⚔️**

*Forge Your Security, Encrypt Your Future*

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: ChaCha20-Poly1305](https://img.shields.io/badge/Security-ChaCha20--Poly1305-green.svg)]()

</div>

---

## 🌟 Features

- **🔐 Military-Grade Encryption**: ChaCha20-Poly1305 authenticated encryption (AEAD)
- **🔑 Advanced Key Derivation**: Argon2id for secure password-based encryption
- **📦 Built-in Compression**: Optional zlib compression before encryption
- **🎯 Batch Operations**: Encrypt/decrypt multiple files at once
- **🛡️ Tamper Detection**: Authentication tags prevent data tampering
- **🎨 Beautiful CLI**: Colorful, user-friendly command-line interface
- **⚡ Memory Efficient**: Handles large files with streaming
- **🔒 Secure Key Management**: Generate and manage encryption keys safely

## 🔧 Technical Specifications

| Feature | Specification |
|---------|--------------|
| **Encryption Algorithm** | ChaCha20-Poly1305 (AEAD) |
| **Key Size** | 256 bits (32 bytes) |
| **Nonce Size** | 96 bits (12 bytes) |
| **Authentication** | Poly1305 MAC (128-bit tag) |
| **Key Derivation** | Argon2id (OWASP recommended) |
| **Compression** | zlib (level 6, optional) |
| **Python Version** | 3.8+ |

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Quick Install

```bash
# Clone or download the repository
cd "EncryptionDecryption Tool"

# Install dependencies
pip install -r requirements.txt
```

### Manual Installation

```bash
pip install cryptography>=41.0.0
pip install argon2-cffi>=23.1.0
pip install click>=8.1.0
pip install colorama>=0.4.6
pip install tqdm>=4.66.0
```

## 🚀 Quick Start

### Display Tool Information

```bash
python main.py info
```

### Generate a Key File

```bash
python main.py generate-key -o my_secret.key
```

### Encrypt a File

```bash
# Using a key file
python main.py encrypt -i document.pdf -o document.pdf.enc -k my_secret.key

# Using a password
python main.py encrypt -i secrets.txt -o secrets.txt.enc -p

# With compression
python main.py encrypt -i large_file.dat -o large_file.enc -k my_secret.key -c
```

### Decrypt a File

```bash
# Using a key file
python main.py decrypt -i document.pdf.enc -o document.pdf -k my_secret.key

# Using a password
python main.py decrypt -i secrets.txt.enc -o secrets.txt -p
```

### Batch Operations

```bash
# Encrypt all .txt and .pdf files
python main.py batch-encrypt -i "*.txt" -i "*.pdf" -o encrypted_files/ -k my_secret.key -c

# Decrypt all .enc files
python main.py batch-decrypt -i "encrypted_files/*.enc" -o decrypted_files/ -k my_secret.key
```

## 🎬 Quick Usage Demonstration

Here's a complete walkthrough showing CipherForge in action:

### Step 1: View Help and Information

```bash
# See all available commands
python main.py --help

# Display detailed encryption information
python main.py info
```

**Output:**
- Beautiful ASCII banner with tool name
- Encryption specifications (ChaCha20-Poly1305, Argon2id)
- Available features and usage examples

### Step 2: Generate an Encryption Key

```bash
python main.py generate-key -o my_master.key
```

**What happens:**
- ✓ Generates a secure 256-bit random key
- ✓ Saves it to `my_master.key` in base64 format
- ✓ Sets restrictive file permissions (600 on Unix)
- ⚠️ Warning: Keep this file secure!

**Generated key file example:**
```
# CipherForge Key File
# Keep this file secure and never share it!
# Key (Base64): <base64-encoded-key>
<base64-encoded-key>
```

### Step 3: Encrypt a File

```bash
# Create a test file
echo "This is my secret data!" > secret.txt

# Encrypt with key file (with compression)
python main.py encrypt -i secret.txt -o secret.txt.enc -k my_master.key -c
```

**Output:**
```
════════════════════════════════════════════════════════════
  File Encryption
════════════════════════════════════════════════════════════

ℹ Loading key from: my_master.key

▶ Encrypting File
ℹ Input:  secret.txt
ℹ Output: secret.txt.enc
ℹ Compression: Enabled
✓ File encrypted successfully!

▶ Operation Statistics
  Original Size:  25.00 B
  Compressed:     21.00 B (16.00% reduction)
  Encrypted Size: 89.00 B
```

**What was created:**
- `secret.txt.enc` - Your encrypted file with authentication tag

### Step 4: Decrypt the File

```bash
python main.py decrypt -i secret.txt.enc -o decrypted.txt -k my_master.key
```

**Output:**
```
════════════════════════════════════════════════════════════
  File Decryption
════════════════════════════════════════════════════════════

ℹ Loading key from: my_master.key

▶ Decrypting File
ℹ Input:  secret.txt.enc
ℹ Output: decrypted.txt
✓ File decrypted successfully!

▶ Operation Statistics
  Encrypted Size: 89.00 B
  Decrypted Size: 25.00 B
  Compression:    Detected and decompressed
```

**Verify integrity:**
```bash
# Compare files (Windows PowerShell)
Get-Content secret.txt
Get-Content decrypted.txt

# Compare files (Linux/Mac)
diff secret.txt decrypted.txt
```

### Step 5: Password-Based Encryption

```bash
# Encrypt with password instead of key file
python main.py encrypt -i important.pdf -o important.pdf.enc -p
```

**Interactive prompts:**
```
Enter encryption password: ********
Confirm password: ********
ℹ Deriving encryption key... (this may take a few seconds)
ℹ Salt saved to: important.pdf.enc.salt
```

**What happens:**
- Prompts for password (hidden input)
- Derives 256-bit key using Argon2id (takes 1-3 seconds)
- Generates and saves salt file (`.salt` extension)
- Encrypts the file

**Decrypt with password:**
```bash
python main.py decrypt -i important.pdf.enc -o important_restored.pdf -p
```

**Interactive prompts:**
```
Enter decryption password: ********
ℹ Salt loaded from: important.pdf.enc.salt
ℹ Deriving decryption key...
```

> **Important:** The `.salt` file must be kept alongside the encrypted file for password-based decryption!

### Step 6: Batch Encryption

```bash
# Create multiple test files
echo "Document 1" > doc1.txt
echo "Document 2" > doc2.txt
echo "Document 3" > doc3.txt

# Encrypt all .txt files at once
python main.py batch-encrypt -i "*.txt" -o encrypted_batch/ -k my_master.key -c
```

**Output:**
```
▶ Batch Operation Results
  Total Files:    3
  Successful:     3
  Failed:         0
```

**Result:** All `.txt` files are now encrypted in the `encrypted_batch/` directory with `.enc` extension.

### Step 7: Batch Decryption

```bash
# Decrypt all encrypted files
python main.py batch-decrypt -i "encrypted_batch/*.enc" -o decrypted_batch/ -k my_master.key
```

**Output:**
```
▶ Batch Operation Results
  Total Files:    3
  Successful:     3
  Failed:         0

✓ Successfully decrypted 3 file(s)
```

### Step 8: View Encryption Details

```bash
python main.py encrypt --info
```

**Output:**
```
Encryption Details:

• Algorithm:     ChaCha20-Poly1305 (AEAD)
• Key Size:      256 bits
• Authentication: Poly1305 MAC
• Key Derivation: Argon2id
• Nonce:         96 bits (random, per encryption)
• Security:      Military-grade encryption
```

### Real-World Use Cases

#### 1. Secure Personal Documents
```bash
# Generate a personal key
python main.py generate-key -o ~/Documents/.personal.key

# Encrypt sensitive documents
python main.py encrypt -i passport.pdf -o passport.pdf.enc -k ~/Documents/.personal.key
python main.py encrypt -i tax_returns.pdf -o tax_returns.pdf.enc -k ~/Documents/.personal.key

# Store encrypted files in cloud, keep key locally
```

#### 2. Secure Backup Before Cloud Upload
```bash
# Compress and encrypt before uploading to cloud
python main.py batch-encrypt -i "backup/*" -o backup_encrypted/ -p -c

# Upload backup_encrypted/ to cloud storage
# Keep the batch.salt file secure locally
```

#### 3. Share Encrypted Files
```bash
# Generate a shared key
python main.py generate-key -o shared_key.key

# Encrypt file
python main.py encrypt -i project_report.docx -o project_report.enc -k shared_key.key

# Share encrypted file AND key through different channels:
# - Email the .enc file
# - Send key via secure messenger
```

#### 4. Protect API Keys and Credentials
```bash
# Encrypt configuration files
python main.py encrypt -i .env -o .env.enc -p
python main.py encrypt -i config/secrets.json -o config/secrets.json.enc -p

# Store encrypted versions in version control
# Keep originals and .salt files out of git
```

### Tips and Best Practices

✅ **DO:**
- Use strong passwords (12+ characters with mix of types)
- Back up key files to multiple secure locations
- Use compression (`-c`) for text files, logs, and JSON
- Test decryption before deleting original files
- Store encrypted files and keys separately

❌ **DON'T:**
- Don't lose your keys or passwords (no recovery possible)
- Don't share keys through insecure channels
- Don't store keys in the same location as encrypted files
- Don't skip password confirmation prompts
- Don't forget to keep `.salt` files for password-based encryption

### Command Cheat Sheet

```bash
# Key management
python main.py generate-key -o <key_file>

# Single file operations
python main.py encrypt -i <input> -o <output> -k <key_file> [-c]
python main.py encrypt -i <input> -o <output> -p [-c]
python main.py decrypt -i <input> -o <output> -k <key_file>
python main.py decrypt -i <input> -o <output> -p

# Batch operations
python main.py batch-encrypt -i "<pattern>" -o <dir> -k <key_file>
python main.py batch-decrypt -i "<pattern>" -o <dir> -k <key_file>

# Information
python main.py info
python main.py --help
python main.py encrypt --help
```

## 📖 Detailed Usage

### Command Reference

#### `generate-key` - Generate Encryption Key

```bash
python main.py generate-key -o <output_file> [--force]

Options:
  -o, --output PATH   Output key file path [required]
  --force            Overwrite existing key file
```

**Example:**
```bash
python main.py generate-key -o ~/.cipherforge/master.key
```

#### `encrypt` - Encrypt Files

```bash
python main.py encrypt -i <input> -o <output> [options]

Options:
  -i, --input PATH    Input file to encrypt [required]
  -o, --output PATH   Output encrypted file [required]
  -p, --password      Use password-based encryption
  -k, --keyfile PATH  Use key file for encryption
  -c, --compress      Compress before encrypting
  --info             Show encryption information
```

**Examples:**
```bash
# Basic encryption with key file
python main.py encrypt -i photo.jpg -o photo.jpg.enc -k my.key

# Password-based encryption with compression
python main.py encrypt -i database.sql -o database.enc -p -c

# Show encryption info
python main.py encrypt --info
```

#### `decrypt` - Decrypt Files

```bash
python main.py decrypt -i <input> -o <output> [options]

Options:
  -i, --input PATH      Input encrypted file [required]
  -o, --output PATH     Output decrypted file [required]
  -p, --password        Use password-based decryption
  -k, --keyfile PATH    Use key file for decryption
  --no-decompress       Skip decompression
```

**Examples:**
```bash
# Basic decryption with key file
python main.py decrypt -i photo.jpg.enc -o photo.jpg -k my.key

# Password-based decryption
python main.py decrypt -i database.enc -o database.sql -p
```

#### `batch-encrypt` - Batch Encrypt Files

```bash
python main.py batch-encrypt -i <pattern> -o <dir> [options]

Options:
  -i, --input PATTERN   Input file pattern(s) [required, multiple allowed]
  -o, --output PATH     Output directory [required]
  -p, --password        Use password-based encryption
  -k, --keyfile PATH    Use key file for encryption
  -c, --compress        Compress before encrypting
  --ext TEXT           Extension for encrypted files (default: .enc)
```

**Examples:**
```bash
# Encrypt all documents in current directory
python main.py batch-encrypt -i "*.doc*" -i "*.pdf" -o secure/ -k my.key -c

# Encrypt with custom extension
python main.py batch-encrypt -i "*.txt" -o encrypted/ -p --ext .locked
```

#### `batch-decrypt` - Batch Decrypt Files

```bash
python main.py batch-decrypt -i <pattern> -o <dir> [options]

Options:
  -i, --input PATTERN   Input file pattern(s) [required, multiple allowed]
  -o, --output PATH     Output directory [required]
  -p, --password        Use password-based decryption
  -k, --keyfile PATH    Use key file for decryption
  --ext TEXT           Extension to remove (default: .enc)
```

**Examples:**
```bash
# Decrypt all encrypted files
python main.py batch-decrypt -i "secure/*.enc" -o restored/ -k my.key

# Decrypt with custom extension
python main.py batch-decrypt -i "encrypted/*.locked" -o plain/ -p --ext .locked
```

#### `info` - Display Information

```bash
python main.py info
```

Shows detailed information about:
- Encryption specifications
- Available features
- Usage examples

## 🔐 Security Features

### ChaCha20-Poly1305 Encryption

CipherForge uses **ChaCha20-Poly1305**, a modern authenticated encryption with associated data (AEAD) cipher:

- **ChaCha20**: Stream cipher designed by Daniel J. Bernstein
- **Poly1305**: Message authentication code (MAC) for integrity verification
- **Benefits**:
  - Faster than AES on systems without hardware acceleration
  - Resistant to timing attacks
  - Provides both confidentiality and authenticity
  - Widely used (TLS 1.3, SSH, VPN protocols)

### Argon2id Key Derivation

For password-based encryption, CipherForge uses **Argon2id**:

- Winner of the Password Hashing Competition (2015)
- OWASP recommended for password storage
- Resistant to GPU/ASIC attacks
- **Parameters**:
  - Time cost: 3 iterations
  - Memory cost: 64 MB
  - Parallelism: 4 threads
  - Output: 256-bit key

### Security Best Practices

1. **Random Nonces**: Each encryption uses a unique 96-bit random nonce
2. **Authentication Tags**: 128-bit Poly1305 tags prevent tampering
3. **Secure Key Storage**: Key files have restrictive permissions (600 on Unix)
4. **Password Strength Validation**: Enforces minimum 8-character passwords
5. **Salt Storage**: Salts stored separately for password-based encryption

## 📁 File Format

CipherForge uses a custom container format for encrypted files:

```
[8 bytes]  Magic Number: "CFORGE01"
[2 bytes]  Version: 1
[16 bytes] Salt (for metadata)
[8 bytes]  Data Length
[N bytes]  Encrypted Data:
  [12 bytes] Nonce
  [M bytes]  Ciphertext
  [16 bytes] Authentication Tag
```

This format ensures:
- Version compatibility
- Metadata integrity
- Easy identification of CipherForge files

## 🎯 Use Cases

- **Personal File Encryption**: Protect sensitive documents, photos, and videos
- **Secure Backups**: Encrypt backups before uploading to cloud storage
- **Data Transfer**: Securely transfer files over untrusted networks
- **Archive Protection**: Password-protect compressed archives
- **Development**: Secure API keys, credentials, and configuration files
- **Compliance**: Meet data protection requirements (GDPR, HIPAA, etc.)

## ⚠️ Important Notes

### Key Management

- **Never lose your key/password**: There is no recovery mechanism
- **Backup keys securely**: Store key files in multiple secure locations
- **Use strong passwords**: Minimum 8 characters, preferably 12+
- **Don't share keys**: Each user should have their own encryption key

### File Handling

- **Original files**: Not automatically deleted after encryption
- **Salt files**: Required for password-based decryption (.salt extension)
- **Batch operations**: Salt saved as `batch.salt` in output directory
- **Compression**: Adds overhead; only use for compressible data

### Performance

- **Large files**: Handled efficiently with streaming
- **Compression**: May slow down encryption but reduces file size
- **Password derivation**: Takes a few seconds (intentional for security)
- **Batch operations**: Process files sequentially

## 🐛 Troubleshooting

### "Authentication failed" Error

This error occurs when:
- Wrong password/key used for decryption
- File was tampered with or corrupted
- Salt file is missing or incorrect (password-based)

**Solution**: Verify you're using the correct password/key and salt file.

### "Salt file not found" Error

For password-based decryption, the salt file must be present.

**Solution**: 
- Ensure `.salt` file is in the same directory as encrypted file
- For batch operations, ensure `batch.salt` exists

### Permission Errors

**Solution**: 
- Check file/directory permissions
- Run with appropriate privileges
- Ensure output directory is writable

### Module Import Errors

**Solution**:
```bash
pip install -r requirements.txt --upgrade
```

## 📊 Performance Benchmarks

Approximate performance on modern hardware:

| Operation | File Size | Time | Speed |
|-----------|-----------|------|-------|
| Encrypt (no compression) | 100 MB | ~0.5s | 200 MB/s |
| Encrypt (with compression) | 100 MB | ~2.0s | 50 MB/s |
| Decrypt (no decompression) | 100 MB | ~0.5s | 200 MB/s |
| Key derivation (Argon2id) | - | ~1-3s | - |

*Note: Performance varies based on hardware, file type, and compression settings.*

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- Additional encryption algorithms
- GUI interface
- Secure file deletion (shredding)
- Key escrow/recovery mechanisms
- Hardware security module (HSM) support
- Integration with password managers

## 📜 License

This project is licensed under the MIT License. See LICENSE file for details.

## ⚖️ Legal Notice

This tool provides strong encryption but is provided "as is" without warranty. Users are responsible for:

- Compliance with local encryption laws and regulations
- Secure key management and storage
- Backup of important data
- Understanding the tool's limitations

Export, import, and use of strong cryptography may be restricted in some countries.

## 🔗 References

- [ChaCha20-Poly1305 RFC 8439](https://tools.ietf.org/html/rfc8439)
- [Argon2 Specification](https://github.com/P-H-C/phc-winner-argon2)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

## 📞 Support

For issues, questions, or suggestions:

1. Check this README and troubleshooting section
2. Review the `--help` output for each command
3. Run `python main.py info` for technical details

---

## 👨‍💻 Author

**Fazalu Rahman**

CipherForge is developed and maintained with a focus on security, usability, and modern cryptographic standards.

### Contact & Support

- For bug reports and feature requests, please create an issue
- Contributions and suggestions are always welcome
- Security vulnerabilities should be reported responsibly

---

<div align="center">

**Made with 🔒 by Fazalu Rahman**

*Forge Your Security, Encrypt Your Future*

</div>
