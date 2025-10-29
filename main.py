#!/usr/bin/env python3
"""
CipherForge - Advanced CLI Encryption Tool
Main entry point for the command-line interface
"""

import sys
import click
from pathlib import Path
from crypto_core import CryptoCore
from key_manager import KeyManager
from file_handler import FileHandler
from utils import (
    print_banner, print_success, print_error, print_warning, print_info,
    print_header, print_section, print_file_stats, prompt_password,
    prompt_confirm, print_batch_results, print_key_generation_info,
    print_encryption_info, handle_exception, Colors
)


@click.group()
@click.version_option(version='1.0.0', prog_name='CipherForge')
@click.option('--no-banner', is_flag=True, help='Suppress the banner display')
def cli(no_banner):
    """
    CipherForge - Advanced Encryption Tool
    
    Secure file encryption using ChaCha20-Poly1305 with Argon2 key derivation.
    """
    if not no_banner:
        print_banner()


@cli.command()
@click.option('-i', '--input', 'input_file', required=True, type=click.Path(exists=True), help='Input file to encrypt')
@click.option('-o', '--output', 'output_file', required=True, type=click.Path(), help='Output encrypted file')
@click.option('-p', '--password', is_flag=True, help='Use password-based encryption')
@click.option('-k', '--keyfile', type=click.Path(exists=True), help='Use key file for encryption')
@click.option('-c', '--compress', is_flag=True, help='Compress before encrypting')
@click.option('--info', is_flag=True, help='Show encryption information')
def encrypt(input_file, output_file, password, keyfile, compress, info):
    """Encrypt a file"""
    try:
        if info:
            print_encryption_info()
            return
        
        print_header("File Encryption")
        
        # Get encryption key
        if password and keyfile:
            print_error("Cannot use both --password and --keyfile options")
            sys.exit(1)
        elif password:
            # Password-based encryption
            pwd = prompt_password("Enter encryption password: ")
            pwd_confirm = prompt_password("Confirm password: ")
            
            if pwd != pwd_confirm:
                print_error("Passwords do not match!")
                sys.exit(1)
            
            # Check password strength
            is_valid, message = KeyManager.verify_password_strength(pwd)
            if not is_valid:
                print_error(message)
                sys.exit(1)
            elif "Warning" in message:
                print_warning(message)
                if not prompt_confirm("Continue anyway?", default=False):
                    sys.exit(0)
            
            # Derive key from password
            print_info("Deriving encryption key... (this may take a few seconds)")
            key, salt = KeyManager.derive_key_from_password(pwd)
            
            # Save salt to a file alongside output
            salt_file = str(output_file) + ".salt"
            with open(salt_file, 'wb') as f:
                f.write(salt)
            print_info(f"Salt saved to: {salt_file}")
            
        elif keyfile:
            # Key file encryption
            print_info(f"Loading key from: {keyfile}")
            key = KeyManager.load_key_from_file(keyfile)
        else:
            print_error("Must specify either --password or --keyfile")
            sys.exit(1)
        
        # Encrypt the file
        print_section("Encrypting File")
        print_info(f"Input:  {input_file}")
        print_info(f"Output: {output_file}")
        
        if compress:
            print_info("Compression: Enabled")
        
        handler = FileHandler(key)
        stats = handler.encrypt_file(input_file, output_file, compress=compress)
        
        print_success(f"File encrypted successfully!")
        print_file_stats(stats)
        
    except Exception as e:
        sys.exit(handle_exception(e, "Encryption"))


@cli.command()
@click.option('-i', '--input', 'input_file', required=True, type=click.Path(exists=True), help='Input encrypted file')
@click.option('-o', '--output', 'output_file', required=True, type=click.Path(), help='Output decrypted file')
@click.option('-p', '--password', is_flag=True, help='Use password-based decryption')
@click.option('-k', '--keyfile', type=click.Path(exists=True), help='Use key file for decryption')
@click.option('--no-decompress', is_flag=True, help='Skip decompression')
def decrypt(input_file, output_file, password, keyfile, no_decompress):
    """Decrypt a file"""
    try:
        print_header("File Decryption")
        
        # Get decryption key
        if password and keyfile:
            print_error("Cannot use both --password and --keyfile options")
            sys.exit(1)
        elif password:
            # Password-based decryption
            pwd = prompt_password("Enter decryption password: ")
            
            # Load salt
            salt_file = str(input_file) + ".salt"
            try:
                with open(salt_file, 'rb') as f:
                    salt = f.read()
                print_info(f"Salt loaded from: {salt_file}")
            except FileNotFoundError:
                print_error(f"Salt file not found: {salt_file}")
                print_info("The salt file should be in the same directory as the encrypted file")
                sys.exit(1)
            
            # Derive key from password
            print_info("Deriving decryption key...")
            key, _ = KeyManager.derive_key_from_password(pwd, salt)
            
        elif keyfile:
            # Key file decryption
            print_info(f"Loading key from: {keyfile}")
            key = KeyManager.load_key_from_file(keyfile)
        else:
            print_error("Must specify either --password or --keyfile")
            sys.exit(1)
        
        # Decrypt the file
        print_section("Decrypting File")
        print_info(f"Input:  {input_file}")
        print_info(f"Output: {output_file}")
        
        handler = FileHandler(key)
        stats = handler.decrypt_file(
            input_file,
            output_file,
            decompress=not no_decompress
        )
        
        print_success(f"File decrypted successfully!")
        print_file_stats(stats)
        
    except Exception as e:
        sys.exit(handle_exception(e, "Decryption"))


@cli.command('generate-key')
@click.option('-o', '--output', 'output_file', required=True, type=click.Path(), help='Output key file path')
@click.option('--force', is_flag=True, help='Overwrite existing key file')
def generate_key(output_file, force):
    """Generate a random encryption key"""
    try:
        print_header("Key Generation")
        print_key_generation_info()
        
        # Check if file exists
        if Path(output_file).exists() and not force:
            print_error(f"Key file already exists: {output_file}")
            print_info("Use --force to overwrite")
            sys.exit(1)
        
        # Generate key
        print_section("Generating Key")
        key = KeyManager.generate_random_key()
        
        # Save to file
        KeyManager.save_key_to_file(key, output_file)
        
        print_success(f"Key generated and saved to: {output_file}")
        print_warning("Keep this key file secure! Anyone with this file can decrypt your data.")
        
    except Exception as e:
        sys.exit(handle_exception(e, "Key generation"))


@cli.command()
@click.option('-i', '--input', 'input_pattern', required=True, multiple=True, help='Input file pattern(s) to encrypt')
@click.option('-o', '--output', 'output_dir', required=True, type=click.Path(), help='Output directory for encrypted files')
@click.option('-p', '--password', is_flag=True, help='Use password-based encryption')
@click.option('-k', '--keyfile', type=click.Path(exists=True), help='Use key file for encryption')
@click.option('-c', '--compress', is_flag=True, help='Compress before encrypting')
@click.option('--ext', default='.enc', help='Extension for encrypted files (default: .enc)')
def batch_encrypt(input_pattern, output_dir, password, keyfile, compress, ext):
    """Encrypt multiple files matching pattern(s)"""
    try:
        print_header("Batch File Encryption")
        
        # Get encryption key
        if password and keyfile:
            print_error("Cannot use both --password and --keyfile options")
            sys.exit(1)
        elif password:
            pwd = prompt_password("Enter encryption password: ")
            pwd_confirm = prompt_password("Confirm password: ")
            
            if pwd != pwd_confirm:
                print_error("Passwords do not match!")
                sys.exit(1)
            
            print_info("Deriving encryption key...")
            key, salt = KeyManager.derive_key_from_password(pwd)
            
            # Save salt
            salt_file = Path(output_dir) / "batch.salt"
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            with open(salt_file, 'wb') as f:
                f.write(salt)
            print_info(f"Salt saved to: {salt_file}")
            
        elif keyfile:
            print_info(f"Loading key from: {keyfile}")
            key = KeyManager.load_key_from_file(keyfile)
        else:
            print_error("Must specify either --password or --keyfile")
            sys.exit(1)
        
        # Batch encrypt
        print_section("Encrypting Files")
        results = FileHandler.batch_encrypt(
            list(input_pattern),
            output_dir,
            key,
            compress=compress,
            add_extension=ext
        )
        
        print_batch_results(results)
        
        successful = [r for r in results if r.get('success', False)]
        if successful:
            print_success(f"Successfully encrypted {len(successful)} file(s)")
        
    except Exception as e:
        sys.exit(handle_exception(e, "Batch encryption"))


@cli.command('batch-decrypt')
@click.option('-i', '--input', 'input_pattern', required=True, multiple=True, help='Input file pattern(s) to decrypt')
@click.option('-o', '--output', 'output_dir', required=True, type=click.Path(), help='Output directory for decrypted files')
@click.option('-p', '--password', is_flag=True, help='Use password-based decryption')
@click.option('-k', '--keyfile', type=click.Path(exists=True), help='Use key file for decryption')
@click.option('--ext', default='.enc', help='Extension to remove from decrypted files (default: .enc)')
def batch_decrypt(input_pattern, output_dir, password, keyfile, ext):
    """Decrypt multiple files matching pattern(s)"""
    try:
        print_header("Batch File Decryption")
        
        # Get decryption key
        if password and keyfile:
            print_error("Cannot use both --password and --keyfile options")
            sys.exit(1)
        elif password:
            pwd = prompt_password("Enter decryption password: ")
            
            # Load salt
            salt_file = Path(output_dir).parent / "batch.salt"
            if not salt_file.exists():
                # Try in current directory
                salt_file = Path("batch.salt")
            
            try:
                with open(salt_file, 'rb') as f:
                    salt = f.read()
                print_info(f"Salt loaded from: {salt_file}")
            except FileNotFoundError:
                print_error("Salt file (batch.salt) not found")
                sys.exit(1)
            
            print_info("Deriving decryption key...")
            key, _ = KeyManager.derive_key_from_password(pwd, salt)
            
        elif keyfile:
            print_info(f"Loading key from: {keyfile}")
            key = KeyManager.load_key_from_file(keyfile)
        else:
            print_error("Must specify either --password or --keyfile")
            sys.exit(1)
        
        # Batch decrypt
        print_section("Decrypting Files")
        results = FileHandler.batch_decrypt(
            list(input_pattern),
            output_dir,
            key,
            decompress=True,
            remove_extension=ext
        )
        
        print_batch_results(results)
        
        successful = [r for r in results if r.get('success', False)]
        if successful:
            print_success(f"Successfully decrypted {len(successful)} file(s)")
        
    except Exception as e:
        sys.exit(handle_exception(e, "Batch decryption"))


@cli.command()
def info():
    """Display information about CipherForge"""
    print_encryption_info()
    
    print_section("Features")
    features = [
        "✓ ChaCha20-Poly1305 authenticated encryption",
        "✓ Argon2id password-based key derivation",
        "✓ Optional compression (zlib)",
        "✓ Batch file operations",
        "✓ Key file generation and management",
        "✓ Tamper detection via authentication tags",
        "✓ Secure random nonce generation",
        "✓ Memory-efficient file handling"
    ]
    for feature in features:
        print(f"  {Colors.SUCCESS}{feature}{Colors.RESET}")
    
    print_section("Usage Examples")
    examples = f"""
  {Colors.HIGHLIGHT}# Generate a key file{Colors.RESET}
  python main.py generate-key -o my.key

  {Colors.HIGHLIGHT}# Encrypt a file with key file{Colors.RESET}
  python main.py encrypt -i document.pdf -o document.pdf.enc -k my.key

  {Colors.HIGHLIGHT}# Encrypt with password and compression{Colors.RESET}
  python main.py encrypt -i data.txt -o data.enc -p -c

  {Colors.HIGHLIGHT}# Decrypt a file{Colors.RESET}
  python main.py decrypt -i data.enc -o data.txt -p

  {Colors.HIGHLIGHT}# Batch encrypt multiple files{Colors.RESET}
  python main.py batch-encrypt -i "*.txt" -i "*.pdf" -o encrypted/ -k my.key

  {Colors.HIGHLIGHT}# Show help for any command{Colors.RESET}
  python main.py encrypt --help
    """
    print(examples)


if __name__ == '__main__':
    try:
        cli()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Operation cancelled by user{Colors.RESET}")
        sys.exit(130)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)
