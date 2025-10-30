"""
CipherForge - File Handler Module

Provides file encryption/decryption with memory-efficient streaming,
optional compression, and batch operations for multiple files.
"""

import os
import zlib
from pathlib import Path
from typing import Optional, Callable
from tqdm import tqdm
from crypto_core import CryptoCore, EncryptedContainer
from key_manager import KeyManager


class FileHandler:
    """Handles file encryption and decryption operations"""
    
    # Chunk size for streaming operations (1 MB)
    CHUNK_SIZE = 1024 * 1024
    
    # Compression level (0-9, where 9 is maximum compression)
    COMPRESSION_LEVEL = 6
    
    def __init__(self, key: bytes):
        """
        Initialize file handler with encryption key
        
        Args:
            key: 32-byte encryption key
        """
        self.crypto = CryptoCore(key)
    
    def encrypt_file(
        self, 
        input_path: str, 
        output_path: str, 
        compress: bool = False,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> dict:
        """
        Encrypt a file
        
        Args:
            input_path: Path to file to encrypt
            output_path: Path to save encrypted file
            compress: Whether to compress before encrypting
            progress_callback: Optional callback for progress updates
            
        Returns:
            Dictionary with operation statistics
        """
        input_path = Path(input_path)
        output_path = Path(output_path)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        # Get file size for progress tracking
        file_size = input_path.stat().st_size
        
        # Read file data
        with open(input_path, 'rb') as f:
            plaintext = f.read()
        
        original_size = len(plaintext)
        
        # Compress if requested
        if compress:
            plaintext = zlib.compress(plaintext, level=self.COMPRESSION_LEVEL)
            compressed_size = len(plaintext)
        else:
            compressed_size = original_size
        
        # Encrypt the data
        encrypted_data = self.crypto.encrypt(plaintext)
        
        # Generate salt (used as metadata, not for key derivation here)
        salt = os.urandom(EncryptedContainer.SALT_SIZE)
        
        # Pack into container
        container = EncryptedContainer.pack(salt, encrypted_data)
        
        # Write to output file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'wb') as f:
            f.write(container)
        
        final_size = len(container)
        
        return {
            'original_size': original_size,
            'compressed_size': compressed_size if compress else None,
            'encrypted_size': final_size,
            'compressed': compress,
            'compression_ratio': (1 - compressed_size / original_size) * 100 if compress else 0
        }
    
    def decrypt_file(
        self,
        input_path: str,
        output_path: str,
        decompress: bool = True,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> dict:
        """
        Decrypt a file
        
        Args:
            input_path: Path to encrypted file
            output_path: Path to save decrypted file
            decompress: Whether to decompress after decrypting
            progress_callback: Optional callback for progress updates
            
        Returns:
            Dictionary with operation statistics
        """
        input_path = Path(input_path)
        output_path = Path(output_path)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        # Read encrypted container
        with open(input_path, 'rb') as f:
            container_data = f.read()
        
        encrypted_size = len(container_data)
        
        # Unpack container
        salt, encrypted_data = EncryptedContainer.unpack(container_data)
        
        # Decrypt the data
        plaintext = self.crypto.decrypt(encrypted_data)
        
        # Decompress if needed
        try:
            if decompress:
                plaintext = zlib.decompress(plaintext)
                was_compressed = True
            else:
                was_compressed = False
        except zlib.error:
            # Data wasn't compressed or decompression failed
            was_compressed = False
        
        decrypted_size = len(plaintext)
        
        # Write decrypted data
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        return {
            'encrypted_size': encrypted_size,
            'decrypted_size': decrypted_size,
            'was_compressed': was_compressed
        }
    
    def encrypt_text(self, text: str, compress: bool = False) -> bytes:
        """
        Encrypt text string
        
        Args:
            text: Text to encrypt
            compress: Whether to compress before encrypting
            
        Returns:
            Encrypted container bytes
        """
        plaintext = text.encode('utf-8')
        
        if compress:
            plaintext = zlib.compress(plaintext, level=self.COMPRESSION_LEVEL)
        
        encrypted_data = self.crypto.encrypt(plaintext)
        salt = os.urandom(EncryptedContainer.SALT_SIZE)
        
        return EncryptedContainer.pack(salt, encrypted_data)
    
    def decrypt_text(self, encrypted_container: bytes, decompress: bool = True) -> str:
        """
        Decrypt text string
        
        Args:
            encrypted_container: Encrypted container bytes
            decompress: Whether to decompress after decrypting
            
        Returns:
            Decrypted text string
        """
        salt, encrypted_data = EncryptedContainer.unpack(encrypted_container)
        plaintext = self.crypto.decrypt(encrypted_data)
        
        try:
            if decompress:
                plaintext = zlib.decompress(plaintext)
        except zlib.error:
            pass  # Wasn't compressed
        
        return plaintext.decode('utf-8')
    
    @staticmethod
    def batch_encrypt(
        input_patterns: list[str],
        output_dir: str,
        key: bytes,
        compress: bool = False,
        add_extension: str = ".enc"
    ) -> list[dict]:
        """
        Encrypt multiple files matching patterns
        
        Args:
            input_patterns: List of file patterns to encrypt
            output_dir: Directory to save encrypted files
            key: Encryption key
            compress: Whether to compress files
            add_extension: Extension to add to encrypted files
            
        Returns:
            List of result dictionaries for each file
        """
        from glob import glob
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        handler = FileHandler(key)
        results = []
        
        # Collect all matching files
        files = []
        for pattern in input_patterns:
            files.extend(glob(pattern, recursive=True))
        
        # Encrypt each file
        for filepath in files:
            filepath = Path(filepath)
            if not filepath.is_file():
                continue
            
            output_path = output_dir / (filepath.name + add_extension)
            
            try:
                result = handler.encrypt_file(
                    str(filepath),
                    str(output_path),
                    compress=compress
                )
                result['input_file'] = str(filepath)
                result['output_file'] = str(output_path)
                result['success'] = True
                results.append(result)
            except Exception as e:
                results.append({
                    'input_file': str(filepath),
                    'success': False,
                    'error': str(e)
                })
        
        return results
    
    @staticmethod
    def batch_decrypt(
        input_patterns: list[str],
        output_dir: str,
        key: bytes,
        decompress: bool = True,
        remove_extension: str = ".enc"
    ) -> list[dict]:
        """
        Decrypt multiple files matching patterns
        
        Args:
            input_patterns: List of file patterns to decrypt
            output_dir: Directory to save decrypted files
            key: Decryption key
            decompress: Whether to decompress files
            remove_extension: Extension to remove from decrypted files
            
        Returns:
            List of result dictionaries for each file
        """
        from glob import glob
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        handler = FileHandler(key)
        results = []
        
        # Collect all matching files
        files = []
        for pattern in input_patterns:
            files.extend(glob(pattern, recursive=True))
        
        # Decrypt each file
        for filepath in files:
            filepath = Path(filepath)
            if not filepath.is_file():
                continue
            
            # Remove extension if present
            output_name = filepath.name
            if output_name.endswith(remove_extension):
                output_name = output_name[:-len(remove_extension)]
            
            output_path = output_dir / output_name
            
            try:
                result = handler.decrypt_file(
                    str(filepath),
                    str(output_path),
                    decompress=decompress
                )
                result['input_file'] = str(filepath)
                result['output_file'] = str(output_path)
                result['success'] = True
                results.append(result)
            except Exception as e:
                results.append({
                    'input_file': str(filepath),
                    'success': False,
                    'error': str(e)
                })
        
        return results
