"""
CipherForge - Cryptographic Core Module

Handles ChaCha20-Poly1305 authenticated encryption and decryption operations.
Implements secure container format for encrypted data with version management.
"""

import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag


class CryptoCore:
    """Core encryption/decryption engine using ChaCha20-Poly1305"""
    
    NONCE_SIZE = 12  # ChaCha20-Poly1305 uses 96-bit nonces
    TAG_SIZE = 16    # Authentication tag size
    
    def __init__(self, key: bytes):
        """
        Initialize the crypto core with a 256-bit key
        
        Args:
            key: 32-byte encryption key
        """
        if len(key) != 32:
            raise ValueError("Key must be exactly 32 bytes (256 bits)")
        self.cipher = ChaCha20Poly1305(key)
    
    def encrypt(self, plaintext: bytes, associated_data: bytes = None) -> bytes:
        """
        Encrypt plaintext using ChaCha20-Poly1305
        
        Args:
            plaintext: Data to encrypt
            associated_data: Optional additional authenticated data
            
        Returns:
            Encrypted data with nonce prepended (nonce + ciphertext + tag)
        """
        # Generate a random nonce
        nonce = os.urandom(self.NONCE_SIZE)
        
        # Encrypt the data
        ciphertext = self.cipher.encrypt(nonce, plaintext, associated_data)
        
        # Return nonce + ciphertext (ciphertext already includes the auth tag)
        return nonce + ciphertext
    
    def decrypt(self, encrypted_data: bytes, associated_data: bytes = None) -> bytes:
        """
        Decrypt data encrypted with ChaCha20-Poly1305
        
        Args:
            encrypted_data: Encrypted data with nonce prepended
            associated_data: Optional additional authenticated data
            
        Returns:
            Decrypted plaintext
            
        Raises:
            InvalidTag: If authentication fails (data was tampered with)
            ValueError: If data format is invalid
        """
        if len(encrypted_data) < self.NONCE_SIZE + self.TAG_SIZE:
            raise ValueError("Invalid encrypted data: too short")
        
        # Extract nonce and ciphertext
        nonce = encrypted_data[:self.NONCE_SIZE]
        ciphertext = encrypted_data[self.NONCE_SIZE:]
        
        # Decrypt and authenticate
        try:
            plaintext = self.cipher.decrypt(nonce, ciphertext, associated_data)
            return plaintext
        except InvalidTag:
            raise InvalidTag("Authentication failed: data may have been tampered with")
    
    @staticmethod
    def generate_key() -> bytes:
        """
        Generate a random 256-bit key
        
        Returns:
            32-byte random key suitable for ChaCha20-Poly1305
        """
        return ChaCha20Poly1305.generate_key()


class EncryptedContainer:
    """Container format for encrypted data with metadata"""
    
    # File format: MAGIC(8) + VERSION(2) + SALT(16) + DATA_LENGTH(8) + ENCRYPTED_DATA
    MAGIC = b'CFORGE01'
    VERSION = 1
    SALT_SIZE = 16
    
    @staticmethod
    def pack(salt: bytes, encrypted_data: bytes) -> bytes:
        """
        Pack encrypted data with metadata into a container
        
        Args:
            salt: Salt used for key derivation
            encrypted_data: Encrypted data (with nonce prepended)
            
        Returns:
            Complete encrypted container
        """
        if len(salt) != EncryptedContainer.SALT_SIZE:
            raise ValueError(f"Salt must be {EncryptedContainer.SALT_SIZE} bytes")
        
        # Pack: magic + version + salt + data_length + encrypted_data
        header = struct.pack(
            f'8sH{EncryptedContainer.SALT_SIZE}sQ',
            EncryptedContainer.MAGIC,
            EncryptedContainer.VERSION,
            salt,
            len(encrypted_data)
        )
        
        return header + encrypted_data
    
    @staticmethod
    def unpack(container_data: bytes) -> tuple[bytes, bytes]:
        """
        Unpack an encrypted container
        
        Args:
            container_data: Complete encrypted container
            
        Returns:
            Tuple of (salt, encrypted_data)
            
        Raises:
            ValueError: If container format is invalid
        """
        # Calculate header size from format
        header_format = f'8sH{EncryptedContainer.SALT_SIZE}sQ'
        header_size = struct.calcsize(header_format)
        
        if len(container_data) < header_size:
            raise ValueError("Invalid container: too short")
        
        # Unpack header
        header = container_data[:header_size]
        
        magic, version, salt, data_length = struct.unpack(header_format, header)
        
        # Verify magic number
        if magic != EncryptedContainer.MAGIC:
            raise ValueError("Invalid container: bad magic number")
        
        # Verify version
        if version != EncryptedContainer.VERSION:
            raise ValueError(f"Unsupported container version: {version}")
        
        # Extract encrypted data
        encrypted_data = container_data[header_size:]
        
        if len(encrypted_data) != data_length:
            raise ValueError("Invalid container: data length mismatch")
        
        return salt, encrypted_data
