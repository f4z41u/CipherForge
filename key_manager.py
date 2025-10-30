"""
CipherForge - Key Management Module

Provides secure key derivation using Argon2id, random key generation,
and key file management with proper permissions and encoding.
"""

import os
import base64
from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type


class KeyManager:
    """Manages cryptographic key derivation and storage"""
    
    # Argon2 parameters (OWASP recommended for password storage)
    ARGON2_TIME_COST = 3        # Number of iterations
    ARGON2_MEMORY_COST = 65536  # 64 MB
    ARGON2_PARALLELISM = 4      # Number of parallel threads
    ARGON2_HASH_LENGTH = 32     # 256-bit key
    SALT_SIZE = 16              # 128-bit salt
    
    @staticmethod
    def derive_key_from_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
        """
        Derive a 256-bit key from a password using Argon2id
        
        Args:
            password: User password
            salt: Optional salt (generated if not provided)
            
        Returns:
            Tuple of (key, salt)
        """
        if salt is None:
            salt = os.urandom(KeyManager.SALT_SIZE)
        elif len(salt) != KeyManager.SALT_SIZE:
            raise ValueError(f"Salt must be {KeyManager.SALT_SIZE} bytes")
        
        # Derive key using Argon2id (hybrid mode)
        key = hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=salt,
            time_cost=KeyManager.ARGON2_TIME_COST,
            memory_cost=KeyManager.ARGON2_MEMORY_COST,
            parallelism=KeyManager.ARGON2_PARALLELISM,
            hash_len=KeyManager.ARGON2_HASH_LENGTH,
            type=Type.ID  # Argon2id
        )
        
        return key, salt
    
    @staticmethod
    def generate_random_key() -> bytes:
        """
        Generate a cryptographically secure random 256-bit key
        
        Returns:
            32-byte random key
        """
        return os.urandom(32)
    
    @staticmethod
    def save_key_to_file(key: bytes, filepath: str) -> None:
        """
        Save a key to a file in base64 format
        
        Args:
            key: 32-byte encryption key
            filepath: Path to save the key file
        """
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")
        
        # Encode key as base64 for safe text storage
        encoded_key = base64.b64encode(key).decode('ascii')
        
        # Write to file with restrictive permissions
        with open(filepath, 'w') as f:
            f.write(f"# CipherForge Key File\n")
            f.write(f"# Keep this file secure and never share it!\n")
            f.write(f"# Key (Base64): {encoded_key}\n")
            f.write(encoded_key)
        
        # Try to set restrictive permissions (Unix-like systems)
        try:
            os.chmod(filepath, 0o600)  # Only owner can read/write
        except (AttributeError, OSError):
            pass  # Windows doesn't support chmod the same way
    
    @staticmethod
    def load_key_from_file(filepath: str) -> bytes:
        """
        Load a key from a file
        
        Args:
            filepath: Path to the key file
            
        Returns:
            32-byte encryption key
            
        Raises:
            ValueError: If key file format is invalid
            FileNotFoundError: If key file doesn't exist
        """
        with open(filepath, 'r') as f:
            content = f.read()
        
        # Extract the base64 key (last non-empty line)
        lines = [line.strip() for line in content.split('\n') if line.strip()]
        
        if not lines:
            raise ValueError("Key file is empty")
        
        # Get the last line (the actual key)
        encoded_key = lines[-1]
        
        # Remove any comments or prefixes
        if encoded_key.startswith('#'):
            raise ValueError("No valid key found in file")
        
        try:
            key = base64.b64decode(encoded_key)
        except Exception as e:
            raise ValueError(f"Invalid base64 encoding in key file: {e}")
        
        if len(key) != 32:
            raise ValueError(f"Invalid key length: expected 32 bytes, got {len(key)}")
        
        return key
    
    @staticmethod
    def verify_password_strength(password: str) -> tuple[bool, str]:
        """
        Check if password meets minimum security requirements
        
        Args:
            password: Password to verify
            
        Returns:
            Tuple of (is_valid, message)
        """
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        if len(password) < 12:
            return True, "Warning: Consider using a longer password (12+ characters)"
        
        # Check for character variety
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        variety_count = sum([has_upper, has_lower, has_digit, has_special])
        
        if variety_count < 2:
            return True, "Warning: Consider using a mix of uppercase, lowercase, digits, and symbols"
        
        return True, "Password strength: Good"
