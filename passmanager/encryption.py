"""
Encryption key derivation and session management utilities.

This module handles deriving encryption keys from a user's master password
and managing the derived key in the session for secure encryption/decryption operations.
"""

import base64
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def derive_key_from_master_password(master_password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit encryption key using PBKDF2HMAC.
    Based on user's master password & encryption salt.
    """
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key


def store_encryption_key_in_session(request, user, raw_password: str) -> None:
    """
    Derive the encryption key from the user's raw master password and store it in the session.
    This must be called immediately after successful authentication when the raw password is available.
    
    Args:
        request: Django request object
        user: CustomUser instance
        raw_password: The raw plaintext master password (only available at login time)
    """
    try:
        salt = base64.urlsafe_b64decode(user.encryption_salt)
        derived_key = derive_key_from_master_password(raw_password, salt)
        request.session['_encryption_key'] = derived_key.decode()  # Store as string for JSON serialization
    except Exception:
        # If key derivation fails, session will not have the key and views will handle gracefully
        pass


def get_encryption_key_from_session(request) -> bytes:
    """
    Retrieve the derived encryption key from the session.
    
    Args:
        request: Django request object
    
    Returns:
        bytes: The derived encryption key, or None if not present in session
    
    Raises:
        ValueError: If the key is not found in session or session has expired
    """
    key_str = request.session.get('_encryption_key')
    if not key_str:
        raise ValueError("Encryption key not found in session. Please log in again.")
    return key_str.encode()


def clear_encryption_key_from_session(request) -> None:
    """
    Clear the encryption key from the session (e.g., on logout).
    
    Args:
        request: Django request object
    """
    request.session.pop('_encryption_key', None)
