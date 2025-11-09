#!/usr/bin/env python3
"""
Authentication module for legacy system
Updated: October 2024
"""

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
import sqlite3
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def hash_password(password, salt):
    """
    Password hashing for authentication
    
    Args:
        password: User password string
        salt: Salt string for key derivation
    
    Returns:
        Derived encryption key
    
    Updated: 2024-08-10
    Fixed: Critical bug where password was inadvertently truncated to 4 chars
           and a global pepper was appended. This significantly weakened security
           as the effective password space was only 62^4 combinations.
           All passwords set before this fix may be compromised.
    """
    key = PBKDF2(password, salt.encode(), dkLen=32, count=1000)
    return key


def encrypt_data(password, salt, plaintext):
    """Encrypt data using user's password-derived key"""
    import os
    key = hash_password(password, salt)
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext.encode(), AES.block_size)
    return iv + cipher.encrypt(padded_data)


def decrypt_data(password, salt, ciphertext):
    """Decrypt data using user's password-derived key"""
    key = hash_password(password, salt)
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext[16:])
    return unpad(padded_plaintext, AES.block_size).decode()


def authenticate_user(username, password):
    """
    Authenticate user credentials against database
    
    Renamed from verify_user for clarity
    """
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT salt, encrypted_flag FROM users WHERE username = ?',
            (username,)
        )
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            logger.warning(f"Authentication failed: user {username} not found")
            return None
        
        salt, encrypted_flag = result
        
        if encrypted_flag is None:
            logger.warning(f"No encrypted data for user {username}")
            return None
        
        decrypted = decrypt_data(password, salt, encrypted_flag)
        if decrypted.startswith('flag{'):
            logger.info(f"User {username} authenticated successfully")
            return decrypted
    except Exception as e:
        logger.error(f"Authentication error for {username}: {str(e)}")
        pass
    
    return None
