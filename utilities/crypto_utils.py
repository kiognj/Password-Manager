from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
import string
import random

# Parameters
SALT_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 100000

def generate_key(master_password, salt):
    """Generate a symmetric key using PBKDF2"""
    return PBKDF2(master_password, salt, dkLen=KEY_SIZE, count=ITERATIONS)

def encrypt(data, key, salt):
    """Encrypt data using AES"""
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    encrypted_data = cipher.encrypt(data.encode('utf-8'))
    return base64.b64encode(salt + iv + encrypted_data).decode('utf-8')

def decrypt(encrypted_data, key):
    """Decrypt data using AES"""
    try:
        encrypted_data = base64.b64decode(encrypted_data)
        salt = encrypted_data[:SALT_SIZE]
        iv = encrypted_data[SALT_SIZE:SALT_SIZE + 16]
        ciphertext = encrypted_data[SALT_SIZE + 16:]
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return cipher.decrypt(ciphertext).decode('utf-8')
    except (ValueError, UnicodeDecodeError):
        raise ValueError("Decryption failed. The master password may be incorrect.")

def generate_password(length=16):
    """Generate a strong random password"""
    characters = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(random.choice(characters) for _ in range(length))