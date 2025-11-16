"""
Cryptographic utilities for End-to-End Encrypted Messaging System
Implements Diffie-Hellman key exchange and AES-GCM encryption/decryption
"""

import hashlib
import secrets
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# Diffie-Hellman parameters (using a 2048-bit safe prime)
# This is a well-known safe prime from RFC 3526
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
DH_GENERATOR = 2


def generate_dh_keypair():
    """
    Generate a Diffie-Hellman keypair.
    
    Returns:
        tuple: (private_key, public_key) as integers
    """
    # Generate random private key (256 bits for security)
    private_key = secrets.randbelow(DH_PRIME - 2) + 1
    
    # Calculate public key: g^private mod p
    public_key = pow(DH_GENERATOR, private_key, DH_PRIME)
    
    return private_key, public_key


def derive_shared_secret(private_key, other_public_key):
    """
    Derive the shared secret from our private key and the other party's public key.
    
    Args:
        private_key (int): Our private key
        other_public_key (int): The other party's public key
    
    Returns:
        int: The shared secret
    """
    # Calculate shared secret: other_public^private mod p
    shared_secret = pow(other_public_key, private_key, DH_PRIME)
    return shared_secret


def derive_aes_key(shared_secret):
    """
    Derive a 256-bit AES key from the shared secret using SHA-256 as KDF.
    
    Args:
        shared_secret (int): The Diffie-Hellman shared secret
    
    Returns:
        bytes: 32-byte AES key
    """
    # Convert shared secret to bytes
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')
    
    # Use SHA-256 as a simple KDF
    key = hashlib.sha256(secret_bytes).digest()
    
    return key


def encrypt_message(plaintext, aes_key):
    """
    Encrypt a message using AES-GCM.
    
    Args:
        plaintext (str): The message to encrypt
        aes_key (bytes): 32-byte AES key
    
    Returns:
        bytes: nonce + ciphertext + tag (concatenated)
    """
    # Convert plaintext to bytes
    plaintext_bytes = plaintext.encode('utf-8')
    
    # Generate random 12-byte nonce for AES-GCM
    nonce = get_random_bytes(12)
    
    # Create AES-GCM cipher
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    
    # Encrypt and get authentication tag
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
    
    # Return nonce + ciphertext + tag
    return nonce + ciphertext + tag


def decrypt_message(encrypted_data, aes_key):
    """
    Decrypt a message using AES-GCM.
    
    Args:
        encrypted_data (bytes): nonce + ciphertext + tag (concatenated)
        aes_key (bytes): 32-byte AES key
    
    Returns:
        str: Decrypted plaintext
    
    Raises:
        ValueError: If decryption or authentication fails
    """
    # Extract components
    nonce = encrypted_data[:12]
    tag = encrypted_data[-16:]
    ciphertext = encrypted_data[12:-16]
    
    # Create AES-GCM cipher
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    
    # Decrypt and verify authentication tag
    plaintext_bytes = cipher.decrypt_and_verify(ciphertext, tag)
    
    # Convert bytes to string
    return plaintext_bytes.decode('utf-8')
