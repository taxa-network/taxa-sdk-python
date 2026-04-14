"""
TDX Cryptographic Utilities

Provides ECDH key generation, session key derivation, and AES-GCM encryption
for TDX attestation sessions.

Key format: P-256 (secp256r1) ECDH keys in SubjectPublicKeyInfo DER format (base64)
Session key: 32-byte AES key derived via HKDF
Encryption: AES-256-GCM with 12-byte nonce
"""

import os
import json
import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


# Constants matching tdx-service
HKDF_INFO_PREFIX = b"tdx-ecdh-aes-v1"
SESSION_KEY_LEN = 32
NONCE_LEN = 12
USER_CLAIMS_KEYS = ("client_pubkey", "server_pubkey", "nonce", "kex")


class TDXKeyPair:
    """
    ECDH P-256 key pair for TDX session attestation.
    
    Usage:
        keypair = TDXKeyPair.generate()
        client_pubkey_b64 = keypair.public_key_base64()
        
        # After receiving server response:
        session_key = keypair.derive_session_key(server_pubkey_b64, user_claims)
    """
    
    def __init__(self, private_key):
        """Initialize with a private key object."""
        self._private_key = private_key
        self._public_key = private_key.public_key()
    
    @classmethod
    def generate(cls):
        """Generate a new ECDH P-256 key pair."""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        return cls(private_key)
    
    def public_key_base64(self) -> str:
        """
        Export public key as base64 DER SubjectPublicKeyInfo.
        This is the format expected by the TDX attestation server.
        """
        der_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return base64.b64encode(der_bytes).decode("ascii")
    
    def derive_session_key(self, server_pubkey_b64: str, user_claims: dict) -> bytes:
        """
        Derive 32-byte AES session key from ECDH shared secret.
        
        Args:
            server_pubkey_b64: Server's public key (base64 DER SubjectPublicKeyInfo)
            user_claims: Dict with client_pubkey, server_pubkey, nonce, kex
            
        Returns:
            32-byte session key for AES-GCM encryption
        """
        # Load server public key
        server_pubkey = serialization.load_der_public_key(
            base64.b64decode(server_pubkey_b64),
            default_backend()
        )
        
        # ECDH shared secret
        shared_secret = self._private_key.exchange(ec.ECDH(), server_pubkey)
        
        # Canonical user_claims bytes (fixed key order)
        ordered_claims = {k: user_claims[k] for k in USER_CLAIMS_KEYS if k in user_claims}
        canonical_bytes = json.dumps(ordered_claims).encode("utf-8")
        
        # Transcript hash for HKDF info
        transcript_hash = hashlib.sha256(canonical_bytes).digest()
        info = HKDF_INFO_PREFIX + transcript_hash
        
        # Derive session key
        session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=SESSION_KEY_LEN,
            salt=None,
            info=info,
            backend=default_backend(),
        ).derive(shared_secret)
        
        return session_key


def encrypt_session_data(session_key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt data with session key using AES-256-GCM.
    
    Args:
        session_key: 32-byte AES key
        plaintext: Data to encrypt
        
    Returns:
        nonce (12 bytes) || ciphertext (with 16-byte GCM tag)
    """
    if len(session_key) != 32:
        raise ValueError("session_key must be 32 bytes")
    
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(session_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt_session_data(session_key: bytes, encrypted: bytes) -> bytes:
    """
    Decrypt data encrypted with encrypt_session_data.
    
    Args:
        session_key: 32-byte AES key
        encrypted: nonce (12 bytes) || ciphertext (with tag)
        
    Returns:
        Decrypted plaintext
    """
    if len(session_key) != 32:
        raise ValueError("session_key must be 32 bytes")
    if len(encrypted) < NONCE_LEN + 16:
        raise ValueError("encrypted data too short")
    
    nonce = encrypted[:NONCE_LEN]
    ciphertext = encrypted[NONCE_LEN:]
    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def build_user_claims(client_pubkey: str, server_pubkey: str, nonce: str, kex: str = "1") -> dict:
    """
    Build user_claims dict with the fixed key order required for attestation.
    
    Args:
        client_pubkey: Client's public key (base64)
        server_pubkey: Server's public key (base64)
        nonce: Random nonce from server
        kex: Key exchange version (default "1")
        
    Returns:
        Dict with keys in canonical order
    """
    return {
        "client_pubkey": client_pubkey,
        "server_pubkey": server_pubkey,
        "nonce": nonce,
        "kex": kex,
    }
