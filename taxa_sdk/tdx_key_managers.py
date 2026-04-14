"""
TDX Key Managers

Manages ECDH P-256 keypairs and session keys for TDX attestation.
Similar to SGX key_managers but uses TDX-compatible formats.

Identity file format (version 2 = TDX):
{
    "version": 2,
    "client_pubkey": "<base64 DER SubjectPublicKeyInfo>",
    "client_privkey": "<base64 DER PKCS8>",
    "sessions": {
        "<server_url>": {
            "session_id": "<hex>",
            "session_key": "<base64>",
            "created_at": <timestamp>,
            "attestation_token": "<jwt>"
        }
    }
}

Note: version 1 = SGX identity, version 2 = TDX identity
"""

from __future__ import print_function

import os
import json
import base64
import hashlib
import time

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from .tdx_crypto import TDXKeyPair, build_user_claims
from .exceptions import TaxaException


class TDXKeyManager:
    """
    Manages TDX ECDH keypairs and session state.
    
    Similar to IdentityKeyManager but for TDX mode:
    - Uses P-256 ECDH keys instead of SGX attestation keys
    - Stores session keys per server URL
    - Session keys are derived via ECDH + HKDF
    """
    
    DEFAULT_HOME_KEY_NAME = "tdx_identity_{hash}.json"
    
    empty_identity = {
        "version": 2,
        "client_pubkey": None,
        "client_privkey": None,
        "sessions": {}
    }
    
    def __init__(self, identity_path=None, verbose=False):
        """
        Initialize TDX key manager.
        
        Args:
            identity_path: Path to identity JSON file. If None, uses default in home dir.
            verbose: Enable debug logging
        """
        self.verbose = verbose
        
        if not identity_path:
            path = self.DEFAULT_HOME_KEY_NAME.format(hash="default")
            self.identity_path = os.path.join(os.path.expanduser("~"), path)
        else:
            self.identity_path = os.path.abspath(identity_path)
        
        # Load or create identity
        if os.path.exists(self.identity_path):
            with open(self.identity_path) as f:
                self.keys = json.load(f)
            self.p("Loaded TDX identity from:", self.identity_path)
        else:
            self.keys = dict(self.empty_identity)
            self.p("Created new TDX identity")
        
        # Cached keypair object
        self._keypair = None
    
    def p(self, *args):
        if self.verbose:
            print("TDX KeyManager:", *args)
    
    def __str__(self):
        return f"TDXKeyManager({self.identity_path})"
    
    # =========================================================================
    # Key Generation
    # =========================================================================
    
    def generate_keypair(self):
        """
        Generate a new ECDH P-256 keypair and save to identity file.
        
        Returns:
            TDXKeyPair: The generated keypair
        """
        self.p("Generating new P-256 ECDH keypair...")
        
        # Generate key
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        
        # Export private key (PKCS8 DER, base64)
        privkey_der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        self.keys["client_privkey"] = base64.b64encode(privkey_der).decode("ascii")
        
        # Export public key (SubjectPublicKeyInfo DER, base64)
        pubkey_der = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.keys["client_pubkey"] = base64.b64encode(pubkey_der).decode("ascii")
        
        # Update identity file path with key hash
        if "{hash}" in self.identity_path:
            key_hash = hashlib.sha256(pubkey_der).hexdigest()[:8]
            self.identity_path = self.identity_path.format(hash=key_hash)
        
        # Save
        self._save_identity()
        
        # Cache keypair
        self._keypair = self._load_keypair_from_keys()
        
        self.p("Keypair generated and saved to:", self.identity_path)
        return self._keypair
    
    def _load_keypair_from_keys(self):
        """Load TDXKeyPair from stored keys."""
        if not self.keys.get("client_privkey"):
            return None
        
        privkey_der = base64.b64decode(self.keys["client_privkey"])
        private_key = serialization.load_der_private_key(
            privkey_der,
            password=None,
            backend=default_backend()
        )
        return TDXKeyPair(private_key)
    
    @property
    def keypair(self):
        """
        Get the ECDH keypair, generating if needed.
        
        Returns:
            TDXKeyPair: The client's keypair
        """
        if self._keypair:
            return self._keypair
        
        if self.keys.get("client_privkey"):
            self._keypair = self._load_keypair_from_keys()
            return self._keypair
        
        # Generate new keypair
        return self.generate_keypair()
    
    @property
    def client_pubkey(self):
        """Get client public key as base64 (generating keypair if needed)."""
        return self.keypair.public_key_base64()
    
    @property
    def client_pubkey_bytes(self):
        """Get client public key as raw DER bytes."""
        return base64.b64decode(self.keys.get("client_pubkey", ""))
    
    @property
    def client_pubkey_hash(self):
        """Get SHA256 hash of client public key."""
        return hashlib.sha256(self.client_pubkey_bytes).digest()
    
    # =========================================================================
    # Session Management
    # =========================================================================
    
    def has_session(self, server_url):
        """Check if a valid session exists for the given server."""
        return server_url in self.keys.get("sessions", {})
    
    def get_session(self, server_url):
        """
        Get session info for a server.
        
        Args:
            server_url: The TDX API server URL
            
        Returns:
            dict: Session info with session_id, session_key, etc. or None
        """
        session = self.keys.get("sessions", {}).get(server_url)
        if session:
            # Decode session key from base64
            session = dict(session)
            if session.get("session_key"):
                session["session_key"] = base64.b64decode(session["session_key"])
        return session
    
    def get_session_key(self, server_url):
        """
        Get the session key for a server.
        
        Args:
            server_url: The TDX API server URL
            
        Returns:
            bytes: 32-byte session key or None
        """
        session = self.get_session(server_url)
        return session.get("session_key") if session else None
    
    def save_session(self, server_url, session_id, session_key, attestation_token=None, **extra):
        """
        Save session info for a server.
        
        Args:
            server_url: The TDX API server URL
            session_id: Session ID from server
            session_key: 32-byte derived session key
            attestation_token: JWT attestation token (optional)
            **extra: Additional fields to store
        """
        if "sessions" not in self.keys:
            self.keys["sessions"] = {}
        
        self.keys["sessions"][server_url] = {
            "session_id": session_id,
            "session_key": base64.b64encode(session_key).decode("ascii"),
            "created_at": int(time.time()),
            "attestation_token": attestation_token,
            **extra
        }
        
        self._save_identity()
        self.p("Saved session for:", server_url)
    
    def delete_session(self, server_url):
        """Delete session info for a server."""
        if server_url in self.keys.get("sessions", {}):
            del self.keys["sessions"][server_url]
            self._save_identity()
            self.p("Deleted session for:", server_url)
    
    def clear_sessions(self):
        """Delete all sessions."""
        self.keys["sessions"] = {}
        self._save_identity()
        self.p("Cleared all sessions")
    
    # =========================================================================
    # Identity File Management
    # =========================================================================
    
    def _save_identity(self):
        """Save identity to JSON file."""
        # Create directory if needed
        os.makedirs(os.path.dirname(self.identity_path) or ".", exist_ok=True)
        
        with open(self.identity_path, 'w') as f:
            json.dump(self.keys, f, indent=2)
    
    def export_identity(self, include_private=False):
        """
        Export identity as JSON string.
        
        Args:
            include_private: Include private key (default False for safety)
            
        Returns:
            str: JSON string
        """
        export = dict(self.keys)
        if not include_private:
            export.pop("client_privkey", None)
        return json.dumps(export, indent=2)
    
    @classmethod
    def from_json(cls, json_str, identity_path=None, verbose=False):
        """
        Create key manager from JSON string.
        
        Args:
            json_str: JSON identity string
            identity_path: Path to save identity file
            verbose: Enable debug logging
            
        Returns:
            TDXKeyManager: Initialized key manager
        """
        manager = cls(identity_path=identity_path, verbose=verbose)
        manager.keys = json.loads(json_str)
        manager._save_identity()
        return manager
    
    def key_exists(self, which):
        """Check if a key exists (for compatibility with SGX key manager interface)."""
        if which == "client_cert":
            return bool(self.keys.get("client_pubkey"))
        elif which == "client_key":
            return bool(self.keys.get("client_privkey"))
        elif which == "master_key":
            # TDX doesn't have a single master key, it has session keys per server
            return False
        return False


class TDXFileKeyManager(TDXKeyManager):
    """
    TDX key manager that stores keys in separate files (like SGX FileKeyManager).
    
    Files:
    - {base}.pub: Public key (DER, base64)
    - {base}.key: Private key (DER PKCS8, base64)
    - {base}.sessions.json: Session data
    """
    
    def __init__(self, key_path=None, verbose=False):
        """
        Initialize file-based TDX key manager.
        
        Args:
            key_path: Base path for key files (without extension)
            verbose: Enable debug logging
        """
        self.verbose = verbose
        
        if not key_path:
            key_path = os.path.join(os.path.expanduser("~"), "tdx_identity")
        
        self.key_path = key_path
        self.pubkey_path = key_path + ".pub"
        self.privkey_path = key_path + ".key"
        self.sessions_path = key_path + ".sessions.json"
        
        # Load existing keys
        self.keys = dict(self.empty_identity)
        self._load_from_files()
        
        self._keypair = None
    
    def _load_from_files(self):
        """Load keys from separate files."""
        if os.path.exists(self.pubkey_path):
            with open(self.pubkey_path, 'r') as f:
                self.keys["client_pubkey"] = f.read().strip()
        
        if os.path.exists(self.privkey_path):
            with open(self.privkey_path, 'r') as f:
                self.keys["client_privkey"] = f.read().strip()
        
        if os.path.exists(self.sessions_path):
            with open(self.sessions_path, 'r') as f:
                self.keys["sessions"] = json.load(f)
    
    def _save_identity(self):
        """Save keys to separate files."""
        if self.keys.get("client_pubkey"):
            with open(self.pubkey_path, 'w') as f:
                f.write(self.keys["client_pubkey"])
        
        if self.keys.get("client_privkey"):
            with open(self.privkey_path, 'w') as f:
                f.write(self.keys["client_privkey"])
            # Set restrictive permissions on private key
            os.chmod(self.privkey_path, 0o600)
        
        with open(self.sessions_path, 'w') as f:
            json.dump(self.keys.get("sessions", {}), f, indent=2)
    
    @property
    def identity_path(self):
        """For compatibility."""
        return self.key_path
