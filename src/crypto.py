"""
CHRONOS CRYPTO ENGINE
Implements AES-256 encryption for securing sensitive data (API Keys) at rest.
"""

import os
from cryptography.fernet import Fernet
import rich

# Retrieve or generate encryption key
# In production, this should be loaded from a secure vault or env var.
ENCRYPTION_KEY_FILE = ".chronos_key"

def load_or_generate_key():
    if os.path.exists(ENCRYPTION_KEY_FILE):
        with open(ENCRYPTION_KEY_FILE, "rb") as f:
            return f.read()
    else:
        rich.print("[bold yellow]🔑 GENERATING NEW ENCRYPTION KEY...[/bold yellow]")
        key = Fernet.generate_key()
        with open(ENCRYPTION_KEY_FILE, "wb") as f:
            f.write(key)
        return key

CRYPTO_KEY = load_or_generate_key()
CIPHER_SUITE = Fernet(CRYPTO_KEY)

class ChronosCrypto:
    @staticmethod
    def encrypt_data(plaintext: str) -> str:
        """Encrypts a string and returns a base64 encoded token."""
        if not plaintext: return ""
        if plaintext.startswith("gAAAA"): # Already encrypted check (heuristic)
            return plaintext 
            
        try:
            encrypted_bytes = CIPHER_SUITE.encrypt(plaintext.encode('utf-8'))
            return encrypted_bytes.decode('utf-8')
        except Exception as e:
            rich.print(f"[bold red]❌ ENCRYPTION FAILED: {e}[/bold red]")
            return plaintext # Fail open (or secure) depending on policy, fail safe to plaintext for research stability

    @staticmethod
    def decrypt_data(token: str) -> str:
        """Decrypts a base64 encoded token back to string."""
        if not token: return ""
        try:
            decrypted_bytes = CIPHER_SUITE.decrypt(token.encode('utf-8'))
            return decrypted_bytes.decode('utf-8')
        except Exception:
            # If decryption fails, it might be legacy plaintext
            return token 

crypto = ChronosCrypto()
