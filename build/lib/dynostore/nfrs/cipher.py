import os
import pickle
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class SecureObjectStore:
    def __init__(self, password: str):
        self.password = password.encode()
        self.backend = default_backend()

    def _derive_key(self, salt: bytes) -> bytes:
        """Derives a 256-bit AES key from the password and given salt using PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256
            salt=salt,
            iterations=100_000,
            backend=self.backend
        )
        return kdf.derive(self.password)

    def encrypt(self, obj) -> bytes:
        """Encrypt a Python object using AES-256-GCM, embedding salt and IV in the payload."""
        data = pickle.dumps(obj)
        salt = os.urandom(16)  # Random salt for KDF
        iv = os.urandom(12)    # Recommended IV size for GCM
        key = self._derive_key(salt)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(iv, data, None)
        return salt + iv + ciphertext  # Embed salt and IV in output

    def decrypt(self, encrypted_data: bytes):
        """Decrypt the AES-256-GCM encrypted object by extracting salt and IV from payload."""
        print(f"[DEBUG] Type of encrypted_data: {type(encrypted_data)}")
        print(len(encrypted_data))
        encrypted_data = bytes(encrypted_data)
        salt = encrypted_data[:16]
        iv = encrypted_data[16:28]
        ciphertext = encrypted_data[28:]
        key = self._derive_key(salt)
        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(iv, ciphertext, None)
        return pickle.loads(decrypted)


if __name__ == "__main__":
    # Example usage
    store = SecureObjectStore("my_secret_password")
    
    # Encrypt an object
    original_data = {"key": "value", "number": 42}
    with open("../../1MB", "rb") as f:
        #pickle.dump(original_data, f)
        encrypted_data = store.encrypt(f.read())
        print("Encrypted data:", encrypted_data)
        print("Encrypted data size:", len(encrypted_data))
        # Decrypt the object
        decrypted_data = store.decrypt(encrypted_data)
        print("Decrypted data:", decrypted_data)
        
        assert original_data == decrypted_data, "Decryption failed!"