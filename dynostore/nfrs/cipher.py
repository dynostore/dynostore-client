import os
import pickle
import struct
import unicodedata
import cloudpickle

from typing import Optional, Tuple
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes

# Header format (big-endian):
# MAGIC(3) | VER(1) | KDF(1='P') | salt_len(1) | nonce_len(1) | pbkdf2_iters(>0, uint32) | salt | nonce | ciphertext
MAGIC = b"DS1"
VER = 1
KDF_ID_PBKDF2 = b"P"
HEADER_STRUCT = "!3sccccI"   # MAGIC(3s), VER(1c), KDF(1c), salt_len(1c), nonce_len(1c), iters(uint32)

class SecureObjectStore:
    def __init__(self, password: str, *, pbkdf2_iters: int = 600_000, salt_len: int = 16, nonce_len: int = 12):
        # Normalize password for portability across machines and keyboard layouts
        pwd = unicodedata.normalize("NFKC", password).encode("utf-8")
        if len(pwd) < 12:
            raise ValueError("Password too short; require at least 12 characters.")
        self._password = pwd
        self._pbkdf2_iters = int(pbkdf2_iters)
        self._salt_len = int(salt_len)
        self._nonce_len = int(nonce_len)

    # -------- public API: bytes ----------
    def encrypt_bytes(self, data: bytes, *, aad: Optional[bytes] = None) -> bytes:
        salt = os.urandom(self._salt_len)
        nonce = os.urandom(self._nonce_len)
        key = self._derive_key_p2(salt, self._pbkdf2_iters)
        ct = AESGCM(key).encrypt(nonce, data, aad)

        header = struct.pack(
            HEADER_STRUCT,
            MAGIC,
            bytes([VER]),
            KDF_ID_PBKDF2,
            bytes([self._salt_len]),
            bytes([self._nonce_len]),
            self._pbkdf2_iters,
        )
        return header + salt + nonce + ct

    def decrypt_bytes(self, blob: bytes, *, aad: Optional[bytes] = None) -> bytes:
        salt, nonce, iters, offset = self._parse_header(blob)
        key = self._derive_key_p2(bytes(salt), iters)
        return AESGCM(key).decrypt(nonce, blob[offset:], aad)

    # -------- public API: Python objects (⚠ untrusted data = unsafe) ----------
    def encrypt_obj(self, obj, *, aad: Optional[bytes] = None) -> bytes:
        return self.encrypt_bytes(cloudpickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL), aad=aad)

    def decrypt_obj(self, blob: bytes, *, aad: Optional[bytes] = None):
        return cloudpickle.loads(self.decrypt_bytes(blob, aad=aad))

    # -------- internals ----------
    def _derive_key_p2(self, salt: bytes, iters: int) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iters,
        )
        return kdf.derive(self._password)

    def _parse_header(self, blob: bytes) -> Tuple[bytes, bytes, int, int]:
        if len(blob) < struct.calcsize(HEADER_STRUCT):
            raise ValueError("Ciphertext too short")
        magic, ver, kdf_id, salt_len_b, nonce_len_b, iters = struct.unpack(
            HEADER_STRUCT, blob[: struct.calcsize(HEADER_STRUCT)]
        )
        if magic != MAGIC:
            raise ValueError("Invalid magic")
        if ver != bytes([VER]):
            raise ValueError(f"Unsupported version: {ver!r}")
        if kdf_id != KDF_ID_PBKDF2:
            raise ValueError(f"Unsupported KDF id: {kdf_id!r}")
        salt_len = salt_len_b[0]
        nonce_len = nonce_len_b[0]

        pos = struct.calcsize(HEADER_STRUCT)
        end_salt = pos + salt_len
        end_nonce = end_salt + nonce_len
        if end_nonce > len(blob):
            raise ValueError("Truncated header")
        salt = blob[pos:end_salt]
        nonce = blob[end_salt:end_nonce]
        return salt, nonce, iters, end_nonce


if __name__ == "__main__":
    # Example 1: encrypt/decrypt BYTES
    store = SecureObjectStore("my_secret_password")

    with open("../../1MB", "rb") as f:
        original_bytes = f.read()
    ct = store.encrypt_bytes(original_bytes, aad=b"object-id:1MB")  # optional AAD binds context
    pt = store.decrypt_bytes(ct, aad=b"object-id:1MB")
    assert pt == original_bytes
    print("Bytes round-trip OK:", len(ct), "bytes (ciphertext)")

    # Example 2: encrypt/decrypt a PYTHON OBJECT (⚠ only if both ends are trusted)
    original_obj = {"key": "value", "number": 42}
    ct2 = store.encrypt_obj(original_obj)
    obj2 = store.decrypt_obj(ct2)
    assert obj2 == original_obj
    print("Object round-trip OK")
