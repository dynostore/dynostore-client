import pytest
import zlib
from dynostore.nfrs.compress import ObjectCompressor
from dynostore.nfrs.cipher import SecureObjectStore

def test_object_compressor_roundtrip():
    compressor = ObjectCompressor()
    obj = {"test": "data", "number": 123}
    
    compressed = compressor.compress(obj)
    assert isinstance(compressed, bytes)
    assert len(compressed) > 0
    
    decompressed = compressor.decompress(compressed)
    assert decompressed == obj

def test_object_compressor_decompress_failure():
    compressor = ObjectCompressor()
    # Invalid zlib data
    decompressed = compressor.decompress(b'not compressed data')
    assert decompressed is None

def test_secure_object_store_bytes_roundtrip():
    store = SecureObjectStore("a_very_secure_password_123")
    original = b"hello world this is some secret data"
    aad = b"my_aad"
    
    encrypted = store.encrypt_bytes(original, aad=aad)
    assert isinstance(encrypted, bytes)
    assert encrypted != original
    
    decrypted = store.decrypt_bytes(encrypted, aad=aad)
    assert decrypted == original

def test_secure_object_store_obj_roundtrip():
    store = SecureObjectStore("another_very_secure_password_123")
    obj = {"key": "value", "list": [1, 2, 3]}
    
    encrypted = store.encrypt_obj(obj)
    assert isinstance(encrypted, bytes)
    
    decrypted = store.decrypt_obj(encrypted)
    assert decrypted == obj

def test_secure_object_store_short_password():
    with pytest.raises(ValueError, match="Password too short"):
        SecureObjectStore("short")

def test_secure_object_store_invalid_header():
    store = SecureObjectStore("a_very_secure_password_123")
    with pytest.raises(ValueError, match="Ciphertext too short"):
        store.decrypt_bytes(b"short")

    # Tamper with magic
    valid_ct = store.encrypt_bytes(b"data")
    tampered_ct = b"XXX" + valid_ct[3:]
    with pytest.raises(ValueError, match="Invalid magic"):
        store.decrypt_bytes(tampered_ct)
