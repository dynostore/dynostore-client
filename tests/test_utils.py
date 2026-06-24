import pytest
from dynostore.utils.data import chunk_bytes, bytes_to_readable, readable_to_bytes

def test_chunk_bytes():
    data = b"1234567890"
    chunks = list(chunk_bytes(data, 3))
    assert len(chunks) == 4
    assert chunks[0] == b"123"
    assert chunks[1] == b"456"
    assert chunks[2] == b"789"
    assert chunks[3] == b"0"

    chunks = list(chunk_bytes(b"", 5))
    assert len(chunks) == 0

    chunks = list(chunk_bytes(data, 20))
    assert len(chunks) == 1
    assert chunks[0] == data

def test_bytes_to_readable():
    assert bytes_to_readable(500) == "500 B"
    assert bytes_to_readable(1024) == "1.024 KB"
    assert bytes_to_readable(1500000) == "1.5 MB"
    assert bytes_to_readable(2000000000) == "2 GB"
    assert bytes_to_readable(3500000000000) == "3.5 TB"
    
    with pytest.raises(ValueError, match="Size \\(-1\\) cannot be negative."):
        bytes_to_readable(-1)

def test_readable_to_bytes():
    assert readable_to_bytes("500") == 500
    assert readable_to_bytes("1 KB") == 1000
    assert readable_to_bytes("1.5 MB") == 1500000
    assert readable_to_bytes("2 GB") == 2000000000
    assert readable_to_bytes("1 KiB") == 1024
    assert readable_to_bytes("1 MiB") == 1048576

    with pytest.raises(ValueError, match="must contain only a value and a unit"):
        readable_to_bytes("1 KB MB")
    
    with pytest.raises(ValueError, match="Unable to interpret"):
        readable_to_bytes("abc KB")

    with pytest.raises(ValueError, match="Unknown unit type"):
        readable_to_bytes("1 ZZ")
