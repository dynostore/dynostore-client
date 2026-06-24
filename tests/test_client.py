import pytest
import os
import requests
from dynostore.client import Client, CompressException, EncryptionException, DecompressException

@pytest.fixture
def mock_authenticator(mocker):
    # Mock DeviceAuthenticator so Client __init__ doesn't block or hit the network
    mocker.patch("dynostore.client.DeviceAuthenticator.authenticate")
    mocker.patch("dynostore.client.DeviceAuthenticator.token_data", new_callable=mocker.PropertyMock, return_value={"user_token": "test_user_token"}, create=True)

@pytest.fixture
def client(mock_authenticator):
    return Client(metadata_server="localhost:5000")

def test_client_evict(client, requests_mock):
    key = "test_key"
    url = f"http://localhost:5000/storage/test_user_token/{key}"
    requests_mock.delete(url, status_code=200)
    
    # Should not raise an exception
    client.evict(key)

def test_client_exists(client, requests_mock):
    key = "test_key"
    url = f"http://localhost:5000/storage/test_user_token/{key}/exists"
    
    requests_mock.get(url, json={"exists": True}, status_code=200)
    assert client.exists(key) is True
    
    requests_mock.get(url, json={"exists": False}, status_code=200)
    assert client.exists(key) is False

def test_client_get(client, requests_mock, mocker):
    key = "test_key"
    url = f"http://localhost:5000/storage/test_user_token/{key}"
    
    # Mock unencrypted data (it will go through decompression)
    # We mock decompression to just return what it gets for simplicity
    mocker.patch.object(client.object_compressor, "decompress", return_value=b"dec_data")
    
    requests_mock.get(url, content=b"comp_data", headers={"is_encrypted": "False"}, status_code=200)
    
    data = client.get(key)
    assert data == b"dec_data"

def test_client_get_encrypted(client, requests_mock, mocker):
    key = "test_key"
    url = f"http://localhost:5000/storage/test_user_token/{key}"
    
    mocker.patch.object(client.object_encrypter, "decrypt_bytes", return_value=b"decrypted_data")
    mocker.patch.object(client.object_compressor, "decompress", return_value=b"decompressed_data")
    
    requests_mock.get(url, content=b"enc_data", headers={"is_encrypted": "True"}, status_code=200)
    
    data = client.get(key)
    assert data == b"decompressed_data"
    client.object_encrypter.decrypt_bytes.assert_called_once_with(b"enc_data")

def test_client_get_metadata(client, requests_mock):
    key = "test_key"
    url = f"http://localhost:5000/storage/test_user_token/{key}/exists"
    
    requests_mock.get(url, json={"metadata": {"name": "test.txt", "size": 100}}, status_code=200)
    meta = client.get_metadata(key)
    assert meta == {"name": "test.txt", "size": 100}

def test_client_get_files_in_catalog(client, requests_mock, tmp_path, mocker):
    catalog = "my_catalog"
    catalog_url = f"http://localhost:5000/pubsub/test_user_token/catalog/{catalog}"
    requests_mock.get(catalog_url, json={"data": {"tokencatalog": "cat_key"}}, status_code=200)
    
    list_url = f"http://localhost:5000/pubsub/test_user_token/catalog/cat_key/list"
    requests_mock.get(list_url, json={"data": [{"token_file": "file1"}, {"token_file": "file2"}]}, status_code=201)
    
    mocker.patch.object(client, "get_metadata", return_value={"name": "test1.txt"})
    mocker.patch.object(client, "get", return_value=b"data")
    
    output_dir = str(tmp_path / "out")
    paths = client.get_files_in_catalog(catalog, output_dir=output_dir)
    
    assert len(paths) == 2
    assert os.path.exists(paths[0])
    assert os.path.exists(paths[1])

def test_client_put(client, requests_mock, mocker):
    key = "test_key"
    catalog = "my_catalog"
    data = b"my_data"
    
    mocker.patch.object(client.object_compressor, "compress", return_value=b"compressed")
    mocker.patch.object(client.object_encrypter, "encrypt_bytes", return_value=b"encrypted")
    
    metadata_url = f"http://localhost:5000/metadata/test_user_token/{key}"
    requests_mock.post(metadata_url, status_code=200)
    
    upload_url = f"http://localhost:5000/upload/test_user_token/{catalog}/{key}"
    requests_mock.put(upload_url, json={"time_metadata_ms": 10, "time_upload": 2000000}, status_code=201)
    
    res = client.put(data=data, catalog=catalog, key=key, is_encrypted=True)
    assert res is not None
    assert res["key_object"] == key
    assert res["metadata_time"] == 10
    assert res["upload_time"] == 2.0
