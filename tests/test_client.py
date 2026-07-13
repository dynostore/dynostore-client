import pytest
import os
import httpx
from dynostore.client import Client, CompressException, EncryptionException, DecompressException

@pytest.fixture
def mock_authenticator(mocker):
    # Mock DeviceAuthenticator so Client __init__ doesn't block or hit the network
    mocker.patch("dynostore.client.DeviceAuthenticator.authenticate")
    mocker.patch("dynostore.client.DeviceAuthenticator.token_data", new_callable=mocker.PropertyMock, return_value={"user_token": "test_user_token"}, create=True)

@pytest.fixture
def client(mock_authenticator):
    return Client(metadata_server="localhost:5000")

@pytest.mark.asyncio
async def test_client_evict(client, httpx_mock):
    key = "test_key"
    url = f"http://localhost:5000/storage/test_user_token/{key}"
    httpx_mock.add_response(method='DELETE', url=url, status_code=200)
    
    # Should not raise an exception
    await client.evict(key)

@pytest.mark.asyncio
async def test_client_exists(client, httpx_mock):
    key = "test_key"
    url = f"http://localhost:5000/storage/test_user_token/{key}/exists"
    
    httpx_mock.add_response(method='GET', url=url, json={"exists": True}, status_code=200)
    assert await client.exists(key) is True
    
    httpx_mock.add_response(method='GET', url=url, json={"exists": False}, status_code=200)
    assert await client.exists(key) is False

@pytest.mark.asyncio
async def test_client_get(client, httpx_mock, mocker):
    key = "test_key"
    url = f"http://localhost:5000/storage/test_user_token/{key}"
    
    # Mock unencrypted data (it will go through decompression)
    # We mock decompression to just return what it gets for simplicity
    mocker.patch.object(client.object_compressor, "decompress", return_value=b"dec_data")
    
    httpx_mock.add_response(method='GET', url=url, content=b"comp_data", headers={"is_encrypted": "False"}, status_code=200)
    
    data = await client.get(key)
    assert data == b"dec_data"

@pytest.mark.asyncio
async def test_client_get_encrypted(client, httpx_mock, mocker):
    key = "test_key"
    url = f"http://localhost:5000/storage/test_user_token/{key}"
    
    mocker.patch.object(client.object_encrypter, "decrypt_bytes", return_value=b"decrypted_data")
    mocker.patch.object(client.object_compressor, "decompress", return_value=b"decompressed_data")
    
    httpx_mock.add_response(method='GET', url=url, content=b"enc_data", headers={"is_encrypted": "True"}, status_code=200)
    
    data = await client.get(key)
    assert data == b"decompressed_data"
    client.object_encrypter.decrypt_bytes.assert_called_once_with(b"enc_data")

@pytest.mark.asyncio
async def test_client_get_metadata(client, httpx_mock):
    key = "test_key"
    url = f"http://localhost:5000/storage/test_user_token/{key}/exists"
    
    httpx_mock.add_response(method='GET', url=url, json={"metadata": {"name": "test.txt", "size": 100}}, status_code=200)
    meta = await client.get_metadata(key)
    assert meta == {"name": "test.txt", "size": 100}

@pytest.mark.asyncio
async def test_client_get_files_in_catalog(client, httpx_mock, tmp_path, mocker):
    catalog = "my_catalog"
    catalog_url = f"http://localhost:5000/pubsub/test_user_token/catalog/{catalog}"
    httpx_mock.add_response(method='GET', url=catalog_url, json={"data": {"tokencatalog": "cat_key"}}, status_code=200)
    
    list_url = f"http://localhost:5000/pubsub/test_user_token/catalog/cat_key/list"
    httpx_mock.add_response(method='GET', url=list_url, json={"data": [{"token_file": "file1"}, {"token_file": "file2"}]}, status_code=201)
    
    mocker.patch.object(client, "get_metadata", return_value={"name": "test1.txt"})
    mocker.patch.object(client, "get", return_value=b"data")
    
    output_dir = str(tmp_path / "out")
    paths = await client.get_files_in_catalog(catalog, output_dir=output_dir)
    
    assert len(paths) == 2
    assert os.path.exists(paths[0])
    assert os.path.exists(paths[1])

@pytest.mark.asyncio
async def test_client_put(client, httpx_mock, mocker):
    key = "test_key"
    catalog = "my_catalog"
    data = b"my_data"
    
    mocker.patch.object(client.object_compressor, "compress", return_value=b"compressed")
    mocker.patch.object(client.object_encrypter, "encrypt_bytes", return_value=b"encrypted")
    
    metadata_url = f"http://localhost:5000/metadata/test_user_token/{key}"
    httpx_mock.add_response(method='POST', url=metadata_url, status_code=200)
    
    upload_url = f"http://localhost:5000/upload/test_user_token/{catalog}/{key}"
    httpx_mock.add_response(method='PUT', url=upload_url, json={"time_metadata_ms": 10, "time_upload": 2000000}, status_code=201)
    
    res = await client.put(data=data, catalog=catalog, key=key, is_encrypted=True)
    assert res is not None
    assert res["key_object"] == key
    assert res["metadata_time"] == 10
    assert res["upload_time"] == 2.0
