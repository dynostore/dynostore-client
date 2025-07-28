import requests
import uuid
import time
import hashlib
import io
import os
import json
from dynostore.nfrs.compress import ObjectCompressor
from dynostore.nfrs.cipher import SecureObjectStore
from dynostore.auth.authenticate import DeviceAuthenticator


class Client(object):

    def __init__(self, metadata_server):
        self.metadata_server = metadata_server
        self.object_compressor = ObjectCompressor()
        self.object_encrypter = SecureObjectStore("aaaa")
        authenticator = DeviceAuthenticator(auth_url=self.metadata_server)
        authenticator.authenticate()
        self.token_data = authenticator.token_data

    def evict(self, key: str, session: requests.Session = None, retries: int = 5) -> None:
        url = f'http://{self.metadata_server}/storage/{self.token_data["user_token"]}/{key}'
        method = (session or requests).delete
        response = Client._retry_request(method, url, retries=retries, expected_code=200)
        return

    def exists(self, key: str, session: requests.Session = None, retries: int = 5) -> bool:
        url = f'http://{self.metadata_server}/storage/{self.token_data["user_token"]}/{key}/exists'
        method = (session or requests).get
        response = Client._retry_request(method, url, retries=retries, expected_code=200)
        return response.json()["exists"]

    def get(self, key: str, session: requests.Session = None, retries: int = 5) -> bytes:
        url = f'http://{self.metadata_server}/storage/{self.token_data["user_token"]}/{key}'
        method = (session or requests).get
        response = Client._retry_request(method, url, retries=retries, retry_codes=(404,), expected_code=200, stream=True)

        data = bytearray()
        for chunk in response.iter_content(chunk_size=None):
            data += chunk

        if response.headers.get('is_encrypted', '0') == '1':
            data = self.object_encrypter.decrypt(data)

        data = self.object_compressor.decompress(data)
        return bytes(data)

    def get_metadata(self, key: str, session: requests.Session = None, retries: int = 5) -> dict:
        url = f'http://{self.metadata_server}/storage/{self.token_data["user_token"]}/{key}/exists'
        method = (session or requests).get
        response = Client._retry_request(method, url, retries=retries, expected_code=200)
        return response.json()["metadata"]

    def get_files_in_catalog(self, catalog: str, output_dir: str = None, session: requests.Session = None, retries: int = 5) -> list:
        method = (session or requests).get
        catalog_url = f'http://{self.metadata_server}/pubsub/{self.token_data["user_token"]}/catalog/{catalog}'
        response = Client._retry_request(method, catalog_url, retries=retries)
        catalog_info = response.json()["data"]
        catalog_key = catalog_info["tokencatalog"]

        list_url = f'http://{self.metadata_server}/pubsub/{self.token_data["user_token"]}/catalog/{catalog_key}/list'
        response = Client._retry_request(method, list_url, retries=retries, expected_code=201)
        files = response.json()["data"]

        os.makedirs(output_dir, exist_ok=True)
        for f in files:
            print("Getting file:", f["token_file"])
            key = f["token_file"]
            metadata = self.get_metadata(key, session=session)
            data = self.get(key, session=session)
            output_path = os.path.join(output_dir, metadata["name"])
            with open(output_path, "wb") as file_out:
                file_out.write(data)

    def put(self,
            data: bytes,
            catalog: str,
            key: str = str(uuid.uuid4()),
            name: str = None,
            session: requests.Session = None,
            is_encrypted: bool = False,
            resiliency: int = 1,
            nodes=None,
            retries: int = 5):

        start_time = time.perf_counter_ns()
        data_hash = hashlib.sha3_256(data).hexdigest()
        name = data_hash if name is None else name
        key = str(uuid.uuid4())

        data_compressed = self.object_compressor.compress(data)
        data_encrypted = self.object_encrypter.encrypt(data_compressed) if is_encrypted else data_compressed
        fake_file = io.BytesIO(data_encrypted)

        payload = {
            "name": name, "size": len(data_compressed), "hash": data_hash, "key": key,
            "is_encrypted": int(is_encrypted), "resiliency": resiliency, "nodes": nodes
        }

        files = [
            ('json', ('payload.json', json.dumps(payload), 'application/json')),
            ('data', ('data.bin', fake_file, 'application/octet-stream'))
        ]

        url = f'http://{self.metadata_server}/storage/{self.token_data["user_token"]}/{catalog}/{key}'
        method = (session or requests).put
        response = Client._retry_request(method, url, retries=retries, expected_code=201, files=files)

        res = response.json()
        end = time.perf_counter_ns()
        return {
            "total_time": (end - start_time) / 1e6,
            "metadata_time": res["total_time"] / 1e6,
            "upload_time": res["time_upload"] / 1e6,
            "key_object": res["key_object"]
        }

    @staticmethod
    def _retry_request(method, url, retries=5, retry_codes=(404,), expected_code=200, stream=False, **kwargs):
        for i in range(retries):
            try:
                response = method(url, stream=stream, **kwargs)
                if response.status_code == expected_code:
                    return response
                elif response.status_code in retry_codes and i < retries - 1:
                    print(f"[Retry {i + 1}/{retries}] Retrying on status {response.status_code}: {url}")
                    time.sleep(2 ** i)
                else:
                    response.raise_for_status()
            except requests.exceptions.RequestException as e:
                if i < retries - 1:
                    print(f"[Retry {i + 1}/{retries}] Exception: {e}. Retrying {url}")
                    time.sleep(2 ** i)
                else:
                    raise e
        raise RuntimeError(f"Failed to get a valid response after {retries} retries: {url}")
