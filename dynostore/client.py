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
        print(self.metadata_server)
        authenticator = DeviceAuthenticator(auth_url=self.metadata_server)
        authenticator.authenticate()
        self.token_data = authenticator.token_data
        print(self.token_data, flush=True)

    def evict(
        self,
        key: str,
        session: requests.Session = None
    ) -> None:
        delete_ = requests.delete if session is None else session.delete
        response = delete_(
            f'http://{self.metadata_server}/storage/{self.token_data["user_token"]}/{key}'
        )

        if not response.ok:
            raise requests.exceptions.RequestException(
                f'Server returned HTTP error code {response.status_code}. '
                f'{response.text}',
                response=response,
            )

    def exists(
        self,
        key: str,
        session: requests.Session = None
    ) -> bool:

        get_ = requests.get if session is None else session.get
        response = get_(
            f'http://{self.metadata_server}/storage/{self.token_data["user_token"]}/{key}/exists'
        )
        if not response.ok:
            raise requests.exceptions.RequestException(
                f'Server returned HTTP error code {response.status_code}. '
                f'{response.text}',
                response=response,
            )

        return response.json()["exists"]

    def get(
        self,
        key: str,
        session: requests.Session = None,
        retries: int = 3
    ) -> bytes:
        get_method = requests.get if session is None else session.get
        url = f'http://{self.metadata_server}/storage/{self.token_data["user_token"]}/{key}'

        response = Client._retry_request(
            get_method,
            url,
            retries=retries,
            retry_codes=(404,),
            expected_code=200,
            stream=True
        )

        # Read content in chunks
        data = bytearray()
        for chunk in response.iter_content(chunk_size=None):
            data += chunk

        # Decrypt if needed
        if response.headers.get('is_encrypted', '0') == '1':
            data = self.object_encrypter.decrypt(data)

        # Uncompress
        data = self.object_compressor.decompress(data)

        return bytes(data)

    def get_metadata(
        self,
        key: str,
        session: requests.Session = None
    ) -> dict:

        get_ = requests.get if session is None else session.get
        response = get_(
            f'http://{self.metadata_server}/storage/{self.token_data["user_token"]}/{key}/exists'
        )
        if not response.ok:
            raise requests.exceptions.RequestException(
                f'Server returned HTTP error code {response.status_code}. '
                f'{response.text}',
                response=response,
            )

        return response.json()["metadata"]

    def _retry_request(get, url, retries=5, retry_codes=(404,), expected_code=200, stream=False):
        for i in range(retries):
            try:
                response = get(url, stream=stream)
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


    def get_files_in_catalog(self, catalog: str, output_dir: str = None, session: requests.Session = None, retries: int = 3) -> list:
        get = requests.get if session is None else session.get

        # Step 1: Get catalog metadata
        catalog_url = f'http://{self.metadata_server}/pubsub/{self.token_data["user_token"]}/catalog/{catalog}'
        response = Client._retry_request(get, catalog_url, retries=retries)
        catalog_info = response.json()["data"]
        catalog_key = catalog_info["tokencatalog"]

        # Step 2: Get file list
        list_url = f'http://{self.metadata_server}/pubsub/{self.token_data["user_token"]}/catalog/{catalog_key}/list'
        response = Client._retry_request(get, list_url, retries=retries, expected_code=201)
        files = response.json()["data"]

        # Step 3: Download files
        os.makedirs(output_dir, exist_ok=True)
        for f in files:
            print("Getting file:", f["token_file"])
            key = f["token_file"]
            metadata = self.get_metadata(key, session=session)
            data = self.get(key, session=session)
            output_path = os.path.join(output_dir, metadata["name"])
            with open(output_path, "wb") as file_out:
                file_out.write(data)

    def put(
        self,
        data: bytes,
        catalog: str,
        key: str = str(uuid.uuid4()),
        name: str = None,
        session: requests.Session = None,
        is_encrypted: bool = False,
        resiliency: int = 1,
        nodes=None
    ) -> None:
        start_time = time.perf_counter_ns()
        data_hash = hashlib.sha3_256(data).hexdigest()
        name = data_hash if name is None else name
        key = str(uuid.uuid4())

        put = requests.put if session is None else session.put
        data_compressed = self.object_compressor.compress(data)
        data_encrypted = self.object_encrypter.encrypt(
            data_compressed) if is_encrypted else data_compressed
        print(key)
        fake_file = io.BytesIO(data_encrypted)

        payload = {"name": name, "size": len(data_compressed), "hash": data_hash, "key": key,
                   "is_encrypted": int(is_encrypted), "resiliency": resiliency,
                   "nodes": nodes}
        files = [
            ('json', ('payload.json', json.dumps(payload), 'application/json')),
            ('data', ('data.bin', fake_file, 'application/octet-stream'))
        ]
        response = put(
            f'http://{self.metadata_server}/storage/{self.token_data["user_token"]}/{catalog}/{key}', files=files)

        if response.status_code == 201:
            res = response.json()
        else:
            raise requests.exceptions.RequestException(
                f'Metadata server returned HTTP error code {response.status_code}. '
                f'{response.text}',
                response=response,
            )
        end = time.perf_counter_ns()
        return {
            "total_time": (end - start_time) / 1e6,
            "metadata_time": res["total_time"] / 1e6,
            "upload_time": res["time_upload"] / 1e6,
            "key_object": res["key_object"]

        }
