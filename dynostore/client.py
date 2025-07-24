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
        session: requests.Session = None
    ) -> bytes:
        get = requests.get if session is None else session.get
        # print(key, type(key), sep=" - ")
        response = get(
            f'http://{self.metadata_server}/storage/{self.token_data["user_token"]}/{key}'
        )

        if response.status_code == 404:
            raise requests.exceptions.RequestException(
                f'DynoStore returned HTTP error code {response.status_code}. '
                f'{response.text}',
                response=response,
            )

        if response.status_code == 200:

            data = bytearray()
            for chunk in response.iter_content(chunk_size=None):
                data += chunk
            
            # Decrypt the data if it was encrypted
            if response.headers.get('is_encrypted', '0') == '1':
                data = self.object_encrypter.decrypt(data)

            # Uncompress the data
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
        
    def get_files_in_catalog(
            self,
            catalog: str,
            output_dir: str = None,
            session: requests.Session = None
    ) -> list:
        # First get the medata of the catalog
        get = requests.get if session is None else session.get
        response = get(
            f'http://{self.metadata_server}/pubsub/{self.token_data["user_token"]}/catalog/{catalog}'
        )

        if response.status_code == 404:
            raise requests.exceptions.RequestException(
                f'DynoStore returned HTTP error code {response.status_code}. '
                f'{response.text}',
                response=response,
            )
        

        if response.status_code == 200:
            catalog_info = response.json()["data"]
            catalog_key = catalog_info["tokencatalog"]
            
            # Now get the files in the catalog
            response = get(
                f'http://{self.metadata_server}/pubsub/{self.token_data["user_token"]}/catalog/{catalog_key}/list'
            )

            if response.status_code == 404:
                raise requests.exceptions.RequestException(
                    f'DynoStore returned HTTP error code {response.status_code}. '
                    f'{response.text}',
                    response=response,
                )
            if response.status_code == 201:
                files = response.json()["data"]

                os.makedirs(output_dir, exist_ok=True) 
                
                # Now iterate over the files and download them
                for f in files:
                    print("Getting file:", f["token_file"])
                    key = f["token_file"]
                    # Get the metadata of the file
                    metadata = self.get_metadata(key, session=session)

                    # Get the data of the file
                    data = self.get(key, session=session)

                    # Write the data to the output dir
                    output_path = os.path.join(output_dir, metadata["name"])
                    with open(output_path, "wb") as f:
                        f.write(data)

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
        data_encrypted = self.object_encrypter.encrypt(data_compressed) if is_encrypted else data_compressed
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

    