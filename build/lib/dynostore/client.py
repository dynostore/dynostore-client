import requests
import uuid
import time
import hashlib
import os
import logging
from math import ceil
from dynostore.nfrs.compress import ObjectCompressor
from dynostore.nfrs.cipher import SecureObjectStore
from dynostore.auth.authenticate import DeviceAuthenticator
from dynostore.utils.data import chunk_bytes
from dynostore.constants import MAX_CHUNK_LENGTH


class EncryptionException(Exception):
    pass


class DecompressException(Exception):
    pass


class CompressException(Exception):
    pass


class Client(object):

    def __init__(self, metadata_server):
        self.logger = logging.getLogger(__name__)
        self.logger.debug('CLIENT,INIT,START,metadata_server=%s', metadata_server)

        self.metadata_server = metadata_server
        self.object_compressor = ObjectCompressor()
        self.object_encrypter = SecureObjectStore("aaaa")

        self.logger.debug('CLIENT,INIT,AUTH,START,auth_url=%s', self.metadata_server)
        authenticator = DeviceAuthenticator(auth_url=self.metadata_server)
        authenticator.authenticate()
        self.token_data = authenticator.token_data
        self.logger.debug('CLIENT,INIT,AUTH,END,SUCCESS,user_token=%s', self.token_data.get("user_token", "NA"))
        self.logger.debug('CLIENT,INIT,END,SUCCESS')

    def evict(self, key: str, session: requests.Session = None, retries: int = 5) -> None:
        self.logger.debug('CLIENT,EVICT,%s,START', key)
        url = f'http://{self.metadata_server}/storage/{self.token_data["user_token"]}/{key}'
        method = (session or requests).delete
        try:
            response = Client._retry_request(method, url, retries=retries, expected_code=200)
            if response.ok:
                self.logger.debug('CLIENT,EVICT,%s,END,SUCCESS,msg=%s', key, response.text)
        except Exception as e:
            self.logger.error('CLIENT,EVICT,%s,ERROR,%s', key, e)
        return

    def exists(self, key: str, session: requests.Session = None, retries: int = 5) -> bool:
        self.logger.debug('CLIENT,EXISTS,%s,START', key)
        url = f'http://{self.metadata_server}/storage/{self.token_data["user_token"]}/{key}/exists'
        method = (session or requests).get
        try:
            response = Client._retry_request(method, url, retries=retries, expected_code=200)
            if response.ok:
                self.logger.debug('CLIENT,EXISTS,%s,END,SUCCESS,msg=%s', key, response.text)
            return response.json().get("exists", False)
        except Exception as e:
            self.logger.error('CLIENT,EXISTS,%s,ERROR,%s', key, e)
            return False

    def get(self, key: str, session: requests.Session = None, retries: int = 5) -> bytes:
        self.logger.debug('CLIENT,GET,%s,START', key)
        url = f'http://{self.metadata_server}/storage/{self.token_data["user_token"]}/{key}'
        method = (session or requests).get
        retransmit = True
        max_retries = 3

        while retransmit and max_retries > 0:
            try:
                response = Client._retry_request(
                    method, url, retries=retries, retry_codes=(404,), expected_code=200, stream=True
                )
            except Exception as e:
                self.logger.debug('CLIENT,GET,%s,END,ERROR,msg=%s,remaining_retries=%d', key, str(e), max_retries - 1)
                max_retries -= 1
                continue

            self.logger.debug('CLIENT,GET,%s,RESPONSE,SUCCESS,headers_is_encrypted=%s',
                              key, response.headers.get('is_encrypted', '0'))

            data = bytearray()
            start_recv = time.perf_counter_ns()
            for chunk in response.iter_content(chunk_size=None):
                data += chunk
            recv_time_ms = (time.perf_counter_ns() - start_recv) / 1e6

            self.logger.debug('CLIENT,GET,%s,RECEIVE,END,bytes=%d,time_ms=%.3f', key, len(data), recv_time_ms)

            if response.headers.get('is_encrypted', '0') == '1':
                try:
                    self.logger.debug('CLIENT,GET,%s,DECRYPT,START', key)
                    t0 = time.perf_counter_ns()
                    data = self.object_encrypter.decrypt(data)
                    t1 = time.perf_counter_ns()
                    self.logger.debug('CLIENT,GET,%s,DECRYPT,END,SUCCESS,time_ms=%.3f,bytes=%d',
                                      key, (t1 - t0) / 1e6, len(data))
                except Exception as e:
                    self.logger.debug('CLIENT,GET,%s,DECRYPT,END,ERROR,msg=%s', key, str(e))
                    raise EncryptionException(f'Decryption failed: {str(e)}')

            try:
                self.logger.debug('CLIENT,GET,%s,DECOMPRESS,START', key)
                t0 = time.perf_counter_ns()
                data = self.object_compressor.decompress(data)
                t1 = time.perf_counter_ns()
                self.logger.debug('CLIENT,GET,%s,DECOMPRESS,END,SUCCESS,time_ms=%.3f,bytes=%s',
                                  key, (t1 - t0) / 1e6, 'None' if data is None else len(data))
            except Exception as e:
                self.logger.debug('CLIENT,GET,%s,DECOMPRESS,END,ERROR,msg=%s', key, str(e))
                raise DecompressException(f'Decompression failed: {str(e)}')

            if data is None:
                self.logger.debug('CLIENT,GET,%s,END,ERROR,msg=Decompression returned None,retry', key)
                max_retries -= 1
                retransmit = True
            else:
                retransmit = False

        if retransmit:
            self.logger.debug('CLIENT,GET,%s,END,ERROR,msg=Max retries reached, aborting', key)
            return None

        self.logger.debug('CLIENT,GET,%s,END,SUCCESS,FINAL_BYTES=%d', key, len(data))
        return bytes(data)

    def get_metadata(self, key: str, session: requests.Session = None, retries: int = 5) -> dict:
        self.logger.debug('CLIENT,GET_METADATA,%s,START', key)
        url = f'http://{self.metadata_server}/storage/{self.token_data["user_token"]}/{key}/exists'
        method = (session or requests).get
        try:
            response = Client._retry_request(method, url, retries=retries, expected_code=200)
            meta = response.json().get("metadata", {})
            self.logger.debug('CLIENT,GET_METADATA,%s,END,SUCCESS,metadata_keys=%s', key, list(meta.keys()))
            return meta
        except Exception as e:
            self.logger.error('CLIENT,GET_METADATA,%s,ERROR,%s', key, e)
            return {}

    def get_files_in_catalog(self, catalog: str, output_dir: str = None,
                             session: requests.Session = None, retries: int = 5) -> list:
        self.logger.debug('CLIENT,LIST_CATALOG,%s,START,output_dir=%s', catalog, output_dir)
        method = (session or requests).get
        catalog_url = f'http://{self.metadata_server}/pubsub/{self.token_data["user_token"]}/catalog/{catalog}'
        try:
            response = Client._retry_request(method, catalog_url, retries=retries, expected_code=200)
        except Exception as e:
            self.logger.error('CLIENT,LIST_CATALOG,%s,ERROR,lookup_failed,%s', catalog, e)
            return []

        catalog_info = response.json().get("data", {})
        catalog_key = catalog_info.get("tokencatalog")
        self.logger.debug('CLIENT,LIST_CATALOG,%s,TOKEN,%s', catalog, catalog_key)

        list_url = f'http://{self.metadata_server}/pubsub/{self.token_data["user_token"]}/catalog/{catalog_key}/list'
        try:
            response = Client._retry_request(method, list_url, retries=retries, expected_code=201)
        except Exception as e:
            self.logger.error('CLIENT,LIST_CATALOG,%s,ERROR,list_failed,%s', catalog, e)
            return []

        files = response.json().get("data", [])
        self.logger.debug('CLIENT,LIST_CATALOG,%s,FILES_FOUND,count=%d', catalog, len(files))

        i = 0
        while not files and i < 10:
            self.logger.debug('CLIENT,LIST_CATALOG,%s,FILES_EMPTY,RETRY,%d', catalog, i + 1)
            try:
                response = Client._retry_request(method, list_url, retries=retries, expected_code=201)
                files = response.json().get("data", [])
            except Exception as e:
                self.logger.error('CLIENT,LIST_CATALOG,%s,RETRY_ERROR,%s', catalog, e)
                break
            i += 1

        self.logger.debug('CLIENT,LIST_CATALOG,%s,FILES_FINAL,count=%d', catalog, len(files))

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            self.logger.debug('CLIENT,LIST_CATALOG,%s,OUTPUT_DIR,CREATED,%s', catalog, output_dir)

        written = []
        try:
            for f in files:
                key = f.get("token_file")
                self.logger.debug('CLIENT,LIST_CATALOG,%s,GET_FILE,START,key=%s', catalog, key)
                metadata = self.get_metadata(key, session=session)
                data = self.get(key, session=session)
                if data is None:
                    self.logger.error('CLIENT,LIST_CATALOG,%s,GET_FILE,ERROR,key=%s,msg=download_failed', catalog, key)
                    continue
                if output_dir:
                    output_path = os.path.join(output_dir, metadata.get("name", key))
                    with open(output_path, "wb") as file_out:
                        file_out.write(data)
                    written.append(output_path)
                    self.logger.debug('CLIENT,LIST_CATALOG,%s,GET_FILE,END,SAVED,key=%s,path=%s,bytes=%d',
                                      catalog, key, output_path, len(data))
        except Exception as e:
            self.logger.exception('CLIENT,LIST_CATALOG,%s,ERROR,exception=%s', catalog, e)

        self.logger.debug('CLIENT,LIST_CATALOG,%s,END,SUCCESS,written_count=%d', catalog, len(written))
        return written

    def put(self,
            data: bytes,
            catalog: str,
            key: str = None,
            name: str = None,
            session: requests.Session = None,
            is_encrypted: bool = False,
            resiliency: int = 1,
            nodes=None,
            retries: int = 5):

        start_time = time.perf_counter_ns()
        session = session or requests.Session()

        # --- Metadata prep ---
        key = str(uuid.uuid4()) if key is None else key
        data_hash = hashlib.sha3_256(data).hexdigest()
        name = data_hash if name is None else name

        self.logger.debug('CLIENT,PUT,%s,START,catalog=%s,name=%s,raw_bytes=%d,encrypted=%d,resiliency=%d,nodes=%d',
                          key, catalog, name, len(data), int(is_encrypted), resiliency, len(nodes or []))

        # Compression
        t0 = time.perf_counter_ns()
        try:
            data_compressed = self.object_compressor.compress(data)
        except Exception as e:
            self.logger.error('CLIENT,PUT,%s,COMPRESS,ERROR,%s', key, e)
            raise CompressException(f'Compression failed: {str(e)}')
        t1 = time.perf_counter_ns()
        self.logger.debug('CLIENT,PUT,%s,COMPRESS,END,bytes_in=%d,bytes_out=%d,time_ms=%.3f,ratio=%.4f',
                          key, len(data), len(data_compressed), (t1 - t0) / 1e6,
                          (len(data_compressed) / max(1, len(data))))

        # Encryption (optional)
        if is_encrypted:
            self.logger.debug('CLIENT,PUT,%s,ENCRYPT,START', key)
        t0 = time.perf_counter_ns()
        try:
            data_encrypted = self.object_encrypter.encrypt(data_compressed) if is_encrypted else data_compressed
        except Exception as e:
            self.logger.error('CLIENT,PUT,%s,ENCRYPT,ERROR,%s', key, e)
            raise EncryptionException(f'Encryption failed: {str(e)}')
        t1 = time.perf_counter_ns()
        if is_encrypted:
            self.logger.debug('CLIENT,PUT,%s,ENCRYPT,END,bytes=%d,time_ms=%.3f',
                              key, len(data_encrypted), (t1 - t0) / 1e6)

        enc_len = len(data_encrypted)
        enc_hash = hashlib.sha3_256(data_encrypted).hexdigest()
        num_chunks = ceil(enc_len / MAX_CHUNK_LENGTH)

        self.logger.debug('CLIENT,PUT,%s,DATA_READY,bytes=%d,hash_enc=%s,max_chunk_len=%d,num_chunks=%d',
                          key, enc_len, enc_hash, MAX_CHUNK_LENGTH, num_chunks)

        payload = {
            "name": name,
            "size": enc_len,
            "hash": data_hash,
            "key": key,
            "is_encrypted": int(is_encrypted),
            "resiliency": resiliency,
            "nodes": nodes or [],
        }

        # --- Step 1: Send metadata ---
        metadata_url = f'http://{self.metadata_server}/metadata/{self.token_data["user_token"]}/{key}'
        self.logger.debug('CLIENT,PUT,%s,METADATA,START,url=%s', key, metadata_url)
        try:
            t0 = time.perf_counter_ns()
            metadata_resp = Client._retry_request(
                session.post, metadata_url, retries=retries, expected_code=200, json=payload
            )
            t1 = time.perf_counter_ns()
            self.logger.debug('CLIENT,PUT,%s,METADATA,END,SUCCESS,status=%d,time_ms=%.3f',
                              key, metadata_resp.status_code, (t1 - t0) / 1e6)
        except Exception as e:
            self.logger.error('CLIENT,PUT,%s,METADATA,END,ERROR,%s', key, e)
            return None

        # --- Step 2: Stream file content ---
        upload_url = f'http://{self.metadata_server}/upload/{self.token_data["user_token"]}/{catalog}/{key}'
        self.logger.debug('CLIENT,PUT,%s,UPLOAD,START,url=%s,num_chunks=%d', key, upload_url, num_chunks)
        try:
            t0 = time.perf_counter_ns()
            upload_resp = Client._retry_request(
                session.put, upload_url, retries=retries, expected_code=201,
                data=chunk_bytes(data_encrypted, MAX_CHUNK_LENGTH),
                stream=True,
                headers={"Content-Type": "application/octet-stream"}
            )
            t1 = time.perf_counter_ns()
            self.logger.debug('CLIENT,PUT,%s,UPLOAD,END,SUCCESS,status=%d,time_ms=%.3f',
                              key, upload_resp.status_code, (t1 - t0) / 1e6)
        except Exception as e:
            self.logger.error('CLIENT,PUT,%s,UPLOAD,END,ERROR,%s', key, e)
            return None

        end = time.perf_counter_ns()
        try:
            upload_json = upload_resp.json()
        except Exception:
            upload_json = {}

        result = {
            "total_time": (end - start_time) / 1e6,
            "metadata_time": metadata_resp.json().get("total_time", 0) / 1e6 if metadata_resp is not None else 0.0,
            "upload_time": upload_json.get("time_upload", 0) / 1e6,
            "key_object": key
        }

        self.logger.debug('CLIENT,PUT,%s,END,SUCCESS,total_time_ms=%.3f,metadata_time_ms=%.3f,upload_time_ms=%.3f',
                          key, result["total_time"], result["metadata_time"], result["upload_time"])
        return result

    @staticmethod
    def _retry_request(method, url, retries=5, retry_codes=(404,), expected_code=200, stream=False, **kwargs):
        logger = logging.getLogger(__name__)
        backoff = 1.0
        last_exception = None
        response = None

        for i in range(retries):
            try:
                logger.debug('CLIENT,HTTP,REQUEST,TRY,%d,url=%s,expected=%d', i + 1, url, expected_code)
                response = method(url, stream=stream, **kwargs)
                status = response.status_code
                if status == expected_code:
                    logger.debug('CLIENT,HTTP,REQUEST,SUCCESS,try=%d,status=%d,url=%s', i + 1, status, url)
                    return response
                elif status in retry_codes and i < retries - 1:
                    logger.debug('CLIENT,HTTP,REQUEST,RETRY,%d,status=%d,url=%s,backoff_s=%.1f',
                                 i + 1, status, url, backoff)
                    time.sleep(backoff)
                    backoff *= 2
                else:
                    # Not retryable or no retries left
                    try:
                        response.raise_for_status()
                    except requests.exceptions.RequestException as e:
                        last_exception = e
                        logger.error('CLIENT,HTTP,REQUEST,ERROR,try=%d,status=%d,url=%s,msg=%s',
                                     i + 1, status, url, e)
                    break
            except requests.exceptions.RequestException as e:
                last_exception = e
                if i < retries - 1:
                    logger.warning('CLIENT,HTTP,REQUEST,EXCEPTION,try=%d,url=%s,msg=%s,backoff_s=%.1f',
                                   i + 1, url, e, backoff)
                    time.sleep(backoff)
                    backoff *= 2
                else:
                    logger.error('CLIENT,HTTP,REQUEST,EXCEPTION,final,url=%s,msg=%s', url, e)

        # If we reach here, we failed
        body = None
        try:
            if response is not None:
                body = response.text
        except Exception:
            body = None
        msg = f"Failed to get a valid response after {retries} retries: {url}"
        if body:
            msg += f" | last_body={body[:512]}"
        if last_exception:
            msg += f" | exception={last_exception}"
        logger.error('CLIENT,HTTP,REQUEST,FAIL,url=%s,msg=%s', url, msg)
        raise RuntimeError(msg)
