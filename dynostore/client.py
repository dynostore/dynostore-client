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


logger = logging.getLogger(__name__)


def _log(operation: str, key: str, phase: str, status: str, msg: str = ""):
    # Format: SERVICE, OPERATION, OBJECTKEY, START/END, Status, MSG
    logger.debug(f"CLIENT,{operation},{key},{phase},{status},{msg}")


class EncryptionException(Exception):
    pass


class DecompressException(Exception):
    pass


class CompressException(Exception):
    pass


class Client(object):

    def __init__(self, metadata_server):
        self.metadata_server = metadata_server
        self.object_compressor = ObjectCompressor()
        self.object_encrypter = SecureObjectStore("aaaa")
        _log("INIT", "-", "START", "RUN", f"metadata_server={metadata_server}")
        authenticator = DeviceAuthenticator(auth_url=self.metadata_server)
        authenticator.authenticate()
        self.token_data = authenticator.token_data
        _log("INIT", "-", "END", "SUCCESS", f"user_token={self.token_data.get('user_token','NA')}")

    def evict(self, key: str, session: requests.Session = None, retries: int = 5) -> None:
        _log("EVICT", key, "START", "RUN", "")
        url = f'http://{self.metadata_server}/storage/{self.token_data["user_token"]}/{key}'
        method = (session or requests).delete
        try:
            response = Client._retry_request(method, url, retries=retries, expected_code=200,
                                             op="EVICT_HTTP", obj_key=key)
            if response.ok:
                _log("EVICT", key, "END", "SUCCESS", f"status={response.status_code}")
        except Exception as e:
            _log("EVICT", key, "END", "ERROR", f"msg={e}")
        return

    def exists(self, key: str, session: requests.Session = None, retries: int = 5) -> bool:
        _log("EXISTS", key, "START", "RUN", "")
        url = f'http://{self.metadata_server}/storage/{self.token_data["user_token"]}/{key}/exists'
        method = (session or requests).get
        try:
            response = Client._retry_request(method, url, retries=retries, expected_code=200,
                                             op="EXISTS_HTTP", obj_key=key)
            ok = response.json().get("exists", False)
            _log("EXISTS", key, "END", "SUCCESS", f"status={response.status_code};exists={ok}")
            return ok
        except Exception as e:
            _log("EXISTS", key, "END", "ERROR", f"msg={e}")
            return False

    def get(self, key: str, session: requests.Session = None, retries: int = 5) -> bytes:
        _log("GET", key, "START", "RUN", "")
        url = f'http://{self.metadata_server}/storage/{self.token_data["user_token"]}/{key}'
        method = (session or requests).get
        retransmit = True
        max_retries = 3

        while retransmit and max_retries > 0:
            try:
                response = Client._retry_request(method, url, retries=retries, retry_codes=(404,),
                                                 expected_code=200, stream=True, op="GET_HTTP", obj_key=key)
            except Exception as e:
                max_retries -= 1
                _log("GET", key, "END", "ERROR", f"phase=HTTP;remaining_retries={max_retries};msg={e}")
                continue

            data = bytearray()
            t0 = time.perf_counter_ns()
            for chunk in response.iter_content(chunk_size=None):
                data += chunk
            recv_ms = (time.perf_counter_ns() - t0) / 1e6
            _log("GET", key, "END", "SUCCESS", f"phase=RECEIVE;bytes={len(data)};time_ms={recv_ms:.3f}")

            if response.headers.get('is_encrypted', '0') == '1':
                try:
                    _log("GET", key, "START", "RUN", "phase=DECRYPT")
                    t0 = time.perf_counter_ns()
                    data = self.object_encrypter.decrypt(data)
                    _log("GET", key, "END", "SUCCESS",
                         f"phase=DECRYPT;bytes={len(data)};time_ms={(time.perf_counter_ns()-t0)/1e6:.3f}")
                except Exception as e:
                    _log("GET", key, "END", "ERROR", f"phase=DECRYPT;msg={e}")
                    raise EncryptionException(f'Decryption failed: {str(e)}')

            try:
                _log("GET", key, "START", "RUN", "phase=DECOMPRESS")
                t0 = time.perf_counter_ns()
                data = self.object_compressor.decompress(data)
                out_bytes = 'None' if data is None else len(data)
                _log("GET", key, "END", "SUCCESS",
                     f"phase=DECOMPRESS;bytes={out_bytes};time_ms={(time.perf_counter_ns()-t0)/1e6:.3f}")
            except Exception as e:
                _log("GET", key, "END", "ERROR", f"phase=DECOMPRESS;msg={e}")
                raise DecompressException(f'Decompression failed: {str(e)}')

            if data is None:
                max_retries -= 1
                retransmit = True
                _log("GET", key, "END", "ERROR", "phase=DECOMPRESS;msg=None_bytes;retrying=1")
            else:
                retransmit = False

        if retransmit:
            _log("GET", key, "END", "ERROR", "msg=Max retries reached;aborting")
            return None

        _log("GET", key, "END", "SUCCESS", f"FINAL_BYTES={len(data)}")
        return bytes(data)

    def get_metadata(self, key: str, session: requests.Session = None, retries: int = 5) -> dict:
        _log("GET_METADATA", key, "START", "RUN", "")
        url = f'http://{self.metadata_server}/storage/{self.token_data["user_token"]}/{key}/exists'
        method = (session or requests).get
        try:
            response = Client._retry_request(method, url, retries=retries, expected_code=200,
                                             op="GET_METADATA_HTTP", obj_key=key)
            meta = response.json().get("metadata", {})
            _log("GET_METADATA", key, "END", "SUCCESS", f"keys={list(meta.keys())}")
            return meta
        except Exception as e:
            _log("GET_METADATA", key, "END", "ERROR", f"msg={e}")
            return {}

    def get_files_in_catalog(self, catalog: str, output_dir: str = None,
                             session: requests.Session = None, retries: int = 5) -> list:
        op = "GET_CATALOG"
        _log(op, catalog, "START", "RUN", f"output_dir={output_dir}")
        method = (session or requests).get

        catalog_url = f'http://{self.metadata_server}/pubsub/{self.token_data["user_token"]}/catalog/{catalog}'
        try:
            response = Client._retry_request(method, catalog_url, retries=retries, expected_code=200,
                                             op=f"{op}_LOOKUP", obj_key=catalog)
        except Exception as e:
            _log(op, catalog, "END", "ERROR", f"phase=LOOKUP;msg={e}")
            return []

        catalog_info = response.json().get("data", {})
        catalog_key = catalog_info.get("tokencatalog")

        list_url = f'http://{self.metadata_server}/pubsub/{self.token_data["user_token"]}/catalog/{catalog_key}/list'
        try:
            response = Client._retry_request(method, list_url, retries=retries, expected_code=201,
                                             op=f"{op}_LIST", obj_key=catalog)
        except Exception as e:
            _log(op, catalog, "END", "ERROR", f"phase=LIST;msg={e}")
            return []

        print("Response:", response.status_code, response.text)
        files = response.json().get("data", [])
        print(files)
        _log(op, catalog, "END", "SUCCESS", f"phase=LIST;count={len(files)}")

        i = 0
        while not files and i < 10:
            try:
                response = Client._retry_request(method, list_url, retries=retries, expected_code=201,
                                                 op=f"{op}_LIST_RETRY", obj_key=catalog)
                files = response.json().get("data", [])
                _log(op, catalog, "END", "SUCCESS", f"phase=LIST_RETRY;attempt={i+1};count={len(files)}")
            except Exception as e:
                _log(op, catalog, "END", "ERROR", f"phase=LIST_RETRY;attempt={i+1};msg={e}")
                break
            i += 1

        paths = []
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            _log(op, catalog, "END", "SUCCESS", f"phase=MKDIR;output_dir={output_dir}")

        try:
            for f in files:
                key = f.get("token_file")
                _log(op, key or "-", "START", "RUN", "phase=DOWNLOAD_FILE")
                metadata = self.get_metadata(key, session=session)
                data = self.get(key, session=session)
                if data is None:
                    _log(op, key or "-", "END", "ERROR", "phase=DOWNLOAD_FILE;msg=null_data")
                    continue
                if output_dir:
                    out = os.path.join(output_dir, metadata.get("name", key))
                    with open(out, "wb") as fo:
                        fo.write(data)
                    paths.append(out)
                    _log(op, key or "-", "END", "SUCCESS", f"phase=WRITE_FILE;path={out};bytes={len(data)}")
        except Exception as e:
            _log(op, catalog, "END", "ERROR", f"phase=FILES_LOOP;msg={e}")

        _log(op, catalog, "END", "SUCCESS", f"written_count={len(paths)}")
        return paths

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

        session = session or requests.Session()
        key = str(uuid.uuid4()) if key is None else key
        data_hash = hashlib.sha3_256(data).hexdigest()
        name = data_hash if name is None else name

        _log("PUT", key, "START", "RUN",
             f"catalog={catalog};name={name};raw_bytes={len(data)};encrypted={int(is_encrypted)};"
             f"resiliency={resiliency};nodes={len(nodes or [])}")

        # Compress
        try:
            t0 = time.perf_counter_ns()
            data_compressed = self.object_compressor.compress(data)
            _log("PUT", key, "END", "SUCCESS",
                 f"phase=COMPRESS;bytes_in={len(data)};bytes_out={len(data_compressed)};"
                 f"time_ms={(time.perf_counter_ns()-t0)/1e6:.3f};ratio={len(data_compressed)/max(1,len(data)):.4f}")
        except Exception as e:
            _log("PUT", key, "END", "ERROR", f"phase=COMPRESS;msg={e}")
            raise CompressException(f'Compression failed: {str(e)}')

        # Encrypt (optional)
        try:
            t0 = time.perf_counter_ns()
            data_encrypted = self.object_encrypter.encrypt(data_compressed) if is_encrypted else data_compressed
            if is_encrypted:
                _log("PUT", key, "END", "SUCCESS",
                     f"phase=ENCRYPT;bytes={len(data_encrypted)};time_ms={(time.perf_counter_ns()-t0)/1e6:.3f}")
        except Exception as e:
            _log("PUT", key, "END", "ERROR", f"phase=ENCRYPT;msg={e}")
            raise EncryptionException(f'Encryption failed: {str(e)}')

        enc_len = len(data_encrypted)
        enc_hash = hashlib.sha3_256(data_encrypted).hexdigest()
        num_chunks = ceil(enc_len / MAX_CHUNK_LENGTH)
        _log("PUT", key, "END", "SUCCESS",
             f"phase=DATA_READY;bytes={enc_len};hash_enc={enc_hash};max_chunk_len={MAX_CHUNK_LENGTH};num_chunks={num_chunks}")

        payload = {
            "name": name,
            "size": enc_len,
            "hash": data_hash,
            "key": key,
            "is_encrypted": int(is_encrypted),
            "resiliency": resiliency,
            "nodes": nodes or [],
        }

        # Step 1: metadata
        metadata_url = f'http://{self.metadata_server}/metadata/{self.token_data["user_token"]}/{key}'
        _log("PUT", key, "START", "RUN", f"phase=METADATA;url={metadata_url}")
        try:
            metadata_resp = Client._retry_request(session.post, metadata_url, retries=retries, expected_code=200,
                                                  json=payload, op="PUT_METADATA_HTTP", obj_key=key)
            _log("PUT", key, "END", "SUCCESS", f"phase=METADATA;status={metadata_resp.status_code}")
        except Exception as e:
            _log("PUT", key, "END", "ERROR", f"phase=METADATA;msg={e}")
            return None

        # Step 2: upload
        upload_url = f'http://{self.metadata_server}/upload/{self.token_data["user_token"]}/{catalog}/{key}'
        _log("PUT", key, "START", "RUN", f"phase=UPLOAD;url={upload_url};num_chunks={num_chunks}")
        try:
            upload_resp = Client._retry_request(session.put, upload_url, retries=retries, expected_code=201,
                                                data=chunk_bytes(data_encrypted, MAX_CHUNK_LENGTH),
                                                stream=True,
                                                headers={"Content-Type": "application/octet-stream"},
                                                op="PUT_UPLOAD_HTTP", obj_key=key)
            _log("PUT", key, "END", "SUCCESS", f"phase=UPLOAD;status={upload_resp.status_code}")
        except Exception as e:
            _log("PUT", key, "END", "ERROR", f"phase=UPLOAD;msg={e}")
            return None

        # Summary
        try:
            upload_json = upload_resp.json()
        except Exception:
            upload_json = {}

        result = {
            "total_time": None,  # not tracked here after refactor
            "metadata_time": metadata_resp.json().get("total_time", 0) / 1e6 if metadata_resp is not None else 0.0,
            "upload_time": upload_json.get("time_upload", 0) / 1e6,
            "key_object": key
        }
        _log("PUT", key, "END", "SUCCESS",
             f"phase=SUMMARY;metadata_time_ms={result['metadata_time']:.3f};upload_time_ms={result['upload_time']:.3f}")
        return result

    @staticmethod
    def _retry_request(method, url, retries=5, retry_codes=(404,), expected_code=200, stream=False,
                       op="HTTP", obj_key="-", **kwargs):
        backoff = 1.0
        last_exception = None
        response = None

        for i in range(retries):
            try:
                _log(op, obj_key, "START", "TRY",
                     f"url={url};try={i+1}/{retries};expected={expected_code}")
                response = method(url, stream=stream, **kwargs)
                status = response.status_code
                if status == expected_code:
                    _log(op, obj_key, "END", "SUCCESS", f"url={url};status={status}")
                    return response
                elif status in retry_codes and i < retries - 1:
                    _log(op, obj_key, "END", "RETRY",
                         f"url={url};status={status};backoff_s={backoff:.1f}")
                    time.sleep(backoff)
                    backoff *= 2
                else:
                    try:
                        response.raise_for_status()
                    except requests.exceptions.RequestException as e:
                        last_exception = e
                        _log(op, obj_key, "END", "ERROR", f"url={url};status={status};msg={e}")
                    break
            except requests.exceptions.RequestException as e:
                last_exception = e
                if i < retries - 1:
                    _log(op, obj_key, "END", "RETRY",
                         f"url={url};exception={e};backoff_s={backoff:.1f}")
                    time.sleep(backoff)
                    backoff *= 2
                else:
                    _log(op, obj_key, "END", "ERROR", f"url={url};exception={e}")

        body = None
        try:
            if response is not None:
                body = response.text
        except Exception:
            body = None
        msg = f"url={url}"
        if body:
            msg += f";last_body={body[:256]}"
        if last_exception:
            msg += f";exception={last_exception}"
        _log(op, obj_key, "END", "FAIL", msg)
        raise RuntimeError(f"Failed after {retries} retries: {url}")
