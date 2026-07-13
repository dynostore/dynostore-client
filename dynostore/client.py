import httpx
import asyncio
import uuid
import time
import hashlib
import os
import logging
import urllib.parse
from math import ceil
from dynostore.nfrs.compress import ObjectCompressor
from dynostore.nfrs.cipher import SecureObjectStore
from dynostore.auth.authenticate import DeviceAuthenticator
from dynostore.utils.data import chunk_bytes, async_chunk_bytes
from dynostore.constants import MAX_CHUNK_LENGTH


logger = logging.getLogger(__name__)


def _log(operation: str, key: str, phase: str, status: str, msg: str = ""):
    # Format: SERVICE, OPERATION, OBJECTKEY, START/END, Status, MSG
    logger.debug(f"CLIENT,{operation},{key},{phase},{status},{msg}")


def _ms(ns_start: int) -> float:
    return (time.perf_counter_ns() - ns_start) / 1e6


class EncryptionException(Exception):
    pass


class DecompressException(Exception):
    pass


class CompressException(Exception):
    pass


class Client(object):

    def __init__(self, metadata_server):
        t0 = time.perf_counter_ns()
        self.metadata_server = metadata_server
        self.object_compressor = ObjectCompressor()
        self.object_encrypter = SecureObjectStore("my_secret_password") #ToDO: make password configurable
        authenticator = DeviceAuthenticator(auth_url=self.metadata_server)
        t_auth = time.perf_counter_ns()
        authenticator.authenticate()
        auth_ms = _ms(t_auth)
        self.token_data = authenticator.token_data
        _log("AUTHENTICATION", "-", "-", "SUCCESS",
             f"user_token={self.token_data.get('user_token','NA')};auth_time_ms={auth_ms:.3f};total_time_ms={_ms(t0):.3f}")

    async def evict(self, key: str, session: httpx.AsyncClient = None, retries: int = 5) -> None:
        t0 = time.perf_counter_ns()
        _log("EVICT", key, "START", "RUN", "")
        url = f'http://{self.metadata_server}/storage/{self.token_data["user_token"]}/{urllib.parse.quote(key, safe="")}'
        method = session.delete if session else httpx.AsyncClient().delete
        try:
            t_call = time.perf_counter_ns()
            response = await Client._retry_request(method, url, retries=retries, expected_code=200,
                                             op="EVICT_HTTP", obj_key=key)
            http_ms = (time.perf_counter_ns() - t_call) / 1e6
            if response.is_success:
                _log("EVICT", key, "END", "SUCCESS",
                     f"status={response.status_code};http_time_ms={http_ms:.3f};total_time_ms={_ms(t0):.3f}")
        except Exception as e:
            _log("EVICT", key, "END", "ERROR", f"msg={e};total_time_ms={_ms(t0):.3f}")
            raise RuntimeError(f"Evict failed: {e}")
        return

    async def exists(self, key: str, session: httpx.AsyncClient = None, retries: int = 5) -> bool:
        t0 = time.perf_counter_ns()
        _log("EXISTS", key, "START", "RUN", "")
        url = f'http://{self.metadata_server}/storage/{self.token_data["user_token"]}/{urllib.parse.quote(key, safe="")}/exists'
        method = session.get if session else httpx.AsyncClient().get
        try:
            t_call = time.perf_counter_ns()
            response = await Client._retry_request(method, url, retries=retries, expected_code=200,
                                             op="EXISTS_HTTP", obj_key=key)
            http_ms = (time.perf_counter_ns() - t_call) / 1e6
            ok = response.json().get("exists", False)
            _log("EXISTS", key, "END", "SUCCESS",
                 f"status={response.status_code};exists={ok};http_time_ms={http_ms:.3f};total_time_ms={_ms(t0):.3f}")
            return ok
        except Exception as e:
            _log("EXISTS", key, "END", "ERROR", f"msg={e};total_time_ms={_ms(t0):.3f}")
            raise RuntimeError(f"Exists check failed: {e}")

    async def get(self, key: str, session: httpx.AsyncClient = None, retries: int = 5) -> bytes:
        t_total = time.perf_counter_ns()
        _log("GET", key, "START", "RUN", "")
        url = f'http://{self.metadata_server}/storage/{self.token_data["user_token"]}/{urllib.parse.quote(key, safe="")}'
        method = session.get if session else httpx.AsyncClient().get
        retransmit = True
        max_retries = 3

        while retransmit and max_retries > 0:
            try:
                t_call = time.perf_counter_ns()
                response = await Client._retry_request(method, url, retries=retries, retry_codes=(404, 500, 502, 503, 504),
                                                 expected_code=200, stream=True, op="GET_HTTP", obj_key=key)
                http_ms = (time.perf_counter_ns() - t_call) / 1e6
            except Exception as e:
                max_retries -= 1
                _log("GET", key, "END", "ERROR",
                     f"phase=HTTP;remaining_retries={max_retries};msg={e};total_time_ms={_ms(t_total):.3f}")
                continue

            data = bytearray()
            t_recv = time.perf_counter_ns()
            #for chunk in response.iter_content(chunk_size=None):
            #    data += chunk
            data = response.read() if hasattr(response, 'read') else response.content
            
            recv_ms = (time.perf_counter_ns() - t_recv) / 1e6
            _log("GET", key, "END", "SUCCESS", f"phase=RECEIVE;bytes={len(data)};http_time_ms={http_ms:.3f};time_ms={recv_ms:.3f}")

            if str(response.headers.get('is_encrypted', 'False')).lower() == 'true':
                try:
                    _log("GET", key, "START", "RUN", "phase=DECRYPT")
                    t_dec = time.perf_counter_ns()
                    data = self.object_encrypter.decrypt_bytes(data)
                    _log("GET", key, "END", "SUCCESS",
                         f"phase=DECRYPT;bytes={len(data)};time_ms={(time.perf_counter_ns()-t_dec)/1e6:.3f}")
                except Exception as e:
                    _log("GET", key, "END", "ERROR", f"phase=DECRYPT;msg={e};total_time_ms={_ms(t_total):.3f}")
                    raise EncryptionException(f'Decryption failed: {str(e)}')

            try:
                _log("GET", key, "START", "RUN", "phase=DECOMPRESS")
                t_decomp = time.perf_counter_ns()
                
                data = self.object_compressor.decompress(data)
                
                out_bytes = 'None' if data is None else len(data)
                _log("GET", key, "END", "SUCCESS",
                     f"phase=DECOMPRESS;bytes={out_bytes};time_ms={(time.perf_counter_ns()-t_decomp)/1e6:.3f}")
            except Exception as e:
                _log("GET", key, "END", "ERROR", f"phase=DECOMPRESS;msg={e};total_time_ms={_ms(t_total):.3f}")
                raise DecompressException(f'Decompression failed: {str(e)}')

            if data is None:
                max_retries -= 1
                retransmit = True
                _log("GET", key, "END", "ERROR", f"phase=DECOMPRESS;msg=None_bytes;retrying=1;total_time_ms={_ms(t_total):.3f}")
            else:
                retransmit = False

        if retransmit:
            _log("GET", key, "END", "ERROR", f"msg=Max retries reached;aborting;total_time_ms={_ms(t_total):.3f}")
            raise RuntimeError("Max retries reached; aborting GET operation")

        _log("GET", key, "END", "SUCCESS", f"FINAL_BYTES={len(data)};total_time_ms={_ms(t_total):.3f}")
        return bytes(data)

    async def get_metadata(self, key: str, session: httpx.AsyncClient = None, retries: int = 5) -> dict:
        t0 = time.perf_counter_ns()
        _log("GET_METADATA", key, "START", "RUN", "")
        url = f'http://{self.metadata_server}/storage/{self.token_data["user_token"]}/{urllib.parse.quote(key, safe="")}/exists'
        method = session.get if session else httpx.AsyncClient().get
        try:
            t_call = time.perf_counter_ns()
            response = await Client._retry_request(method, url, retries=retries, expected_code=200,
                                             op="GET_METADATA_HTTP", obj_key=key)
            http_ms = (time.perf_counter_ns() - t_call) / 1e6
            meta = response.json().get("metadata", {})
            _log("GET_METADATA", key, "END", "SUCCESS",
                 f"keys={list(meta.keys())};http_time_ms={http_ms:.3f};total_time_ms={_ms(t0):.3f}")
            return meta
        except Exception as e:
            _log("GET_METADATA", key, "END", "ERROR", f"msg={e};total_time_ms={_ms(t0):.3f}")
            raise RuntimeError(f"Get metadata failed: {e}")

    async def get_files_in_catalog(self, catalog: str, output_dir: str = None,
                             session: httpx.AsyncClient = None, retries: int = 5) -> list:
        t_total = time.perf_counter_ns()
        op = "GET_CATALOG"
        _log(op, catalog, "START", "RUN", f"output_dir={output_dir}")
        method = session.get if session else httpx.AsyncClient().get

        catalog_url = f'http://{self.metadata_server}/pubsub/{self.token_data["user_token"]}/catalog/{urllib.parse.quote(catalog, safe="")}'
        try:
            t_call = time.perf_counter_ns()
            response = await Client._retry_request(method, catalog_url, retries=retries, expected_code=200,
                                             op=f"{op}_LOOKUP", obj_key=catalog)
            lookup_http_ms = (time.perf_counter_ns() - t_call) / 1e6
        except Exception as e:
            _log(op, catalog, "END", "ERROR", f"phase=LOOKUP;msg={e};total_time_ms={_ms(t_total):.3f}")
            raise RuntimeError(f"Catalog lookup failed: {e}")

        #print(f"Catalog info: {response}")
        catalog_info = response.json().get("data", {})
        catalog_key = catalog_info.get("tokencatalog")

        list_url = f'http://{self.metadata_server}/pubsub/{self.token_data["user_token"]}/catalog/{urllib.parse.quote(catalog_key, safe="")}/list'
        try:
            t_call = time.perf_counter_ns()
            response = await Client._retry_request(method, list_url, retries=retries, expected_code=201,
                                             op=f"{op}_LIST", obj_key=catalog)
            list_http_ms = (time.perf_counter_ns() - t_call) / 1e6
        except Exception as e:
            _log(op, catalog, "END", "ERROR", f"phase=LIST;msg={e};total_time_ms={_ms(t_total):.3f}")
            raise RuntimeError(f"Catalog list failed: {e}")


        files = response.json().get("data", [])
        _log(op, catalog, "END", "SUCCESS",
             f"phase=LIST;count={len(files)};lookup_http_time_ms={lookup_http_ms:.3f};list_http_time_ms={list_http_ms:.3f}")

        i = 0
        while not files and i < 10:
            print(f"Catalog {catalog} is empty, retrying list (attempt {i+1}/10)...")
            try:
                t_call = time.perf_counter_ns()
                response = await Client._retry_request(method, list_url, retries=retries, expected_code=201,
                                                 op=f"{op}_LIST_RETRY", obj_key=catalog)
                retry_http_ms = (time.perf_counter_ns() - t_call) / 1e6
                files = response.json().get("data", [])
                _log(op, catalog, "END", "SUCCESS",
                     f"phase=LIST_RETRY;attempt={i+1};count={len(files)};http_time_ms={retry_http_ms:.3f}")
            except Exception as e:
                _log(op, catalog, "END", "ERROR",
                     f"phase=LIST_RETRY;attempt={i+1};msg={e};total_time_ms={_ms(t_total):.3f}")
                break
            i += 1

        # If we still have no files, we shall try with subcatalogs
        sub_catalogs_url = f'http://{self.metadata_server}/pubsub/{self.token_data["user_token"]}/catalog/{urllib.parse.quote(catalog_key, safe="")}/children'

        try:
            t_call = time.perf_counter_ns()
            response = await Client._retry_request(method, sub_catalogs_url, retries=retries, expected_code=200,
                                             op=f"{op}_SUBCATALOGS", obj_key=catalog)
            #print(f"Subcatalogs response: {response}")
            subcatalogs_http_ms = (time.perf_counter_ns() - t_call) / 1e6
            sub_catalogs = response.json().get("data", [])
            _log(op, catalog, "END", "SUCCESS",
                 f"phase=SUBCATALOGS;count={len(sub_catalogs)};http_time_ms={subcatalogs_http_ms:.3f}")
            
            for subcat in sub_catalogs:
                subcat_name = subcat.get("namecatalog")
                if not subcat_name:
                    continue
                subcat_files = await self.get_files_in_catalog(subcat_name, output_dir=f"{output_dir}/{subcat_name.split('_')[-1]}" if output_dir else None,
                                                              session=session, retries=retries)
            #    #files.extend(subcat_files)
        except Exception as e:
            _log(op, catalog, "END", "ERROR", f"phase=SUBCATALOGS;msg={e};total_time_ms={_ms(t_total):.3f}")
            raise RuntimeError(f"Catalog subcatalogs failed: {e}")

        paths = []
        if output_dir:
            t_mkdir = time.perf_counter_ns()
            os.makedirs(output_dir, exist_ok=True)
            _log(op, catalog, "END", "SUCCESS",
                 f"phase=MKDIR;output_dir={output_dir};time_ms={_ms(t_mkdir):.3f}")

        async def _download_file(f):
            key = f.get("token_file")
            t_dl = time.perf_counter_ns()
            _log(op, key or "-", "START", "RUN", "phase=DOWNLOAD_FILE")
            metadata = await self.get_metadata(key, session=session)
            data = await self.get(key, session=session)
            dl_ms = _ms(t_dl)
            if data is None:
                _log(op, key or "-", "END", "ERROR", f"phase=DOWNLOAD_FILE;msg=null_data;time_ms={dl_ms:.3f}")
                return None
            if output_dir:
                t_write = time.perf_counter_ns()
                out = os.path.join(output_dir, metadata.get("name", key))
                with open(out, "wb") as fo:
                    fo.write(data)
                _log(op, key or "-", "END", "SUCCESS",
                     f"phase=WRITE_FILE;path={out};bytes={len(data)};download_time_ms={dl_ms:.3f};write_time_ms={_ms(t_write):.3f}")
                return out
            return None

        try:
            results = await asyncio.gather(*[_download_file(f) for f in files])
            paths = [r for r in results if r is not None]
        except Exception as e:
            _log(op, catalog, "END", "ERROR", f"phase=FILES_LOOP;msg={e};total_time_ms={_ms(t_total):.3f}")
            raise RuntimeError(f"Failed to download catalog files: {e}")

        _log(op, catalog, "END", "SUCCESS", f"written_count={len(paths)};total_time_ms={_ms(t_total):.3f}")
        return paths

    async def put(self,
            data: bytes,
            catalog: str,
            key: str = None,
            name: str = None,
            session: httpx.AsyncClient = None,
            is_encrypted: bool = False,
            resiliency: int = 1,
            nodes=None,
            retries: int = 5):

        t_total = time.perf_counter_ns()
        close_session = False
        if session is None:
            session = httpx.AsyncClient()
            close_session = True
        key = str(uuid.uuid4()) if key is None else key
        data_hash = hashlib.sha3_256(data).hexdigest()
        name = data_hash if name is None else name

        _log("PUT", key, "START", "RUN",
             f"catalog={catalog};name={name};raw_bytes={len(data)};encrypted={int(is_encrypted)};"
             f"resiliency={resiliency};")

        # Compress
        try:
            t_comp = time.perf_counter_ns()
            data_compressed = self.object_compressor.compress(data)
            _log("PUT", key, "COMPRESSING", "SUCCESS",
                 f"phase=COMPRESS;bytes_in={len(data)};bytes_out={len(data_compressed)};"
                 f"time_ms={(time.perf_counter_ns()-t_comp)/1e6:.3f};ratio={len(data_compressed)/max(1,len(data)):.4f}")
        except Exception as e:
            _log("PUT", key, "COMPRESSING", "ERROR", f"msg={e};total_time_ms={_ms(t_total):.3f}")
            raise CompressException(f'Compression failed: {str(e)}')

        # Encrypt (optional)
        try:
            t_enc = time.perf_counter_ns()
            data_encrypted = self.object_encrypter.encrypt_bytes(data_compressed) if is_encrypted else data_compressed
            if is_encrypted:
                _log("PUT", key, "ENCRYPT", "SUCCESS",
                     f"bytes={len(data_encrypted)};time_ms={(time.perf_counter_ns()-t_enc)/1e6:.3f}")
        except Exception as e:
            _log("PUT", key, "ENCRYPT", "ERROR", f"msg={e};total_time_ms={_ms(t_total):.3f}")
            raise EncryptionException(f'Encryption failed: {str(e)}')

        enc_len = len(data_encrypted)
        enc_hash = hashlib.sha3_256(data_encrypted).hexdigest()
        num_chunks = ceil(enc_len / MAX_CHUNK_LENGTH)
        
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
        metadata_url = f'http://{self.metadata_server}/metadata/{self.token_data["user_token"]}/{urllib.parse.quote(key, safe="")}'
        try:
            t_http = time.perf_counter_ns()
            metadata_resp = await Client._retry_request(session.post, metadata_url, retries=retries, expected_code=200,
                                                  json=payload, op="PUT_METADATA_HTTP", obj_key=key)
            http_ms = (time.perf_counter_ns() - t_http) / 1e6
            _log("PUT", key, "METADATA_UPLOAD", "SUCCESS", f"status={metadata_resp.status_code};http_time_ms={http_ms:.3f}")
        except Exception as e:
            _log("PUT", key, "METADATA_UPLOAD", "ERROR", f"msg={e};total_time_ms={_ms(t_total):.3f}")
            raise RuntimeError(f"Put metadata failed: {e}")

        # Step 2: upload
        upload_url = f'http://{self.metadata_server}/upload/{self.token_data["user_token"]}/{urllib.parse.quote(catalog, safe="")}/{urllib.parse.quote(key, safe="")}'
        _log("PUT", key, "START", "RUN", f"phase=UPLOAD;url={upload_url};num_chunks={num_chunks}")
        try:
            t_http = time.perf_counter_ns()
            upload_resp = await Client._retry_request(session.put, upload_url, retries=retries, expected_code=201,
                                                content=data_encrypted,
                                                headers={"Content-Type": "application/octet-stream"},
                                                op="PUT_UPLOAD_HTTP", obj_key=key)
            upload_http_ms = (time.perf_counter_ns() - t_http) / 1e6
            _log("PUT", key, "OBJECT_UPLOAD", "SUCCESS", f"status={upload_resp.status_code};http_time_ms={upload_http_ms:.3f}")
        except Exception as e:
            _log("PUT", key, "OBJECT_UPLOAD", "ERROR", f"msg={e};total_time_ms={_ms(t_total):.3f}")
            raise RuntimeError(f"Put object failed: {e}")

        # Summary
        try:
            upload_json = upload_resp.json()
        except Exception:
            upload_json = {}

        result = {
            "total_time": _ms(t_total),  # ms
            "metadata_time": upload_json.get("time_metadata_ms") if upload_json.get("time_metadata_ms") is not None
                               else None,
            "upload_time": upload_json.get("time_upload", 0) / 1e6,  # server-reported ns -> ms (if present)
            "key_object": key
        }
        _log("PUT", key, "SUMMARY", "SUCCESS",
             f"client_total_time_ms={result['total_time']:.3f}")
        if close_session:
            await session.aclose()
        return result

    @staticmethod
    async def _retry_request(method, url, retries=5, retry_codes=(404, 500, 502, 503, 504), expected_code=200, stream=False,
                       op="HTTP", obj_key="-", **kwargs):
        backoff = 1.0
        last_exception = None
        response = None

        # httpx doesn't use stream kwargs in the method call for async clients in the same way, we'll strip it
        for i in range(retries):
            try:
                t_call = time.perf_counter_ns()
                response = await method(url, **kwargs)
                print(f"Response: {response.status_code}, {response.text}")
                dt_ms = (time.perf_counter_ns() - t_call) / 1e6
                status = response.status_code
                if status == expected_code:
                    return response
                elif status in retry_codes and i < retries - 1:
                    await asyncio.sleep(backoff)
                    backoff *= 2
                else:
                    try:
                        response.raise_for_status()
                    except httpx.RequestError as e:
                        last_exception = e
                    except httpx.HTTPStatusError as e:
                        last_exception = e
                    break
            except httpx.RequestError as e:
                print(f"Request error: {e}")
                last_exception = e
                if i < retries - 1:
                    await asyncio.sleep(backoff)
                    backoff *= 2
                else:
                    _log(op, obj_key, "END", "ERROR", f"url={url};exception={e}")

        body = None
        try:
            if response is not None:
                if stream and hasattr(response, "aread"):
                    await response.aread()
                body = response.text
        except Exception:
            body = None
        msg = f"url={url}"
        if body:
            msg += f";last_body={body[:256]}"
        if last_exception:
            msg += f";exception={last_exception}"
        _log(op, obj_key, "END", "FAIL", msg)
        raise RuntimeError(f"Failed after {retries} retries: {url}. Details: {msg}")
