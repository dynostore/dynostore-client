#!/usr/bin/env python3
import argparse
import csv
import json
import os
import sys
import time
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Iterable

import requests
from dynostore.client import Client

logging.basicConfig(level=logging.INFO, format="%(levelname)s,%(name)s,%(message)s", stream=sys.stdout)
logger = logging.getLogger("bench-dyno")

# ---------- Helpers ----------
def human_size_to_bytes(s: str) -> int:
    s = s.strip().lower()
    units = {"":1,"b":1,"k":1024,"kb":1024,"m":1024**2,"mb":1024**2,"g":1024**3,"gb":1024**3}
    num, unit = "", ""
    for ch in s:
        if ch.isdigit() or ch == ".": num += ch
        else: unit += ch
    if not num: raise ValueError(f"Invalid size: {s}")
    unit = unit.strip()
    if unit not in units: raise ValueError(f"Unknown unit in '{s}'")
    return int(float(num) * units[unit])

def make_payload(size: int, pattern: str) -> bytes:
    if size <= 0: return b""
    if pattern == "zero": return bytes(size)
    if pattern == "repeat":
        block = os.urandom(1024)
        reps, rem = divmod(size, len(block))
        return block * reps + block[:rem]
    if pattern == "urandom": return os.urandom(size)
    raise ValueError(f"Unknown pattern: {pattern}")

def duration_from_event(event: Dict[str, Any]) -> Optional[float]:
    """Compute duration in ms from {start, end} dicts."""
    try: return (event["end"] - event["start"]) / 1e6
    except Exception: return None

def poll_upload_timeline(base_url: str, token_user: str, key: str,
                         timeout_s: float, interval_s: float) -> Dict[str, Any]:
    """Poll upload timeline until coding_status is completed/failed or timeout."""
    url = f"http://{base_url}/timeline/{token_user}/{key}"
    deadline = time.time() + timeout_s
    last = {}
    while True:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 404:
                time.sleep(interval_s)
            else:
                r.raise_for_status()
                last = r.json()
                status = str(last.get("coding_status") or "").lower()
                if status in ("completed", "failed"):
                    return last
        except requests.exceptions.RequestException as e:
            logger.warning(f"timeline poll error key={key}: {e}")
        if time.time() >= deadline:
            return last
        time.sleep(interval_s)

def poll_download_timeline(base_url: str, token_user: str, key: str,
                           timeout_s: float, interval_s: float) -> Dict[str, Any]:
    """
    Poll download timeline until 'pull_end' exists or timeout.
    Server's pull_data writes: pull_start, pull_end, and detailed phases.
    """
    url = f"http://{base_url}/timeline/{token_user}/{key}"
    deadline = time.time() + timeout_s
    last = {}
    while True:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 404:
                time.sleep(interval_s)
            else:
                r.raise_for_status()
                last = r.json()
                if "pull_end" in last:
                    return last
        except requests.exceptions.RequestException as e:
            logger.warning(f"pull timeline poll error key={key}: {e}")
        if time.time() >= deadline:
            return last
        time.sleep(interval_s)

def flatten_servers_info(servers_info: Any) -> Dict[str, Any]:
    """Flatten servers_info list into indexed keys for CSV."""
    flat: Dict[str, Any] = {}
    if not isinstance(servers_info, list): return flat
    flat["servers_count"] = len(servers_info)
    for i, item in enumerate(servers_info):
        if isinstance(item, dict):
            for k, v in item.items():
                flat[f"server[{i}].{k}"] = v
        else:
            flat[f"server[{i}]"] = json.dumps(item, ensure_ascii=False)
    return flat

def write_csv(rows: List[Dict[str, Any]], base_order: List[str], path: str):
    if not rows:
        logger.info(f"No rows to write for {path}; skipping.")
        return
    Path(os.path.dirname(path) or ".").mkdir(parents=True, exist_ok=True)
    all_keys = set()
    for r in rows: all_keys.update(r.keys())
    fieldnames = base_order + sorted(all_keys - set(base_order))
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    logger.info(f"Saved {len(rows)} rows to {path}")

# ---------- Core ----------
def run_benchmark(
    server: str,
    catalog: str,
    sizes_labels: List[str],
    count: int,
    pattern: str,
    encrypt: bool,
    resiliency: int,
    op: str,
    csv_upload: str,
    csv_download: str,
    poll_timeout_s: float,
    poll_interval_s: float,
):
    client = Client(metadata_server=server)
    sizes_bytes = [(label, human_size_to_bytes(label)) for label in sizes_labels]
    payload_cache: Dict[int, bytes] = {}

    rows_upload: List[Dict[str, Any]] = []
    rows_download: List[Dict[str, Any]] = []

    # -------- Upload phase (upload count objects per size) --------
    if op in ("upload", "both"):
        for size_label, size_bytes in sizes_bytes:
            logger.info(f"=== Upload size {size_label} ({size_bytes} B): {count} objects ===")
            if size_bytes not in payload_cache:
                payload_cache[size_bytes] = make_payload(size_bytes, pattern)
            payload = payload_cache[size_bytes]

            for i in range(count):
                t0 = time.perf_counter_ns()
                try:
                    result = client.put(
                        data=payload,
                        catalog=catalog,
                        is_encrypted=encrypt,
                        resiliency=resiliency,
                        key=None
                    )
                except Exception as e:
                    logger.error(f"put failed size={size_label} idx={i}: {e}")
                    result = None
                t1 = time.perf_counter_ns()

                key_object = (result or {}).get("key_object")
                local_upload_ms = (t1 - t0) / 1e6

                # Poll server for upload timeline completion
                timeline: Dict[str, Any] = {}
                if key_object:
                    timeline = poll_upload_timeline(
                        base_url=server,
                        token_user=client.token_data.get('user_token','NA'),
                        key=key_object,
                        timeout_s=poll_timeout_s,
                        interval_s=poll_interval_s,
                    )

                row: Dict[str, Any] = {
                    "op": "upload",
                    "size_label": size_label,
                    "size_bytes": size_bytes,
                    "index": i,
                    "key_object": key_object or "",
                    "pattern": pattern,
                    "encrypt": int(encrypt),
                    "resiliency": resiliency,
                    "local_upload_ms": local_upload_ms,
                    "server_status": timeline.get("coding_status", ""),
                    "server_stream_ms": duration_from_event(timeline.get("stream", {})),
                    "server_catalog_ms": duration_from_event(timeline.get("catalog", {})),
                    "server_fragment_push_ms": duration_from_event(timeline.get("fragment_push", {})),
                    "server_ec_ms": duration_from_event(timeline.get("erasure_coding", {})),
                }
                row.update(flatten_servers_info(timeline.get("servers_info")))
                rows_upload.append(row)
                logger.info(f"UP size={size_label} idx={i} key={key_object} up_ms={local_upload_ms:.3f} status={row['server_status']}")

    # -------- Download phase (upload one seed per size, then download it N times) --------
    if op in ("download", "both"):
        for size_label, size_bytes in sizes_bytes:
            # ensure payload exists
            if size_bytes not in payload_cache:
                payload_cache[size_bytes] = make_payload(size_bytes, pattern)
            payload = payload_cache[size_bytes]

            # 1) upload one seed per size
            logger.info(f"=== Seed for download: size {size_label} ({size_bytes} B) ===")
            try:
                seed_result = client.put(
                    data=payload,
                    catalog=catalog,
                    is_encrypted=encrypt,
                    resiliency=resiliency,
                    key=None
                )
            except Exception as e:
                logger.error(f"seed put failed size={size_label}: {e}")
                continue

            seed_key = (seed_result or {}).get("key_object")
            if not seed_key:
                logger.error(f"Missing key_object for seed size={size_label}")
                continue

            # wait for EC completion for seed to avoid partial availability issues
            _ = poll_upload_timeline(
                base_url=server,
                token_user=client.token_data.get('user_token','NA'),
                key=seed_key,
                timeout_s=poll_timeout_s,
                interval_s=poll_interval_s,
            )

            # 2) download seed N times
            logger.info(f"=== Download size {size_label}: key={seed_key} x {count} ===")
            for j in range(count):
                t0 = time.perf_counter_ns()
                try:
                    data = client.get(seed_key)
                except Exception as e:
                    logger.error(f"get failed size={size_label} rep={j} key={seed_key}: {e}")
                    data = None
                t1 = time.perf_counter_ns()

                local_download_ms = (t1 - t0) / 1e6
                downloaded_bytes = len(data) if data is not None else None

                # Poll for the pull timeline (pull_end)
                pull_tl: Dict[str, Any] = poll_download_timeline(
                    base_url=server,
                    token_user=client.token_data.get('user_token','NA'),
                    key=seed_key,
                    timeout_s=poll_timeout_s,
                    interval_s=poll_interval_s,
                )

                pull_total_ms = None
                try:
                    pull_total_ms = (pull_tl["pull_end"] - pull_tl["pull_start"]) / 1e6
                except Exception:
                    pass

                row: Dict[str, Any] = {
                    "op": "download",
                    "size_label": size_label,
                    "size_bytes": size_bytes,
                    "index": j,                      # repetition index
                    "key_object": seed_key,
                    "pattern": pattern,
                    "encrypt": int(encrypt),
                    "resiliency": resiliency,
                    "local_download_ms": local_download_ms,
                    "downloaded_bytes": downloaded_bytes,
                    "server_pull_total_ms": pull_total_ms,
                    "server_pull_metadata_ms": duration_from_event(pull_tl.get("Metadata retrieval", {})),
                    "server_pull_chunks_ms": duration_from_event(pull_tl.get("Chunk retrieval", {})),
                    "server_pull_reconstruct_ms": duration_from_event(pull_tl.get("Object reconstruction", {})),
                    "server_pull_cache_ms": duration_from_event(pull_tl.get("Object caching", {})),
                }
                rows_download.append(row)
                logger.info(f"DOWN size={size_label} rep={j} key={seed_key} down_ms={local_download_ms:.3f} pull_ms={pull_total_ms}")

    # ---------- CSVs ----------
    base_order_upload = [
        "op",
        "size_label",
        "size_bytes",
        "index",
        "key_object",
        "pattern",
        "encrypt",
        "resiliency",
        "local_upload_ms",
        "server_status",
        "server_stream_ms",
        "server_catalog_ms",
        "server_fragment_push_ms",
        "server_ec_ms",
        # servers_info columns will follow
    ]
    base_order_download = [
        "op",
        "size_label",
        "size_bytes",
        "index",
        "key_object",
        "pattern",
        "encrypt",
        "resiliency",
        "local_download_ms",
        "downloaded_bytes",
        "server_pull_total_ms",
        "server_pull_metadata_ms",
        "server_pull_chunks_ms",
        "server_pull_reconstruct_ms",
        "server_pull_cache_ms",
    ]

    if rows_upload:
        write_csv(rows_upload, base_order_upload, csv_upload)
    if rows_download:
        write_csv(rows_download, base_order_download, csv_download)

# ---------- CLI ----------
def main():
    p = argparse.ArgumentParser(
        description="DynoStore benchmark: upload/download/both; multi-sizes. Saves upload and download metrics to separate CSVs."
    )
    p.add_argument("--server", required=True, help="Server address, e.g., 127.0.0.1:5000")
    p.add_argument("--catalog", required=False, default="default", help="Catalog name")
    p.add_argument("--sizes", nargs="+", default=["10MB"], help="Sizes for operations, e.g., 1MB 10MB 100MB")
    p.add_argument("--count", type=int, default=5, help="Objects per size (upload) OR repetitions per size (download)")
    p.add_argument("--pattern", choices=["zero", "repeat", "urandom"], default="repeat", help="Payload pattern for uploads/seeds")
    p.add_argument("--encrypt", default=True, action="store_true", help="Encrypt uploads")
    p.add_argument("--resiliency", type=int, default=1, help="Resiliency level")
    p.add_argument("--op", choices=["upload","download","both"], default="upload", help="What to benchmark")
    p.add_argument("--csv-upload", default="bench_upload.csv", help="CSV path for upload metrics")
    p.add_argument("--csv-download", default="bench_download.csv", help="CSV path for download metrics")
    p.add_argument("--poll-timeout", type=float, default=60.0, help="Max seconds to wait for upload EC / pull completion")
    p.add_argument("--poll-interval", type=float, default=1.0, help="Seconds between timeline polls")
    args = p.parse_args()

    run_benchmark(
        server=args.server,
        catalog=args.catalog,
        sizes_labels=args.sizes,
        count=args.count,
        pattern=args.pattern,
        encrypt=args.encrypt,
        resiliency=args.resiliency,
        op=args.op,
        csv_upload=args.csv_upload,
        csv_download=args.csv_download,
        poll_timeout_s=args.poll_timeout,
        poll_interval_s=args.poll_interval,
    )
    return 0

if __name__ == "__main__":
    sys.exit(main())
