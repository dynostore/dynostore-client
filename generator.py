#!/usr/bin/env python3
import argparse
import os
from pathlib import Path
from random import Random

MIN_BYTES_DEFAULT = 1 * 1024           # 1 KB
MAX_BYTES_DEFAULT = 10 * 1024 * 1024   # 10 MB
CHUNK_SIZE = 1 * 1024 * 1024           # write in 1 MB chunks

def human(n: int) -> str:
    for unit in ("B","KB","MB","GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.2f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024

def make_file(path: Path, size_bytes: int, rng: Random) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    remaining = size_bytes
    with path.open("wb") as f:
        while remaining > 0:
            chunk_len = min(CHUNK_SIZE, remaining)
            f.write(os.urandom(chunk_len))
            remaining -= chunk_len

def main():
    p = argparse.ArgumentParser(description="Create N files with random sizes between 1KB and 10MB.")
    p.add_argument("n", type=int, help="number of files to create")
    p.add_argument("-o", "--outdir", default="./random_files", help="output directory (default: ./random_files)")
    p.add_argument("--min-kb", type=int, default=MIN_BYTES_DEFAULT // 1024, help="minimum size in KB (default: 1)")
    p.add_argument("--max-mb", type=int, default=MAX_BYTES_DEFAULT // (1024*1024), help="maximum size in MB (default: 10)")
    p.add_argument("--prefix", default="file_", help="filename prefix (default: file_)")
    p.add_argument("--seed", type=int, default=None, help="random seed (optional; for reproducible sizes)")
    args = p.parse_args()

    if args.n <= 0:
        raise SystemExit("n must be > 0")

    min_bytes = args.min_kb * 1024
    max_bytes = args.max_mb * 1024 * 1024
    if min_bytes > max_bytes:
        raise SystemExit("min-kb must be <= max-mb*1024")

    rng = Random(args.seed)
    outdir = Path(args.outdir)

    print(f"Creating {args.n} files in {outdir.resolve()} (sizes {args.min_kb}KB .. {args.max_mb}MB)")
    for i in range(1, args.n + 1):
        size_bytes = rng.randint(min_bytes, max_bytes)
        name = f"{args.prefix}{i:04d}_{size_bytes}B.bin"
        path = outdir / name
        make_file(path, size_bytes, rng)
        print(f" ✓ {name}  ({human(size_bytes)})")

if __name__ == "__main__":
    main()
